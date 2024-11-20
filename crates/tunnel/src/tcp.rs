use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::stream::FuturesUnordered;
use futures::Sink;
use futures::Stream;
use pin_project_lite::pin_project;
use std::any::Any;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::ready;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::{TcpListener, TcpSocket};
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes;

use crate::common::check_scheme_and_get_socket_addr_ext;
use crate::packet_def::TCPTunnelHeader;
use crate::IpVersion;
use crate::{
    buf::BufList,
    common::{
        build_url_from_socket_addr, check_scheme_and_get_socket_addr, setup_sokcet2,
        wait_for_connect_futures, TunnelWrapper,
    },
    packet_def::{PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE},
    Error, SinkItem, StreamItem, Tunnel, TunnelInfo, TunnelListener, ZCPacket, ZCPacketType,
};

const TCP_MTU_BYTES: usize = 2000;

pub struct TcpZCPacketToBytes;

pub trait ZCPacketToBytes {
    fn into_bytes(&self, zc_packet: ZCPacket) -> Result<Bytes, Error>;
}

impl ZCPacketToBytes for TcpZCPacketToBytes {
    fn into_bytes(&self, item: ZCPacket) -> Result<Bytes, Error> {
        let mut item = item.convert_type(ZCPacketType::TCP);

        let tcp_len = PEER_MANAGER_HEADER_SIZE + item.payload_len();
        let header = item.mut_tcp_tunnel_header()?;
        header.len.set(tcp_len.try_into().unwrap());

        Ok(item.into_bytes())
    }
}

pin_project! {
    pub struct FramedWriter<W, C> {
        #[pin]
        writer: W,
        sending_bufs: BufList<Bytes>,
        associate_data: Option<Box<dyn Any + Send + 'static>>,

        converter: C,
    }
}

impl<W, C> FramedWriter<W, C> {
    fn max_buffer_count(&self) -> usize {
        64
    }
}

impl<W> FramedWriter<W, TcpZCPacketToBytes> {
    pub fn new(writer: W) -> Self {
        Self::new_with_associate_data(writer, None)
    }

    pub fn new_with_associate_data(
        writer: W,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        FramedWriter {
            writer,
            sending_bufs: BufList::new(),
            associate_data,
            converter: TcpZCPacketToBytes {},
        }
    }
}

impl<W, C: ZCPacketToBytes + Send + 'static> FramedWriter<W, C> {
    pub fn new_with_converter(writer: W, converter: C) -> Self {
        Self::new_with_converter_and_associate_data(writer, converter, None)
    }

    pub fn new_with_converter_and_associate_data(
        writer: W,
        converter: C,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        FramedWriter {
            writer,
            sending_bufs: BufList::new(),
            associate_data,
            converter,
        }
    }
}

impl<W, C> Sink<SinkItem> for FramedWriter<W, C>
where
    W: AsyncWrite + Send + 'static,
    C: ZCPacketToBytes + Send + 'static,
{
    type Error = Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let max_buffer_count = self.max_buffer_count();
        if self.sending_bufs.bufs_cnt() >= max_buffer_count {
            self.as_mut().poll_flush(cx)
        } else {
            tracing::trace!(bufs_cnt = self.sending_bufs.bufs_cnt(), "ready to send");
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: ZCPacket) -> Result<(), Self::Error> {
        let pinned = self.project();
        pinned.sending_bufs.push(pinned.converter.into_bytes(item)?);

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let mut pinned = self.project();
        let mut remaining = pinned.sending_bufs.remaining();
        while remaining != 0 {
            let n = ready!(poll_write_buf(
                pinned.writer.as_mut(),
                cx,
                pinned.sending_bufs
            ))?;
            if n == 0 {
                return Poll::Ready(Err(Error::IOError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to \
                     write frame to transport",
                ))));
            }
            remaining -= n;
        }

        tracing::trace!(?remaining, "flushed");

        // Try flushing the underlying IO
        ready!(pinned.writer.poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        ready!(self.project().writer.poll_shutdown(cx))?;

        Poll::Ready(Ok(()))
    }
}

// a length delimited codec for async reader
pin_project! {
    pub struct FramedReader<R> {
        #[pin]
        reader: R,
        buf: BytesMut,
        max_packet_size: usize,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    }
}

// usize means the size remaining to read
// enum FrameReaderState {
//     ReadingHeader(usize),
//     ReadingBody(usize),
// }

impl<R> FramedReader<R> {
    pub fn new(reader: R, max_packet_size: usize) -> Self {
        Self::new_with_associate_data(reader, max_packet_size, None)
    }

    pub fn new_with_associate_data(
        reader: R,
        max_packet_size: usize,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        FramedReader {
            reader,
            buf: BytesMut::with_capacity(max_packet_size),
            // state: FrameReaderState::ReadingHeader(4),
            max_packet_size,
            associate_data,
        }
    }

    fn extract_one_packet(
        buf: &mut BytesMut,
        max_packet_size: usize,
    ) -> Option<Result<ZCPacket, Error>> {
        if buf.len() < TCP_TUNNEL_HEADER_SIZE {
            // header is not complete
            return None;
        }

        let (header, _) = TCPTunnelHeader::ref_from_prefix(&buf[..]).unwrap();
        let body_len = header.len.get() as usize;
        if body_len > max_packet_size {
            // body is too long
            return Some(Err(Error::InvalidPacket("body too long".to_string())));
        }

        if buf.len() < TCP_TUNNEL_HEADER_SIZE + body_len {
            // body is not complete
            return None;
        }

        // extract one packet
        let packet_buf = buf.split_to(TCP_TUNNEL_HEADER_SIZE + body_len);
        Some(Ok(ZCPacket::new_from_buf(packet_buf, ZCPacketType::TCP)))
    }
}

pub fn reserve_buf(buf: &mut BytesMut, min_size: usize, max_size: usize) {
    if buf.capacity() < min_size {
        buf.reserve(max_size);
    }
}

impl<R> Stream for FramedReader<R>
where
    R: AsyncRead + Send + 'static + Unpin,
{
    type Item = StreamItem;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut self_mut = self.project();

        loop {
            while let Some(packet) =
                Self::extract_one_packet(self_mut.buf, *self_mut.max_packet_size)
            {
                return Poll::Ready(Some(packet));
            }

            reserve_buf(
                &mut self_mut.buf,
                *self_mut.max_packet_size,
                *self_mut.max_packet_size * 32,
            );

            let cap = self_mut.buf.capacity() - self_mut.buf.len();
            let buf = self_mut.buf.chunk_mut().as_mut_ptr();
            let buf = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
            let mut buf = ReadBuf::new(buf);

            let ret = ready!(self_mut.reader.as_mut().poll_read(cx, &mut buf));
            let len = buf.filled().len();
            unsafe { self_mut.buf.advance_mut(len) };

            match ret {
                Ok(_) => {
                    if len == 0 {
                        return Poll::Ready(None);
                    }
                }
                Err(e) => {
                    return Poll::Ready(Some(Err(Error::IOError(e))));
                }
            }
        }
    }
}

fn get_tunnel_with_tcp_stream(
    stream: TcpStream,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, Error> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(?e, "set_nodelay fail in get_tunnel_with_tcp_stream");
    }

    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(
            build_url_from_socket_addr(&stream.local_addr()?.to_string(), "tcp").into(),
        ),
        remote_addr: Some(remote_url.into()),
    };

    let (r, w) = stream.into_split();
    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new(r, TCP_MTU_BYTES),
        FramedWriter::new(w),
        Some(info),
    )))
}

#[derive(Debug)]
pub struct TcpTunnelConnector {
    addr: url::Url,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
}

impl TcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelConnector {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
        }
    }

    async fn connect_with_default_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, Error> {
        tracing::info!(addr = ?self.addr, "connect tcp start");
        let stream = TcpStream::connect(addr).await?;
        tracing::info!(addr = ?self.addr, "connect tcp succ");
        return get_tunnel_with_tcp_stream(stream, self.addr.clone().into());
    }

    async fn connect_with_custom_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(bind_addr = ?bind_addr, ?addr, "bind addr");

            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(addr),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;

            if let Err(e) = setup_sokcet2(&socket2_socket, bind_addr) {
                tracing::error!(bind_addr = ?bind_addr, ?addr, "bind addr fail: {:?}", e);
                continue;
            }

            let socket = TcpSocket::from_std_stream(socket2_socket.into());
            futures.push(socket.connect(addr.clone()));
        }

        let ret = wait_for_connect_futures(futures).await;
        return get_tunnel_with_tcp_stream(ret?, self.addr.clone().into());
    }
}

#[async_trait]
impl super::TunnelConnector for TcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        let addr =
            check_scheme_and_get_socket_addr_ext::<SocketAddr>(&self.addr, "tcp", self.ip_version)?;
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}

#[derive(Debug)]
pub struct TcpTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
}

impl TcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelListener {
            addr,
            listener: None,
        }
    }
}

#[async_trait]
impl TunnelListener for TcpTunnelListener {
    async fn listen(&mut self) -> Result<(), Error> {
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;

        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        setup_sokcet2(&socket2_socket, &addr)?;
        let socket = TcpSocket::from_std_stream(socket2_socket.into());

        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!(?e, "set_nodelay fail in listen");
        }

        self.addr
            .set_port(Some(socket.local_addr()?.port()))
            .unwrap();

        self.listener = Some(socket.listen(1024)?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await?;

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(?e, "set_nodelay fail in accept");
        }

        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                build_url_from_socket_addr(&stream.peer_addr()?.to_string(), "tcp").into(),
            ),
        };

        let (r, w) = stream.into_split();
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new(r, TCP_MTU_BYTES),
            FramedWriter::new(w),
            Some(info),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

mod tests {

    #[tokio::test]
    async fn tcp_pingpong() {
        use super::*;
        use crate::common::tests::_tunnel_pingpong;

        let listener = TcpTunnelListener::new("tcp://0.0.0.0:31011".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:31011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }
}
