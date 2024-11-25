use crate::{Error, IpVersion, Tunnel, TunnelInfo, ZCPacketSink, ZCPacketStream};
use futures::{stream::FuturesUnordered, StreamExt};
use network_interface::NetworkInterfaceConfig;
use std::{
    any::Any,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
};

use url::Url;

pub struct NetNSGuard {}

impl NetNSGuard {
    pub fn new(_ns: Option<String>) -> Box<Self> {
        Box::new(NetNSGuard {})
    }
}

#[derive(Clone, Debug)]
pub struct NetNS {
    name: Option<String>,
}

impl NetNS {
    pub fn new(name: Option<String>) -> Self {
        NetNS { name }
    }

    pub async fn run_async<F, Fut, Ret>(&self, f: F) -> Ret
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Ret>,
    {
        // TODO: do we really need this lock
        // let _lock = LOCK.lock().await;
        let _guard = NetNSGuard::new(self.name.clone());
        f().await
    }

    pub fn run<F, Ret>(&self, f: F) -> Ret
    where
        F: FnOnce() -> Ret,
    {
        let _guard = NetNSGuard::new(self.name.clone());
        f()
    }

    pub fn guard(&self) -> Box<NetNSGuard> {
        NetNSGuard::new(self.name.clone())
    }

    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }
}

pub(crate) async fn wait_for_connect_futures<Fut, Ret, E>(
    mut futures: FuturesUnordered<Fut>,
) -> Result<Ret, Error>
where
    Fut: Future<Output = Result<Ret, E>> + Send + Sync,
    E: std::error::Error + Into<Error> + Send + Sync + 'static,
{
    // return last error
    let mut last_err = None;

    while let Some(ret) = futures.next().await {
        if let Err(e) = ret {
            last_err = Some(e.into());
        } else {
            return ret.map_err(|e| e.into());
        }
    }

    Err(last_err.unwrap_or(Error::Shutdown))
}

pub(crate) fn setup_sokcet2_ext(
    socket2_socket: &socket2::Socket,
    bind_addr: &SocketAddr,
    #[allow(unused_variables)] bind_dev: Option<String>,
) -> Result<(), Error> {
    #[cfg(target_os = "windows")]
    {
        let is_udp = matches!(socket2_socket.r#type()?, socket2::Type::DGRAM);
        crate::platform::windows::setup_socket_for_win(
            socket2_socket,
            bind_addr,
            bind_dev,
            is_udp,
        )?;
    }

    if bind_addr.is_ipv6() {
        socket2_socket.set_only_v6(true)?;
    }

    socket2_socket.set_nonblocking(true)?;
    socket2_socket.set_reuse_address(true)?;
    socket2_socket.bind(&socket2::SockAddr::from(*bind_addr))?;

    // #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    // socket2_socket.set_reuse_port(true)?;

    if bind_addr.ip().is_unspecified() {
        return Ok(());
    }

    // linux/mac does not use interface of bind_addr to send packet, so we need to bind device
    // win can handle this with bind correctly
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if let Some(dev_name) = bind_dev {
        // use IP_BOUND_IF to bind device
        unsafe {
            let dev_idx = nix::libc::if_nametoindex(dev_name.as_str().as_ptr() as *const i8);
            tracing::warn!(?dev_idx, ?dev_name, "bind device");
            socket2_socket.bind_device_by_index_v4(std::num::NonZeroU32::new(dev_idx))?;
            tracing::warn!(?dev_idx, ?dev_name, "bind device doen");
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(dev_name) = bind_dev {
        tracing::trace!(dev_name = ?dev_name, "bind device");
        socket2_socket.bind_device(Some(dev_name.as_bytes()))?;
    }

    Ok(())
}

pub(crate) fn get_interface_name_by_ip(local_ip: &IpAddr) -> Option<String> {
    if local_ip.is_unspecified() || local_ip.is_multicast() {
        return None;
    }
    let ifaces = network_interface::NetworkInterface::show().ok()?;
    for iface in ifaces {
        for addr in iface.addr {
            if addr.ip() == *local_ip {
                return Some(iface.name);
            }
        }
    }

    tracing::error!(?local_ip, "can not find interface name by ip");
    None
}

pub(crate) fn setup_sokcet2(
    socket2_socket: &socket2::Socket,
    bind_addr: &SocketAddr,
) -> Result<(), Error> {
    setup_sokcet2_ext(
        socket2_socket,
        bind_addr,
        get_interface_name_by_ip(&bind_addr.ip()),
    )
}

pub(crate) trait FromUrl {
    fn from_url(url: Url, ip_version: IpVersion) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromUrl for SocketAddr {
    fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, Error> {
        let addrs = url.socket_addrs(|| None)?;
        tracing::debug!(?addrs, ?ip_version, ?url, "convert url to socket addrs");
        let addrs = addrs
            .into_iter()
            .filter(|addr| match ip_version {
                IpVersion::V4 => addr.is_ipv4(),
                IpVersion::V6 => addr.is_ipv6(),
                IpVersion::Both => true,
            })
            .collect::<Vec<_>>();

        use rand::seq::SliceRandom;
        // randomly select one address
        addrs
            .choose(&mut rand::thread_rng())
            .copied()
            .ok_or(Error::NoDnsRecordFound(ip_version))
    }
}

pub(crate) fn check_scheme_and_get_socket_addr_ext<T>(
    url: &url::Url,
    scheme: &str,
    ip_version: IpVersion,
) -> Result<T, Error>
where
    T: FromUrl,
{
    if url.scheme() != scheme {
        return Err(Error::InvalidProtocol(url.scheme().to_string()));
    }

    Ok(T::from_url(url.clone(), ip_version)?)
}

pub(crate) fn check_scheme_and_get_socket_addr<T>(url: &url::Url, scheme: &str) -> Result<T, Error>
where
    T: FromUrl,
{
    if url.scheme() != scheme {
        return Err(Error::InvalidProtocol(url.scheme().to_string()));
    }

    Ok(T::from_url(url.clone(), IpVersion::Both)?)
}

pub fn build_url_from_socket_addr(addr: &String, scheme: &str) -> url::Url {
    if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
        let mut ret_url = url::Url::parse(format!("{}://0.0.0.0", scheme).as_str()).unwrap();
        ret_url.set_ip_host(sock_addr.ip()).unwrap();
        ret_url.set_port(Some(sock_addr.port())).unwrap();
        ret_url
    } else {
        url::Url::parse(format!("{}://{}", scheme, addr).as_str()).unwrap()
    }
}

pub struct TunnelWrapper<R, W> {
    reader: Arc<Mutex<Option<R>>>,
    writer: Arc<Mutex<Option<W>>>,
    info: Option<TunnelInfo>,
    associate_data: Option<Box<dyn Any + Send + 'static>>,
}

impl<R, W> TunnelWrapper<R, W> {
    pub fn new(reader: R, writer: W, info: Option<TunnelInfo>) -> Self {
        Self::new_with_associate_data(reader, writer, info, None)
    }

    pub fn new_with_associate_data(
        reader: R,
        writer: W,
        info: Option<TunnelInfo>,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        TunnelWrapper {
            reader: Arc::new(Mutex::new(Some(reader))),
            writer: Arc::new(Mutex::new(Some(writer))),
            info,
            associate_data,
        }
    }
}

impl<R, W> Tunnel for TunnelWrapper<R, W>
where
    R: ZCPacketStream + Send + 'static,
    W: ZCPacketSink + Send + 'static,
{
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>) {
        let reader = self.reader.lock().unwrap().take().unwrap();
        let writer = self.writer.lock().unwrap().take().unwrap();
        (Box::pin(reader), Box::pin(writer))
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub mod tests {
    use super::NetNS;
    use crate::{packet_def::ZCPacket, TunnelConnector, TunnelListener};
    use bytes::{BufMut, Bytes, BytesMut};
    use futures::{SinkExt, StreamExt, TryStreamExt};
    use std::time::Instant;

    pub(crate) async fn _tunnel_bench<L, C>(mut listener: L, mut connector: C)
    where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        listener.listen().await.unwrap();

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            _tunnel_echo_server(ret, false).await
        });

        let tunnel = connector.connect().await.unwrap();

        let (recv, mut send) = tunnel.split();

        // prepare a 4k buffer with random data
        let mut send_buf = BytesMut::new();
        for _ in 0..64 {
            send_buf.put_i128(rand::random::<i128>());
        }

        let r = tokio::spawn(async move {
            let now = Instant::now();
            let count = recv
                .try_fold(0usize, |mut ret, _| async move {
                    ret += 1;
                    Ok(ret)
                })
                .await
                .unwrap();

            println!(
                "bps: {}",
                (count / 1024) * 4 / now.elapsed().as_secs() as usize
            );
        });

        let now = Instant::now();
        while now.elapsed().as_secs() < 10 {
            // send.feed(item)
            let item = ZCPacket::new_with_payload(send_buf.as_ref());
            let _ = send.feed(item).await.unwrap();
        }

        send.close().await.unwrap();
        drop(send);
        drop(connector);
        drop(tunnel);

        tracing::warn!("wait for recv to finish...");

        let _ = tokio::join!(r);

        lis.abort();
        let _ = tokio::join!(lis);
    }

    pub(crate) async fn _tunnel_pingpong<L, C>(listener: L, connector: C)
    where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        _tunnel_pingpong_netns(
            listener,
            connector,
            NetNS::new(None),
            NetNS::new(None),
            "12345678abcdefg".as_bytes().to_vec(),
        )
        .await;
    }

    pub async fn _tunnel_echo_server(tunnel: Box<dyn super::Tunnel>, once: bool) {
        let (mut recv, mut send) = tunnel.split();

        if !once {
            while let Some(item) = recv.next().await {
                let Ok(msg) = item else {
                    continue;
                };
                if let Err(_) = send.send(msg).await {
                    break;
                }
            }
        } else {
            let Some(ret) = recv.next().await else {
                assert!(false, "recv error");
                return;
            };

            if ret.is_err() {
                tracing::debug!(?ret, "recv error");
                return;
            }

            let res = ret.unwrap();
            tracing::debug!(?res, "recv a msg, try echo back");
            send.send(res).await.unwrap();
        }
        let _ = send.flush().await;
        let _ = send.close().await;

        tracing::warn!("echo server exit...");
    }

    pub(crate) async fn _tunnel_pingpong_netns<L, C>(
        mut listener: L,
        mut connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
        buf: Vec<u8>,
    ) where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        l_netns
            .run_async(|| async {
                listener.listen().await.unwrap();
            })
            .await;

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            println!("accept: {:?}", ret.info());
            assert_eq!(
                url::Url::from(ret.info().unwrap().local_addr.unwrap()),
                listener.local_url()
            );
            _tunnel_echo_server(ret, false).await
        });

        let tunnel = c_netns.run_async(|| connector.connect()).await.unwrap();
        println!("connect: {:?}", tunnel.info());

        assert_eq!(
            url::Url::from(tunnel.info().unwrap().remote_addr.unwrap()),
            connector.remote_url(),
        );

        let (mut recv, mut send) = tunnel.split();

        send.send(ZCPacket::new_with_payload(buf.as_slice()))
            .await
            .unwrap();

        let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        println!("echo back: {:?}", ret);
        assert_eq!(ret.payload(), Bytes::from(buf));

        send.close().await.unwrap();

        if ["udp", "wg"].contains(&connector.remote_url().scheme()) {
            lis.abort();
        } else {
            // lis should finish in 1 second
            let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), lis).await;
            assert!(ret.is_ok());
        }
    }
}
