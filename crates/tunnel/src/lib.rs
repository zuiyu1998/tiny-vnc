//!EasyTier

pub mod buf;
pub mod common;
pub mod packet_def;
pub mod platform;
pub mod tcp;

use async_trait::async_trait;
use futures::{Sink, Stream};
use network_interface::NetworkInterfaceConfig;
use packet_def::{ZCPacket, ZCPacketType};
use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};
use thiserror::Error;
use url::Url;
use zerocopy::CastError;

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

pub(crate) fn check_scheme_and_get_socket_addr<T>(url: &url::Url, scheme: &str) -> Result<T, Error>
where
    T: FromUrl,
{
    if url.scheme() != scheme {
        return Err(Error::InvalidProtocol(url.scheme().to_string()));
    }

    Ok(T::from_url(url.clone(), IpVersion::Both)?)
}

pub type StreamItem = Result<ZCPacket, Error>;
pub type SinkItem = ZCPacket;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid packet. msg: {0}")]
    InvalidPacket(String),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),
    #[error("no dns record found")]
    NoDnsRecordFound(IpVersion),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Both,
}

///隧道读信道
pub trait ZCPacketStream: Stream<Item = StreamItem> + Send {}

impl<T: Stream<Item = StreamItem> + Send> ZCPacketStream for T {}

///隧道写信道
pub trait ZCPacketSink: Sink<SinkItem, Error = Error> + Send {}

impl<T: Sink<SinkItem, Error = Error> + Send> ZCPacketSink for T {}

//隧道信息
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    tunnel_type: String,
    local_addr: Option<Url>,
    remote_addr: Option<Url>,
}

///隧道
pub trait Tunnel: Send {
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>);
    fn info(&self) -> Option<TunnelInfo>;
}

///服务器
#[async_trait]
pub trait TunnelListener: Send {
    async fn listen(&mut self) -> Result<(), Error>;
    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, Error>;
    fn local_url(&self) -> Url;
    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        #[derive(Debug)]
        struct FakeTunnelConnCounter {}
        impl TunnelConnCounter for FakeTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                None
            }
        }
        Arc::new(Box::new(FakeTunnelConnCounter {}))
    }
}

//客户端
#[async_trait]
pub trait TunnelConnector: Send {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, Error>;
    fn remote_url(&self) -> Url;
    fn set_bind_addrs(&mut self, _addrs: Vec<SocketAddr>) {}
    fn set_ip_version(&mut self, _ip_version: IpVersion) {}
}

pub trait TunnelConnCounter: 'static + Send + Sync + Debug {
    fn get(&self) -> Option<u32>;
}
