use crate::{Error, IpVersion, Tunnel, TunnelInfo, ZCPacketSink, ZCPacketStream};
use network_interface::NetworkInterfaceConfig;
use std::{
    any::Any,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
};

use url::Url;

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
