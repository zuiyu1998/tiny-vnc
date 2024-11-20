//!EasyTier

pub mod buf;
pub mod common;
pub mod packet_def;
pub mod platform;
pub mod tcp;

use async_trait::async_trait;
use futures::{Sink, Stream};
use packet_def::{ZCPacket, ZCPacketType};
use std::{fmt::Debug, net::SocketAddr, pin::Pin, sync::Arc};
use thiserror::Error;
use url::Url;

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
    #[error("shutdown")]
    Shutdown,
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
