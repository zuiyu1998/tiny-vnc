use std::{
    collections::HashMap,
    fmt::Debug,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{ready, Context, Poll},
};

use crate::{
    common::{build_url_from_socket_addr, check_scheme_and_get_socket_addr, TunnelWrapper}, Error, SinkError, SinkItem, StreamItem, Tunnel, TunnelConnector, TunnelInfo, TunnelListener
};
use async_ringbuf::{traits::*, AsyncHeapCons, AsyncHeapProd, AsyncHeapRb};
use async_trait::async_trait;
use crossbeam::atomic::AtomicCell;
use futures::{Sink, SinkExt, Stream, StreamExt};
use uuid::Uuid;

use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    Mutex,
};

pub static RING_TUNNEL_CAP: usize = 128;
static RING_TUNNEL_RESERVERD_CAP: usize = 4;

type RingLock = parking_lot::Mutex<()>;

type RingItem = SinkItem;

pub struct RingTunnelConnector {
    remote_addr: url::Url,
}

impl RingTunnelConnector {
    pub fn new(remote_addr: url::Url) -> Self {
        RingTunnelConnector { remote_addr }
    }
}

#[async_trait]
impl TunnelConnector for RingTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        let remote_addr = check_scheme_and_get_socket_addr::<Uuid>(&self.remote_addr, "ring")?;
        let entry = CONNECTION_MAP
            .lock()
            .await
            .get(&remote_addr)
            .unwrap()
            .clone();
        tracing::info!("connecting");
        let conn = Arc::new(Connection {
            client: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
            server: Arc::new(RingTunnel::new_with_id(
                remote_addr.clone(),
                RING_TUNNEL_CAP,
            )),
        });
        entry
            .send(conn.clone())
            .map_err(|_| Error::InternalError("send conn to listner failed".to_owned()))?;
        Ok(Box::new(get_tunnel_for_client(conn)))
    }

    fn remote_url(&self) -> url::Url {
        self.remote_addr.clone()
    }
}

pub fn create_ring_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let conn = Arc::new(Connection {
        client: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
        server: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
    });
    (
        Box::new(get_tunnel_for_server(conn.clone())),
        Box::new(get_tunnel_for_client(conn)),
    )
}

struct Connection {
    client: Arc<RingTunnel>,
    server: Arc<RingTunnel>,
}

static CONNECTION_MAP: LazyLock<Arc<Mutex<HashMap<uuid::Uuid, UnboundedSender<Arc<Connection>>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Debug)]
pub struct RingTunnelListener {
    listerner_addr: url::Url,
    conn_sender: UnboundedSender<Arc<Connection>>,
    conn_receiver: UnboundedReceiver<Arc<Connection>>,
}

fn get_tunnel_for_client(conn: Arc<Connection>) -> impl Tunnel {
    TunnelWrapper::new(
        RingStream::new(conn.client.clone()),
        RingSink::new(conn.server.clone()),
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: Some(build_url_from_socket_addr(&conn.client.id.into(), "ring").into()),
            remote_addr: Some(build_url_from_socket_addr(&conn.server.id.into(), "ring").into()),
        }),
    )
}

fn get_tunnel_for_server(conn: Arc<Connection>) -> impl Tunnel {
    TunnelWrapper::new(
        RingStream::new(conn.server.clone()),
        RingSink::new(conn.client.clone()),
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: Some(build_url_from_socket_addr(&conn.server.id.into(), "ring").into()),
            remote_addr: Some(build_url_from_socket_addr(&conn.client.id.into(), "ring").into()),
        }),
    )
}

impl RingTunnelListener {
    fn get_addr(&self) -> Result<uuid::Uuid, Error> {
        check_scheme_and_get_socket_addr::<Uuid>(&self.listerner_addr, "ring")
    }
}

#[async_trait]
impl TunnelListener for RingTunnelListener {
    async fn listen(&mut self) -> Result<(), Error> {
        tracing::info!("listen new conn of key: {}", self.listerner_addr);
        CONNECTION_MAP
            .lock()
            .await
            .insert(self.get_addr()?, self.conn_sender.clone());
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        tracing::info!("waiting accept new conn of key: {}", self.listerner_addr);
        let my_addr = self.get_addr()?;
        if let Some(conn) = self.conn_receiver.recv().await {
            if conn.server.id == my_addr {
                tracing::info!("accept new conn of key: {}", self.listerner_addr);
                return Ok(Box::new(get_tunnel_for_server(conn)));
            } else {
                tracing::error!(?conn.server.id, ?my_addr, "got new conn with wrong id");
                return Err(Error::InternalError(
                    "accept got wrong ring server id".to_owned(),
                ));
            }
        }

        return Err(Error::InternalError("conn receiver stopped".to_owned()));
    }

    fn local_url(&self) -> url::Url {
        self.listerner_addr.clone()
    }
}

pub struct RingTunnel {
    id: Uuid,

    ring_cons_impl: AtomicCell<Option<AsyncHeapCons<RingItem>>>,
    ring_prod_impl: AtomicCell<Option<AsyncHeapProd<RingItem>>>,
}

impl RingTunnel {
    fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn new(cap: usize) -> Self {
        let id = Uuid::new_v4();
        let ring_impl = AsyncHeapRb::new(std::cmp::max(RING_TUNNEL_RESERVERD_CAP * 2, cap));
        let (ring_prod_impl, ring_cons_impl) = ring_impl.split();
        Self {
            id: id.clone(),
            ring_cons_impl: AtomicCell::new(Some(ring_cons_impl)),
            ring_prod_impl: AtomicCell::new(Some(ring_prod_impl)),
        }
    }

    pub fn new_with_id(id: Uuid, cap: usize) -> Self {
        let mut ret = Self::new(cap);
        ret.id = id;
        ret
    }
}

impl Debug for RingTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingTunnel").field("id", &self.id).finish()
    }
}

pub struct RingSink {
    id: Uuid,
    ring_prod_impl: AsyncHeapProd<RingItem>,
}

impl RingSink {
    pub fn new(tunnel: Arc<RingTunnel>) -> Self {
        Self {
            id: tunnel.id.clone(),
            ring_prod_impl: tunnel.ring_prod_impl.take().unwrap(),
        }
    }

    pub fn try_send(&mut self, item: RingItem) -> Result<(), RingItem> {
        let base = self.ring_prod_impl.base();
        if base.occupied_len() >= base.capacity().get() - RING_TUNNEL_RESERVERD_CAP {
            return Err(item);
        }
        self.ring_prod_impl.try_push(item)
    }

    pub fn force_send(&mut self, item: RingItem) -> Result<(), RingItem> {
        self.ring_prod_impl.try_push(item)
    }
}

impl Sink<SinkItem> for RingSink {
    type Error = SinkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ret = ready!(self.get_mut().ring_prod_impl.poll_ready_unpin(cx));
        Poll::Ready(ret.map_err(|_| SinkError::Shutdown))
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        self.get_mut()
            .ring_prod_impl
            .start_send_unpin(item)
            .map_err(|_| SinkError::Shutdown)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ret = ready!(self.get_mut().ring_prod_impl.poll_flush_unpin(cx));
        Poll::Ready(ret.map_err(|_| SinkError::Shutdown))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let ret = ready!(self.get_mut().ring_prod_impl.poll_close_unpin(cx));
        Poll::Ready(ret.map_err(|_| SinkError::Shutdown))
    }
}

impl Debug for RingSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSink")
            .field("id", &self.id)
            .field("len", &self.ring_prod_impl.base().occupied_len())
            .field("cap", &self.ring_prod_impl.base().capacity())
            .finish()
    }
}

pub struct RingStream {
    id: Uuid,
    ring_cons_impl: AsyncHeapCons<RingItem>,
}

impl RingStream {
    pub fn new(tunnel: Arc<RingTunnel>) -> Self {
        Self {
            id: tunnel.id.clone(),
            ring_cons_impl: tunnel.ring_cons_impl.take().unwrap(),
        }
    }
}

impl Stream for RingStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ret = ready!(self.get_mut().ring_cons_impl.poll_next_unpin(cx));

        match ret {
            Some(item) => Poll::Ready(Some(Ok(item))),
            None => Poll::Ready(None),
        }
    }
}

impl Debug for RingStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingStream")
            .field("id", &self.id)
            .field("len", &self.ring_cons_impl.base().occupied_len())
            .field("cap", &self.ring_cons_impl.base().capacity())
            .finish()
    }
}