//! The extension points every inbound, outbound and transport plugs into.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::Stream;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::session::{DatagramSource, Network, Session, SocksAddr};

pub mod inbound;
pub mod outbound;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    DatagramWarn(anyhow::Error),
    #[error(transparent)]
    DatagramFatal(anyhow::Error),
}

pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatagramTransportType {
    Reliable,
    Unreliable,
    Unknown,
}

pub trait Tag {
    fn tag(&self) -> &String;
}

/// A reliable transport for both inbound and outbound handlers.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<S> ProxyStream for S where S: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

pub type AnyStream = Box<dyn ProxyStream>;

pub trait BaseHandler: Tag + Send + Sync + Unpin {}

/// An outbound handler for both UDP and TCP outgoing connections.
pub trait OutboundHandler: BaseHandler {
    fn stream(&self) -> io::Result<&AnyOutboundStreamHandler>;
    fn datagram(&self) -> io::Result<&AnyOutboundDatagramHandler>;
    fn is_direct(&self) -> bool {
        false
    }
}

pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

#[derive(Debug, Clone)]
pub enum OutboundConnect {
    Proxy(Network, String, u16),
    Direct,
    Next,
    Unknown,
}

/// An outbound handler for outgoing TCP conections.
#[async_trait]
pub trait OutboundStreamHandler: Send + Sync + Unpin {
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Handles a session with the given stream. On success, returns a
    /// stream wraps the incoming stream.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream>;
}

pub type AnyOutboundStreamHandler = Arc<dyn OutboundStreamHandler>;

/// An unreliable transport for outbound handlers.
pub trait OutboundDatagram: Send + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    );
}

pub type AnyOutboundDatagram = Box<dyn OutboundDatagram>;

/// The receive half.
#[async_trait]
pub trait OutboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a message on the socket. On success, returns the number of
    /// bytes read and the origin of the message.
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)>;
}

/// The send half.
#[async_trait]
pub trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize>;

    /// Close the soccket gracefully.
    async fn close(&mut self) -> io::Result<()>;
}

/// An outbound handler for outgoing UDP connections.
#[async_trait]
pub trait OutboundDatagramHandler: Send + Sync + Unpin {
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Returns the transport type of this handler.
    fn transport_type(&self) -> DatagramTransportType;

    /// Handles a session with the transport. On success, returns an outbound
    /// datagram wraps the incoming transport.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram>;
}

pub type AnyOutboundDatagramHandler = Arc<dyn OutboundDatagramHandler>;

/// An outbound transport represents either a reliable or unreliable transport.
pub enum OutboundTransport<S, D> {
    /// The reliable transport.
    Stream(S),
    /// The unreliable transport.
    Datagram(D),
}

pub type AnyOutboundTransport = OutboundTransport<AnyStream, AnyOutboundDatagram>;

pub trait InboundHandler: BaseHandler {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler>;
    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler>;
}

pub type AnyInboundHandler = Arc<dyn InboundHandler>;

/// An inbound handler for incoming TCP connections.
#[async_trait]
pub trait InboundStreamHandler: Send + Sync + Unpin {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport>;
}

pub type AnyInboundStreamHandler = Arc<dyn InboundStreamHandler>;

/// An inbound handler for incoming UDP connections.
#[async_trait]
pub trait InboundDatagramHandler: Send + Sync + Unpin {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport>;
}

pub type AnyInboundDatagramHandler = Arc<dyn InboundDatagramHandler>;

/// An unreliable transport for inbound handlers.
pub trait InboundDatagram: Send + Sync + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    );

    /// Turns the datagram into a [`std::net::UdpSocket`].
    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket>;
}

pub type AnyInboundDatagram = Box<dyn InboundDatagram>;

/// The receive half.
#[async_trait]
pub trait InboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read, the source where this message
    /// originated and the destination this message shall be sent to.
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)>;
}

/// The send half.
#[async_trait]
pub trait InboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a datagram message on the socket to `dst_addr`, the `src_addr`
    /// specifies the origin of the message. On success, returns the number
    /// of bytes sent.
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize>;

    /// Close the socket gracefully.
    async fn close(&mut self) -> io::Result<()>;
}

pub enum BaseInboundTransport<S, D> {
    /// The reliable transport.
    Stream(S, Session),
    /// The unreliable transport.
    Datagram(D, Option<Session>),
    /// None.
    Empty,
}

pub type AnyBaseInboundTransport = BaseInboundTransport<AnyStream, AnyInboundDatagram>;

pub type IncomingTransport<S, D> =
    Box<dyn Stream<Item = BaseInboundTransport<S, D>> + Send + Unpin>;

pub type AnyIncomingTransport = IncomingTransport<AnyStream, AnyInboundDatagram>;

/// An inbound transport represents either a reliable or unreliable transport.
pub enum InboundTransport<S, D> {
    /// The reliable transport.
    Stream(S, Session),
    /// The unreliable transport.
    Datagram(D, Option<Session>),
    /// Incoming transports can be either reliable or unreliable.
    Incoming(IncomingTransport<S, D>),
    /// None.
    Empty,
}

pub type AnyInboundTransport = InboundTransport<AnyStream, AnyInboundDatagram>;
