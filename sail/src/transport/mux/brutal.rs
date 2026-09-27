//! TCP Brutal, as sing-mux negotiates it: a congestion control that sends
//! at a fixed rate whatever the losses, set on the TCP connection under a
//! mux connection at both ends.
//!
//! A client with `brutal` opens one stream on each new mux connection, to
//! the destination `_BrutalBwExchange`, and sends on it the rate it can
//! receive at, in bytes per second, a `u64`. The server answers, after the
//! stream's status, `ok bool`, then with `ok` the rate it can receive at, a
//! `u64`, or else an error message, a length (uvarint) and its bytes. Each
//! end sends at the lower of its own upload rate and the other's download
//! rate. The server fails the exchange when it cannot set the rate on its
//! socket; the client only logs that.
//!
//! Setting the rate takes Linux and the tcp-brutal kernel module: the
//! congestion control `brutal` (`TCP_CONGESTION`), then its rate and
//! congestion window gain (`TCP_BRUTAL_PARAMS`). See
//! <https://github.com/apernet/tcp-brutal>.

use std::io;
use std::net::SocketAddr;
use std::sync::OnceLock;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::session::{Session, SocksAddr};

use super::{read_uvarint, MAX_ERROR_MESSAGE};

/// The destination of the stream a client negotiates on.
pub const EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
/// The lowest rate either way, in bytes per second.
pub const MIN_SPEED_BPS: u64 = 65536;
/// A megabit per second, in bytes per second, as sing-box counts it.
const MBPS_TO_BPS: u64 = 125_000;

/// One end's rates, in bytes per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Brutal {
    pub send_bps: u64,
    pub receive_bps: u64,
}

impl Brutal {
    /// The rates of a `brutal` block, checked as sing-box does.
    pub fn from_mbps(up_mbps: u64, down_mbps: u64) -> Result<Brutal, String> {
        let bps = |mbps: u64| {
            mbps.checked_mul(MBPS_TO_BPS)
                .filter(|bps| *bps >= MIN_SPEED_BPS)
        };
        Ok(Brutal {
            send_bps: bps(up_mbps).ok_or("brutal: invalid upload speed")?,
            receive_bps: bps(down_mbps).ok_or("brutal: invalid download speed")?,
        })
    }
}

/// Whether a stream asks to negotiate: sing-mux looks at the domain only.
pub fn is_exchange(destination: &SocksAddr) -> bool {
    matches!(destination, SocksAddr::Domain(domain, _) if domain == EXCHANGE_DOMAIN)
}

/// The destination a client negotiates on.
pub fn exchange_destination() -> SocksAddr {
    SocksAddr::Domain(EXCHANGE_DOMAIN.to_string(), 0)
}

pub fn encode_request(receive_bps: u64, buf: &mut BytesMut) {
    buf.put_u64(receive_bps);
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    r.read_u64().await
}

/// The server's answer: the rate it receives at, or why it refuses.
pub fn encode_response(response: Result<u64, &str>, buf: &mut BytesMut) {
    match response {
        Ok(receive_bps) => {
            buf.put_u8(1);
            buf.put_u64(receive_bps);
        }
        Err(message) => {
            buf.put_u8(0);
            let mut len = message.len() as u64;
            while len >= 0x80 {
                buf.put_u8(len as u8 | 0x80);
                len >>= 7;
            }
            buf.put_u8(len as u8);
            buf.put_slice(message.as_bytes());
        }
    }
}

/// Reads the server's answer: the rate it receives at, or its refusal as
/// an error.
pub async fn read_response<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    // Go reads any byte but 0 as true.
    if r.read_u8().await? != 0 {
        return r.read_u64().await;
    }
    let len = read_uvarint(r).await?;
    if len > MAX_ERROR_MESSAGE {
        return Err(io::Error::other("remote error"));
    }
    let mut message = vec![0; len as usize];
    r.read_exact(&mut message).await?;
    Err(io::Error::other(format!(
        "remote error: {}",
        String::from_utf8_lossy(&message)
    )))
}

/// The TCP connection a mux connection runs over, by descriptor. Its
/// addresses tell it from a socket opened later with the same descriptor,
/// once it is closed.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Socket {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
    local: SocketAddr,
    peer: SocketAddr,
}

impl Socket {
    pub fn of(socket: &socket2::SockRef<'_>) -> io::Result<Socket> {
        let addr = |a: socket2::SockAddr| {
            a.as_socket()
                .ok_or_else(|| io::Error::other("brutal: not an IP socket"))
        };
        Ok(Socket {
            #[cfg(target_os = "linux")]
            fd: std::os::fd::AsRawFd::as_raw_fd(&**socket),
            local: addr(socket.local_addr()?)?,
            peer: addr(socket.peer_addr()?)?,
        })
    }
}

/// Sends at `send_bps` on `socket` with TCP Brutal. Without a socket, the
/// mux connection runs over something other than a TCP connection of its
/// own, such as a stream of another multiplexing protocol.
pub fn set(socket: Option<&Socket>, send_bps: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let socket = socket.ok_or_else(|| {
            io::Error::other(
                "brutal: nested multiplexing is not supported: \
                 no TCP connection of its own under the mux connection",
            )
        })?;
        linux::set(socket, send_bps)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, send_bps);
        Err(io::Error::other("TCP Brutal is only supported on Linux"))
    }
}

/// Whether TCP Brutal can be set at all here.
pub const AVAILABLE: bool = cfg!(target_os = "linux");

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::BorrowedFd;

    use socket2::SockRef;

    use super::Socket;

    /// The option of the tcp-brutal module that sets its parameters.
    const TCP_BRUTAL_PARAMS: libc::c_int = 23301;
    /// The congestion window gain, in tenths, as sing-mux and Hysteria 2
    /// set it.
    const CWND_GAIN: u32 = 20;

    #[repr(C)]
    struct TcpBrutalParams {
        rate: u64,
        cwnd_gain: u32,
    }

    pub(super) fn set(socket: &Socket, send_bps: u64) -> io::Result<()> {
        // SAFETY: the descriptor is only borrowed for this call; that it
        // is still the socket recorded is checked before anything is set.
        let fd = unsafe { BorrowedFd::borrow_raw(socket.fd) };
        let sock = SockRef::from(&fd);
        let same = sock.local_addr().ok().and_then(|a| a.as_socket()) == Some(socket.local)
            && sock.peer_addr().ok().and_then(|a| a.as_socket()) == Some(socket.peer);
        if !same {
            return Err(io::Error::other("brutal: the connection is closed"));
        }
        sock.set_tcp_congestion(b"brutal").map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "setsockopt IPPROTO_TCP TCP_CONGESTION brutal: {}: \
                     please make sure you have installed the tcp-brutal kernel module",
                    e
                ),
            )
        })?;
        let params = TcpBrutalParams {
            rate: send_bps,
            cwnd_gain: CWND_GAIN,
        };
        // SAFETY: `params` is the module's `struct brutal_params`, and
        // lives through the call.
        let ret = unsafe {
            libc::setsockopt(
                socket.fd,
                libc::IPPROTO_TCP,
                TCP_BRUTAL_PARAMS,
                &params as *const TcpBrutalParams as *const libc::c_void,
                std::mem::size_of::<TcpBrutalParams>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!("setsockopt IPPROTO_TCP TCP_BRUTAL_PARAMS: {}", e),
            ));
        }
        Ok(())
    }
}

/// What a connection that came in through an inbound knows of TCP Brutal:
/// the inbound's rates, if it enables it, and the TCP connection it came
/// in on. It is kept in the connection's state, which the sessions of its
/// mux streams share.
#[derive(Debug, Default)]
pub struct InboundConnection {
    pub(super) brutal: OnceLock<Brutal>,
    pub(super) socket: OnceLock<Socket>,
}

/// Serves a stream that asks to negotiate, on a mux connection that came
/// in as `sess`, then closes it.
pub async fn serve_exchange<S>(mut stream: S, sess: &Session) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_receive_bps = read_request(&mut stream).await?;
    let conn = sess.state.get::<InboundConnection>();
    let response = negotiate(conn.brutal.get(), client_receive_bps, |send_bps| {
        set(conn.socket.get(), send_bps)
    });
    let mut buf = BytesMut::new();
    encode_response(response.as_ref().copied().map_err(String::as_str), &mut buf);
    stream.write_all(&buf).await?;
    stream.shutdown().await
}

/// The server's side: what it answers a client that receives at
/// `client_receive_bps`, having set its own rate with `set`.
fn negotiate(
    brutal: Option<&Brutal>,
    client_receive_bps: u64,
    set: impl FnOnce(u64) -> io::Result<()>,
) -> Result<u64, String> {
    let Some(brutal) = brutal else {
        return Err("brutal is not enabled by the server".to_string());
    };
    let send_bps = brutal.send_bps.min(client_receive_bps);
    set(send_bps).map_err(|e| format!("enable TCP Brutal: {}", e))?;
    debug!("mux: TCP Brutal, sending at {} B/s", send_bps);
    Ok(brutal.receive_bps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn rates_are_checked_as_sing_box_does() {
        assert_eq!(
            Brutal::from_mbps(100, 1000).unwrap(),
            Brutal {
                send_bps: 12_500_000,
                receive_bps: 125_000_000,
            }
        );
        assert_eq!(
            Brutal::from_mbps(0, 10).unwrap_err(),
            "brutal: invalid upload speed"
        );
        assert_eq!(
            Brutal::from_mbps(10, 0).unwrap_err(),
            "brutal: invalid download speed"
        );
        assert!(Brutal::from_mbps(u64::MAX, 10).is_err());
    }

    #[test]
    fn requests_and_responses_on_the_wire() {
        runtime().block_on(async {
            let mut buf = BytesMut::new();
            encode_request(125_000_000, &mut buf);
            assert_eq!(&buf[..], &125_000_000u64.to_be_bytes());
            assert_eq!(read_request(&mut &buf[..]).await.unwrap(), 125_000_000);

            let mut buf = BytesMut::new();
            encode_response(Ok(12_500_000), &mut buf);
            assert_eq!(buf[0], 1);
            assert_eq!(&buf[1..], &12_500_000u64.to_be_bytes());
            assert_eq!(read_response(&mut &buf[..]).await.unwrap(), 12_500_000);

            let mut buf = BytesMut::new();
            encode_response(Err("no"), &mut buf);
            assert_eq!(&buf[..], &[0, 2, b'n', b'o']);
            let err = read_response(&mut &buf[..]).await.unwrap_err();
            assert_eq!(err.to_string(), "remote error: no");

            // A message of 200 bytes takes two bytes of length.
            let long = "x".repeat(200);
            let mut buf = BytesMut::new();
            encode_response(Err(&long), &mut buf);
            assert_eq!(&buf[..3], &[0, 0xc8, 0x01]);
            let err = read_response(&mut &buf[..]).await.unwrap_err();
            assert_eq!(err.to_string(), format!("remote error: {}", long));
        });
    }

    #[test]
    fn the_exchange_destination() {
        let mut buf = BytesMut::new();
        super::super::StreamRequest::Tcp(exchange_destination()).encode(&mut buf);
        let mut expected = vec![0, 0, 3, EXCHANGE_DOMAIN.len() as u8];
        expected.extend_from_slice(EXCHANGE_DOMAIN.as_bytes());
        expected.extend_from_slice(&[0, 0]);
        assert_eq!(&buf[..], &expected[..]);
        assert!(is_exchange(&SocksAddr::Domain(EXCHANGE_DOMAIN.into(), 443)));
        assert!(!is_exchange(&SocksAddr::Domain("example.com".into(), 0)));
    }

    #[test]
    fn the_server_sends_at_the_lower_rate() {
        let brutal = Brutal {
            send_bps: 1_000_000,
            receive_bps: 2_000_000,
        };
        let mut set_to = None;
        let response = negotiate(Some(&brutal), 500_000, |bps| {
            set_to = Some(bps);
            Ok(())
        });
        assert_eq!(response.unwrap(), 2_000_000);
        assert_eq!(set_to, Some(500_000));

        let mut set_to = None;
        negotiate(Some(&brutal), 9_000_000, |bps| {
            set_to = Some(bps);
            Ok(())
        })
        .unwrap();
        assert_eq!(set_to, Some(1_000_000));
    }

    #[test]
    fn the_server_refuses() {
        let response = negotiate(None, 500_000, |_| panic!("not enabled"));
        assert_eq!(response.unwrap_err(), "brutal is not enabled by the server");
        let brutal = Brutal {
            send_bps: 1_000_000,
            receive_bps: 2_000_000,
        };
        let response = negotiate(Some(&brutal), 500_000, |_| {
            Err(io::Error::other("no module"))
        });
        assert_eq!(response.unwrap_err(), "enable TCP Brutal: no module");
    }

    #[test]
    fn setting_it_fails_as_sing_mux_does() {
        let err = set(None, MIN_SPEED_BPS).unwrap_err().to_string();
        if AVAILABLE {
            assert!(
                err.contains("nested multiplexing is not supported"),
                "{}",
                err
            );
        } else {
            assert_eq!(err, "TCP Brutal is only supported on Linux");
        }
    }

    /// On Linux, without the module, as on most hosts, the congestion
    /// control is not there; with it, the rate is set.
    #[cfg(target_os = "linux")]
    #[test]
    fn setting_it_on_a_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let socket = Socket::of(&socket2::SockRef::from(&client)).unwrap();
        let loaded = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
            .is_ok_and(|s| s.split_whitespace().any(|c| c == "brutal"));
        match set(Some(&socket), MIN_SPEED_BPS) {
            // The module may also be loaded on demand.
            Ok(()) => {}
            Err(e) => {
                assert!(!loaded, "{}", e);
                assert!(
                    e.to_string()
                        .starts_with("setsockopt IPPROTO_TCP TCP_CONGESTION brutal: ")
                        && e.to_string().ends_with(
                            "please make sure you have installed the tcp-brutal kernel module"
                        ),
                    "{}",
                    e
                );
            }
        }
        drop(client);
        // A descriptor that no longer holds the socket is left alone.
        assert!(set(Some(&socket), MIN_SPEED_BPS).is_err());
    }
}
