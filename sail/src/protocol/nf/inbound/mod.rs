#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::mem::transmute;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::ffi::OsStringExt;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::{LazyLock, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, trace, warn};

use packed::{SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

use crate::adapter::inbound::Handler as InboundHandler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::app::fake_dns::{FakeDns, FakeDnsMode};
use serde_derive::Deserialize;

const MAX_PATH: usize = 260;
const IPPROTO_TCP: i32 = 6;

pub const NF_STATUS_SUCCESS: NfStatus = 0;

#[allow(dead_code)]
#[derive(Debug)]
enum NfDirection {
    In,
    Out,
    Both,
    Unknown(u8),
}

impl NfDirection {
    fn value(&self) -> u8 {
        match self {
            Self::In => 1,
            Self::Out => 2,
            Self::Both => 3,
            Self::Unknown(v) => *v,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum NfFilteringFlag {
    NfAllow,                     // Allow the activity without filtering transmitted packets
    NfBlock,                     // Block the activity
    NfFilter,                    // Filter the transmitted packets
    NfSuspended,                 // Suspend receives from server and sends from client
    NfOffline,                   // Emulate establishing a TCP connection with remote server
    NfIndicateConnectRequests,   // Indicate outgoing connect requests to API
    NfDisableRedirectProtection, // Disable blocking indicating connect requests for outgoing connections of local proxies
    NfPendConnectRequest, // Pend outgoing connect request to complete it later using nf_complete(TCP|UDP)ConnectRequest
    NfFilterAsIpPackets,  // Indicate the traffic as IP packets via ipSend/ipReceive
    NfReadonly, // Don't block the IP packets and indicate them to ipSend/ipReceive only for monitoring
    NfControlFlow, // Use the flow limit rules even without NF_FILTER flag
    NfRedirect, // Redirect the outgoing TCP connections to address specified in redirectTo
    NfBypassIpPackets, // Bypass the traffic as IP packets, when used with NF_FILTER_AS_IP_PACKETS flag
    Unknown(u32),
}

impl NfFilteringFlag {
    fn value(&self) -> u32 {
        match self {
            Self::NfAllow => 0,
            Self::NfBlock => 1,
            Self::NfFilter => 2,
            Self::NfSuspended => 4,
            Self::NfOffline => 8,
            Self::NfIndicateConnectRequests => 16,
            Self::NfDisableRedirectProtection => 32,
            Self::NfPendConnectRequest => 64,
            Self::NfFilterAsIpPackets => 128,
            Self::NfReadonly => 256,
            Self::NfControlFlow => 512,
            Self::NfRedirect => 1024,
            Self::NfBypassIpPackets => 2048,
            Self::Unknown(v) => *v,
        }
    }
}

pub type NfStatus = i32;

type NfInitFn = unsafe extern "C" fn(*const u8, *const NfEventHandler) -> NfStatus;
type NfFreeFn = unsafe extern "C" fn();
type NfAddRuleFn = unsafe extern "C" fn(*const NfRule, i32) -> NfStatus;
type NfTcpPostReceiveFn = unsafe extern "C" fn(EndpointId, *const u8, i32) -> NfStatus;
type NfTcpPostSendFn = unsafe extern "C" fn(EndpointId, *const u8, i32) -> NfStatus;
type NfUdpPostReceiveFn =
    unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions) -> NfStatus;
type NfUdpPostSendFn =
    unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions) -> NfStatus;
type NfTcpDisableFilteringFn = unsafe extern "C" fn(EndpointId);
type NfUdpDisableFilteringFn = unsafe extern "C" fn(EndpointId);
type NfAdjustProcessPriviledgesFn = unsafe extern "C" fn();
type NfGetUdpConnInfoFn = unsafe extern "C" fn(EndpointId, *mut NfUdpConnInfo) -> NfStatus;
type NfGetProcessNameFn = unsafe extern "C" fn(u32, *mut u8, u32) -> bool;
type NfGetProcessNameFromKernelFn = unsafe extern "C" fn(u32, *mut u8, u32) -> bool;

/// The loaded `nfapi.dll`. It stays loaded once loaded, so the function
/// pointers in `NF` stay valid.
static NFAPI: RwLock<Option<libloading::Library>> = RwLock::new(None);

/// The driver's functions, resolved from `nfapi.dll`.
struct NfFns {
    init: NfInitFn,
    free: NfFreeFn,
    add_rule: NfAddRuleFn,
    tcp_post_receive: NfTcpPostReceiveFn,
    #[allow(dead_code)]
    tcp_post_send: NfTcpPostSendFn,
    udp_post_receive: NfUdpPostReceiveFn,
    udp_post_send: NfUdpPostSendFn,
    tcp_disable_filtering: NfTcpDisableFilteringFn,
    udp_disable_filtering: NfUdpDisableFilteringFn,
    adjust_process_priviledges: NfAdjustProcessPriviledgesFn,
    get_udp_conn_info: NfGetUdpConnInfoFn,
    get_process_name: NfGetProcessNameFn,
    get_process_name_from_kernel: NfGetProcessNameFromKernelFn,
}

/// Set once by `init_nf_fns`, read by the driver callbacks.
static NF: OnceLock<NfFns> = OnceLock::new();

/// Why the driver's functions are set when a callback calls them: the
/// callbacks start with `nf_init`, which runs after `init_nf_fns` set them.
const NF_FN_SET: &str = "init_nf_fns sets the nf functions before nf_init";

/// The driver's functions; only called once `init_nf_fns` has set them.
fn nf() -> &'static NfFns {
    NF.get().expect(NF_FN_SET)
}

/// The tag of the NetFilter inbound, whose listeners the driver callbacks
/// redirect to. Set on every build.
static NF_TAG: RwLock<Option<String>> = RwLock::new(None);

/// The NetFilter inbound's tag, or "nf" when no inbound was built.
fn nf_tag() -> String {
    if let Some(tag) = NF_TAG.read().as_ref() {
        return tag.clone();
    }
    debug!("nf inbound tag not set, using \"nf\"");
    "nf".to_string()
}

/// Kept so the receiver in `init_nf` blocks for the life of the process.
static TX: Mutex<Option<std::sync::mpsc::Sender<bool>>> = Mutex::new(None);
static UDP_SEND_SOCKET: RwLock<Option<std::net::UdpSocket>> = RwLock::new(None);

/// How long a `TCP_INFO` entry waits for its redirected connection. A
/// judgment value: the redirected connection reaches sail's listener within
/// milliseconds; an entry this old belongs to a connection that never came,
/// and its port may be reused.
const TCP_INFO_TTL: Duration = Duration::from_secs(60);

struct ConnInfo {
    remote_addr: SocketAddr,
    process_name: Option<String>,
    inserted: Instant,
}

/// Removes the entries older than `TCP_INFO_TTL` at `now`.
fn prune(map: &mut HashMap<u16, ConnInfo>, now: Instant) {
    map.retain(|_, info| now.saturating_duration_since(info.inserted) < TCP_INFO_TTL);
}

#[derive(Debug)]
pub struct UdpLocalInfo {
    local_address: SocketAddr,
    process_name: Option<String>,
}

pub static UDP_LOCAL_INFO: LazyLock<Mutex<HashMap<EndpointId, UdpLocalInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static UDP_ENDPOINT: LazyLock<Mutex<HashMap<SocketAddr, EndpointId>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static UDP_OPTIONS: LazyLock<Mutex<HashMap<EndpointId, Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static TCP_INFO: LazyLock<Mutex<HashMap<u16, ConnInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

type EndpointId = u64;

#[repr(C, packed)]
#[derive(Default)]
struct NfRule {
    protocol: i32,
    processId: u32,
    direction: u8,
    localPort: u16,
    remotePort: u16,
    ip_family: u16,
    localIpAddress: [u8; 16],
    localIpAddressMask: [u8; 16],
    remoteIpAddress: [u8; 16],
    remoteIpAddressMask: [u8; 16],
    filteringFlag: u32,
}

#[repr(C, packed)]
struct NfTcpConnInfo {
    filteringFlag: u32,
    processId: u32,
    direction: u8,
    ip_family: u16,
    localAddress: [u8; 28],
    remoteAddress: [u8; 28],
}

impl NfTcpConnInfo {
    unsafe fn get_local_address(info: *const NfTcpConnInfo) -> Result<SocketAddr> {
        sockaddr_to_socketaddr(
            &addr_of!((*info).localAddress).read_unaligned() as *const [u8; 28] as *const SOCKADDR,
        )
    }

    unsafe fn get_remote_address(info: *const NfTcpConnInfo) -> Result<SocketAddr> {
        sockaddr_to_socketaddr(
            &addr_of!((*info).remoteAddress).read_unaligned() as *const [u8; 28] as *const SOCKADDR,
        )
    }
}

#[repr(C, packed)]
struct NfUdpConnInfo {
    processId: u32,
    ip_family: u16,
    localAddress: [u8; 28],
}

impl NfUdpConnInfo {
    unsafe fn get_local_address(info: *const NfUdpConnInfo) -> Result<SocketAddr> {
        sockaddr_to_socketaddr(
            &addr_of!((*info).localAddress).read_unaligned() as *const [u8; 28] as *const SOCKADDR,
        )
    }
}

impl Default for NfUdpConnInfo {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C, packed)]
struct NfUdpConnRequest {
    filteringFlag: u32,
    processId: u32,
    ip_family: u16,
    localAddress: [u8; 28],
    remoteAddress: [u8; 28],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct NfUdpOptions {
    flags: u32,
    optionsLength: i32,
    options: [u8; 1],
}

#[repr(C, packed)]
struct NfEventHandler {
    threadStart: unsafe extern "C" fn(),
    threadEnd: unsafe extern "C" fn(),
    tcpConnectRequest: unsafe extern "C" fn(EndpointId, *mut NfTcpConnInfo),
    tcpConnected: unsafe extern "C" fn(EndpointId, *mut NfTcpConnInfo),
    tcpClosed: unsafe extern "C" fn(EndpointId, *mut NfTcpConnInfo),
    tcpReceive: unsafe extern "C" fn(EndpointId, *const u8, i32),
    tcpSend: unsafe extern "C" fn(EndpointId, *const u8, i32),
    tcpCanReceive: unsafe extern "C" fn(EndpointId),
    tcpCanSend: unsafe extern "C" fn(EndpointId),
    udpCreated: unsafe extern "C" fn(EndpointId, *mut NfUdpConnInfo),
    udpConnectRequest: unsafe extern "C" fn(EndpointId, *mut NfUdpConnRequest),
    udpClosed: unsafe extern "C" fn(EndpointId, *mut NfUdpConnInfo),
    udpReceive: unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions),
    udpSend: unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions),
    udpCanReceive: unsafe extern "C" fn(EndpointId),
    udpCanSend: unsafe extern "C" fn(EndpointId),
}

unsafe extern "C" fn threadStart() {
    trace!("threadStart tid={:?}", thread::current().id());
}

unsafe extern "C" fn threadEnd() {
    trace!("threadEnd tid={:?}", thread::current().id());
}

unsafe extern "C" fn tcpConnectRequest(id: EndpointId, conn_info: *mut NfTcpConnInfo) {
    let Ok(local_addr) = NfTcpConnInfo::get_local_address(conn_info) else {
        debug!("unable to get local address");
        return;
    };
    let Ok(remote_addr) = NfTcpConnInfo::get_remote_address(conn_info) else {
        debug!("unable to get remote address");
        return;
    };

    trace!(
        "tcpConnectRequest id={} local={} remote={}",
        id,
        &local_addr,
        &remote_addr
    );

    if remote_addr.is_ipv6() {
        // Block IPv6.
        addr_of_mut!((*conn_info).filteringFlag).write_unaligned(NfFilteringFlag::NfBlock.value());
        return;
    }

    if remote_addr.ip().is_loopback() {
        return;
    }

    let process_id = addr_of!((*conn_info).processId).read_unaligned();
    let process_name = get_process_name(process_id).ok();

    debug!(
        "tcpConnectRequest id={} local={} remote={} process_id={} process_name={}",
        id,
        &local_addr,
        &remote_addr,
        process_id,
        process_name.as_deref().unwrap_or("Unknown")
    );

    {
        let now = Instant::now();
        let mut tcp_info = TCP_INFO.lock();
        prune(&mut tcp_info, now);
        if tcp_info
            .insert(
                local_addr.port(),
                ConnInfo {
                    remote_addr,
                    process_name,
                    inserted: now,
                },
            )
            .is_some()
        {
            warn!("duplicated local_addr.port={}", local_addr.port());
        }
    }

    let tag = nf_tag();
    let network = crate::session::Network::Tcp;
    let Some(new_remote_addr) = crate::app::inbound::get_network_listen_addr(&tag, network) else {
        debug!("cannot get listen address, tag={} network={}", tag, network);
        return;
    };

    match new_remote_addr {
        SocketAddr::V4(addr) => {
            let new_remote_addr: SOCKADDR_IN = addr.into();
            let addr_ptr = &new_remote_addr as *const SOCKADDR_IN as *const u8;
            let addr_len = std::mem::size_of::<packed::SOCKADDR_IN>();
            let new_remote_addr_data = std::slice::from_raw_parts(addr_ptr, addr_len);
            let mut write_buf = [0u8; 28];
            write_buf[..addr_len].copy_from_slice(&new_remote_addr_data[..addr_len]);
            addr_of_mut!((*conn_info).remoteAddress).write_unaligned(write_buf);
        }
        SocketAddr::V6(addr) => {
            let new_remote_addr: SOCKADDR_IN6 = addr.into();
            let addr_ptr = &new_remote_addr as *const SOCKADDR_IN6 as *const u8;
            let addr_len = std::mem::size_of::<SOCKADDR_IN6>();
            let new_remote_addr_data = std::slice::from_raw_parts(addr_ptr, addr_len);
            let mut write_buf = [0u8; 28];
            write_buf[..addr_len].copy_from_slice(&new_remote_addr_data[..addr_len]);
            addr_of_mut!((*conn_info).remoteAddress).write_unaligned(write_buf);
        }
    }

    // SAFETY: a driver callback, so `nf_init` has run with `id` live; the
    // function comes from the loaded `nfapi.dll`.
    (nf().tcp_disable_filtering)(id);
}

unsafe extern "C" fn tcpConnected(id: EndpointId, _conn_info: *mut NfTcpConnInfo) {
    trace!("tcpConnected id={}", id);
}

unsafe extern "C" fn tcpClosed(id: EndpointId, _conn_info: *mut NfTcpConnInfo) {
    trace!("tcpClosed id={}", id);
}

unsafe extern "C" fn tcpReceive(id: EndpointId, buf: *const u8, len: i32) {
    trace!(
        "tcpReceive tid={:?} id={} len={}",
        thread::current().id(),
        id,
        len
    );
    // SAFETY: passes on the buffer the driver gave this callback, unchanged.
    (nf().tcp_post_receive)(id, buf, len);
}

unsafe extern "C" fn tcpSend(id: EndpointId, _buf: *const u8, len: i32) {
    trace!(
        "tcpSend tid={:?} id={} len={}",
        thread::current().id(),
        id,
        len
    );
}

unsafe extern "C" fn tcpCanReceive(id: EndpointId) {
    trace!("tcpCanReceive id={}", id);
}

unsafe extern "C" fn tcpCanSend(id: EndpointId) {
    trace!("tcpCanSend id={}", id);
}

unsafe extern "C" fn udpCreated(id: EndpointId, conn_info: *mut NfUdpConnInfo) {
    let Ok(local_address) = NfUdpConnInfo::get_local_address(conn_info) else {
        debug!("unable to get local address");
        return;
    };

    let process_id = addr_of!((*conn_info).processId).read_unaligned();
    let process_name = get_process_name(process_id).ok();

    debug!(
        "udpCreated id={} local={} process_id={} process_name={}",
        id,
        &local_address,
        process_id,
        process_name.as_deref().unwrap_or("Unknown")
    );

    // The local address here can be 0.0.0.0:0, we will check and override in udpSend.
    UDP_LOCAL_INFO.lock().insert(
        id,
        UdpLocalInfo {
            local_address,
            process_name,
        },
    );
    UDP_ENDPOINT.lock().insert(local_address, id);
}

unsafe extern "C" fn udpConnectRequest(id: EndpointId, _conn_req: *mut NfUdpConnRequest) {
    trace!("udpConnectRequest id={}", id);
}

unsafe extern "C" fn udpClosed(id: EndpointId, _conn_info: *mut NfUdpConnInfo) {
    UDP_OPTIONS.lock().remove(&id);
    if let Some(info) = UDP_LOCAL_INFO.lock().remove(&id) {
        UDP_ENDPOINT.lock().remove(&info.local_address);
    }
}

unsafe extern "C" fn udpReceive(
    id: EndpointId,
    remote_address: *const u8,
    buf: *const u8,
    len: i32,
    options: *mut NfUdpOptions,
) {
    trace!("udpReceive id={}", id);
    // SAFETY: passes on the pointers the driver gave this callback, unchanged.
    (nf().udp_post_receive)(id, remote_address, buf, len, options);
}

unsafe extern "C" fn udpSend(
    id: EndpointId,
    remote_address: *const u8,
    buf: *const u8,
    len: i32,
    options: *mut NfUdpOptions,
) {
    let Ok(remote_addr) =
        sockaddr_to_socketaddr(transmute::<*const u8, *const SOCKADDR>(remote_address))
    else {
        debug!("unable to get remote address");
        return;
    };

    trace!("udpSend id={} remote={} len={}", id, &remote_addr, len);

    // Drop IPv6
    if remote_addr.is_ipv6() {
        trace!("Pass IPv6");
        // SAFETY: passes on the pointers the driver gave this callback, unchanged.
        let status = (nf().udp_post_send)(id, remote_address, buf, len, options);
        if status != NF_STATUS_SUCCESS {
            debug!("send to local failed, status={}", status);
        }
        return;
    }

    if remote_addr.ip().is_loopback() {
        // SAFETY: a driver callback, so `nf_init` has run with `id` live.
        (nf().udp_disable_filtering)(id);
        return;
    }

    let mut conn_info = NfUdpConnInfo::default();
    // SAFETY: `conn_info` is a live, writable `NfUdpConnInfo` for the call.
    let status = (nf().get_udp_conn_info)(id, &mut conn_info as *mut _);
    if status != NF_STATUS_SUCCESS {
        debug!("get udp conn info failed id={} status={}", id, status);
        return;
    }
    let Ok(local_address) = NfUdpConnInfo::get_local_address(&conn_info as *const NfUdpConnInfo)
    else {
        debug!("unable to get local address");
        return;
    };

    UDP_LOCAL_INFO.lock().entry(id).and_modify(|x| {
        if x.local_address.port() == 0 {
            x.local_address = local_address;
            UDP_ENDPOINT.lock().insert(local_address, id);
        }
    });

    UDP_OPTIONS.lock().entry(id).or_insert_with(|| {
        let opts_len = (*options).optionsLength;
        let opts_data_len = std::mem::size_of::<NfUdpOptions>() - 1 + opts_len as usize;
        let mut opts_buf = vec![0u8; opts_data_len];
        let options_data = std::slice::from_raw_parts(options as *mut u8, opts_data_len);
        opts_buf[..opts_data_len]
            .as_mut()
            .copy_from_slice(&options_data[..opts_data_len]);
        opts_buf
    });

    let Ok(original_remote_addr) =
        sockaddr_to_socketaddr(transmute::<*const u8, *const SOCKADDR>(remote_address))
    else {
        debug!("unable to get original remote address");
        return;
    };

    let mut new_buf = BytesMut::new();
    let dst_addr = crate::session::SocksAddr::from(original_remote_addr);
    dst_addr.write_buf(&mut new_buf, crate::session::SocksAddrWireType::PortLast);
    new_buf.put_u64(id);
    let buf = std::slice::from_raw_parts(buf, len as _);
    new_buf.put_slice(buf);

    let tag = nf_tag();
    let network = crate::session::Network::Udp;
    let Some(new_remote_addr) = crate::app::inbound::get_network_listen_addr(&tag, network) else {
        debug!("cannot get listen address tag={} network={}", tag, network);
        return;
    };

    // Set only after nf_init, so a datagram can come first.
    let socket = UDP_SEND_SOCKET.read();
    let Some(socket) = socket.as_ref() else {
        debug!("udp send socket not ready id={}", id);
        return;
    };
    if let Err(e) = socket.send_to(&new_buf, new_remote_addr) {
        debug!("send to local failed: {}", e);
    }
}

unsafe extern "C" fn udpCanReceive(id: EndpointId) {
    trace!("udpCanReceive id={}", id);
}

unsafe extern "C" fn udpCanSend(id: EndpointId) {
    trace!("udpCanSend id={}", id);
}

pub mod packed {
    pub type ADDRESS_FAMILY = u16;

    pub const AF_INET: ADDRESS_FAMILY = 2u16;
    pub const AF_INET6: ADDRESS_FAMILY = 23u16;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SOCKADDR {
        pub sa_family: ADDRESS_FAMILY,
        pub sa_data: [i8; 14],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN_ADDR_0_0 {
        pub s_b1: u8,
        pub s_b2: u8,
        pub s_b3: u8,
        pub s_b4: u8,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN_ADDR_0_1 {
        pub s_w1: u16,
        pub s_w2: u16,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union IN_ADDR_0 {
        pub S_un_b: IN_ADDR_0_0,
        pub S_un_w: IN_ADDR_0_1,
        pub S_addr: u32,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN_ADDR {
        pub S_un: IN_ADDR_0,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SOCKADDR_IN {
        pub sin_family: ADDRESS_FAMILY,
        pub sin_port: u16,
        pub sin_addr: IN_ADDR,
        pub sin_zero: [i8; 8],
    }

    impl Default for SOCKADDR_IN {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union IN6_ADDR_0 {
        pub Byte: [u8; 16],
        pub Word: [u16; 8],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SCOPE_ID_0_0 {
        pub _bitfield: u32,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union SCOPE_ID_0 {
        pub Anonymous: SCOPE_ID_0_0,
        pub Value: u32,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SCOPE_ID {
        pub Anonymous: SCOPE_ID_0,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union SOCKADDR_IN6_0 {
        pub sin6_scope_id: u32,
        pub sin6_scope_struct: SCOPE_ID,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN6_ADDR {
        pub u: IN6_ADDR_0,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SOCKADDR_IN6 {
        pub sin6_family: ADDRESS_FAMILY,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: IN6_ADDR,
        pub Anonymous: SOCKADDR_IN6_0,
    }

    impl Default for SOCKADDR_IN6 {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    impl From<std::net::SocketAddrV4> for SOCKADDR_IN {
        fn from(addr: std::net::SocketAddrV4) -> Self {
            // addr.port() is in host byte order
            // sin_port must be big-endian, network byte order
            SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: addr.port().to_be(),
                sin_addr: (*addr.ip()).into(),
                ..Default::default()
            }
        }
    }

    impl From<std::net::SocketAddrV6> for SOCKADDR_IN6 {
        fn from(addr: std::net::SocketAddrV6) -> Self {
            // addr.port() and addr.flowinfo() are in host byte order
            // sin6_port and sin6_flowinfo must be big-endian, network byte order
            // sin6_scope_id is a bitfield without endianness
            SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo().to_be(),
                sin6_addr: (*addr.ip()).into(),
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: addr.scope_id(),
                },
            }
        }
    }

    impl From<IN_ADDR> for std::net::Ipv4Addr {
        fn from(in_addr: IN_ADDR) -> Self {
            // SAFETY: this is safe because the union variants are just views of the same exact data
            // in_addr.S_un.S_addr is big-endian, network byte order
            // Ipv4Addr::new() expects the parameter in host byte order
            Self::from(u32::from_be(unsafe { in_addr.S_un.S_addr }))
        }
    }

    impl From<std::net::Ipv4Addr> for IN_ADDR {
        fn from(addr: std::net::Ipv4Addr) -> Self {
            // u32::from(addr) is in host byte order
            // S_addr must be big-endian, network byte order
            Self {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(addr).to_be(),
                },
            }
        }
    }

    impl From<IN6_ADDR> for std::net::Ipv6Addr {
        fn from(in6_addr: IN6_ADDR) -> Self {
            // SAFETY: this is safe because the union variants are just views of the same exact data
            Self::from(unsafe { in6_addr.u.Byte })
        }
    }

    impl From<std::net::Ipv6Addr> for IN6_ADDR {
        fn from(addr: std::net::Ipv6Addr) -> Self {
            Self {
                u: IN6_ADDR_0 {
                    Byte: addr.octets(),
                },
            }
        }
    }
}

unsafe fn sockaddr_to_socketaddr(addr: *const packed::SOCKADDR) -> Result<SocketAddr> {
    match addr_of!((*addr).sa_family).read_unaligned() {
        packed::AF_INET => {
            let addr: *const packed::SOCKADDR_IN = transmute(addr);
            Ok(SocketAddr::new(
                IpAddr::V4(addr_of!((*addr).sin_addr).read_unaligned().into()),
                u16::from_be(addr_of!((*addr).sin_port).read_unaligned()),
            ))
        }
        packed::AF_INET6 => {
            let addr: *const packed::SOCKADDR_IN6 = transmute(addr);
            Ok(SocketAddr::new(
                IpAddr::V6(addr_of!((*addr).sin6_addr).read_unaligned().into()),
                u16::from_be(addr_of!((*addr).sin6_port).read_unaligned()),
            ))
        }
        _ => Err(anyhow!("unknown address family")),
    }
}

/// The function `name` in `lib`, copied out of its symbol.
///
/// # Safety
/// `T` must be the type of the function `name`.
unsafe fn nf_fn<T: Copy>(lib: &libloading::Library, name: &[u8]) -> Result<T> {
    Ok(*lib.get::<T>(name)?)
}

unsafe fn init_nf_fns<P: AsRef<OsStr>>(nfapi: P) -> Result<()> {
    if NF.get().is_some() {
        // A second init: the library from the first stays loaded and its
        // functions stay set.
        return Ok(());
    }

    let nfapi = libloading::Library::new(nfapi)?;

    // SAFETY: each type alias matches the nfapi.dll export of that name.
    let fns = NfFns {
        init: nf_fn::<NfInitFn>(&nfapi, b"nf_init\0")?,
        free: nf_fn::<NfFreeFn>(&nfapi, b"nf_free\0")?,
        add_rule: nf_fn::<NfAddRuleFn>(&nfapi, b"nf_addRule\0")?,
        tcp_post_receive: nf_fn::<NfTcpPostReceiveFn>(&nfapi, b"nf_tcpPostReceive\0")?,
        tcp_post_send: nf_fn::<NfTcpPostSendFn>(&nfapi, b"nf_tcpPostSend\0")?,
        udp_post_receive: nf_fn::<NfUdpPostReceiveFn>(&nfapi, b"nf_udpPostReceive\0")?,
        udp_post_send: nf_fn::<NfUdpPostSendFn>(&nfapi, b"nf_udpPostSend\0")?,
        tcp_disable_filtering: nf_fn::<NfTcpDisableFilteringFn>(
            &nfapi,
            b"nf_tcpDisableFiltering\0",
        )?,
        udp_disable_filtering: nf_fn::<NfUdpDisableFilteringFn>(
            &nfapi,
            b"nf_udpDisableFiltering\0",
        )?,
        adjust_process_priviledges: nf_fn::<NfAdjustProcessPriviledgesFn>(
            &nfapi,
            b"nf_adjustProcessPriviledges\0",
        )?,
        get_udp_conn_info: nf_fn::<NfGetUdpConnInfoFn>(&nfapi, b"nf_getUDPConnInfo\0")?,
        get_process_name: nf_fn::<NfGetProcessNameFn>(&nfapi, b"nf_getProcessNameW\0")?,
        get_process_name_from_kernel: nf_fn::<NfGetProcessNameFromKernelFn>(
            &nfapi,
            b"nf_getProcessNameFromKernel\0",
        )?,
    };

    // Kept loaded for the life of the process: the pointers in `NF` point
    // into it.
    *NFAPI.write() = Some(nfapi);
    // Init runs on one thread at a time (IS_NF_INITIALIZED), so this set
    // cannot lose to another.
    let _ = NF.set(fns);

    Ok(())
}

unsafe fn init_nf<P: AsRef<OsStr>>(
    driver_name: String,
    nfapi: P,
    res_tx: std::sync::mpsc::Sender<bool>,
) -> Result<()> {
    init_nf_fns(nfapi)?;
    let fns = nf();

    // SAFETY: takes no arguments.
    (fns.adjust_process_priviledges)();

    let eh = NfEventHandler {
        threadStart,
        threadEnd,
        tcpConnectRequest,
        tcpConnected,
        tcpClosed,
        tcpReceive,
        tcpSend,
        tcpCanReceive,
        tcpCanSend,
        udpCreated,
        udpConnectRequest,
        udpClosed,
        udpReceive,
        udpSend,
        udpCanReceive,
        udpCanSend,
    };

    let driver_name =
        CString::new(driver_name).map_err(|_| anyhow!("driver_name: contains a NUL character"))?;
    // SAFETY: `driver_name` is NUL-terminated; `eh` outlives the driver's use
    // of it, as this thread blocks below until the process ends.
    let status = (fns.init)(driver_name.as_bytes_with_nul().as_ptr(), &eh as *const _);
    if status != NF_STATUS_SUCCESS {
        return Err(anyhow!("nf_init failed, status={}", status));
    }

    // Required for the `tcpConnectRequest` handler to be called.
    let rule = NfRule {
        protocol: IPPROTO_TCP,
        direction: NfDirection::Out.value(),
        filteringFlag: NfFilteringFlag::NfIndicateConnectRequests.value(),
        ..Default::default()
    };
    // SAFETY: `rule` is a live `NfRule` for the call.
    let status = (fns.add_rule)(&rule as *const _, 0);
    if status != NF_STATUS_SUCCESS {
        return Err(anyhow!("adding rule failed: {}", status));
    }

    let rule = NfRule {
        filteringFlag: NfFilteringFlag::NfFilter.value(),
        ..Default::default()
    };
    // SAFETY: `rule` is a live `NfRule` for the call.
    let status = (fns.add_rule)(&rule as *const _, 0);
    if status != NF_STATUS_SUCCESS {
        return Err(anyhow!("adding rule failed: {}", status));
    }

    *UDP_SEND_SOCKET.write() = Some(std::net::UdpSocket::bind("0.0.0.0:0")?);

    let (tx, rx) = std::sync::mpsc::channel();
    *TX.lock() = Some(tx);

    if let Err(e) = res_tx.send(true) {
        debug!("unable to send nf init result: {}", e);
    }

    let _ = rx.recv();

    Ok(())
}

fn init_if_needed<P: AsRef<OsStr>>(driver_name: String, nfapi: P) -> Result<()> {
    let nfapi = nfapi.as_ref().to_string_lossy().to_string();
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        unsafe {
            if let Err(e) = init_nf(driver_name, nfapi, res_tx.clone()) {
                debug!("initialize nf failed: {}", e);
                let _ = res_tx.send(false);
            }
        };
    });
    if let Ok(res) = res_rx.recv() {
        if res {
            return Ok(());
        }
    }
    Err(anyhow!("initialize nf failed"))
}

static IS_NF_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn init<P: AsRef<OsStr>>(driver_name: String, nfapi: P) -> Result<()> {
    if !IS_NF_INITIALIZED.swap(true, Ordering::Relaxed) {
        if let Err(e) = init_if_needed(driver_name, nfapi) {
            // Not initialized: a later start tries again, and uninit has
            // nothing to free.
            IS_NF_INITIALIZED.store(false, Ordering::Relaxed);
            return Err(e);
        }
    }
    Ok(())
}

unsafe fn uninit_nf() {
    if IS_NF_INITIALIZED.swap(false, Ordering::Relaxed) {
        // Not set when nf never initialised. The library stays loaded: the
        // pointers in `NF` point into it, and a later init reuses them.
        if let Some(fns) = NF.get() {
            // SAFETY: takes no arguments; the library is still loaded.
            (fns.free)();
        }
    }
}

pub fn uninit() {
    // SAFETY: `uninit_nf` only calls `nf_free` from the loaded library.
    unsafe { uninit_nf() };
}

/// # Safety
pub unsafe fn get_process_name(pid: u32) -> Result<String> {
    let mut process_name_buf = vec![0u16; MAX_PATH];
    let process_name_len = process_name_buf.len() as u32;
    let Some(fns) = NF.get() else {
        return Err(anyhow!("nf is not initialized"));
    };
    let (from_kernel, get_process_name) = (fns.get_process_name_from_kernel, fns.get_process_name);
    // SAFETY: both write at most `process_name_len` UTF-16 units into
    // `process_name_buf`, which holds that many.
    if !from_kernel(pid, process_name_buf.as_mut_ptr() as _, process_name_len)
        && !get_process_name(pid, process_name_buf.as_mut_ptr() as _, process_name_len)
    {
        return Err(anyhow!("Unable to get process name pid={}", pid));
    }
    let process_name: OsString = OsString::from_wide(
        process_name_buf
            .into_iter()
            .take_while(|x| *x != 0)
            .collect::<Vec<_>>()
            .as_slice(),
    );
    // Return the full path instead of just the filename
    Ok(process_name.to_string_lossy().to_string())
}

pub struct NfManager {
    pub fake_dns: Arc<FakeDns>,
}

impl NfManager {
    pub fn new(driver_name: String, nfapi: String, fake_dns: Arc<FakeDns>) -> Result<Self> {
        init(driver_name, nfapi)?;
        Ok(Self { fake_dns })
    }
}

impl Drop for NfManager {
    fn drop(&mut self) {
        uninit();
    }
}

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("nf", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NfInboundOptions {
    driver_name: String,
    #[serde(default = "default_nfapi")]
    nfapi: String,
    #[serde(default)]
    fake_dns_exclude: Vec<String>,
    #[serde(default)]
    fake_dns_include: Vec<String>,
}

fn default_nfapi() -> String {
    "nfapi.dll".to_string()
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: NfInboundOptions = ctx.options()?;
    let (mode, filters) = if !options.fake_dns_include.is_empty() {
        (FakeDnsMode::Include, options.fake_dns_include)
    } else {
        (FakeDnsMode::Exclude, options.fake_dns_exclude)
    };
    let fake_dns = Arc::new(FakeDns::new(mode, filters));
    *NF_TAG.write() = Some(ctx.tag.to_owned());
    let manager = Arc::new(NfManager::new(
        options.driver_name,
        options.nfapi,
        fake_dns,
    )?);
    let stream = Arc::new(StreamHandler {
        manager: manager.clone(),
    });
    let datagram = Arc::new(DatagramHandler { manager });
    Ok(Arc::new(InboundHandler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_info(inserted: Instant) -> ConnInfo {
        ConnInfo {
            remote_addr: "1.2.3.4:443".parse().unwrap(),
            process_name: None,
            inserted,
        }
    }

    #[test]
    fn prune_removes_only_entries_older_than_the_ttl() {
        let start = Instant::now();
        let mut map = HashMap::new();
        map.insert(1, conn_info(start));
        map.insert(2, conn_info(start + Duration::from_secs(30)));
        map.insert(3, conn_info(start + TCP_INFO_TTL));

        prune(&mut map, start + TCP_INFO_TTL + Duration::from_secs(1));

        let mut left: Vec<u16> = map.keys().copied().collect();
        left.sort_unstable();
        assert_eq!(left, vec![2, 3]);
    }

    #[test]
    fn prune_keeps_entries_inserted_after_now() {
        let start = Instant::now();
        let mut map = HashMap::new();
        map.insert(1, conn_info(start + Duration::from_secs(5)));

        prune(&mut map, start);

        assert_eq!(map.len(), 1);
    }
}
