//! The socket options and calls a transparent proxy needs, which neither
//! std nor socket2 covers for IPv6.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};

use socket2::{Domain, SockAddr, SockRef, Socket, Type};

fn set_int_option(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `one` outlives the call, and its size is passed along.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &one as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Lets `socket` take traffic TPROXY diverts to it, and bind an address
/// that is not the host's. Both options set the same flag; an IPv6 socket
/// takes IPv4 traffic too when it is dual-stack.
pub fn set_transparent(socket: &SockRef<'_>, ipv6: bool) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    if ipv6 {
        set_int_option(fd, libc::SOL_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        set_int_option(fd, libc::SOL_IP, libc::IP_TRANSPARENT)
    }
}

/// Has the kernel report the destination each datagram received on
/// `socket` was sent to. A dual-stack IPv6 socket reports that of an IPv4
/// datagram only when asked on the IPv4 level as well.
pub fn set_recv_original_destination(socket: &SockRef<'_>, ipv6: bool) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_int_option(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR)?;
    if ipv6 {
        set_int_option(fd, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR)?;
    }
    Ok(())
}

/// Room for the control messages a datagram comes with: one original
/// destination, an IPv6 one at most, with room to spare. As `u64`s for
/// the alignment `cmsghdr` needs.
const CONTROL_LEN: usize = 16;

/// Receives one datagram on the non-blocking `fd` into `buf`: its length,
/// its source, and the destination it was sent to, if the kernel reported
/// one (see `set_recv_original_destination`).
pub fn recv_with_original_destination(
    fd: RawFd,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    // SAFETY: all-zero is a valid `sockaddr_storage` and `msghdr`.
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut control = [0u64; CONTROL_LEN];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut source as *mut libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = mem::size_of_val(&control) as _;

    // SAFETY: every pointer in `msg` points into a live buffer of the
    // length given with it.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel wrote a socket address of `msg_namelen` bytes.
    let source = unsafe { SockAddr::new(source, msg.msg_namelen) }
        .as_socket()
        .ok_or_else(|| io::Error::other("datagram from a source that is not an IP address"))?;

    let mut destination = None;
    // SAFETY: the control messages are walked with the kernel's own macros,
    // within the `msg_controllen` bytes it wrote.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let kind = (*cmsg).cmsg_type;
            let len = match (level, kind) {
                (libc::SOL_IP, libc::IP_ORIGDSTADDR) => mem::size_of::<libc::sockaddr_in>(),
                (libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR) => mem::size_of::<libc::sockaddr_in6>(),
                _ => 0,
            };
            let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
            if len != 0 && data_len >= len {
                let mut storage: libc::sockaddr_storage = mem::zeroed();
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    len,
                );
                destination = SockAddr::new(storage, len as libc::socklen_t).as_socket();
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((n as usize, source, destination))
}

/// A UDP socket bound to `address`, which need not be the host's, for
/// sending replies that look like they come from it.
pub fn bind_transparent_udp(address: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(address), Type::DGRAM, None)?;
    // Another reply socket, of this or another inbound, may be bound to
    // the same address for another client.
    socket.set_reuse_address(true)?;
    set_transparent(&SockRef::from(&socket), address.is_ipv6())?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}
