//! XTLS Vision, as the layers of one connection share it.

use crate::session::Session;

/// XTLS Vision state shared between the VLESS stream, which parses and writes
/// Vision frames, and the TLS stream beneath it.
///
/// While Vision is pending the server may switch to raw data right after any
/// TLS record, so the TLS stream reads exactly up to record boundaries until
/// Vision switches to direct copy or finishes.
#[derive(Clone, Default, Debug)]
pub struct VisionState(std::sync::Arc<VisionShared>);

#[derive(Default, Debug)]
pub struct VisionShared {
    read: std::sync::atomic::AtomicU8,
    write_direct: std::sync::atomic::AtomicBool,
    raw_capable: std::sync::atomic::AtomicBool,
}

impl VisionState {
    /// The Vision state of the connection `sess` is on.
    pub fn of(sess: &Session) -> Self {
        VisionState(sess.state.get::<VisionShared>())
    }

    const PENDING: u8 = 1;
    const DIRECT_COPY: u8 = 2;
    const DONE: u8 = 3;

    fn set_read(&self, state: u8) {
        self.0
            .read
            .store(state, std::sync::atomic::Ordering::Relaxed);
    }

    fn read(&self) -> u8 {
        self.0.read.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Vision is in use on this connection (set by VLESS before its request).
    pub fn start(&self) {
        self.set_read(Self::PENDING);
    }

    /// The server switched to raw data: read the transport directly.
    pub fn set_direct_copy(&self) {
        self.set_read(Self::DIRECT_COPY);
    }

    /// Vision ended without direct copy; TLS carries the rest of the
    /// connection and can no longer switch.
    pub fn set_done(&self) {
        self.set_read(Self::DONE);
    }

    pub fn is_pending(&self) -> bool {
        self.read() == Self::PENDING
    }

    pub fn is_direct_copy(&self) -> bool {
        self.read() == Self::DIRECT_COPY
    }

    /// The TLS layer can switch to raw reads and writes on the transport.
    pub fn set_raw_capable(&self) {
        self.0
            .raw_capable
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_raw_capable(&self) -> bool {
        self.0
            .raw_capable
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// VLESS sent PaddingDirect: further writes go to the transport directly.
    pub fn set_write_direct(&self) {
        self.0
            .write_direct
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_write_direct(&self) -> bool {
        self.0
            .write_direct
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
