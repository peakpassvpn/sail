//! What the HTTP proxy's HTTP/2 is set up with at either end: sing-box
//! 1.15's HTTP/2 fields, and what sail takes for those left unset.

use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::runtime::Profile;

/// A stream's and a connection's receive windows when
/// `stream_receive_window` and `connection_receive_window` are unset, by
/// profile. A stream's is what one tunnel can have in flight towards this
/// end, so what it can move a round trip; a connection's, four of those.
///
/// Desktop and server, 16 MiB and 64 MiB: measured (2026-10-15, sail to
/// sail over a veth pair, one tunnel's bulk each way, Mbit/s): at 50 ms RTT
/// a 1 MiB window gave 164, 2 MiB 317, 4 MiB 368-410, 16 MiB 478-665, plain
/// TCP 510; at 150 ms 56, 110, 138-144, 208-232, plain TCP 198. 16 MiB
/// alone keeps up with TCP on a long path. Four tunnels on one connection
/// together moved no more than one alone (407-553 at 50 ms, 111-132 at
/// 150 ms with 16 MiB), the one TCP connection under them being the limit.
///
/// Mobile, 4 MiB and 16 MiB, and router, 2 MiB and 8 MiB: judgment values,
/// muxcore's h2mux window for these profiles, for their memory: unread data
/// a connection lets in is bounded by its window, and a tunnel nothing reads
/// is reset by the stall guard.
pub fn windows(profile: Profile) -> (u32, u32) {
    let stream: u32 = match profile {
        Profile::Desktop | Profile::Server => 16 << 20,
        Profile::Mobile => 4 << 20,
        Profile::Router => 2 << 20,
    };
    (stream, stream * CONNECTION_WINDOWS)
}

/// A connection's receive window in stream windows: with only
/// `stream_receive_window` set too.
pub const CONNECTION_WINDOWS: u32 = 4;

/// The largest header block accepted. A CONNECT's headers are a few
/// hundred bytes.
pub const MAX_HEADER_LIST: u32 = 16 << 10;

/// How long a ping may go unanswered when `idle_timeout` is unset, as Go's
/// HTTP/2 `PingTimeout`, which sing-box leaves to its default.
pub const PING_TIMEOUT: Duration = Duration::from_secs(15);

/// The tunnels one connection carries at once when
/// `max_concurrent_streams` is unset.
pub const MAX_STREAMS: u32 = 128;

/// The largest window HTTP/2 allows (RFC 9113 6.9.1).
const MAX_WINDOW: u64 = (1 << 31) - 1;

/// sing-box 1.15's HTTP/2 fields, as they are written.
#[derive(Default, Clone, Copy)]
pub struct Fields {
    pub idle_timeout: Option<Duration>,
    pub keep_alive_period: Option<Duration>,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub max_concurrent_streams: Option<u32>,
}

impl Fields {
    /// The first one set, for a configuration that may set none.
    pub fn first_set(&self) -> Option<&'static str> {
        [
            ("idle_timeout", self.idle_timeout.is_some()),
            ("keep_alive_period", self.keep_alive_period.is_some()),
            (
                "stream_receive_window",
                self.stream_receive_window.is_some(),
            ),
            (
                "connection_receive_window",
                self.connection_receive_window.is_some(),
            ),
            (
                "max_concurrent_streams",
                self.max_concurrent_streams.is_some(),
            ),
        ]
        .into_iter()
        .find(|(_, set)| *set)
        .map(|(name, _)| name)
    }
}

/// HTTP/2 as the fields set it up.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub stream_window: u32,
    pub connection_window: u32,
    pub max_streams: u32,
    /// After this long with nothing received, a ping (sing-box's
    /// `keep_alive_period`, Go's `ReadIdleTimeout`); unset, none.
    pub keep_alive: Option<Duration>,
    /// How long a ping may go unanswered (`idle_timeout`, Go's
    /// `PingTimeout`).
    pub ping_timeout: Duration,
    /// A server's connection with no tunnel open for this long is closed
    /// (`idle_timeout`, Go's server `IdleTimeout`); unset, never.
    #[cfg_attr(not(feature = "inbound-http"), allow(dead_code))]
    pub idle_close: Option<Duration>,
}

impl Settings {
    /// What `fields` set, over the defaults. Errors name the field, at
    /// `at` (`[tag] outbound`).
    pub fn new(at: &str, fields: &Fields, profile: Profile) -> Result<Self> {
        let (default_stream, default_connection) = windows(profile);
        let window = |name: &str, value: Option<u64>| -> Result<Option<u32>> {
            match value {
                None | Some(0) => Ok(None),
                Some(v) if (65_535..=MAX_WINDOW).contains(&v) => Ok(Some(v as u32)),
                Some(v) => Err(anyhow!(
                    "{}: {}: {} is not a window, 65535 to {} bytes",
                    at,
                    name,
                    v,
                    MAX_WINDOW
                )),
            }
        };
        let stream = window("stream_receive_window", fields.stream_receive_window)?;
        let stream_window = stream.unwrap_or(default_stream);
        let connection_window = window(
            "connection_receive_window",
            fields.connection_receive_window,
        )?
        .unwrap_or_else(|| {
            if stream.is_none() {
                return default_connection;
            }
            u32::try_from(u64::from(stream_window) * u64::from(CONNECTION_WINDOWS))
                .unwrap_or(MAX_WINDOW as u32)
                .min(MAX_WINDOW as u32)
        });
        let nonzero = |d: Option<Duration>| d.filter(|d| !d.is_zero());
        Ok(Settings {
            stream_window,
            connection_window,
            max_streams: fields
                .max_concurrent_streams
                .filter(|n| *n > 0)
                .unwrap_or(MAX_STREAMS),
            keep_alive: nonzero(fields.keep_alive_period),
            ping_timeout: nonzero(fields.idle_timeout).unwrap_or(PING_TIMEOUT),
            idle_close: nonzero(fields.idle_timeout),
        })
    }

    #[cfg(feature = "outbound-http")]
    pub fn client(&self) -> h2::client::Builder {
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(self.stream_window)
            .initial_connection_window_size(self.connection_window)
            .max_header_list_size(MAX_HEADER_LIST)
            .enable_push(false);
        builder
    }

    #[cfg(feature = "inbound-http")]
    pub fn server(&self) -> h2::server::Builder {
        let mut builder = h2::server::Builder::new();
        builder
            .initial_window_size(self.stream_window)
            .initial_connection_window_size(self.connection_window)
            .max_header_list_size(MAX_HEADER_LIST)
            .max_concurrent_streams(self.max_streams);
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each profile's windows, which the fields set go before.
    #[test]
    fn the_windows_are_the_profile_s_unless_set() {
        const MIB: u32 = 1 << 20;
        for (profile, stream, connection) in [
            (Profile::Desktop, 16 * MIB, 64 * MIB),
            (Profile::Server, 16 * MIB, 64 * MIB),
            (Profile::Mobile, 4 * MIB, 16 * MIB),
            (Profile::Router, 2 * MIB, 8 * MIB),
        ] {
            let settings = Settings::new("[h] outbound", &Fields::default(), profile).unwrap();
            assert_eq!(
                (settings.stream_window, settings.connection_window),
                (stream, connection),
                "{:?}",
                profile
            );
            let set = Fields {
                stream_receive_window: Some(MIB.into()),
                connection_receive_window: Some((3 * MIB).into()),
                ..Fields::default()
            };
            let settings = Settings::new("[h] outbound", &set, profile).unwrap();
            assert_eq!(
                (settings.stream_window, settings.connection_window),
                (MIB, 3 * MIB)
            );
            let stream_only = Fields {
                stream_receive_window: Some(MIB.into()),
                ..Fields::default()
            };
            let settings = Settings::new("[h] outbound", &stream_only, profile).unwrap();
            assert_eq!(settings.connection_window, MIB * CONNECTION_WINDOWS);
        }
    }

    #[test]
    fn unset_fields_take_the_defaults_and_windows_are_checked() {
        let settings = Settings::new("[h] outbound", &Fields::default(), Profile::Desktop).unwrap();
        assert_eq!(settings.max_streams, MAX_STREAMS);
        assert_eq!(settings.keep_alive, None);
        assert_eq!(settings.ping_timeout, PING_TIMEOUT);
        assert_eq!(settings.idle_close, None);

        let fields = Fields {
            idle_timeout: Some(Duration::from_secs(30)),
            keep_alive_period: Some(Duration::from_secs(10)),
            stream_receive_window: Some(1 << 20),
            connection_receive_window: None,
            max_concurrent_streams: Some(16),
        };
        let settings = Settings::new("[h] outbound", &fields, Profile::Desktop).unwrap();
        assert_eq!(settings.stream_window, 1 << 20);
        assert_eq!(settings.connection_window, (1 << 20) * CONNECTION_WINDOWS);
        assert_eq!(settings.max_streams, 16);
        assert_eq!(settings.keep_alive, Some(Duration::from_secs(10)));
        assert_eq!(settings.ping_timeout, Duration::from_secs(30));
        assert_eq!(settings.idle_close, Some(Duration::from_secs(30)));

        let err = Settings::new(
            "[h] outbound",
            &Fields {
                stream_receive_window: Some(1 << 31),
                ..Fields::default()
            },
            Profile::Desktop,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.starts_with("[h] outbound: stream_receive_window:"),
            "{}",
            err
        );
    }
}
