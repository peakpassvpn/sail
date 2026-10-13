//! `ntp`: the offset of the system's clock from an NTP server's, measured
//! with SNTP (RFC 4330) every `interval`, which the instance's protocols
//! correct the time they check by (`crate::clock`). The system's clock is
//! never set.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

use crate::app::SyncDnsClient;
use crate::config::model::Ntp;
use crate::net::dial::{InboundDialer, InstanceDial};
use crate::runtime::scope::TaskScope;
use crate::session::SocksAddr;

/// sing-box's defaults.
const DEFAULT_PORT: u16 = 123;
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// How long a server has to answer: a judgment value, as the DNS servers'
/// default answer time.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);
/// Seconds from the NTP era (1900) to the Unix one (1970).
const NTP_TO_UNIX: u64 = 2_208_988_800;

/// The service, checked: what the instance runs.
pub struct NtpService {
    server: SocksAddr,
    interval: Duration,
    dialer: InboundDialer,
    dns: SyncDnsClient,
}

impl NtpService {
    /// The service `ntp` asks for, if enabled; an error names the field.
    pub fn new(ntp: &Ntp, dial: &InstanceDial) -> Result<Option<Self>> {
        let Some((server, interval)) = checked(ntp)? else {
            return Ok(None);
        };
        let dialer = dial.dialer(&ntp.dial).map_err(|e| anyhow!("ntp.{:#}", e))?;
        Ok(Some(NtpService {
            server,
            interval,
            dialer,
            dns: dial.dns.clone(),
        }))
    }
}

/// The server and the interval `ntp` names, if enabled.
fn checked(ntp: &Ntp) -> Result<Option<(SocksAddr, Duration)>> {
    if !ntp.enabled {
        return Ok(None);
    }
    if ntp.write_to_system {
        return Err(anyhow!(
            "ntp.write_to_system: setting the system's clock is not supported: sail \
             corrects the time its protocols check instead"
        ));
    }
    let server = ntp
        .server
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ntp.server: missing"))?;
    let server = SocksAddr::try_from((server, ntp.server_port.unwrap_or(DEFAULT_PORT)))
        .map_err(|e| anyhow!("ntp.server: {}", e))?;
    let interval = match ntp.interval {
        Some(i) if i.is_zero() => return Err(anyhow!("ntp.interval: must be more than 0")),
        Some(i) => i,
        None => DEFAULT_INTERVAL,
    };
    Ok(Some((server, interval)))
}

impl NtpService {
    /// Measures the offset now and every `interval`, into the scope of the
    /// instance it runs in. A measure that fails keeps the last.
    pub fn runner(self) -> crate::Runner {
        Box::pin(async move {
            let Some(scope) = TaskScope::current() else {
                warn!("ntp: not run in an instance; the time is the system's");
                return;
            };
            loop {
                match self.measure().await {
                    Ok(offset) => {
                        let was = scope.clock_offset();
                        scope.set_clock_offset(offset);
                        if was == 0 {
                            info!(
                                "ntp: {}: the system's clock is {} ms behind",
                                self.server,
                                offset / 1_000_000
                            );
                        } else {
                            debug!(
                                "ntp: {}: the system's clock is {} ms behind",
                                self.server,
                                offset / 1_000_000
                            );
                        }
                    }
                    Err(e) => warn!("ntp: {}: {:#}; the last offset is kept", self.server, e),
                }
                tokio::time::sleep(self.interval).await;
            }
        })
    }

    /// What the system's clock is behind the server's, in nanoseconds.
    async fn measure(&self) -> Result<i64> {
        let datagram = self
            .dialer
            .dialer()
            .datagram(&self.dns, None, &self.server)
            .await?;
        let (mut recv, mut send) = datagram.split();
        let sent = SystemTime::now();
        let request = request(sent);
        send.send_to(&request, &self.server).await?;
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(ANSWER_WITHIN, recv.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow!("no answer within {:?}", ANSWER_WITHIN))??
            .0;
        let received = SystemTime::now();
        let _ = send.close().await;
        answer(&buf[..n], &request, sent, received)
    }
}

/// A client's request, mode 3 of version 4, its transmit time `sent`: the
/// server gives it back as the reply's origin.
fn request(sent: SystemTime) -> [u8; 48] {
    let mut packet = [0u8; 48];
    // LI 0, VN 4, mode 3.
    packet[0] = 0b00_100_011;
    packet[40..48].copy_from_slice(&timestamp(sent).to_be_bytes());
    packet
}

/// The offset a reply to `request`, sent at `t0` and received at `t3`,
/// tells: ((t1 − t0) + (t2 − t3)) / 2. Taken only from a server's reply
/// (mode 4) that is not a kiss-o'-death (stratum 0), to this request (its
/// origin is the request's transmit time), with a transmit time.
fn answer(reply: &[u8], request: &[u8; 48], t0: SystemTime, t3: SystemTime) -> Result<i64> {
    if reply.len() < 48 {
        return Err(anyhow!("a reply of {} bytes", reply.len()));
    }
    if reply[0] & 0b111 != 4 {
        return Err(anyhow!("not a server's reply (mode {})", reply[0] & 0b111));
    }
    if reply[1] == 0 {
        let code = String::from_utf8_lossy(&reply[12..16]).to_string();
        return Err(anyhow!("kiss-o'-death {:?}", code));
    }
    if reply[24..32] != request[40..48] {
        return Err(anyhow!("a reply to another request"));
    }
    let field = |at: usize| u64::from_be_bytes(reply[at..at + 8].try_into().unwrap());
    let (t1, t2) = (field(32), field(40));
    if t2 == 0 {
        return Err(anyhow!("a reply with no transmit time"));
    }
    let nanos = |ntp: u64| -> i128 {
        let secs = (ntp >> 32) as i128 - NTP_TO_UNIX as i128;
        let frac = ((ntp & 0xffff_ffff) as i128 * 1_000_000_000) >> 32;
        secs * 1_000_000_000 + frac
    };
    let unix = |t: SystemTime| -> i128 {
        t.duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0)
    };
    let offset = ((nanos(t1) - unix(t0)) + (nanos(t2) - unix(t3))) / 2;
    i64::try_from(offset).map_err(|_| anyhow!("an offset of {} ns", offset))
}

/// `time` as an NTP timestamp: seconds from 1900, and the fraction.
fn timestamp(time: SystemTime) -> u64 {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() + NTP_TO_UNIX;
    let frac = ((since.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server's reply to `request`, its clock `ahead` of the client's,
    /// answering at once.
    fn reply(request: &[u8; 48], at: SystemTime, ahead: Duration) -> [u8; 48] {
        let mut r = [0u8; 48];
        r[0] = 0b00_100_100;
        r[1] = 2;
        r[24..32].copy_from_slice(&request[40..48]);
        let server = timestamp(at + ahead);
        r[32..40].copy_from_slice(&server.to_be_bytes());
        r[40..48].copy_from_slice(&server.to_be_bytes());
        r
    }

    #[test]
    fn the_offset_is_the_server_s_clock_less_the_client_s() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let request = request(t0);
        let ahead = Duration::from_millis(1500);
        // Half the 40 ms round trip each way.
        let at = t0 + Duration::from_millis(20);
        let t3 = t0 + Duration::from_millis(40);
        let offset = answer(&reply(&request, at, ahead), &request, t0, t3).unwrap();
        // Within the NTP fraction's rounding.
        assert!((offset - 1_500_000_000).abs() < 10, "{}", offset);
    }

    #[test]
    fn only_a_server_s_reply_to_this_request_is_taken() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let request = request(t0);
        let good = reply(&request, t0, Duration::ZERO);
        assert!(answer(&good, &request, t0, t0).is_ok());
        let mut client = good;
        client[0] = 0b00_100_011;
        assert!(answer(&client, &request, t0, t0).is_err());
        let mut kod = good;
        kod[1] = 0;
        kod[12..16].copy_from_slice(b"RATE");
        let e = answer(&kod, &request, t0, t0).unwrap_err();
        assert!(e.to_string().contains("RATE"), "{}", e);
        let mut late = good;
        late[24..32].copy_from_slice(&timestamp(t0 - Duration::from_secs(1)).to_be_bytes());
        assert!(answer(&late, &request, t0, t0).is_err());
        let mut silent = good;
        silent[40..48].copy_from_slice(&[0; 8]);
        assert!(answer(&silent, &request, t0, t0).is_err());
        assert!(answer(&good[..47], &request, t0, t0).is_err());
    }

    #[test]
    fn write_to_system_is_refused() {
        let ntp: Ntp = serde_json::from_value(serde_json::json!({
            "enabled": true, "server": "time.example", "write_to_system": true
        }))
        .unwrap();
        let e = checked(&ntp).unwrap_err();
        assert!(e.to_string().contains("ntp.write_to_system"), "{}", e);
        let off: Ntp =
            serde_json::from_value(serde_json::json!({ "server": "t.example" })).unwrap();
        assert!(checked(&off).unwrap().is_none());
        let (server, interval) = checked(&Ntp {
            enabled: true,
            ..off
        })
        .unwrap()
        .unwrap();
        assert_eq!(server.to_string(), "t.example:123");
        assert_eq!(interval, DEFAULT_INTERVAL);
    }
}
