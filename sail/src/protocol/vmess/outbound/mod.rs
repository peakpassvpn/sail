use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

use super::body::Security;
use super::header::*;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "vmess",
        OutboundFactory::standalone(build).with_blocks(Blocks::ALL),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VMessOutboundOptions {
    server: String,
    server_port: u16,
    uuid: String,
    /// `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` or `zero`.
    #[serde(default = "default_security")]
    security: String,
    /// Only 0: legacy VMess is not spoken.
    #[serde(default)]
    alter_id: u32,
    /// Random padding after each chunk, as v2ray pads.
    #[serde(default)]
    global_padding: bool,
    /// `""` (VMess's own UDP) or `xudp`.
    #[serde(default)]
    packet_encoding: String,
}

fn default_security() -> String {
    "auto".to_string()
}

/// What a client asks for: the security and options of each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSecurity {
    Aead(Security),
    /// `none` and `zero`: no encryption and, but for UDP, no chunks -- the
    /// bare stream. That is what sing-box means by either; v2ray's `none`
    /// keeps masked chunks, which sing-box 1.13's server mishandles (it
    /// ends the stream with an empty chunk of its own), and every server
    /// takes the bare stream.
    None,
}

impl ClientSecurity {
    pub fn parse(security: &str) -> Result<Self> {
        match security {
            "auto" => Ok(ClientSecurity::Aead(auto_security())),
            "aes-128-gcm" => Ok(ClientSecurity::Aead(Security::Aes128Gcm)),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                Ok(ClientSecurity::Aead(Security::Chacha20Poly1305))
            }
            "none" | "zero" => Ok(ClientSecurity::None),
            other => Err(anyhow!(
                "unsupported \"{}\", expected auto, aes-128-gcm, chacha20-poly1305, none or zero",
                other
            )),
        }
    }

    /// The security and options of a request with `command`.
    pub fn request(self, command: u8, global_padding: bool) -> (u8, u8) {
        let padding = if global_padding {
            OPTION_GLOBAL_PADDING
        } else {
            0
        };
        let chunked = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | padding;
        match self {
            ClientSecurity::Aead(security) => (security.wire(), chunked),
            // UDP needs chunks to keep its packets apart.
            ClientSecurity::None if command == COMMAND_UDP => (SECURITY_NONE, OPTION_CHUNK_STREAM),
            ClientSecurity::None => (SECURITY_NONE, 0),
        }
    }
}

/// AES-128-GCM where the CPU has AES instructions, else ChaCha20-Poly1305,
/// as `auto` means in v2ray and sing-box.
fn auto_security() -> Security {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("aes")
        && std::arch::is_x86_feature_detected!("pclmulqdq")
    {
        return Security::Aes128Gcm;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        return Security::Aes128Gcm;
    }
    Security::Chacha20Poly1305
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: VMessOutboundOptions = ctx.options()?;
    let uuid = *uuid::Uuid::parse_str(&options.uuid)
        .map_err(|e| anyhow!("[{}] outbound: uuid: {}", ctx.tag, e))?
        .as_bytes();
    if options.alter_id != 0 {
        return Err(anyhow!(
            "[{}] outbound: alter_id: only 0 is supported, legacy VMess is not",
            ctx.tag
        ));
    }
    let security = ClientSecurity::parse(&options.security)
        .map_err(|e| anyhow!("[{}] outbound: security: {}", ctx.tag, e))?;
    let xudp = match options.packet_encoding.as_str() {
        "" => false,
        "xudp" => true,
        other => {
            return Err(anyhow!(
                "[{}] outbound: packet_encoding: unsupported \"{}\", expected \"\" or \"xudp\"",
                ctx.tag,
                other
            ))
        }
    };
    let client = Arc::new(stream::Client {
        cmd_key: cmd_key(&uuid),
        security,
        global_padding: options.global_padding,
    });
    let stream = Arc::new(StreamHandler {
        address: options.server.clone(),
        port: options.server_port,
        client: client.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: options.server,
        port: options.server_port,
        client,
        xudp,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_options() {
        assert!(ClientSecurity::parse("aes-128-cfb").is_err());
        let aes = ClientSecurity::parse("aes-128-gcm").unwrap();
        assert_eq!(
            aes.request(COMMAND_TCP, true),
            (
                SECURITY_AES128_GCM,
                OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING
            )
        );
        let zero = ClientSecurity::parse("zero").unwrap();
        assert_eq!(zero.request(COMMAND_TCP, false), (SECURITY_NONE, 0));
        assert_eq!(zero.request(COMMAND_MUX, false), (SECURITY_NONE, 0));
        assert_eq!(
            zero.request(COMMAND_UDP, false),
            (SECURITY_NONE, OPTION_CHUNK_STREAM)
        );
        assert_eq!(ClientSecurity::parse("none").unwrap(), zero);
        assert!(matches!(
            ClientSecurity::parse("auto").unwrap(),
            ClientSecurity::Aead(_)
        ));
    }
}
