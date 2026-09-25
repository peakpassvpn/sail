use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::{self, Blocks};
use serde_derive::Deserialize;

pub mod datagram;
mod ss2022;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use super::shadow;
use super::sip022;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "shadowsocks",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIALER),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksOutboundOptions {
    server: String,
    server_port: u16,
    method: String,
    /// With a 2022 method, the base64 PSK, or `iPSK:uPSK` for a server
    /// with users.
    password: String,
    /// Bytes sent before the first payload, percent-encoded.
    #[serde(default)]
    prefix: Option<String>,
    /// Only `obfs-local` (simple-obfs) is supported.
    #[serde(default)]
    plugin: Option<String>,
    /// `obfs=http|tls;obfs-host=<host>;obfs-uri=<path>`, as simple-obfs
    /// takes them.
    #[serde(default)]
    plugin_opts: Option<String>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: ShadowsocksOutboundOptions = ctx.options()?;
    let ss = if sip022::is_2022(&options.method) {
        build_2022(ctx.tag, &options)?
    } else {
        shadow::check_method("outbound", ctx.tag, &options.method)?;
        let stream = Arc::new(StreamHandler::new(
            options.server.clone(),
            options.server_port,
            options.method.clone(),
            options.password.clone(),
            options.prefix.clone(),
        )?);
        let datagram = Arc::new(DatagramHandler {
            address: options.server.clone(),
            port: options.server_port,
            cipher: options.method.clone(),
            password: options.password.clone(),
        });
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build()
    };
    match options.plugin.as_deref() {
        None => Ok(ss),
        Some("obfs-local") => {
            let obfs = obfs(ctx.tag, options.plugin_opts.as_deref().unwrap_or_default())?;
            layers::chain_outbound(ctx.tag, vec![obfs, ss])
        }
        Some(plugin) => Err(anyhow!(
            "[{}] outbound: plugin: unsupported plugin \"{}\", only obfs-local is",
            ctx.tag,
            plugin
        )),
    }
}

fn build_2022(tag: &str, options: &ShadowsocksOutboundOptions) -> Result<AnyOutboundHandler> {
    let method = sip022::Method::from_name(&options.method)
        .map_err(|e| anyhow!("[{}] outbound: method: {}", tag, e))?;
    let psks = sip022::decode_psk_list(method, &options.password)
        .map_err(|e| anyhow!("[{}] outbound: password: {}", tag, e))?;
    // The 2022 salt is all random; a fixed prefix would weaken it.
    if options.prefix.is_some() {
        return Err(anyhow!(
            "[{}] outbound: prefix: not available with the 2022 methods",
            tag
        ));
    }
    let psks = Arc::new(psks);
    let stream = Arc::new(ss2022::StreamHandler {
        address: options.server.clone(),
        port: options.server_port,
        method,
        psks: psks.clone(),
    });
    let datagram = Arc::new(ss2022::DatagramHandler {
        address: options.server.clone(),
        port: options.server_port,
        method,
        psks,
    });
    Ok(HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}

/// The simple-obfs layer `plugin_opts` describes.
fn obfs(tag: &str, plugin_opts: &str) -> Result<AnyOutboundHandler> {
    let mut mode = None;
    let mut host = String::new();
    let mut path = "/".to_string();
    for opt in plugin_opts
        .split(';')
        .map(str::trim)
        .filter(|o| !o.is_empty())
    {
        let (key, value) = opt.split_once('=').ok_or_else(|| {
            anyhow!(
                "[{}] outbound: plugin_opts: invalid option \"{}\"",
                tag,
                opt
            )
        })?;
        match key {
            "obfs" => mode = Some(value.to_string()),
            "obfs-host" => host = value.to_string(),
            "obfs-uri" => path = value.to_string(),
            _ => {
                return Err(anyhow!(
                    "[{}] outbound: plugin_opts: unknown option \"{}\"",
                    tag,
                    key
                ))
            }
        }
    }
    #[cfg(feature = "outbound-obfs")]
    {
        use crate::transport::obfs::{HttpObfsStreamHandler, TlsObfsStreamHandler};
        let stream: crate::adapter::AnyOutboundStreamHandler = match mode.as_deref() {
            Some("http") => Arc::new(HttpObfsStreamHandler::new(path.as_bytes(), host.as_bytes())),
            Some("tls") => Arc::new(TlsObfsStreamHandler::new(host.as_bytes())),
            _ => {
                return Err(anyhow!(
                    "[{}] outbound: plugin_opts: obfs must be http or tls",
                    tag
                ))
            }
        };
        Ok(HandlerBuilder::default()
            .tag(format!("{}/obfs", tag))
            .stream_handler(stream)
            .build())
    }
    #[cfg(not(feature = "outbound-obfs"))]
    {
        let _ = (mode, host, path);
        Err(anyhow!(
            "[{}] outbound: plugin: obfs-local needs the outbound-obfs feature, which is not compiled in",
            tag
        ))
    }
}
