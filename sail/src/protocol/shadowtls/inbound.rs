//! The ShadowTLS inbound. It relays an authenticated client's handshake
//! with the handshake server, then hands the connection to the inbound its
//! `detour` names, usually a Shadowsocks one, as sing-box does. Everyone
//! else is relayed to the handshake server whole, outside the handshake
//! deadline, so a prober talks to the real site for as long as it likes.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use hmac::Mac;
use serde_derive::Deserialize;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tracing::Instrument;

use super::{
    authenticate, check_version, data_hmac, picks_tls13, server_name, server_random, tag, Records,
    SiteRecords, VerifiedStream, APPLICATION_DATA, TAGGED_HEADER_LEN,
};
use crate::adapter::inbound::Handler as InboundHandlerImpl;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry, Options};
use crate::adapter::*;
use crate::net::{InboundDialer, InstanceDial};
use crate::protocol::fallback;
use crate::session::Session;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("shadowtls", InboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowTlsInboundOptions {
    /// Must be 3: versions 1 and 2 are not supported. sing-box's default
    /// is 1.
    #[serde(default = "version_one")]
    version: u32,
    /// Version 2's, and an error: version 3 takes `users`.
    #[serde(default)]
    password: Option<String>,
    /// At least one.
    #[serde(default)]
    users: Vec<ShadowTlsUser>,
    /// The site whose handshake is relayed, for everyone the other fields
    /// do not send elsewhere. Needed unless `wildcard_sni` is on.
    #[serde(default)]
    handshake: Option<ShadowTlsHandshake>,
    /// Handshake servers by the server name the ClientHello asks for.
    #[serde(default)]
    handshake_for_server_name: HashMap<String, ShadowTlsHandshake>,
    /// Relays a ServerHello that does not pick TLS 1.3 as it would an
    /// unauthenticated client.
    #[serde(default)]
    strict_mode: bool,
    #[serde(default)]
    wildcard_sni: WildcardSni,
    /// The inbound connections go to after the handshake, by tag: needed.
    #[serde(default)]
    detour: Option<String>,
}

fn version_one() -> u32 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowTlsUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: String,
    password: String,
}

/// A server and port, and sing-box's dial fields, which it is dialled
/// with over the instance's defaults, as REALITY's handshake server is.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowTlsHandshake {
    #[serde(default)]
    server: String,
    #[serde(default)]
    server_port: u16,
    #[serde(flatten)]
    dial: crate::net::dial::DialFields,
}

/// Whether the handshake server is the one the ClientHello names, on port
/// 443, when no `handshake_for_server_name` entry does.
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum WildcardSni {
    #[default]
    #[serde(alias = "")]
    Off,
    /// For authenticated clients; the others go to `handshake`.
    Authed,
    All,
}

#[derive(Clone, Debug)]
struct Target {
    server: String,
    port: u16,
    dialer: InboundDialer,
}

impl ShadowTlsHandshake {
    fn target(self, tag: &str, field: &str, dial: &InstanceDial) -> Result<Target> {
        let context = |e: anyhow::Error| anyhow!("[{}] inbound: {}: {}", tag, field, e);
        self.dial
            .check(crate::transport::layers::HANDSHAKE_DIAL)
            .map_err(context)?;
        let dialer = dial.dialer(&self.dial).map_err(context)?;
        if self.server.is_empty() || self.server_port == 0 {
            return Err(anyhow!(
                "[{}] inbound: {}: needs server and server_port",
                tag,
                field
            ));
        }
        Ok(Target {
            server: self.server,
            port: self.server_port,
            dialer,
        })
    }
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    match options.get("detour") {
        Some(Value::String(detour)) => Ok(vec![detour.clone()]),
        Some(_) => Err(anyhow!(
            "[{}] inbound: detour: must be an inbound's tag",
            tag
        )),
        None => Err(anyhow!(
            "[{}] inbound: detour: ShadowTLS needs the inbound its connections go to",
            tag
        )),
    }
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let options: ShadowTlsInboundOptions = ctx.options()?;
    check_version(options.version).map_err(|e| anyhow!("[{}] inbound: version: {}", tag, e))?;
    if options.password.is_some() {
        return Err(anyhow!(
            "[{}] inbound: password: only for ShadowTLS v2; version 3 takes users",
            tag
        ));
    }
    if options.users.is_empty() {
        return Err(anyhow!("[{}] inbound: users: needs at least one", tag));
    }
    let mut users = Vec::new();
    for (i, user) in options.users.into_iter().enumerate() {
        if user.password.is_empty() {
            return Err(anyhow!(
                "[{}] inbound: users[{}].password: cannot be empty",
                tag,
                i
            ));
        }
        let name = ctx.env.users.bind_named(Some(&user.name));
        users.push((name, user.password.into_bytes()));
    }
    let default = options
        .handshake
        .map(|h| h.target(tag, "handshake", ctx.dial))
        .transpose()?;
    if default.is_none() && options.wildcard_sni == WildcardSni::Off {
        return Err(anyhow!(
            "[{}] inbound: handshake: needs server and server_port",
            tag
        ));
    }
    let mut by_name = HashMap::new();
    for (name, handshake) in options.handshake_for_server_name {
        let target = handshake.target(
            tag,
            &format!("handshake_for_server_name.{}", name),
            ctx.dial,
        )?;
        by_name.insert(name, target);
    }
    let detour_tag = options.detour.unwrap_or_default();
    let detour = ctx.handler(&detour_tag)?;
    detour.stream().map_err(|_| {
        anyhow!(
            "[{}] inbound: detour: [{}] takes no TCP connections",
            tag,
            detour_tag
        )
    })?;
    let stream = Arc::new(Handler {
        users,
        default,
        by_name,
        strict: options.strict_mode,
        wildcard: options.wildcard_sni,
        detour,
        detour_tag,
        dialer: ctx.dial.default_dialer(),
    });
    Ok(Arc::new(InboundHandlerImpl::new(
        tag.to_owned(),
        Some(stream),
        None,
    )))
}

pub struct Handler {
    /// Names, and passwords.
    users: Vec<(Option<crate::user::UserRef>, Vec<u8>)>,
    default: Option<Target>,
    by_name: HashMap<String, Target>,
    strict: bool,
    wildcard: WildcardSni,
    detour: AnyInboundHandler,
    detour_tag: String,
    /// Dials the wildcard handshake servers where there is no `handshake`
    /// to dial them as: the instance's dial defaults.
    dialer: InboundDialer,
}

impl Handler {
    /// The handshake server for a ClientHello naming `name`: an
    /// authenticated client's, and everyone else's.
    fn targets(&self, name: &str) -> (Option<Target>, Option<Target>) {
        if let Some(target) = self.by_name.get(name) {
            return (Some(target.clone()), Some(target.clone()));
        }
        // Dialled as `handshake` is, if it is set.
        let wildcard = (!name.is_empty()).then(|| Target {
            server: name.to_string(),
            port: 443,
            dialer: self
                .default
                .as_ref()
                .map_or_else(|| self.dialer.clone(), |d| d.dialer.clone()),
        });
        match self.wildcard {
            WildcardSni::Off => (self.default.clone(), self.default.clone()),
            WildcardSni::Authed => (wildcard, self.default.clone()),
            WildcardSni::All => (wildcard.clone(), wildcard),
        }
    }
}

fn denied(why: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("shadowtls: {}", why),
    )
}

/// Relays `client` and `server` both ways, with what was read of each and
/// not yet passed on first, on a task of its own.
fn splice(
    sess: &Session,
    mut client: AnyStream,
    client_read: BytesMut,
    mut server: tokio::net::TcpStream,
    server_read: BytesMut,
) {
    let task = async move {
        let result = async {
            server.write_all(&client_read).await?;
            client.write_all(&server_read).await?;
            tokio::io::copy_bidirectional(&mut client, &mut server).await
        }
        .await;
        if let Err(e) = result {
            tracing::debug!("shadowtls: relay to the handshake server: {}", e);
        }
    };
    crate::runtime::scope::spawn("shadowtls handshake relay", task.instrument(sess.span()));
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut records = Records::default();
        let hello = records.expect(&mut stream).await?;
        let name = server_name(&hello)
            .ok_or_else(|| denied("the first record is not a ClientHello".into()))?;
        let (target, other) = self.targets(&name);
        let user =
            authenticate(&hello, self.users.iter().map(|(_, p)| p.as_slice())).and_then(|i| {
                match crate::user::shut_out(&self.users[i].0) {
                    false => Ok(i),
                    true => Err("no user's password signed it"),
                }
            });
        let (user, password) = match user {
            Ok(i) => (&self.users[i].0, &self.users[i].1),
            Err(why) => {
                let other = other.ok_or_else(|| {
                    denied(format!("{}; no handshake server for {:?}", why, name))
                })?;
                let mut consumed = hello.to_vec();
                consumed.extend_from_slice(&records.into_inner());
                crate::runtime::scope::spawn(
                    "shadowtls fallback relay",
                    fallback::relay(
                        other.dialer.clone(),
                        stream,
                        consumed,
                        other.server.clone(),
                        other.port,
                    )
                    .instrument(sess.span()),
                );
                return Err(denied(format!(
                    "{}; relayed to the handshake server {}:{}",
                    why, other.server, other.port
                )));
            }
        };
        let target = target.ok_or_else(|| denied(format!("no handshake server for {:?}", name)))?;
        let mut server = target.dialer.tcp(&target.server, target.port).await?;
        server.write_all(&hello).await?;
        let mut server_records = Records::default();
        let server_hello = server_records.expect(&mut server).await?;
        stream.write_all(&server_hello).await?;
        let random = match server_random(&server_hello) {
            Some(random) if !self.strict || picks_tls13(&server_hello) => random,
            random => {
                let why = match random {
                    Some(_) => "the handshake server did not pick TLS 1.3",
                    None => "the handshake server's first record is not a ServerHello",
                };
                splice(
                    &sess,
                    stream,
                    records.into_inner(),
                    server,
                    server_records.into_inner(),
                );
                return Err(denied(format!("{}; relayed", why)));
            }
        };

        // The handshake, relayed, until the client's first data record.
        let mut marks = SiteRecords::new(password, &random);
        let (mut client_rx, mut client_tx) = tokio::io::split(stream);
        let (mut server_rx, mut server_tx) = server.into_split();
        let (mut first, verify) = loop {
            tokio::select! {
                record = records.next(&mut client_rx) => {
                    let record = record?.ok_or_else(|| denied("the client left".into()))?;
                    if record[0] == APPLICATION_DATA && record.len() > TAGGED_HEADER_LEN {
                        let mut verify = data_hmac(password, &random, b"C");
                        verify.update(&record[TAGGED_HEADER_LEN..]);
                        let tag = tag(&verify);
                        if tag == record[super::HEADER_LEN..TAGGED_HEADER_LEN] {
                            verify.update(&tag);
                            break (record, verify);
                        }
                    }
                    server_tx.write_all(&record).await?;
                }
                record = server_records.next(&mut server_rx) => {
                    let record = record?.ok_or_else(|| {
                        denied("the handshake server left during the handshake".into())
                    })?;
                    client_tx.write_all(&marks.mark(record)).await?;
                }
            }
        };
        drop((server_rx, server_tx));
        let stream = client_rx.unsplit(client_tx);
        let verified = VerifiedStream::new(
            stream,
            data_hmac(password, &random, b"S"),
            verify,
            None,
            records.into_inner(),
            first.split_off(TAGGED_HEADER_LEN),
        );
        tracing::trace!("shadowtls: handshake relayed");
        sess.user = user.clone();
        sess.inbound_tag = self.detour_tag.clone();
        self.detour.stream()?.handle(sess, Box::new(verified)).await
    }
}
