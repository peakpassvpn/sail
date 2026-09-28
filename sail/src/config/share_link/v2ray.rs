//! The TLS, REALITY and transport parameters VLESS, Trojan and VMess links
//! share, as Xray's share link standard names them
//! (<https://github.com/XTLS/Xray-core/discussions/716>), in sing-box's
//! `tls` and `transport` objects.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::url::{shown, Link};

/// What a link says of its TLS and transport.
#[derive(Default)]
pub struct Params {
    /// `security`: `tls`, `reality` or `none`.
    pub security: Option<String>,
    pub sni: Option<String>,
    pub fp: Option<String>,
    pub alpn: Option<String>,
    pub insecure: bool,
    pub pbk: Option<String>,
    pub sid: Option<String>,
    /// REALITY's ML-DSA-65 verification key, which sail cannot check.
    pub pqv: bool,
    /// A pinned certificate hash, which sail cannot check.
    pub pinned: bool,
    /// `type`: `tcp`, `ws`, `grpc`, `httpupgrade`, ...
    pub network: Option<String>,
    pub header_type: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub service_name: Option<String>,
    /// gRPC's `mode`: `gun` or `multi`.
    pub mode: Option<String>,
    pub authority: bool,
    /// WebSocket early data, as a query parameter rather than in the path.
    pub ed: Option<String>,
    pub eh: Option<String>,
}

impl Params {
    /// The parameters of a VLESS, Trojan or Xray-style VMess link.
    pub fn of_link(link: &Link) -> Result<Self> {
        let owned = |k: &str| link.get(k).map(str::to_string);
        Ok(Params {
            security: link.get("security").map(str::to_ascii_lowercase),
            // `peer` is the older name, from trojan-gfw's links.
            sni: link.get_any(&["sni", "peer"]).map(str::to_string),
            fp: owned("fp"),
            alpn: owned("alpn"),
            insecure: link.any_flag(&["allowInsecure", "insecure", "allow_insecure"])?,
            pbk: owned("pbk"),
            sid: owned("sid"),
            pqv: link.get("pqv").is_some(),
            pinned: link.get_any(&["pcs", "pinSHA256"]).is_some(),
            network: link.get("type").map(str::to_ascii_lowercase),
            header_type: link.get("headerType").map(str::to_ascii_lowercase),
            host: owned("host"),
            path: owned("path"),
            service_name: owned("serviceName"),
            mode: link.get("mode").map(str::to_ascii_lowercase),
            authority: link.get("authority").is_some(),
            ed: owned("ed"),
            eh: owned("eh"),
        })
    }

    /// The `tls` object, if TLS or REALITY is on; `default` is the
    /// security when the link names none.
    pub fn tls(&self, default: &str) -> Result<Option<Value>> {
        let security = self.security.as_deref().unwrap_or(default);
        let reality = match security {
            "" | "none" => {
                if self.pbk.is_some() {
                    return Err(anyhow!("pbk: REALITY without security=reality"));
                }
                return Ok(None);
            }
            "tls" => false,
            "reality" => true,
            "xtls" => {
                return Err(anyhow!(
                    "security: legacy XTLS is not supported, only tls and reality"
                ))
            }
            other => {
                return Err(anyhow!(
                    "security: unknown {}, expected tls, reality or none",
                    shown(other)
                ))
            }
        };
        if self.pinned {
            return Err(anyhow!(
                "pcs: sail cannot pin a certificate's hash; drop it or pin by certificate"
            ));
        }
        let mut tls = Map::new();
        tls.insert("enabled".into(), json!(true));
        // With no SNI, the Host a transport sends, as v2rayN and mihomo
        // take it; else the server's address, as sing-box does.
        if let Some(sni) = self.sni.clone().or_else(|| self.transport_host()) {
            tls.insert("server_name".into(), json!(sni));
        }
        // REALITY has no certificate to skip checking, as Xray ignores it.
        if self.insecure && !reality {
            tls.insert("insecure".into(), json!(true));
        }
        if let Some(alpn) = &self.alpn {
            tls.insert("alpn".into(), json!(split_list(alpn)));
        }
        if let Some(fp) = &self.fp {
            tls.insert(
                "utls".into(),
                json!({ "enabled": true, "fingerprint": fingerprint(fp)? }),
            );
        }
        if reality {
            let Some(pbk) = &self.pbk else {
                return Err(anyhow!("pbk: REALITY needs the server's public key"));
            };
            if self.pqv {
                return Err(anyhow!(
                    "pqv: sail cannot verify REALITY's ML-DSA-65 signature"
                ));
            }
            let mut r = Map::new();
            r.insert("enabled".into(), json!(true));
            r.insert("public_key".into(), json!(pbk));
            if let Some(sid) = &self.sid {
                r.insert("short_id".into(), json!(sid));
            }
            tls.insert("reality".into(), Value::Object(r));
        }
        Ok(Some(Value::Object(tls)))
    }

    fn network(&self) -> &str {
        self.network.as_deref().unwrap_or("tcp")
    }

    /// The Host a transport sends, the first if the link lists several.
    fn transport_host(&self) -> Option<String> {
        match self.network() {
            "ws" | "httpupgrade" => self.host.as_deref().and_then(|h| {
                h.split(',')
                    .map(str::trim)
                    .find(|h| !h.is_empty())
                    .map(str::to_string)
            }),
            _ => None,
        }
    }

    /// The `transport` object, if any.
    pub fn transport(&self) -> Result<Option<Value>> {
        let network = self.network();
        let transport = match network {
            "tcp" | "raw" => {
                match self.header_type.as_deref() {
                    None | Some("none") => {}
                    Some("http") => {
                        return Err(anyhow!(
                            "headerType: TCP's HTTP header obfuscation is not supported"
                        ))
                    }
                    Some(other) => {
                        return Err(anyhow!("headerType: unknown {} for tcp", shown(other)))
                    }
                }
                return Ok(None);
            }
            "ws" => {
                let (path, ed, eh) = early_data(self.path.as_deref().unwrap_or("/"))?;
                let mut ws = Map::new();
                ws.insert("type".into(), json!("ws"));
                ws.insert("path".into(), json!(path));
                if let Some(host) = self.transport_host() {
                    ws.insert("headers".into(), json!({ "Host": host }));
                }
                let ed = match (ed, &self.ed) {
                    (Some(ed), _) => Some(ed),
                    (None, Some(ed)) => Some(
                        ed.parse::<usize>()
                            .map_err(|_| anyhow!("ed: not a number"))?,
                    ),
                    (None, None) => None,
                };
                if let Some(ed) = ed.filter(|ed| *ed > 0) {
                    ws.insert("max_early_data".into(), json!(ed));
                    let eh = eh
                        .or_else(|| self.eh.clone())
                        .unwrap_or_else(|| "Sec-WebSocket-Protocol".to_string());
                    ws.insert("early_data_header_name".into(), json!(eh));
                }
                ws
            }
            "httpupgrade" => {
                // Xray's early data over HTTPUpgrade is only an
                // optimization the server does not need.
                let (path, _, _) = early_data(self.path.as_deref().unwrap_or("/"))?;
                let mut hu = Map::new();
                hu.insert("type".into(), json!("httpupgrade"));
                if let Some(host) = self.transport_host() {
                    hu.insert("host".into(), json!(host));
                }
                hu.insert("path".into(), json!(path));
                hu
            }
            "grpc" | "gun" => {
                match self.mode.as_deref() {
                    None | Some("gun") => {}
                    Some("multi") => {
                        return Err(anyhow!(
                            "mode: gRPC's multi mode is not supported, only gun"
                        ))
                    }
                    Some(other) => return Err(anyhow!("mode: unknown {}", shown(other))),
                }
                if self.authority {
                    return Err(anyhow!("authority: not supported for gRPC"));
                }
                let mut grpc = Map::new();
                grpc.insert("type".into(), json!("grpc"));
                // v2rayN's VMess JSON puts the service name in `path`.
                if let Some(name) = self.service_name.as_ref().or(self.path.as_ref()) {
                    grpc.insert("service_name".into(), json!(name));
                }
                grpc
            }
            "http" | "h2" => {
                return Err(anyhow!(
                    "type: the HTTP/2 transport is not supported by sail"
                ))
            }
            "xhttp" | "splithttp" => {
                return Err(anyhow!("type: XHTTP is not supported by sail yet"))
            }
            "kcp" | "mkcp" => return Err(anyhow!("type: mKCP is not supported by sail")),
            "quic" => {
                return Err(anyhow!(
                    "type: the V2Ray QUIC transport is not supported by sail"
                ))
            }
            other => return Err(anyhow!("type: unknown transport {}", shown(other))),
        };
        Ok(Some(Value::Object(transport)))
    }

    /// Adds the `tls` and `transport` objects to `outbound`; `default` is
    /// the security when the link names none. The ALPN is checked against
    /// the transport as sail checks it: a transport speaking one version
    /// of HTTP needs it offered.
    pub fn apply(&self, outbound: &mut Map<String, Value>, default: &str) -> Result<()> {
        let tls = self.tls(default)?;
        let transport = self.transport()?;
        if let (Some(tls), Some(transport)) = (&tls, &transport) {
            let wanted = match transport["type"].as_str() {
                Some("grpc") => "h2",
                _ => "http/1.1",
            };
            if let Some(alpn) = tls["alpn"].as_array() {
                if !alpn.iter().any(|p| p == wanted) {
                    return Err(anyhow!(
                        "alpn: the transport speaks {}, which is not offered",
                        wanted
                    ));
                }
            }
        }
        if let Some(tls) = tls {
            outbound.insert("tls".into(), tls);
        }
        if let Some(transport) = transport {
            outbound.insert("transport".into(), transport);
        }
        Ok(())
    }
}

/// A comma-separated list, its items trimmed.
pub fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// The fingerprint `fp` names, as sail's `utls.fingerprint` takes it.
pub fn fingerprint(fp: &str) -> Result<String> {
    let fp = fp.to_ascii_lowercase();
    match fp.as_str() {
        "chrome" | "edge" | "firefox" | "safari" | "ios" | "android" | "random" => Ok(fp),
        _ => Err(anyhow!(
            "fp: sail has no fingerprint {}, only chrome, edge, firefox, safari, ios, android and random",
            shown(&fp)
        )),
    }
}

/// A WebSocket path, with Xray's `ed` (early data size) and `eh` (its
/// header) taken out of its query.
fn early_data(path: &str) -> Result<(String, Option<usize>, Option<String>)> {
    let Some((base, query)) = path.split_once('?') else {
        return Ok((path.to_string(), None, None));
    };
    let (mut ed, mut eh) = (None, None);
    let mut kept = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("ed", v)) => {
                ed = Some(
                    v.parse::<usize>()
                        .map_err(|_| anyhow!("path: ed: not a number"))?,
                )
            }
            Some(("eh", v)) => eh = Some(v.to_string()),
            _ => kept.push(pair),
        }
    }
    let path = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, kept.join("&"))
    };
    Ok((path, ed, eh))
}
