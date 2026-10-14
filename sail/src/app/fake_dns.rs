use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{rdata, DNSClass, RData, Record, RecordType};
use tokio::sync::RwLock;
use tracing::debug;

use crate::util::DnsMessageExt;

pub enum FakeDnsMode {
    Include,
    Exclude,
}

/// The fake addresses given, by domain and back: kept apart from the
/// filters of who gives them, so that what a reload builds anew goes on
/// with the same addresses, and an address an app holds stands for its
/// domain still.
#[derive(Clone, Default)]
pub struct FakePool(Arc<RwLock<FakeDnsImpl>>);

impl Default for FakeDnsImpl {
    fn default() -> Self {
        Self::new()
    }
}

/// A pool of fake addresses, and which domains get one from it.
pub struct FakeDns {
    pool: FakePool,
    filter: Filter,
}

/// Which domains get a fake address.
struct Filter {
    mode: FakeDnsMode,
    filters: Vec<String>,
}

impl FakeDns {
    /// With a pool of its own.
    pub fn new(mode: FakeDnsMode, filters: Vec<String>) -> Self {
        Self::in_pool(FakePool::default(), mode, filters)
    }

    /// Giving addresses from `pool`, as others built with it do.
    pub fn in_pool(pool: FakePool, mode: FakeDnsMode, filters: Vec<String>) -> Self {
        Self {
            pool,
            filter: Filter { mode, filters },
        }
    }

    pub async fn query_domain(&self, ip: &IpAddr) -> Option<String> {
        self.pool.0.read().await.query_domain(ip)
    }

    pub async fn query_fake_ip(&self, domain: &str) -> Option<IpAddr> {
        self.pool.0.read().await.query_fake_ip(domain)
    }

    pub async fn generate_fake_response(&self, request: &[u8]) -> Result<Vec<u8>> {
        let req = Message::from_vec(request)?;
        let domain = FakeDnsImpl::domain_of(&req)?;
        if !self.filter.accept(&domain) {
            return Err(anyhow!("domain {} not accepted", domain));
        }
        self.pool
            .0
            .write()
            .await
            .generate_fake_response(&req, &domain)
    }

    pub async fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        self.pool.0.read().await.is_fake_ip(ip)
    }
}

struct FakeDnsImpl {
    ip_to_domain: HashMap<u32, String>,
    domain_to_ip: HashMap<String, u32>,
    cursor: u32,
    min_cursor: u32,
    max_cursor: u32,
    ttl: u32,
}

impl Filter {
    fn accept(&self, domain: &str) -> bool {
        match self.mode {
            FakeDnsMode::Exclude => {
                for d in &self.filters {
                    if domain.contains(d) || d == "*" {
                        return false;
                    }
                }
                true
            }
            FakeDnsMode::Include => {
                for d in &self.filters {
                    if domain.contains(d) || d == "*" {
                        return true;
                    }
                }
                false
            }
        }
    }
}

impl FakeDnsImpl {
    pub(self) fn new() -> Self {
        let min_cursor = Self::ip_to_u32(&Ipv4Addr::new(198, 18, 0, 0));
        let max_cursor = Self::ip_to_u32(&Ipv4Addr::new(198, 18, 255, 255));
        Self {
            ip_to_domain: HashMap::new(),
            domain_to_ip: HashMap::new(),
            cursor: min_cursor,
            min_cursor,
            max_cursor,
            ttl: 1,
        }
    }

    pub(self) fn query_domain(&self, ip: &IpAddr) -> Option<String> {
        let ip = match ip {
            IpAddr::V4(ip) => ip,
            _ => return None,
        };
        self.ip_to_domain.get(&Self::ip_to_u32(ip)).cloned()
    }

    pub(self) fn query_fake_ip(&self, domain: &str) -> Option<IpAddr> {
        self.domain_to_ip
            .get(domain)
            .map(|v| IpAddr::V4(Self::u32_to_ip(v.to_owned())))
    }

    /// The domain `req` asks for: of a query in class IN, for A, AAAA or
    /// HTTPS; not the root, nor a name that is an address already.
    fn domain_of(req: &Message) -> Result<String> {
        if req.queries().is_empty() {
            return Err(anyhow!("no queries in this DNS request"));
        }

        let query = &req.queries()[0];
        if query.query_class() != DNSClass::IN {
            return Err(anyhow!("unsupported query class {}", query.query_class()));
        }

        let t = query.query_type();
        if t != RecordType::A && t != RecordType::AAAA && t != RecordType::HTTPS {
            return Err(anyhow!(
                "unsupported query record type {:?}",
                query.query_type()
            ));
        }

        let raw_name = query.name();

        let domain = if raw_name.is_fqdn() {
            let fqdn = raw_name.to_ascii();
            fqdn[..fqdn.len() - 1].to_string()
        } else {
            raw_name.to_ascii()
        };

        // A fake address stands for a domain: not for the root, nor for a
        // name that is an address already.
        if domain.is_empty() || domain.parse::<IpAddr>().is_ok() {
            return Err(anyhow!("{:?} is no domain to give a fake address", domain));
        }
        Ok(domain)
    }

    pub(self) fn generate_fake_response(&mut self, req: &Message, domain: &str) -> Result<Vec<u8>> {
        let query = &req.queries()[0];
        let raw_name = query.name();
        let domain = domain.to_owned();

        let ip = if let Some(ip) = self.query_fake_ip(&domain) {
            match ip {
                IpAddr::V4(a) => a,
                _ => return Err(anyhow!("unexpected Ipv6 fake IP")),
            }
        } else {
            let ip = self.allocate_ip(&domain)?;
            debug!("allocate {} for {}", &ip, &domain);
            ip
        };

        let mut resp = Message::new(0, MessageType::Query, OpCode::Query);

        // sets the response according to request
        // https://github.com/miekg/dns/blob/f515aa579d28efa1af67d9a62cc57f2dfe59da76/defaults.go#L15
        resp.set_id(req.id())
            .set_message_type(MessageType::Response)
            .set_op_code(req.op_code());

        if resp.op_code() == OpCode::Query {
            resp.set_recursion_desired(req.recursion_desired())
                .set_checking_disabled(req.checking_disabled());
        }
        resp.set_response_code(ResponseCode::NoError);
        if !req.queries().is_empty() {
            resp.add_query(query.clone());
        }

        if query.query_type() == RecordType::A {
            let ans = Record::from_rdata(raw_name.clone(), self.ttl, RData::A(rdata::A(ip)));
            resp.add_answer(ans);
        }

        Ok(resp.to_vec()?)
    }

    pub(self) fn is_fake_ip(&self, ip: &IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V4(ip) => ip,
            _ => return false,
        };
        let ip = Self::ip_to_u32(ip);
        ip >= self.min_cursor && ip <= self.max_cursor
    }

    fn allocate_ip(&mut self, domain: &str) -> Result<Ipv4Addr> {
        if let Some(prev_domain) = self.ip_to_domain.insert(self.cursor, domain.to_owned()) {
            // Remove the entry in the reverse map to make sure we won't have
            // multiple domains point to a same IP.
            self.domain_to_ip.remove(&prev_domain);
        }
        self.domain_to_ip.insert(domain.to_owned(), self.cursor);
        let ip = Self::u32_to_ip(self.cursor);
        self.prepare_next_cursor()?;
        Ok(ip)
    }

    // Make sure `self.cursor` is valid and can be used immediately for next fake IP.
    fn prepare_next_cursor(&mut self) -> Result<()> {
        for _ in 0..3 {
            self.cursor += 1;
            if self.cursor > self.max_cursor {
                self.cursor = self.min_cursor;
            }
            // avoid network and broadcast addresses
            match Self::u32_to_ip(self.cursor).octets()[3] {
                0 | 255 => {
                    continue;
                }
                _ => return Ok(()),
            }
        }
        Err(anyhow!("unable to prepare next cursor"))
    }

    fn u32_to_ip(ip: u32) -> Ipv4Addr {
        Ipv4Addr::from(ip)
    }

    fn ip_to_u32(ip: &Ipv4Addr) -> u32 {
        u32::from_be_bytes(ip.octets())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn query(name: &str) -> Vec<u8> {
        use hickory_proto::op::Query;
        use hickory_proto::rr::Name;
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message.to_vec().unwrap()
    }

    /// The fake address in `response`.
    fn address(response: &[u8]) -> IpAddr {
        match Message::from_vec(response).unwrap().answers()[0].data {
            RData::A(a) => IpAddr::V4(a.0),
            ref other => panic!("{:?}", other),
        }
    }

    /// A query for the root, or for a name that is an address, gets no
    /// fake address; a domain does.
    #[tokio::test]
    async fn only_a_domain_gets_a_fake_address() {
        let fake = FakeDns::new(FakeDnsMode::Exclude, Vec::new());
        assert!(fake
            .generate_fake_response(&query("a.example."))
            .await
            .is_ok());
        for name in [".", "10.0.0.1."] {
            let err = fake.generate_fake_response(&query(name)).await.unwrap_err();
            assert!(err.to_string().contains("no domain"), "{}: {}", name, err);
        }
    }

    /// What a reload builds anew, with other filters, in the same pool:
    /// the addresses given stay with their domains, and only what is given
    /// from now on follows the new filters.
    #[tokio::test]
    async fn a_fake_dns_built_anew_in_the_pool_keeps_its_addresses() {
        let pool = FakePool::default();
        let before = FakeDns::in_pool(pool.clone(), FakeDnsMode::Exclude, Vec::new());
        let a = address(
            &before
                .generate_fake_response(&query("a.example."))
                .await
                .unwrap(),
        );
        let after = FakeDns::in_pool(pool, FakeDnsMode::Include, vec!["b.example".into()]);
        assert_eq!(after.query_domain(&a).await.as_deref(), Some("a.example"));
        assert!(after.is_fake_ip(&a).await);
        assert!(after
            .generate_fake_response(&query("a.example."))
            .await
            .is_err());
        let b = address(
            &after
                .generate_fake_response(&query("b.example."))
                .await
                .unwrap(),
        );
        assert_ne!(a, b);
        assert_eq!(after.query_domain(&b).await.as_deref(), Some("b.example"));
    }

    #[test]
    fn test_u32_to_ip() {
        let ip1 = Ipv4Addr::new(127, 0, 0, 1);
        let ip2 = FakeDnsImpl::u32_to_ip(2130706433u32);
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_ip_to_u32() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let ip1 = FakeDnsImpl::ip_to_u32(&ip);
        let ip2 = 2130706433u32;
        assert_eq!(ip1, ip2);
    }
}
