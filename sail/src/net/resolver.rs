use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use futures::TryFutureExt;

use crate::app::SyncDnsClient;

pub struct Resolver {
    addrs: Vec<SocketAddr>,
}

impl Resolver {
    pub async fn new<'a>(
        dns_client: SyncDnsClient,
        address: &'a String,
        port: &'a u16,
    ) -> Result<Self> {
        let mut ips = {
            dns_client
                .load_full()
                .direct_lookup(address)
                .map_err(|e| anyhow!("lookup {} failed: {}", address, e))
                .await?
        };
        // Tried in the order the DNS client gives them; `next` pops.
        ips.reverse();
        Ok(Resolver {
            addrs: ips.into_iter().map(|x| SocketAddr::new(x, *port)).collect(),
        })
    }
}

impl Iterator for Resolver {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.addrs.pop()
    }
}
