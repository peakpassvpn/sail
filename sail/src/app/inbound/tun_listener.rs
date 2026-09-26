use std::sync::Arc;

use anyhow::Result;

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::config::Inbound;
use crate::protocol::tun;

pub struct TunInboundListener {
    pub inbound: Inbound,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl TunInboundListener {
    pub(crate) fn listen(&self) -> Result<tun::inbound::TunRunner> {
        tun::inbound::new(
            self.inbound.clone(),
            self.dispatcher.clone(),
            self.nat_manager.clone(),
        )
    }
}
