//! Hard resource accounting shared by packet, transport, and IP modules.

mod budget;
mod credit;
mod slab;

pub use budget::{
    BudgetError, BudgetLease, BudgetProfile, BudgetSnapshot, PressureLevel, ResourceBudget,
    ResourceKind, ResourceLedger,
};
pub use slab::{ArenaPacket, PacketArena, SlabChain, SlabClass};

pub use credit::{CreditObserverAlreadyBound, CreditReturnObserver, CreditReturnState};
