//! Redirection, both ways: the inbound takes connections an iptables or
//! nftables REDIRECT rule diverted to it, the outbound sends every
//! connection to one fixed address.

#[cfg(feature = "inbound-redirect")]
pub mod inbound;
#[cfg(feature = "outbound-redirect")]
pub mod outbound;
