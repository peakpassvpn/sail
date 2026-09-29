pub mod crypto;
/// Needs fancy-regex, which Clash's configurations and the smart group
/// bring.
#[cfg(any(feature = "config-clash", feature = "outbound-smart"))]
pub mod name_filter;
