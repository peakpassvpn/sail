pub mod crypto;
/// Needs fancy-regex, which Clash's configurations bring.
#[cfg(feature = "config-clash")]
pub mod name_filter;
