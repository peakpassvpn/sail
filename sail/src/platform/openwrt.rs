//! OpenWrt's firewall (fw4) drops what its input and forward chains do not
//! accept: traffic in and out of the TUN is let through by a drop-in fw4
//! includes, as sing-tun writes it, and fw4 is reloaded.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Result};

use super::nft;

/// The drop-in of the TUN `tun`: one each, so that two instances' do not
/// meet.
pub(crate) fn drop_in_path(tun: &str) -> PathBuf {
    PathBuf::from(format!("/etc/nftables.d/0-sail-auto-redirect-{}.nft", tun))
}

/// The drop-in's text: input and forward accept the TUN's traffic.
pub(crate) fn drop_in(tun: &str) -> String {
    let rules = format!(
        "iifname \"{tun}\" counter accept comment \"!sail: Accept traffic from tun\"\n    \
         oifname \"{tun}\" counter accept comment \"!sail: Accept traffic to tun\""
    );
    format!(
        "chain input {{\n    type filter hook input priority filter; policy accept;\n    {rules}\n}}\n\
         chain forward {{\n    type filter hook forward priority filter; policy accept;\n    {rules}\n}}\n"
    )
}

/// Whether this is OpenWrt with fw4: its table is there, and its command.
fn has_fw4() -> bool {
    let table = nft::list_tables(Some(nft::Family::Inet))
        .is_ok_and(|tables| tables.iter().any(|t| t.name == "fw4"));
    table
        && std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("fw4").is_file()))
}

fn reload() -> Result<()> {
    super::output(Command::new("fw4").arg("reload")).map(|_| ())
}

/// Writes the drop-in for `tun` and reloads fw4, on OpenWrt; elsewhere
/// does nothing. Returns whether it did.
pub(crate) fn setup(tun: &str) -> Result<bool> {
    if !has_fw4() {
        return Ok(false);
    }
    let path = drop_in_path(tun);
    std::fs::write(&path, drop_in(tun)).map_err(|e| anyhow!("{}: {}", path.display(), e))?;
    reload().map_err(|e| anyhow!("auto_redirect: fw4: {:#}", e))?;
    Ok(true)
}

/// Removes the drop-in of `tun`, if there is one, and reloads fw4.
pub(crate) fn cleanup(tun: &str) {
    let path = drop_in_path(tun);
    if !Path::new(&path).exists() {
        return;
    }
    if let Err(e) = std::fs::remove_file(&path) {
        tracing::warn!("{}: {}", path.display(), e);
        return;
    }
    if let Err(e) = reload() {
        tracing::warn!("auto_redirect: fw4: {:#}", e);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_drop_in_accepts_the_tun_s_traffic() {
        assert_eq!(
            super::drop_in("tun0"),
            "chain input {
    type filter hook input priority filter; policy accept;
    iifname \"tun0\" counter accept comment \"!sail: Accept traffic from tun\"
    oifname \"tun0\" counter accept comment \"!sail: Accept traffic to tun\"
}
chain forward {
    type filter hook forward priority filter; policy accept;
    iifname \"tun0\" counter accept comment \"!sail: Accept traffic from tun\"
    oifname \"tun0\" counter accept comment \"!sail: Accept traffic to tun\"
}
"
        );
    }
}
