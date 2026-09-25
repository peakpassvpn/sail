# ClientHello captures

The ClientHello handshake messages that real browsers send, with their 4-byte header and without the record layer. The browser fingerprint tests compare sail's ClientHello against them (`sail/src/transport/tls/hello.rs`).

| File | Browser | Captured | How |
| --- | --- | --- | --- |
| `chrome-153.hello` | Chrome 153.0.8010.53, macOS arm64 | 2026-09-26 | `--headless=new` with a fresh profile, `https://localhost:18443/`, no proxy |
| `firefox-156.hello` | Firefox 156.0.1, macOS arm64 | 2026-09-26 | `-headless` with a fresh profile (`network.proxy.type` 0), `https://localhost:18443/` |
| `safari-26.hello` | Safari 26.3.1, macOS 26.3.1 arm64 | 2026-09-26 | `open -g -a Safari https://localhost:18443/`; an ephemeral URLSession on the same system sends the same ClientHello |

To capture, run a TCP listener that saves the first handshake message of each connection, then open `https://localhost:<port>/` in the browser, starting from a fresh profile so that no session is resumed. Browsers randomize GREASE values, the order of extensions and the ECH GREASE length. The tests compare what stays the same across runs: JA4, and the values inside the extensions.

When a new browser version changes its ClientHello, add a new capture next to the old one and move the profile to it.
