# QUIC Initial captures

The first datagrams real QUIC clients send, as they left the client: long header Initial packets, protected. The QUIC sniffing tests read the server name of the ClientHello out of them (`sail/src/sniff/quic.rs`).

| Files | Client | Captured | How |
| --- | --- | --- | --- |
| `chrome-154-*.initial` | Chrome 154.0.8037.58, macOS arm64 | 2026-09-28 | `--headless=new --use-mock-keychain --origin-to-force-quic-on=localhost:18443` with a fresh profile, `https://localhost:18443/`. The ClientHello, with its post-quantum key share, is split over the first two datagrams in CRYPTO frames out of order; the third is a retransmission |

To capture, run `scripts/capture-quic-initial.py PORT PREFIX`, which saves the first datagrams of the first client without answering, then open `https://localhost:<port>/` in the browser with QUIC forced on for that origin, from a fresh profile.
