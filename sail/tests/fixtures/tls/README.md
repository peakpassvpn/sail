# ClientHello captures

The ClientHello handshake messages that real browsers send, with their 4-byte header and without the record layer. The browser fingerprint tests compare sail's ClientHello against them (`sail/src/transport/tls/hello.rs`).

| File | Browser | Captured | How |
| --- | --- | --- | --- |
| `chrome-154.hello` | Chrome 154.0.8037.58, macOS arm64 (the official stable dmg, run from a copy out of it) | 2026-09-27 | `--headless=new --use-mock-keychain` with a fresh profile, `https://localhost:18443/`, no proxy |
| `firefox-156.hello` | Firefox 156.0.1, macOS arm64 | 2026-09-26 | `-headless` with a fresh profile (`network.proxy.type` 0), `https://localhost:18443/` |
| `safari-26.hello` | Safari 26.3.1, macOS 26.3.1 arm64 | 2026-09-26 | `open -g -a Safari https://localhost:18443/`; an ephemeral URLSession on the same system sends the same ClientHello |
| `ios-26.hello` | URLSession on iOS 26.4 (Xcode simulator, iPhone 17) | 2026-09-26 | an ephemeral URLSession built for the simulator (`swiftc -target arm64-apple-ios26.4-simulator`), run with `xcrun simctl spawn`; the same ClientHello as macOS Safari 26.3. Safari in the headless simulator only produced a retry (with TLS_FALLBACK_SCSV), otherwise identical |
| `android-okhttp4.hello` | OkHttp 4.12.0 on Android 17 (SDK 37, emulator `system-images;android-37.2;google_apis_ps16k;x86_64`) | 2026-09-27 | a minimal OkHttp client dexed with d8 and run with `app_process`, so OkHttp picks `Android10Platform` over the platform Conscrypt; `adb reverse` to the capture listener. OkHttp 5.5.0 (the `okhttp-android` artifact) sends the same ClientHello except the TLS 1.2 cipher order |
| `chrome-android-154.hello` | Chrome 154.0.8037.57 for Android (x86 APK from APKMirror, signed by Google's Chrome key), Android 11 emulator | 2026-09-27 | fresh install, first run skipped with the debug command line, `adb reverse`. The same ClientHello as `chrome-154.hello`; the chrome profile is tested against both |

To capture, run a TCP listener that saves the first handshake message of each connection, then open `https://localhost:<port>/` in the browser, starting from a fresh profile so that no session is resumed. Browsers randomize GREASE values, the order of extensions and the ECH GREASE length. The tests compare what stays the same across runs: JA4, and the values inside the extensions.

When a new browser version changes its ClientHello, add a new capture next to the old one and move the profile to it.
