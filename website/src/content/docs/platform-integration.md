---
title: Platform integration
description: Embed Sail in mobile, desktop, server and router hosts through the core and FFI boundary.
---

Sail keeps proxy behavior in the Rust core and injects host-specific capabilities at the boundary. The same configuration, routing and protocol implementations can therefore run inside a CLI process, a mobile VPN app or another native host.

## Integration layers

| Layer | Responsibility |
| --- | --- |
| Host application | Lifecycle, UI, permissions, platform network changes |
| `sail-ffi` or Rust API | Start, reload, shutdown, tests and callbacks |
| `sail` | Configuration, DNS, routing, protocols and transports |
| `sail-netstack` | User-space TCP/IP for TUN traffic |
| Operating system adapter | TUN device, socket protection, interfaces and logging |

This boundary keeps platform code from leaking into protocol handlers.

## Lifecycle

A host normally follows this sequence:

1. Prepare a config file or config string.
2. Register platform callbacks such as Android socket protection.
3. Start one Sail instance with a unique runtime ID.
4. Forward network-change events to the running instance.
5. Reload after a configuration change.
6. Shut the instance down before releasing host resources.

The FFI exposes entry points for file-based and string-based startup, reload, shutdown, network changes, configuration testing, outbound testing and health checks.

## Start settings

Host tuning is passed separately from the portable proxy configuration:

```json
{
  "profile": "mobile",
  "set": ["relay.buffer_size=32"],
  "data_dir": "/path/to/assets",
  "cache_dir": "/path/to/state",
  "log_to_system": true
}
```

Keeping these values separate lets the same proxy definition use a mobile memory budget in an app and a server budget in a relay.

`asset_sources` maps an asset's name to the URL it is downloaded from, as `{"asn.mmdb": "https://..."}`: the runtime API's `POST /api/v1/runtime/assets/{name}/update` takes it when the request gives no URL. Sail has no default source; the CLI's are its own.

## Assets

The data files a configuration reads (`asn.mmdb`, `geo.mmdb`, `site.dat`, or files its rules name) are the host's to provide in the data directory. `sail_required_assets(config_path, settings)` returns them as JSON, `{"assets": [{"name", "kind", "path", "used_by", "present"}]}`, or `{"error": "..."}`; free the string with `sail_free_string`. Fetch the missing ones before starting: a configuration that needs one that is missing fails to start, naming the path. See the CLI reference for the default sources the CLI uses.

## Network state

Rules and groups that match the network the host is on (`wifi_ssid`, `wifi_bssid`, `network_type`, `network_is_expensive`, `network_is_constrained`) read one state per instance. Hosts that know it -- mobile and desktop apps -- push it whenever it changes, through `sail_set_network_state(rt_id, json)` or `PUT /api/v1/runtime/network` (`GET` reads it back):

```json
{
  "interface": "en0",
  "addresses": ["192.168.1.2/24", "fd00::2/64"],
  "type": "wifi",
  "ssid": "Home",
  "bssid": "aa:bb:cc:dd:ee:ff",
  "gateway": "192.168.1.1",
  "mcc_mnc": "310260",
  "expensive": false,
  "constrained": false
}
```

`type` is `wifi`, `cellular`, `ethernet` or `other`; every field may be left out, and a condition on a field that is not known does not match. Once a host pushes a state, Sail's own detection stops for the rest of the instance's life.

Without a push, Sail detects what the system tells without extra permissions:

| System | Interface, gateway, addresses | Type | SSID and BSSID | Follows changes |
| --- | --- | --- | --- | --- |
| Linux | main table's default route (rtnetlink) | `/sys/class/net` | nl80211 | yes, on the route and address monitor |
| macOS | IPv4 default route | the interface's functional type | no: CoreWLAN needs Location permission | at start and on reload |
| Windows | adapter with a gateway and the lowest metric | the adapter's interface type | WLAN service (Windows 11 24H2 asks for Location permission) | yes, on route and interface change notices |
| Android, iOS | -- | -- | -- | the host pushes |

A cellular network counts as expensive; no system above says whether a network is constrained, so only a host can. A change of state is logged at `info` with the type, interface and gateway; the SSID and BSSID only at `debug`.

### When the network changes

A change counts when the connections made on the network before would not survive it: another default interface, another gateway or type, or other addresses (IPv6 compared by its /64). A new SSID or access point on the same interface and addresses -- a roam -- is not one: rules that match the network see it, and connections stay. `sail_network_changed(rt_id, mtu)` counts as one whatever the state says.

On a change Sail drops what was of the network before: the DNS answers kept and the connections the DNS servers keep, the connections open, and the TUN's flows; new connections are made on the network there is now. It logs one line at `info`, which tests measure by:

```
network changed: generation 3, reason=default-interface, interface=en0→en1, closed=12, dns_flushed=true, took=4ms
```

`reason` is `default-interface`, `state` (what Sail detects), `host` (a push, or `sail_network_changed`) or `wake`.

## Android

Android VPN applications must keep Sail's outbound sockets outside the VPN interface. Register the host callback backed by `VpnService.protect` before starting the instance. The callback can be invoked from multiple runtime threads, so the host implementation must be safe for concurrent calls.

Forward connectivity changes to Sail so DNS, interfaces and long-lived transports can react to Wi-Fi/mobile transitions.

## Apple platforms

The workspace includes scripts for producing Apple libraries and XCFramework artifacts. The host owns Network Extension lifecycle and gives Sail the platform resources it needs. Use the `mobile` profile for iOS unless measurements justify a larger budget.

Relative certificates, GeoIP and GeoSite assets should be placed in an application-controlled data directory and passed through start settings.

## Desktop and server

The CLI is the simplest host and is useful even when the final product embeds the library. Use it to validate a configuration and isolate an outbound before moving the same model into an application.

Servers should use the `server` profile when concurrency matters. Routers should begin with `router` and increase individual runtime values only after measuring memory pressure and throughput.

## Error boundary

FFI calls return stable numeric error categories for invalid arguments, configuration, I/O, runtime management and panics. A panic is caught at the FFI boundary when the build strategy allows it; treat that instance as unusable and rebuild application state instead of continuing to call it.

Configuration errors are designed to be found offline. Run the configuration and outbound test APIs before committing a new configuration to a running VPN session.

## Integration checklist

- Give every concurrent instance a unique runtime ID.
- Register socket protection before startup on Android.
- Keep configuration, assets and persisted selector state in distinct host-managed locations.
- Forward network changes instead of waiting for connections to fail.
- Test configuration offline before reload.
- Pair automatic TUN routing with an explicit egress-interface policy.
- Shut down before destroying callbacks or platform network objects.
