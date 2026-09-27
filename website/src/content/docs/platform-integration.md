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
