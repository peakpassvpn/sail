---
title: MPTP
description: Combine multiple outbound paths into one logical client/server tunnel.
---

MPTP, the Multi-path Transport Protocol, opens several reliable sub-connections and presents them as one logical tunnel. Every path carries a copy of the data, and the receiver keeps whichever copy arrives first: a slow or failing path does not hold the tunnel up while another path keeps up. A common deployment has a local SOCKS inbound on the client, an MPTP outbound across several paths, and an MPTP inbound on the server.

```text
App → SOCKS → MPTP client ⇒ path A ┐
                         ⇒ path B ├→ MPTP server → target
                         ⇒ path C ┘
```

MPTP and its two endpoints are Sail's own, in the default build. sing-box and Mihomo do not have them.

## Client configuration

```json
{
  "inbounds": [
    {
      "type": "socks",
      "tag": "local-socks",
      "listen": "127.0.0.1",
      "listen_port": 1086
    }
  ],
  "outbounds": [
    {
      "type": "mptp",
      "tag": "multipath",
      "outbounds": ["path-a", "path-b"],
      "server": "mptp.example.com",
      "server_port": 3001
    },
    {
      "type": "direct",
      "tag": "path-a"
    },
    {
      "type": "direct",
      "tag": "path-b"
    }
  ],
  "route": {
    "final": "multipath"
  }
}
```

The `mptp` outbound takes `outbounds`, `server` and `server_port`. Each value in `outbounds` is the tag of a sub-path, through which Sail connects to `server`. A real deployment usually makes those tags materially different—for example, different interfaces, upstream proxies or detours. Two identical direct outbounds do not create independent physical networks by themselves.

## Server configuration

```json
{
  "inbounds": [
    {
      "type": "mptp",
      "tag": "mptp-server",
      "listen": "0.0.0.0",
      "listen_port": 3001
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "internet"
    }
  ],
  "route": {
    "final": "internet"
  }
}
```

The `mptp` inbound has no options of its own beyond the listen fields.

:::caution
MPTP has no authentication and no encryption of its own. Anyone who reaches the server's port can use it to connect to any target, and the paths carry the data as the application sent it. Restrict the port to the clients' addresses, or carry the paths over outbounds that encrypt.
:::

Open the listening port in the host firewall and cloud security group for the clients only.

## Start and validate

On the server:

```sh
sail -c server.json -T
sail -c server.json --profile server
```

On the client:

```sh
sail -c client.json -T
sail -c client.json
```

Then test the local listener:

```sh
curl --socks5-hostname 127.0.0.1:1086 https://example.com
```

## What happens on a connection

1. The client creates a random session ID for the application flow.
2. It opens a sub-connection through every path outbound at once, and sends each the session ID, the command (TCP or UDP) and the target.
3. The session starts with the first sub-connection that connects; the others join it as they connect, and a path that fails to connect is left out.
4. Each write becomes a numbered frame, sent on every path that has room for it: a path with 64 KiB queued is skipped until it drains.
5. The receiver keeps the first copy of each frame, drops the duplicates, and delivers the frames in order. The server connects to the target and relays both ways the same way.

UDP is carried as datagrams over the same reliable tunnel. The session ends when the stream finishes, or fails when every path has closed before the data was complete.

The path layer is independent from routing: the router chooses the `multipath` outbound, while MPTP decides which member connections carry each frame.

## Operational notes

- Configure at least two genuinely independent paths to obtain multipath behavior.
- Every member tag must exist and must be able to reach the MPTP server.
- Test member outbounds separately before testing the MPTP outbound.
- Every path carries the whole stream while it keeps up: the traffic, and its cost, is multiplied by the number of paths. MPTP is built for a tunnel that survives a slow or failing path, not to add the paths' bandwidth together.
- Use server runtime tuning for a relay with many concurrent sessions.

The repository also describes the protocol sequence in [`docs/mptp_architecture.md`](https://github.com/peakpassvpn/sail/blob/master/docs/mptp_architecture.md).
