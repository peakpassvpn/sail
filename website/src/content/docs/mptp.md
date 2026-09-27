---
title: MPTP
description: Combine multiple outbound paths into one logical client/server tunnel.
---

MPTP, the Multi-path Transport Protocol, opens several reliable sub-connections and presents them as one logical tunnel. A common deployment has a local SOCKS inbound on the client, an MPTP outbound across several paths, and an MPTP inbound on the server.

```text
App → SOCKS → MPTP client ⇒ path A ┐
                         ⇒ path B ├→ MPTP server → target
                         ⇒ path C ┘
```

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
      "tag": "aggregate",
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
    "final": "aggregate"
  }
}
```

Each value in `outbounds` is the tag of a sub-path. A real deployment usually makes those tags materially different—for example, different interfaces, upstream proxies or detours. Two identical direct outbounds do not create independent physical networks by themselves.

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

Open the listening port in the host firewall and cloud security group. If the server is exposed to the internet, place it behind the network controls appropriate to your deployment.

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

1. The client creates a session ID for the application flow.
2. It establishes sub-connections through the configured path outbounds.
3. Each sub-connection reaches the MPTP server and joins the session.
4. Frames are scheduled across the available paths.
5. The server reassembles the byte stream or datagrams and connects to the target.

The path layer is independent from routing: the router chooses the `aggregate` outbound, while MPTP decides which member connection carries each frame.

## Operational notes

- Configure at least two genuinely independent paths to obtain multipath behavior.
- Every member tag must exist and must be able to reach the MPTP server.
- Test member outbounds separately before testing the aggregate.
- Path latency and loss asymmetry affect reassembly and perceived throughput.
- Use server runtime tuning for a relay with many concurrent sessions.

The repository also contains a protocol sequence and implementation architecture in `docs/mptp_architecture.md`.
