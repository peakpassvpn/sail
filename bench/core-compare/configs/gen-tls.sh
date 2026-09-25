#!/bin/sh
# Generates the TLS and REALITY test material (self-signed certificate,
# REALITY key pair) and the configs that embed it. Nothing here is committed;
# rerun after a fresh checkout. Needs openssl and sing-box.
set -e
cd "$(dirname "$0")"
D=$(pwd)
UUID=b831381d-6324-4d53-ad4f-8cda48b30811

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
	-subj /CN=localhost -addext subjectAltName=DNS:localhost \
	-keyout key.pem -out cert.pem 2>/dev/null
KP=$(sing-box generate reality-keypair)
PRIV=$(echo "$KP" | awk '/PrivateKey/{print $2}')
PUB=$(echo "$KP" | awk '/PublicKey/{print $2}')

TLS="\"tls\": { \"enabled\": true, \"server_name\": \"localhost\", \"certificate_path\": \"$D/cert.pem\", \"key_path\": \"$D/key.pem\" }"

cat > server-singbox-tls.json <<EOF
{
  "log": { "level": "error" },
  "inbounds": [
    { "type": "trojan", "listen": "127.0.0.1", "listen_port": 8443,
      "users": [ { "password": "bench-password" } ], $TLS },
    { "type": "vless", "listen": "127.0.0.1", "listen_port": 8444,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ], $TLS }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF

# The trojan inbound doubles as the REALITY handshake target.
cat > server-singbox-reality.json <<EOF
{
  "log": { "level": "error" },
  "inbounds": [
    { "type": "trojan", "listen": "127.0.0.1", "listen_port": 8443,
      "users": [ { "password": "bench-password" } ], $TLS },
    { "type": "vless", "listen": "127.0.0.1", "listen_port": 8445,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "localhost",
        "reality": { "enabled": true, "handshake": { "server": "127.0.0.1", "server_port": 8443 },
                     "private_key": "$PRIV", "short_id": [ "0123456789abcdef" ] } } }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF

cat > client-sail-reality.json <<EOF
{
  "log": { "level": "error" },
  "inbounds": [ { "type": "socks", "listen": "127.0.0.1", "listen_port": 1081 } ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": 8445, "uuid": "$UUID",
      "tls": { "enabled": true, "server_name": "localhost",
               "reality": { "enabled": true, "public_key": "$PUB", "short_id": "0123456789abcdef" } } }
  ]
}
EOF

cat > client-singbox-reality.json <<EOF
{
  "log": { "level": "error" },
  "inbounds": [ { "type": "socks", "listen": "127.0.0.1", "listen_port": 1081 } ],
  "outbounds": [
    { "type": "vless", "server": "127.0.0.1", "server_port": 8445,
      "uuid": "$UUID", "flow": "xtls-rprx-vision",
      "tls": { "enabled": true, "server_name": "localhost",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": { "enabled": true, "public_key": "$PUB", "short_id": "0123456789abcdef" } } }
  ]
}
EOF
echo "generated TLS / REALITY material and configs in $D"
