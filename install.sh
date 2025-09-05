#!/usr/bin/env bash
# Cloudflared DoH Installer (Ubuntu 24.04)
set -euo pipefail

echo "[*] Installing prerequisites..."
apt update
apt install -y curl dnsutils || true

BIN="/usr/local/bin/cloudflared"
UNIT="/etc/systemd/system/cloudflared-doh.service"
RESOLV="/etc/resolv.conf"

echo "[*] Downloading cloudflared..."
ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then FILE="cloudflared-linux-amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then FILE="cloudflared-linux-arm64"
else echo "Unsupported architecture: $ARCH"; exit 1; fi

curl -L -o "$BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/$FILE"
chmod +x "$BIN"

echo "[*] Creating service user..."
id -u cloudflared >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared

echo "[*] Writing systemd unit..."
cat > "$UNIT" <<'EOF'
[Unit]
Description=Cloudflared DNS over HTTPS
After=network-online.target
Wants=network-online.target

[Service]
User=cloudflared
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ExecStart=/usr/local/bin/cloudflared proxy-dns \
  --address 127.0.0.1 \
  --port 53 \
  --upstream https://1.1.1.1/dns-query \
  --upstream https://1.0.0.1/dns-query \
  --upstream https://2606:4700:4700::1111/dns-query \
  --upstream https://2606:4700:4700::1001/dns-query
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Freeing port 53..."
systemctl disable --now systemd-resolved 2>/dev/null || true
rm -f "$RESOLV"
printf 'nameserver 127.0.0.1\noptions edns0\n' > "$RESOLV"

echo "[*] Starting cloudflared-doh..."
systemctl daemon-reload
systemctl enable --now cloudflared-doh

echo "[*] Testing..."
ss -lpnut | grep ':53'
dig @127.0.0.1 google.com +short
dig @127.0.0.1 AAAA cloudflare.com +short

echo "[✓] Cloudflare DoH installed and active!"
