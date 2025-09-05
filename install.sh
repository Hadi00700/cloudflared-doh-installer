#!/usr/bin/env bash
# Cloudflared DoH Installer/Updater (Ubuntu 24.04)
set -euo pipefail

echo "[*] Installing prerequisites..."
apt update
apt install -y curl dnsutils || true

BIN="/usr/local/bin/cloudflared"
UNIT="/etc/systemd/system/cloudflared-doh.service"
RESOLV="/etc/resolv.conf"

echo "[*] Detecting arch & preparing download..."
ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then FILE="cloudflared-linux-amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then FILE="cloudflared-linux-arm64"
else echo "Unsupported architecture: $ARCH"; exit 1; fi
URL="https://github.com/cloudflare/cloudflared/releases/latest/download/${FILE}"

echo "[*] Downloading cloudflared to temp (safe for upgrades)..."
TMP="${BIN}.new"
rm -f "$TMP"
curl -L --fail -o "$TMP" "$URL"
chmod +x "$TMP"
chown root:root "$TMP"

echo "[*] Creating service user/group (if missing)..."
id -u cloudflared >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin cloudflared

echo "[*] Writing/refreshing systemd unit..."
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

echo "[*] Freeing port 53 and pointing resolv.conf to 127.0.0.1..."
systemctl disable --now systemd-resolved 2>/dev/null || true
rm -f "$RESOLV"
printf 'nameserver 127.0.0.1\noptions edns0\n' > "$RESOLV"

echo "[*] Swapping binary atomically..."
systemctl stop cloudflared-doh 2>/dev/null || true
mv -f "$TMP" "$BIN"

echo "[*] Starting cloudflared-doh..."
systemctl daemon-reload
systemctl enable --now cloudflared-doh

echo "[*] Waiting for service to be up..."
for i in {1..20}; do
  if systemctl is-active --quiet cloudflared-doh; then break; fi
  sleep 0.5
done

echo "[*] Testing (with retry)..."
for i in {1..20}; do
  if ss -lpnut | grep -q ':53'; then
    echo "[+] Port 53 is listening"
    break
  fi
  sleep 0.5
done
ss -lpnut | grep ':53' || echo "[!] Port 53 not found yet (continuing)"

IPv4_OK=""
IPv6_OK=""
for i in {1..5}; do
  A=$(dig @127.0.0.1 google.com +short | head -n1 || true)
  AAAA=$(dig @127.0.0.1 AAAA cloudflare.com +short | head -n1 || true)
  [ -n "$A" ] && IPv4_OK="$A"
  [ -n "$AAAA" ] && IPv6_OK="$AAAA"
  [ -n "$IPv4_OK" ] && break
  sleep 1
done

if [ -n "$IPv4_OK" ]; then
  echo "[+] IPv4 OK: $IPv4_OK"
else
  echo "[!] IPv4 test did not return an IP yet"; exit 1
fi

if [ -n "$IPv6_OK" ]; then
  echo "[+] IPv6 OK: $IPv6_OK"
else
  echo "[!] IPv6 AAAA not returned (may be fine if no IPv6 route)"
fi

echo "[✓] Cloudflare DoH installed/updated and active!"
