#!/usr/bin/env bash
# Cloudflared DoH Installer/Updater (Ubuntu 24.04)
# Features:
#  - Safe binary swap (no "Text file busy")
#  - Robust service wait & testing (IPv4/IPv6)
#  - Precise port checks (no false positives)
#  - Optional --uninstall to restore system defaults
set -euo pipefail

BIN="/usr/local/bin/cloudflared"
UNIT="/etc/systemd/system/cloudflared-doh.service"
RESOLV="/etc/resolv.conf"

log() { printf "%s\n" "$*"; }
die() { printf "[-] %s\n" "$*" >&2; exit 1; }

ensure_root() {
  [ "$(id -u)" -eq 0 ] || die "Please run as root."
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64) FILE="cloudflared-linux-amd64" ;;
    aarch64|arm64) FILE="cloudflared-linux-arm64" ;;
    *) die "Unsupported architecture: $arch" ;;
  esac
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/${FILE}"
}

write_unit() {
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
}

stop_conflicting_services() {
  # Free port 53 if any other DNS service is listening.
  systemctl disable --now systemd-resolved 2>/dev/null || true
  systemctl disable --now dnsmasq 2>/dev/null || true
  systemctl disable --now unbound 2>/dev/null || true
  systemctl disable --now bind9 2>/dev/null || true
}

point_resolv_to_local() {
  rm -f "$RESOLV"
  printf 'nameserver 127.0.0.1\noptions edns0\n' > "$RESOLV"
}

precise_port_check() {
  # Return 0 only if 127.0.0.1:53 is actually listening (UDP or TCP)
  ss -lpnut '( sport = :53 )' | grep -qE '\b127\.0\.0\.1:53\b'
}

wait_for_service() {
  # Wait until systemd marks service active
  for _ in {1..20}; do
    if systemctl is-active --quiet cloudflared-doh; then return 0; fi
    sleep 0.5
  done
  return 1
}

wait_for_port_53() {
  for _ in {1..20}; do
    if precise_port_check; then
      log "[+] Port 53 is listening on 127.0.0.1"
      return 0
    fi
    sleep 0.5
  done
  log "[!] Port 53 not listening yet (continuing)"
  return 1
}

test_dns() {
  local v4 v6
  v4="$(dig @127.0.0.1 google.com +short | head -n1 || true)"
  v6="$(dig @127.0.0.1 AAAA cloudflare.com +short | head -n1 || true)"

  # Retry a few times for slow starts
  for _ in {1..4}; do
    [ -n "$v4" ] && break
    sleep 1
    v4="$(dig @127.0.0.1 google.com +short | head -n1 || true)"
  done

  if [ -n "$v4" ]; then
    log "[+] IPv4 OK: $v4"
  else
    die "IPv4 test did not return an IP. Check logs: journalctl -u cloudflared-doh -e --no-pager"
  fi

  if [ -n "$v6" ]; then
    log "[+] IPv6 OK: $v6"
  else
    log "[!] IPv6 AAAA not returned (may be fine if host lacks IPv6 route)"
  fi
}

install_or_update() {
  log "[*] Installing prerequisites..."
  apt update
  apt install -y curl dnsutils || true

  detect_arch

  log "[*] Downloading cloudflared to temp (safe for upgrades)..."
  local tmp="${BIN}.new"
  rm -f "$tmp"
  curl -L --fail -o "$tmp" "$URL"
  chmod +x "$tmp"
  chown root:root "$tmp"

  log "[*] Creating service user/group (if missing)..."
  id -u cloudflared >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin cloudflared

  log "[*] Writing/refreshing systemd unit..."
  write_unit

  log "[*] Freeing port 53 and pointing resolv.conf to 127.0.0.1..."
  stop_conflicting_services
  point_resolv_to_local

  log "[*] Swapping binary atomically..."
  systemctl stop cloudflared-doh 2>/dev/null || true
  mv -f "$tmp" "$BIN"

  log "[*] Starting cloudflared-doh..."
  systemctl daemon-reload
  systemctl enable --now cloudflared-doh

  log "[*] Waiting for service to be up..."
  wait_for_service || die "Service failed to reach active state."

  log "[*] Testing (with precise port & retry)..."
  wait_for_port_53 || true
  # Print precise listeners (for visibility)
  ss -lpnut '( sport = :53 )' || true

  test_dns
  log "[✓] Cloudflare DoH installed/updated and active!"
}

uninstall_and_restore() {
  log "[*] Uninstalling cloudflared and restoring Ubuntu defaults..."

  systemctl disable --now cloudflared-doh 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload

  rm -f "$BIN"

  # Remove service user and group (ignore errors if in use)
  userdel cloudflared 2>/dev/null || true
  groupdel cloudflared 2>/dev/null || true

  # Restore systemd-resolved default
  systemctl enable --now systemd-resolved 2>/dev/null || true
  rm -f "$RESOLV"
  ln -s /run/systemd/resolve/stub-resolv.conf "$RESOLV" 2>/dev/null || true
  systemctl restart systemd-resolved 2>/dev/null || true

  log "[✓] Uninstall complete. DNS restored to systemd-resolved defaults."
  log "    Verify: resolvectl status"
}

main() {
  ensure_root
  if [ "${1-}" = "--uninstall" ]; then
    uninstall_and_restore
  else
    install_or_update
  fi
}

main "$@"
