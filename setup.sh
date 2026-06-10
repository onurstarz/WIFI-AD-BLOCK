#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# WIFI-AD-BLOCK  —  full environment setup script
# Run as root on the Linux box.  Safe to re-run; each section is idempotent.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROXY_PORT=8080
PROXY_USER="mitm"          # dedicated unprivileged user to run the proxy
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log()  { echo -e "\033[1;32m[setup]\033[0m $*"; }
die()  { echo -e "\033[1;31m[error]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Re-run as root: sudo bash $0"

# ─── 1. System packages ───────────────────────────────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    iptables iptables-persistent \
    net-tools iproute2 \
    curl wget \
    procps

# ─── 2. Python virtualenv ─────────────────────────────────────────────────────
log "Creating Python virtualenv at /opt/mitm-proxy..."
python3 -m venv /opt/mitm-proxy
/opt/mitm-proxy/bin/pip install --upgrade pip --quiet
/opt/mitm-proxy/bin/pip install mitmproxy blackboxprotobuf --quiet
log "Python packages installed."

# ─── 3. Dedicated unprivileged user ───────────────────────────────────────────
if ! id "$PROXY_USER" &>/dev/null; then
    log "Creating system user '$PROXY_USER'..."
    useradd -r -s /sbin/nologin "$PROXY_USER"
fi

# Copy script to a stable location owned by the proxy user
install -m 644 -o "$PROXY_USER" "$SCRIPT_DIR/yt_ad_stripper.py" /opt/mitm-proxy/yt_ad_stripper.py

# ─── 4. IP forwarding ────────────────────────────────────────────────────────
log "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
grep -qxF 'net.ipv4.ip_forward=1'       /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1'       >> /etc/sysctl.conf
grep -qxF 'net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf

# ─── 5. iptables transparent-proxy rules ─────────────────────────────────────
log "Configuring iptables transparent proxy..."

# Flush any previous MITMPROXY chain
iptables -t nat -D PREROUTING -j MITMPROXY 2>/dev/null || true
iptables -t nat -F MITMPROXY               2>/dev/null || true
iptables -t nat -X MITMPROXY               2>/dev/null || true

iptables -t nat -N MITMPROXY

# Don't intercept traffic from the proxy process itself (avoid redirect loop)
iptables -t nat -A MITMPROXY -m owner --uid-owner "$PROXY_USER" -j RETURN

# Don't intercept LAN / loopback addresses
iptables -t nat -A MITMPROXY -d 127.0.0.0/8     -j RETURN
iptables -t nat -A MITMPROXY -d 10.0.0.0/8      -j RETURN
iptables -t nat -A MITMPROXY -d 172.16.0.0/12   -j RETURN
iptables -t nat -A MITMPROXY -d 192.168.0.0/16  -j RETURN

# Redirect HTTP and HTTPS to mitmproxy
iptables -t nat -A MITMPROXY -p tcp --dport 80  -j REDIRECT --to-port "$PROXY_PORT"
iptables -t nat -A MITMPROXY -p tcp --dport 443 -j REDIRECT --to-port "$PROXY_PORT"

# Hook into PREROUTING (catches traffic from other devices forwarded through this box)
iptables -t nat -A PREROUTING -j MITMPROXY

# Also catch local traffic on OUTPUT (for processes running on this box itself)
iptables -t nat -D OUTPUT -j MITMPROXY 2>/dev/null || true
iptables -t nat -A OUTPUT -j MITMPROXY

# Masquerade outbound traffic so replies route back correctly
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
    log "  (MASQUERADE skipped — set interface manually in iptables if needed)"

# Persist rules
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4
log "iptables rules saved."

# ─── 6. Generate mitmproxy CA certificate ────────────────────────────────────
log "Generating mitmproxy root CA (first-time only)..."
MITM_HOME="/opt/mitm-proxy/certs"
mkdir -p "$MITM_HOME"
chown "$PROXY_USER:$PROXY_USER" "$MITM_HOME"

# Run mitmproxy briefly as the proxy user just to generate certs then exit
sudo -u "$PROXY_USER" \
    /opt/mitm-proxy/bin/mitmdump \
    --set confdir="$MITM_HOME" \
    --set listen_port=0 \
    --mode transparent \
    -q --no-server 2>/dev/null || \
sudo -u "$PROXY_USER" \
    /opt/mitm-proxy/bin/mitmdump \
    --set confdir="$MITM_HOME" \
    -q &
MITM_PID=$!
sleep 3
kill "$MITM_PID" 2>/dev/null || true
wait "$MITM_PID" 2>/dev/null || true

if [[ -f "$MITM_HOME/mitmproxy-ca-cert.pem" ]]; then
    # Also export as DER for Android devices
    openssl x509 -in "$MITM_HOME/mitmproxy-ca-cert.pem" \
        -out "$MITM_HOME/mitmproxy-ca-cert.cer" -outform DER 2>/dev/null
    log "CA cert ready:"
    log "  PEM (Linux/macOS/iOS) : $MITM_HOME/mitmproxy-ca-cert.pem"
    log "  DER (Android)         : $MITM_HOME/mitmproxy-ca-cert.cer"
else
    log "WARNING: CA cert not found at $MITM_HOME — run 'mitmdump --set confdir=$MITM_HOME' manually once to generate it."
fi

# ─── 7. systemd service ───────────────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/mitm-adblock.service << EOF
[Unit]
Description=YouTube Ad Stripping Transparent Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${PROXY_USER}
ExecStart=/opt/mitm-proxy/bin/mitmdump \\
    --mode transparent \\
    --listen-port ${PROXY_PORT} \\
    --set confdir=/opt/mitm-proxy/certs \\
    --set ssl_insecure=false \\
    --set connection_strategy=lazy \\
    -s /opt/mitm-proxy/yt_ad_stripper.py
Restart=on-failure
RestartSec=5
# Log to journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mitm-adblock

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mitm-adblock
systemctl restart mitm-adblock
log "Service started.  Check status with: systemctl status mitm-adblock"
log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "  Setup complete.  Next step: install the CA cert on your devices."
log "  See README.md for per-platform instructions."
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
