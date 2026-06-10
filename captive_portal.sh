#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Captive portal setup
#
# When a device connects to the Wi-Fi for the first time its OS probes a
# known URL to detect if it's behind a login wall (captive portal).
# We intercept those probes via AdGuard Home DNS rewrites and serve our own
# welcome page instead — showing network protections and the cert install
# button.  Once the user taps "Got it" we mark them as seen and return the
# correct OS response forever, so no popup ever appears again for that device.
#
# Detection URLs intercepted:
#   iOS / macOS  captive.apple.com/hotspot-detect.html
#   Android      connectivitycheck.gstatic.com/generate_204
#   Windows      www.msftconnecttest.com/connecttest.txt
#   Firefox      detectportal.firefox.com/success.txt
#
# DNS auto-detach: DHCP already scopes DNS to this network.
# When a device leaves the Wi-Fi it gets new DHCP settings from the next
# network — no extra code needed for "detach on disconnect."
#
# Run as root, after setup.sh + dns_sinkhole.sh.  Safe to re-run.
# =============================================================================
set -eu

log()  { printf '\033[1;35m[portal]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]  \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error] \033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━  %s  ━━━\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Match install dirs from setup.sh
if [ -d /opt/mitm-proxy ]; then
    INSTALL_DIR="/opt/mitm-proxy"
else
    INSTALL_DIR="/usr/share/mitm-proxy"
fi

# Detect box IP
BOX_IP="$(ip route get 1.1.1.1 2>/dev/null \
    | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)"
[ -z "$BOX_IP" ] && die "Could not detect box IP."
log "Box IP: $BOX_IP"

# Init system detection
INIT_SYS="sysvinit"
[ -d /run/systemd/system ]            && INIT_SYS=systemd
command -v rc-service >/dev/null 2>&1 && INIT_SYS=openrc
[ -f /etc/openwrt_release ]           && INIT_SYS=procd
command -v sv >/dev/null 2>&1         && INIT_SYS=runit

# Python binary (reuse mitmproxy env or system)
PYTHON_BIN=""
[ -f "$INSTALL_DIR/bin/python3" ] && PYTHON_BIN="$INSTALL_DIR/bin/python3"
[ -z "$PYTHON_BIN" ] && command -v python3 >/dev/null 2>&1 && \
    PYTHON_BIN="$(command -v python3)"
[ -z "$PYTHON_BIN" ] && die "python3 not found — run setup.sh first."

# =============================================================================
# 1. COPY PORTAL SERVER
# =============================================================================
hdr "Installing portal server"

cp "$SCRIPT_DIR/portal_server.py" "$INSTALL_DIR/portal_server.py"
chmod 644 "$INSTALL_DIR/portal_server.py"
log "portal_server.py installed to $INSTALL_DIR"

# =============================================================================
# 2. DNS REWRITES — AdGuard Home
#    Point captive-portal detection domains at this box so the OS probe
#    reaches our portal server instead of the real endpoint.
# =============================================================================
hdr "Adding DNS rewrites in AdGuard Home"

CAPTIVE_DOMAINS="
captive.apple.com
captive.g.aaplimg.com
connectivitycheck.gstatic.com
connectivitycheck.android.com
www.msftconnecttest.com
msftconnecttest.com
detectportal.firefox.com
ipv6.msftconnecttest.com"

add_agh_rewrite() {
    _domain="$1"
    _answer="$2"
    if command -v curl >/dev/null 2>&1; then
        HTTP_STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
            --max-time 5 \
            -X POST "http://127.0.0.1:3000/control/rewrite/add" \
            -H "Content-Type: application/json" \
            -d "{\"domain\":\"${_domain}\",\"answer\":\"${_answer}\"}" \
            2>/dev/null || echo 0)"
        if [ "$HTTP_STATUS" = "200" ]; then
            log "  DNS rewrite: $_domain → $_answer"
            return 0
        fi
    fi
    return 1
}

# Try AdGuard Home API first
AGH_API_OK=0
printf '%s\n' "$CAPTIVE_DOMAINS" | while read -r _dom; do
    [ -z "$_dom" ] && continue
    add_agh_rewrite "$_dom" "$BOX_IP" && AGH_API_OK=1 || true
done

# Fallback: edit AdGuardHome.yaml directly
AGH_YAML="/opt/AdGuardHome/AdGuardHome.yaml"
if [ -f "$AGH_YAML" ]; then
    log "Patching AdGuardHome.yaml rewrites directly..."

    # Build the rewrites YAML block
    REWRITE_BLOCK="rewrites:"
    printf '%s\n' "$CAPTIVE_DOMAINS" | while read -r _dom; do
        [ -z "$_dom" ] && continue
        REWRITE_BLOCK="${REWRITE_BLOCK}
  - domain: $_dom
    answer: $BOX_IP"
    done

    # If a rewrites section already exists, remove it and re-add
    # (Python is already installed — safest YAML editor)
    "$PYTHON_BIN" - << PYEOF
import re, sys

yaml_path = "$AGH_YAML"
box_ip    = "$BOX_IP"

domains = [d.strip() for d in """$CAPTIVE_DOMAINS""".strip().splitlines() if d.strip()]

with open(yaml_path) as f:
    content = f.read()

# Remove existing rewrites block if any
content = re.sub(r'\nrewrites:\n(?:  - .*\n)*', '\n', content)

# Build new rewrites block
block = '\nrewrites:\n'
for d in domains:
    block += f'  - domain: {d}\n    answer: {box_ip}\n'

# Insert at end of file
content = content.rstrip() + '\n' + block

with open(yaml_path, 'w') as f:
    f.write(content)

print("[portal] AdGuardHome.yaml rewrites written.")
PYEOF

    # Restart AdGuard Home to pick up the config change
    case "$INIT_SYS" in
        systemd) systemctl restart AdGuardHome 2>/dev/null || true ;;
        openrc)  rc-service AdGuardHome restart 2>/dev/null || true ;;
        procd)   /etc/init.d/AdGuardHome restart 2>/dev/null || true ;;
        *)       /etc/init.d/AdGuardHome restart 2>/dev/null || true ;;
    esac
    log "AdGuard Home restarted with DNS rewrites."
else
    warn "AdGuardHome.yaml not found — finish AGH first-run wizard then re-run this script."
fi

# =============================================================================
# 3. START PORTAL SERVER AS A SERVICE
# =============================================================================
hdr "Installing captive portal service"

PORTAL_CMD="$PYTHON_BIN $INSTALL_DIR/portal_server.py"

case "$INIT_SYS" in
    systemd)
        cat > /etc/systemd/system/wifi-adblock-portal.service << EOF
[Unit]
Description=WiFi AdBlock Captive Portal
After=network-online.target AdGuardHome.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PORTAL_CMD}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wifi-adblock-portal

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable wifi-adblock-portal
        systemctl restart wifi-adblock-portal
        log "systemd service started."
        log "  Logs: journalctl -fu wifi-adblock-portal"
        ;;

    openrc)
        cat > /etc/init.d/wifi-adblock-portal << EOF
#!/sbin/openrc-run
description="WiFi AdBlock Captive Portal"
command="$PYTHON_BIN"
command_args="$INSTALL_DIR/portal_server.py"
pidfile="/run/wifi-adblock-portal.pid"
command_background=true
depend() { need net; after AdGuardHome; }
EOF
        chmod +x /etc/init.d/wifi-adblock-portal
        rc-update add wifi-adblock-portal default 2>/dev/null || true
        rc-service wifi-adblock-portal restart
        ;;

    procd)
        cat > /etc/init.d/wifi-adblock-portal << EOF
#!/bin/sh /etc/rc.common
START=98
STOP=10
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command $PORTAL_CMD
    procd_set_param respawn \${respawn_threshold:-3600} \${respawn_timeout:-5} \${respawn_retry:-5}
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
        chmod +x /etc/init.d/wifi-adblock-portal
        /etc/init.d/wifi-adblock-portal enable
        /etc/init.d/wifi-adblock-portal restart
        ;;

    runit)
        SV_DIR="/etc/sv/wifi-adblock-portal"
        mkdir -p "$SV_DIR"
        cat > "$SV_DIR/run" << EOF
#!/bin/sh
exec $PORTAL_CMD
EOF
        chmod +x "$SV_DIR/run"
        for _sdir in /var/service /service /run/runit/service; do
            [ -d "$_sdir" ] && ln -sf "$SV_DIR" "$_sdir/wifi-adblock-portal" && break
        done
        ;;

    *)
        cat > /etc/init.d/wifi-adblock-portal << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides: wifi-adblock-portal
# Required-Start: \$network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
### END INIT INFO
PIDFILE=/var/run/wifi-adblock-portal.pid
case "\$1" in
    start) start-stop-daemon --start --background --make-pidfile \
               --pidfile "\$PIDFILE" --exec $PYTHON_BIN -- \
               $INSTALL_DIR/portal_server.py ;;
    stop)  start-stop-daemon --stop --pidfile "\$PIDFILE" --retry 5 ;;
    restart) \$0 stop; \$0 start ;;
esac
EOF
        chmod +x /etc/init.d/wifi-adblock-portal
        command -v update-rc.d >/dev/null 2>&1 && update-rc.d wifi-adblock-portal defaults
        /etc/init.d/wifi-adblock-portal restart
        ;;
esac

# =============================================================================
# 4. ADD PORTAL TO WATCHDOG
# =============================================================================
hdr "Wiring portal into watchdog"

# Append a portal check to watchdog.sh if not already there
WD="$SCRIPT_DIR/watchdog.sh"
if [ -f "$WD" ] && ! grep -q 'wifi-adblock-portal' "$WD"; then
    cat >> "$WD" << 'WDEOF'

# ── 7. Captive portal server ──────────────────────────────────────────────────
_portal_ok=0
for _svc in wifi-adblock-portal; do
    service_running "$_svc" 2>/dev/null && _portal_ok=1 && break
done
if [ "$_portal_ok" = "0" ]; then
    warn "Captive portal server is NOT running — restarting."
    restart_service wifi-adblock-portal 2>/dev/null || true
fi
WDEOF
    log "Watchdog updated to monitor captive portal."
fi

# =============================================================================
# DONE
# =============================================================================
printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  Captive portal active.\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m\n'
log "How it works:"
log "  1. New device joins Wi-Fi."
log "  2. OS probes its captive-portal URL (Apple / Android / Windows)."
log "  3. AdGuard Home resolves that URL to ${BOX_IP}."
log "  4. Portal server serves the welcome page."
log "  5. User taps 'Got it' → marked seen → popup never reappears."
log ""
log "Returning devices get the correct OS response and no popup."
log ""
log "DNS auto-detach: DHCP scopes DNS to this network only."
log "When a device leaves, its next network issues new DHCP settings."
log "No extra code needed — it already works that way."
log ""
log "Portal visible at: http://${BOX_IP}/"
log "Test (simulate new device): curl -H 'Host: captive.apple.com' http://${BOX_IP}/hotspot-detect.html"
