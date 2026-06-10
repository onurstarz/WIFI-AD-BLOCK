#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Single-command installer
#
# Usage (the ONLY command you ever need to run):
#   sudo sh install.sh
#
# What it does — fully automatically, no prompts:
#   1. Auto-detects your network interface, current IP, and router IP
#   2. Runs setup.sh           — mitmproxy YouTube stripper + iptables + service
#   3. Runs dns_sinkhole.sh    — AdGuard Home DNS + malware domain blocking
#   4. Runs malware_block.sh   — ClamAV live download scanning
#   5. Runs network_config.sh  — local dnsmasq DHCP config
#   6. Runs captive_portal.sh  — first-connection welcome page per device
#   7. Runs netwatch_setup.sh  — ARP intercept daemon (no router changes needed)
#   8. Runs onboard_existing.sh — silently protects devices already on the LAN
#   9. Installs autoupdate timer (runs nightly 1–7 AM, self-scheduling)
#  10. Installs watchdog timer (runs every 10 min, auto-heals broken services)
#  11. Runs healthcheck.sh to confirm everything is live
#  12. Runs selftest.sh — a live go-live test. If ANY critical layer fails,
#      install.sh self-destructs (selfdestruct.sh) back to a clean machine so
#      the network is never left in a broken, internet-blocking state.
#
# NOTE: bypass_censorship.sh (WireGuard for Discord/Roblox) is NOT run here
# because it needs your VPN peer keys. Run it separately once you have them:
#   sudo sh bypass_censorship.sh
# =============================================================================
set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="/var/log/wifi-adblock-install.log"
INSTALL_MARKER="/etc/wifi-adblock-installed"

log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*" | tee -a "$LOG_FILE"; }
warn() { printf '\033[1;33m[warn]   \033[0m %s\n' "$*" | tee -a "$LOG_FILE"; }
die()  { printf '\033[1;31m[error]  \033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' | tee -a "$LOG_FILE"
         printf '\033[1;36m  %s\033[0m\n' "$*" | tee -a "$LOG_FILE"
         printf '\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n' | tee -a "$LOG_FILE"; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

printf '\033[1;32m\n'
printf '██╗    ██╗██╗███████╗██╗      █████╗ ██████╗\n'
printf '██║    ██║██║██╔════╝██║     ██╔══██╗██╔══██╗\n'
printf '██║ █╗ ██║██║█████╗  ██║     ███████║██║  ██║\n'
printf '██║███╗██║██║██╔══╝  ██║     ██╔══██║██║  ██║\n'
printf '╚███╔███╔╝██║██║     ██║████╗██║  ██║██████╔╝\n'
printf ' ╚══╝╚══╝ ╚═╝╚═╝     ╚═════╝╚═╝  ╚═╝╚═════╝\n'
printf '  AD-BLOCK  •  MALWARE SHIELD  •  AUTO-HEAL\n'
printf '\033[0m\n'

# Record install start time
mkdir -p "$(dirname "$LOG_FILE")"
printf 'Install started: %s\n' "$(date)" >> "$LOG_FILE"

# =============================================================================
# STEP 1 — AUTO-DETECT NETWORK SETTINGS
# =============================================================================
hdr "Step 1/10 — Detecting network"

# Get the interface used by the default route
_DEF_ROUTE="$(ip route show default 2>/dev/null | head -1)"
AUTO_IFACE="$(printf '%s' "$_DEF_ROUTE" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')"
AUTO_ROUTER="$(printf '%s' "$_DEF_ROUTE" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}')"
AUTO_BOX_IP="$(ip addr show "$AUTO_IFACE" 2>/dev/null \
    | awk '/inet / {split($2,a,"/"); print a[1]; exit}')"
AUTO_SUBNET_PREFIX="$(ip addr show "$AUTO_IFACE" 2>/dev/null \
    | awk '/inet / {split($2,a,"/"); print a[2]; exit}')"
AUTO_SUBNET_PREFIX="${AUTO_SUBNET_PREFIX:-24}"

# Derive DHCP range from router IP (use upper half of /24 subnet)
_ROUTER_BASE="$(printf '%s' "$AUTO_ROUTER" | cut -d. -f1-3)"
AUTO_DHCP_START="${_ROUTER_BASE}.100"
AUTO_DHCP_END="${_ROUTER_BASE}.200"

# Allow env overrides for edge cases
LAN_IFACE="${LAN_IFACE:-$AUTO_IFACE}"
WAN_IFACE="${WAN_IFACE:-$AUTO_IFACE}"
BOX_IP="${BOX_IP:-$AUTO_BOX_IP}"
SUBNET_PREFIX="${SUBNET_PREFIX:-$AUTO_SUBNET_PREFIX}"
ROUTER_IP="${ROUTER_IP:-$AUTO_ROUTER}"
DHCP_START="${DHCP_START:-$AUTO_DHCP_START}"
DHCP_END="${DHCP_END:-$AUTO_DHCP_END}"
DNS_SERVER="${DNS_SERVER:-127.0.0.1}"

[ -z "$LAN_IFACE" ] && die "Could not detect network interface. Set LAN_IFACE=eth0 manually."
[ -z "$ROUTER_IP" ] && die "Could not detect router IP. Set ROUTER_IP=192.168.1.1 manually."
[ -z "$BOX_IP"    ] && die "Could not detect box IP. Set BOX_IP=192.168.1.2 manually."

log "Interface : $LAN_IFACE"
log "Box IP    : $BOX_IP/$SUBNET_PREFIX"
log "Router    : $ROUTER_IP"
log "DHCP pool : $DHCP_START – $DHCP_END"

# Export so subscripts can inherit (for scripts that check env vars)
export LAN_IFACE WAN_IFACE BOX_IP SUBNET_PREFIX ROUTER_IP DHCP_START DHCP_END DNS_SERVER

# Patch the variable block in network_config.sh with detected values
# (network_config.sh reads its own top-of-file variables, so we patch them in-place)
NETCONF="$REPO_DIR/network_config.sh"
if [ -f "$NETCONF" ]; then
    sed \
        -e "s|^LAN_IFACE=.*|LAN_IFACE=\"${LAN_IFACE}\"|" \
        -e "s|^WAN_IFACE=.*|WAN_IFACE=\"${WAN_IFACE}\"|" \
        -e "s|^BOX_IP=.*|BOX_IP=\"${BOX_IP}\"|" \
        -e "s|^SUBNET_PREFIX=.*|SUBNET_PREFIX=\"${SUBNET_PREFIX}\"|" \
        -e "s|^ROUTER_IP=.*|ROUTER_IP=\"${ROUTER_IP}\"|" \
        -e "s|^DHCP_START=.*|DHCP_START=\"${DHCP_START}\"|" \
        -e "s|^DHCP_END=.*|DHCP_END=\"${DHCP_END}\"|" \
        -e "s|^DNS_SERVER=.*|DNS_SERVER=\"${DNS_SERVER}\"|" \
        "$NETCONF" > "${NETCONF}.patched"
    chmod +x "${NETCONF}.patched"
    log "network_config.sh patched with detected values."
fi

# =============================================================================
# STEP 2 — MITMPROXY + IPTABLES
# =============================================================================
hdr "Step 2/10 — mitmproxy transparent proxy"
sh "$REPO_DIR/setup.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 3 — DNS SINKHOLE
# =============================================================================
hdr "Step 3/10 — AdGuard Home DNS sinkhole"
sh "$REPO_DIR/dns_sinkhole.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 4 — MALWARE SHIELD
# =============================================================================
hdr "Step 4/10 — ClamAV malware scanner"
sh "$REPO_DIR/malware_block.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 5 — NETWORK GATEWAY CONFIG (local dnsmasq DHCP)
# =============================================================================
hdr "Step 5/10 — Network gateway (local DHCP)"
sh "${NETCONF}.patched" 2>&1 | tee -a "$LOG_FILE"
rm -f "${NETCONF}.patched"

# =============================================================================
# STEP 6 — CAPTIVE PORTAL
# =============================================================================
hdr "Step 6/10 — Captive portal (first-connection welcome page)"
sh "$REPO_DIR/captive_portal.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 7 — NETWATCH DAEMON (ARP intercept + auto-reconfigure)
# =============================================================================
hdr "Step 7/10 — NetWatch daemon (ARP intercept, portable network support)"
sh "$REPO_DIR/netwatch_setup.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 8 — ONBOARD EXISTING DEVICES (silent, zero interaction)
# =============================================================================
hdr "Step 8/10 — Silent onboarding for existing devices"
sh "$REPO_DIR/onboard_existing.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 9 — INSTALL AUTOUPDATE (1–7 AM WINDOW)
# =============================================================================
hdr "Step 9/10 — Autoupdate timer (1–7 AM)"

INIT_SYS="sysvinit"
[ -d /run/systemd/system ] && INIT_SYS=systemd
command -v rc-service >/dev/null 2>&1 && INIT_SYS=openrc
[ -f /etc/openwrt_release ] && INIT_SYS=procd

if [ "$INIT_SYS" = "systemd" ]; then
    # systemd timer with RandomizedDelaySec spreads execution across 1–7 AM
    cat > /etc/systemd/system/wifi-adblock-update.timer << EOF
[Unit]
Description=WiFi AdBlock Nightly Autoupdate (1–7 AM window)

[Timer]
OnCalendar=*-*-* 01:00:00
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    cat > /etc/systemd/system/wifi-adblock-update.service << EOF
[Unit]
Description=WiFi AdBlock Autoupdate

[Service]
Type=oneshot
ExecStart=sh ${REPO_DIR}/autoupdate.sh
StandardOutput=append:/var/log/wifi-adblock-update.log
StandardError=append:/var/log/wifi-adblock-update.log
EOF
    systemctl daemon-reload
    systemctl enable --now wifi-adblock-update.timer
    log "systemd timer installed (runs at random time 1–7 AM nightly)."
else
    # cron fallback: run at 1 AM, autoupdate.sh sleeps random 0–6h internally
    CRONTAB_LINE="0 1 * * * sh ${REPO_DIR}/autoupdate.sh >> /var/log/wifi-adblock-update.log 2>&1"
    (crontab -l 2>/dev/null | grep -v 'autoupdate.sh'; printf '%s\n' "$CRONTAB_LINE") | crontab -
    log "cron job installed (0 1 * * *)."
fi

# =============================================================================
# STEP 9 — INSTALL WATCHDOG (EVERY 10 MINUTES)
# =============================================================================
hdr "Step 10/10 — Watchdog timer (every 10 min)"

if [ "$INIT_SYS" = "systemd" ]; then
    cat > /etc/systemd/system/wifi-adblock-watchdog.timer << EOF
[Unit]
Description=WiFi AdBlock Watchdog

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
    cat > /etc/systemd/system/wifi-adblock-watchdog.service << EOF
[Unit]
Description=WiFi AdBlock Watchdog

[Service]
Type=oneshot
ExecStart=sh ${REPO_DIR}/watchdog.sh
StandardOutput=append:/var/log/wifi-adblock-watchdog.log
StandardError=append:/var/log/wifi-adblock-watchdog.log
EOF
    systemctl daemon-reload
    systemctl enable --now wifi-adblock-watchdog.timer
    log "systemd watchdog timer installed (every 10 min)."
else
    WD_LINE="*/10 * * * * sh ${REPO_DIR}/watchdog.sh >> /var/log/wifi-adblock-watchdog.log 2>&1"
    (crontab -l 2>/dev/null | grep -v 'watchdog.sh'; printf '%s\n' "$WD_LINE") | crontab -
    log "cron watchdog installed (*/10 * * * *)."
fi

# =============================================================================
# STEP 10 — HEALTH CHECK
# =============================================================================
hdr "Step 11/12 — Verifying all layers are live"
sleep 5  # give services a moment to fully start
sh "$REPO_DIR/healthcheck.sh" -q 2>&1 | tee -a "$LOG_FILE" || true

# =============================================================================
# STEP 11 — GO-LIVE ACCEPTANCE TEST (self-destruct gate)
# =============================================================================
# This is the final gate. selftest.sh drives every layer LIVE. If any critical
# layer is broken — or, worst case, traffic is being redirected into a dead
# proxy — it exits non-zero and we self-destruct: full teardown back to a clean
# machine so the network is NEVER left in a half-working, internet-breaking
# state. A clean machine you can fix beats a live machine that's down.
hdr "Step 12/12 — Go-live acceptance test"
sleep 3  # let services settle after the healthcheck

if sh "$REPO_DIR/selftest.sh" 2>&1 | tee -a "$LOG_FILE"; then
    log "Acceptance test PASSED — going live."
else
    warn "Acceptance test FAILED — triggering self-destruct."
    sh "$REPO_DIR/selfdestruct.sh" 2>&1 | tee -a "$LOG_FILE" || true
    printf '\n\033[1;31m'
    printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
    printf '  INSTALL ABORTED — system self-destructed to a clean state.\n'
    printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
    printf '\033[0m\n'
    log "The network is back to normal. Review the failures above in:"
    log "  $LOG_FILE"
    log "Fix them, then re-run:  sudo sh $0"
    exit 1
fi

# =============================================================================
# MARK AS INSTALLED + DONE
# =============================================================================
printf '%s\n' "$(date)" > "$INSTALL_MARKER"
printf '%s\n' "REPO_DIR=${REPO_DIR}" >> "$INSTALL_MARKER"

printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  INSTALLATION COMPLETE\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m\n'
log "Full install log: $LOG_FILE"
log ""
log "ONE-TIME STEPS (manual, do these now):"
log "  1. AdGuard Home setup wizard → http://${BOX_IP}:3000"
log "     Set DNS to port 53, create login, enable Safe Browsing."
log ""
log "  2. Install the CA cert on each device:"
log "     cd /opt/mitm-proxy/certs && python3 -m http.server 8888"
log "     Then open http://${BOX_IP}:8888 on each phone/tablet/laptop."
log ""
log "  3. Optional — Discord + Roblox bypass (Turkey):"
log "     sudo sh $REPO_DIR/bypass_censorship.sh"
log ""
log "VERIFY AT ANY TIME:  sudo sh $REPO_DIR/healthcheck.sh"
log "UPDATE MANUALLY  :  sudo sh $REPO_DIR/autoupdate.sh"
