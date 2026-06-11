#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Single-command installer
#
# Usage (the ONLY command you ever need to run):
#   sudo sh install.sh
#
# This box is a lean DNS ad-blocker + security appliance. Nothing sits in the
# traffic path — your router simply points its DNS at this box, so the network
# stays fast and no certificates are ever installed on any device.
#
# What it does — fully automatically, no prompts:
#   0. Removes any legacy HTTPS-proxy components from older installs
#      (mitmproxy, CA cert, captive portal, ARP daemon, box-as-gateway DHCP).
#   1. Auto-detects the network interface and this box's IP.
#   2. Runs dns_sinkhole.sh  — AdGuard Home DNS ad/tracker/malware blocking.
#   3. Runs malware_block.sh — ClamAV daemon + DNS Safe Browsing.
#   4. Installs autoupdate timer (nightly 1–7 AM: blocklists, virus DB,
#      fastest-DNS re-benchmark, security patches).
#   5. Installs watchdog timer (every 10 min, auto-heals broken services).
#   6. Runs healthcheck.sh to confirm everything is live.
#   7. Runs selftest.sh — a live go-live test. If a critical layer (DNS) is
#      broken it self-destructs (selfdestruct.sh) back to a clean machine so
#      the network is never left in a broken state.
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
printf '  DNS AD-BLOCK  •  MALWARE SHIELD  •  AUTO-HEAL\n'
printf '\033[0m\n'

mkdir -p "$(dirname "$LOG_FILE")"
printf 'Install started: %s\n' "$(date)" >> "$LOG_FILE"

INIT_SYS="sysvinit"
[ -d /run/systemd/system ] && INIT_SYS=systemd
command -v rc-service >/dev/null 2>&1 && INIT_SYS=openrc
[ -f /etc/openwrt_release ] && INIT_SYS=procd
command -v sv >/dev/null 2>&1 && INIT_SYS=runit

# =============================================================================
# STEP 0 — REMOVE LEGACY HTTPS-PROXY COMPONENTS
# Older versions of this project ran a transparent mitmproxy, a CA cert, a
# captive portal and an ARP daemon. We no longer do any of that. If a previous
# install left them behind, strip them now so this box becomes a clean,
# in-path-free DNS resolver. This is best-effort and never fatal.
# =============================================================================
hdr "Step 0/7 — Removing any legacy proxy components"

# 0a. Stop the ARP daemon first so devices fall back to the real gateway.
for _pat in netwatch.py arpspoof arp_spoof; do
    pkill -f "$_pat" >/dev/null 2>&1 && log "stopped legacy process: $_pat"
done

# 0b. Tear down the transparent-proxy iptables interception. We only touch our
#     own chain + hooks — never the whole nat table, which would break routing.
if command -v iptables >/dev/null 2>&1; then
    while iptables -t nat -D PREROUTING -j MITMPROXY 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT     -j MITMPROXY 2>/dev/null; do :; done
    while iptables -t nat -D OUTPUT -m owner --uid-owner mitm -j RETURN 2>/dev/null; do :; done
    iptables -t nat -F MITMPROXY 2>/dev/null || true
    iptables -t nat -X MITMPROXY 2>/dev/null || true
fi
if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -t nat -D PREROUTING -j MITMPROXY 2>/dev/null; do :; done
    ip6tables -t nat -F MITMPROXY 2>/dev/null || true
    ip6tables -t nat -X MITMPROXY 2>/dev/null || true
fi

# 0c. Stop + disable the services we no longer ship.
for _svc in mitm-adblock wifi-adblock-netwatch wifi-adblock-portal; do
    case "$INIT_SYS" in
        systemd) systemctl stop "$_svc" >/dev/null 2>&1; systemctl disable "$_svc" >/dev/null 2>&1 ;;
        openrc)  rc-service "$_svc" stop >/dev/null 2>&1; rc-update del "$_svc" >/dev/null 2>&1 ;;
        procd)   /etc/init.d/"$_svc" stop >/dev/null 2>&1; /etc/init.d/"$_svc" disable >/dev/null 2>&1 ;;
        runit)   sv stop "$_svc" >/dev/null 2>&1; rm -f "/var/service/$_svc" >/dev/null 2>&1 ;;
        *)       [ -x "/etc/init.d/$_svc" ] && "/etc/init.d/$_svc" stop >/dev/null 2>&1 ;;
    esac
done
for _pat in portal_server.py mitmdump; do
    pkill -f "$_pat" >/dev/null 2>&1 || true
done

# 0d. Remove the legacy unit/init files.
if [ "$INIT_SYS" = "systemd" ]; then
    for _u in mitm-adblock.service wifi-adblock-portal.service wifi-adblock-netwatch.service; do
        rm -f "/etc/systemd/system/$_u" 2>/dev/null || true
    done
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
for _i in /etc/init.d/mitm-adblock /etc/init.d/wifi-adblock-netwatch /etc/init.d/wifi-adblock-portal; do
    [ -f "$_i" ] && rm -f "$_i" 2>/dev/null || true
done
for _sv in /etc/runit/sv/wifi-adblock-netwatch /etc/sv/wifi-adblock-portal /etc/sv/mitm-adblock; do
    [ -d "$_sv" ] && rm -rf "$_sv" 2>/dev/null || true
done

# 0e. Remove the box-as-gateway DHCP config we used to drop in (the router now
#     owns DHCP). Leave any unrelated dnsmasq config untouched.
rm -f /etc/dnsmasq.d/mitm-adblock.conf /etc/dnsmasq.conf.d/mitm-adblock.conf 2>/dev/null || true

# 0f. Remove the proxy install dir + CA cert (no cert is used anymore).
for _d in /opt/mitm-proxy /usr/share/mitm-proxy; do
    [ -d "$_d" ] && rm -rf "$_d" 2>/dev/null && log "removed legacy dir: $_d"
done

log "Legacy proxy components removed (if any were present)."

# =============================================================================
# STEP 1 — AUTO-DETECT NETWORK SETTINGS
# =============================================================================
hdr "Step 1/7 — Detecting network"

_DEF_ROUTE="$(ip route show default 2>/dev/null | head -1)"
AUTO_IFACE="$(printf '%s' "$_DEF_ROUTE" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')"
AUTO_ROUTER="$(printf '%s' "$_DEF_ROUTE" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}')"
AUTO_BOX_IP="$(ip addr show "$AUTO_IFACE" 2>/dev/null \
    | awk '/inet / {split($2,a,"/"); print a[1]; exit}')"

LAN_IFACE="${LAN_IFACE:-$AUTO_IFACE}"
BOX_IP="${BOX_IP:-$AUTO_BOX_IP}"
ROUTER_IP="${ROUTER_IP:-$AUTO_ROUTER}"

[ -z "$LAN_IFACE" ] && die "Could not detect network interface. Set LAN_IFACE=eth0 manually."
[ -z "$BOX_IP"    ] && die "Could not detect box IP. Set BOX_IP=192.168.1.2 manually."

log "Interface : $LAN_IFACE"
log "Box IP    : $BOX_IP"
log "Router    : ${ROUTER_IP:-unknown}"

export LAN_IFACE BOX_IP ROUTER_IP

# =============================================================================
# STEP 2 — DNS SINKHOLE (the core ad blocker)
# =============================================================================
hdr "Step 2/7 — AdGuard Home DNS sinkhole"
sh "$REPO_DIR/dns_sinkhole.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 3 — MALWARE SHIELD
# =============================================================================
hdr "Step 3/7 — ClamAV malware scanner + DNS Safe Browsing"
sh "$REPO_DIR/malware_block.sh" 2>&1 | tee -a "$LOG_FILE"

# =============================================================================
# STEP 4 — AUTOUPDATE TIMER (1–7 AM WINDOW)
# =============================================================================
hdr "Step 4/7 — Autoupdate timer (1–7 AM)"

if [ "$INIT_SYS" = "systemd" ]; then
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
    CRONTAB_LINE="0 1 * * * sh ${REPO_DIR}/autoupdate.sh >> /var/log/wifi-adblock-update.log 2>&1"
    (crontab -l 2>/dev/null | grep -v 'autoupdate.sh'; printf '%s\n' "$CRONTAB_LINE") | crontab -
    log "cron job installed (0 1 * * *)."
fi

# =============================================================================
# STEP 5 — WATCHDOG TIMER (EVERY 10 MINUTES)
# =============================================================================
hdr "Step 5/7 — Watchdog timer (every 10 min)"

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
# STEP 6 — HEALTH CHECK
# =============================================================================
hdr "Step 6/7 — Verifying all layers are live"
sleep 5
sh "$REPO_DIR/healthcheck.sh" -q 2>&1 | tee -a "$LOG_FILE" || true

# =============================================================================
# STEP 7 — GO-LIVE ACCEPTANCE TEST (self-destruct gate)
# =============================================================================
hdr "Step 7/7 — Go-live acceptance test"
sleep 3

# Pipe to tee swallows the exit code in POSIX sh — capture it via temp file.
_st_out="/tmp/wifi-adblock-selftest.log"
sh "$REPO_DIR/selftest.sh" > "$_st_out" 2>&1
_st_rc=$?
cat "$_st_out" | tee -a "$LOG_FILE"
rm -f "$_st_out"

if [ "$_st_rc" = "0" ]; then
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
log "ONE-TIME STEPS (manual):"
log "  1. AdGuard Home wizard → http://${BOX_IP}:3000 (DNS on port 53, admin on 3000)."
log "  2. On your router, set the DHCP DNS server to ${BOX_IP} (both primary"
log "     and secondary), then reconnect devices. That's what makes ad blocking"
log "     cover the whole network."
log ""
log "  Optional — Discord + Roblox bypass (Turkey):"
log "     sudo sh $REPO_DIR/bypass_censorship.sh"
log ""
log "VERIFY AT ANY TIME:  sudo sh $REPO_DIR/healthcheck.sh"
log "UPDATE MANUALLY  :  sudo sh $REPO_DIR/autoupdate.sh"
