#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Self-destruct / full teardown
#
# Triggered automatically by install.sh when selftest.sh reports a critical
# failure. Can also be run manually to completely uninstall:
#   sudo sh selfdestruct.sh
#
# Design priority — ORDER MATTERS:
#   1. FIRST restore normal network flow (stop ARP spoofing, flush the
#      intercept chain). This is the most important step: it guarantees that
#      whatever else happens, every device on the network gets its internet
#      back immediately. We undo the dangerous parts before the cosmetic ones.
#   2. THEN stop and disable every service we installed.
#   3. THEN remove scheduled jobs (cron + systemd timers).
#   4. THEN delete the files we installed.
#
# Everything is best-effort and idempotent — running it twice is harmless,
# and a failure in one step never blocks the next. It does NOT uninstall
# third-party packages (ClamAV, dnsmasq) — only what this project added.
# =============================================================================
# Note: deliberately NOT using `set -e` — teardown must push through errors.
set -u

INSTALL_DIR="/opt/mitm-proxy"
ALT_DIR="/usr/share/mitm-proxy"
LOG="/var/log/wifi-adblock-install.log"

log()  { printf '\033[1;33m[selfdestruct]\033[0m %s\n' "$*" | tee -a "$LOG" 2>/dev/null; }

printf '\033[1;31m\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '  SELF-DESTRUCT — returning this machine to a clean state\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '\033[0m\n'

# ── Init system detection ─────────────────────────────────────────────────────
INIT_SYS="sysvinit"
if [ -d /run/systemd/system ]; then INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1; then INIT_SYS=openrc
elif [ -f /etc/openwrt_release ]; then INIT_SYS=procd
elif command -v sv >/dev/null 2>&1; then INIT_SYS=runit
fi

stop_disable() {
    _svc="$1"
    case "$INIT_SYS" in
        systemd)
            systemctl stop "$_svc" >/dev/null 2>&1
            systemctl disable "$_svc" >/dev/null 2>&1
            ;;
        openrc)
            rc-service "$_svc" stop >/dev/null 2>&1
            rc-update del "$_svc" >/dev/null 2>&1
            ;;
        procd)
            /etc/init.d/"$_svc" stop >/dev/null 2>&1
            /etc/init.d/"$_svc" disable >/dev/null 2>&1
            ;;
        runit)
            sv stop "$_svc" >/dev/null 2>&1
            rm -f "/var/service/$_svc" >/dev/null 2>&1
            ;;
        *)
            [ -x "/etc/init.d/$_svc" ] && "/etc/init.d/$_svc" stop >/dev/null 2>&1
            command -v update-rc.d >/dev/null 2>&1 && update-rc.d -f "$_svc" remove >/dev/null 2>&1
            command -v chkconfig  >/dev/null 2>&1 && chkconfig "$_svc" off >/dev/null 2>&1
            ;;
    esac
}

# =============================================================================
# STEP 1 — RESTORE NORMAL NETWORK FLOW (most important; do this first)
# =============================================================================
log "Step 1/4 — Restoring normal network traffic flow"

# 1a. Kill the ARP-spoofing daemon so we stop impersonating the gateway.
#     Once these processes die, ARP caches naturally heal within seconds and
#     traffic flows directly to the real router again.
for _pat in netwatch.py arpspoof arp_spoof; do
    if pgrep -f "$_pat" >/dev/null 2>&1; then
        pkill -f "$_pat" >/dev/null 2>&1
        log "  stopped ARP/netwatch process: $_pat"
    fi
done

# 1b. Tear down the iptables interception so no traffic is redirected into a
#     proxy that's about to be removed. This is what prevents a network-wide
#     internet outage.
if command -v iptables >/dev/null 2>&1; then
    # Remove the hooks first so nothing new enters the chain...
    while iptables -t nat -D PREROUTING -j MITMPROXY 2>/dev/null; do : ; done
    while iptables -t nat -D OUTPUT     -j MITMPROXY 2>/dev/null; do : ; done
    # ...then flush and delete the chain itself. We only touch our own chain —
    # never `iptables -F` the whole table, which would wipe the box's own
    # routing/NAT and break its networking.
    iptables -t nat -F MITMPROXY 2>/dev/null
    iptables -t nat -X MITMPROXY 2>/dev/null
    # Remove the owner-match loop-breaker rule we added to OUTPUT, if present.
    while iptables -t nat -D OUTPUT -m owner --uid-owner mitm -j RETURN 2>/dev/null; do : ; done
    log "  flushed MITMPROXY chain and removed PREROUTING/OUTPUT hooks"
fi

# 1c. Restore IPv6 interception too, if it was set up.
if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -t nat -D PREROUTING -j MITMPROXY 2>/dev/null; do : ; done
    ip6tables -t nat -F MITMPROXY 2>/dev/null
    ip6tables -t nat -X MITMPROXY 2>/dev/null
fi

log "  network flow restored — every device goes straight to the router again"

# =============================================================================
# STEP 2 — STOP & DISABLE ALL SERVICES WE INSTALLED
# =============================================================================
log "Step 2/4 — Stopping and disabling installed services"

for _svc in \
    mitm-adblock \
    wifi-adblock-netwatch \
    wifi-adblock-portal \
    AdGuardHome adguardhome \
    wifi-adblock-watchdog \
    wifi-adblock-update; do
    stop_disable "$_svc"
done
log "  all project services stopped and disabled"

# Stop any leftover portal / proxy processes by signature.
for _pat in portal_server.py mitmdump dns_optimizer.py; do
    pkill -f "$_pat" >/dev/null 2>&1 && log "  killed lingering process: $_pat"
done

# =============================================================================
# STEP 3 — REMOVE SCHEDULED JOBS
# =============================================================================
log "Step 3/4 — Removing scheduled jobs (cron + timers)"

# 3a. Strip our cron lines (autoupdate + watchdog) without touching others.
if command -v crontab >/dev/null 2>&1; then
    _cur="$(crontab -l 2>/dev/null)"
    if [ -n "$_cur" ]; then
        printf '%s\n' "$_cur" \
            | grep -v 'autoupdate.sh' \
            | grep -v 'watchdog.sh' \
            | crontab - 2>/dev/null
        log "  removed autoupdate + watchdog cron entries"
    fi
fi

# 3b. Remove systemd timers + unit files.
if [ "$INIT_SYS" = "systemd" ]; then
    for _unit in \
        wifi-adblock-watchdog.timer wifi-adblock-watchdog.service \
        wifi-adblock-update.timer   wifi-adblock-update.service \
        mitm-adblock.service \
        wifi-adblock-portal.service \
        wifi-adblock-netwatch.service; do
        systemctl stop "$_unit" >/dev/null 2>&1
        systemctl disable "$_unit" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$_unit" 2>/dev/null
    done
    systemctl daemon-reload >/dev/null 2>&1
    log "  removed systemd timers and unit files"
fi

# 3c. Remove init scripts on non-systemd systems.
for _init in \
    /etc/init.d/mitm-adblock \
    /etc/init.d/wifi-adblock-netwatch \
    /etc/init.d/wifi-adblock-portal; do
    [ -f "$_init" ] && rm -f "$_init" 2>/dev/null
done
# runit service dirs
for _sv in /etc/runit/sv/wifi-adblock-netwatch /etc/runit/sv/mitm-adblock; do
    [ -d "$_sv" ] && rm -rf "$_sv" 2>/dev/null
done

# =============================================================================
# STEP 4 — DELETE INSTALLED FILES
# =============================================================================
log "Step 4/4 — Deleting installed files"

for _d in "$INSTALL_DIR" "$ALT_DIR"; do
    if [ -d "$_d" ]; then
        rm -rf "$_d" 2>/dev/null && log "  removed $_d"
    fi
done

# Remove the install marker so a re-run of install.sh starts fresh.
rm -f /etc/wifi-adblock-installed 2>/dev/null

# Leave logs in place on purpose — they're the breadcrumbs for fixing whatever
# failed. Everything else is gone.

printf '\033[1;32m\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '  TEARDOWN COMPLETE — machine is back to a clean state.\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '\033[0m\n'
log "Network is back to normal. No interception, no ARP spoofing, no services."
log "Diagnostic logs kept at: $LOG"
log "Fix the issue above, then re-run:  sudo sh install.sh"
exit 0
