#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Self-healing watchdog
#
# Runs every 10 minutes (installed by install.sh).
# Checks every layer of the lean DNS-blocker + security box and restarts
# anything that's broken. Silent when healthy. Logs only on action taken.
# =============================================================================
set -eu

LOG_HEADER="[watchdog $(date '+%Y-%m-%d %H:%M:%S')]"

log()  { printf '%s %s\n' "$LOG_HEADER" "$*"; }
warn() { printf '%s WARN: %s\n' "$LOG_HEADER" "$*"; }

# Init system detection
INIT_SYS="sysvinit"
[ -d /run/systemd/system ]             && INIT_SYS=systemd
command -v rc-service >/dev/null 2>&1  && INIT_SYS=openrc
[ -f /etc/openwrt_release ]            && INIT_SYS=procd
command -v sv >/dev/null 2>&1          && INIT_SYS=runit

# ── Helpers ──────────────────────────────────────────────────────────────────

service_running() {
    case "$INIT_SYS" in
        systemd) systemctl is-active --quiet "$1" 2>/dev/null ;;
        openrc)  rc-service "$1" status >/dev/null 2>&1 ;;
        procd)   /etc/init.d/"$1" status >/dev/null 2>&1 ;;
        runit)   sv status "$1" 2>/dev/null | grep -q '^run:' ;;
        *)       /etc/init.d/"$1" status >/dev/null 2>&1 ;;
    esac
}

restart_service() {
    _svc="$1"
    log "Restarting $_svc..."
    case "$INIT_SYS" in
        systemd) systemctl restart "$_svc" 2>/dev/null && log "$_svc restarted." \
                    || warn "$_svc restart FAILED — check: systemctl status $_svc" ;;
        openrc)  rc-service "$_svc" restart 2>/dev/null || warn "$_svc restart failed." ;;
        procd)   /etc/init.d/"$_svc" restart 2>/dev/null || warn "$_svc restart failed." ;;
        runit)   sv restart "$_svc" 2>/dev/null || warn "$_svc restart failed." ;;
        *)       /etc/init.d/"$_svc" restart 2>/dev/null || warn "$_svc restart failed." ;;
    esac
}

# ── 1. AdGuard Home (DNS — the core layer) ────────────────────────────────────

AGH_OK=0
for _svc in AdGuardHome adguardhome; do
    service_running "$_svc" 2>/dev/null && AGH_OK=1 && break
done
if [ "$AGH_OK" = "0" ]; then
    warn "AdGuard Home is NOT running."
    for _svc in AdGuardHome adguardhome; do
        restart_service "$_svc" 2>/dev/null && break || true
    done
fi

# Verify DNS is actually answering
DNS_OK=0
if command -v dig >/dev/null 2>&1; then
    dig +short +timeout=3 example.com @127.0.0.1 >/dev/null 2>&1 && DNS_OK=1
elif command -v nslookup >/dev/null 2>&1; then
    nslookup -timeout=3 example.com 127.0.0.1 >/dev/null 2>&1 && DNS_OK=1
else
    DNS_OK=1  # can't check — assume OK
fi
if [ "$DNS_OK" = "0" ]; then
    warn "DNS not answering on 127.0.0.1:53 — restarting AdGuard Home."
    for _svc in AdGuardHome adguardhome; do
        restart_service "$_svc" 2>/dev/null && break || true
    done
fi

# ── 2. ClamAV ────────────────────────────────────────────────────────────────

CLAMD_OK=0
for _svc in clamav-daemon clamd; do
    service_running "$_svc" 2>/dev/null && CLAMD_OK=1 && break
done
if [ "$CLAMD_OK" = "0" ]; then
    warn "ClamAV daemon is NOT running."
    for _svc in clamav-daemon clamd; do
        restart_service "$_svc" 2>/dev/null && break || true
    done
fi

# Also verify socket is responsive
CLAMD_ALIVE=0
for _s in /run/clamav/clamd.ctl /var/run/clamav/clamd.ctl \
          /run/clamav/clamd.sock /var/run/clamav/clamd.socket; do
    [ -S "$_s" ] && CLAMD_ALIVE=1 && break
done
if [ "$CLAMD_ALIVE" = "0" ] && [ "$CLAMD_OK" = "1" ]; then
    warn "clamd socket missing despite service running — restarting."
    for _svc in clamav-daemon clamd; do
        restart_service "$_svc" 2>/dev/null && break || true
    done
fi

# ── 3. Disk space guard ───────────────────────────────────────────────────────
# ClamAV DB + logs can grow. Warn (and prune old logs) if disk > 85% full.

DISK_USE="$(df / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')"
if [ -n "$DISK_USE" ] && [ "$DISK_USE" -gt 85 ]; then
    warn "Root filesystem is ${DISK_USE}% full — pruning logs older than 30 days."
    find /var/log -name '*.log' -mtime +30 -delete 2>/dev/null || true
    find /var/log -name '*.gz'  -mtime +30 -delete 2>/dev/null || true
fi

# ── 4. WireGuard bypass (if configured) ──────────────────────────────────────

if command -v wg >/dev/null 2>&1 && [ -f /etc/wireguard/wg-bypass.conf ]; then
    if ! wg show wg-bypass >/dev/null 2>&1; then
        warn "WireGuard wg-bypass tunnel is down — bringing it back up."
        wg-quick up wg-bypass 2>/dev/null || warn "wg-quick up failed — check peer connectivity."
    fi
fi

# Done — no output if everything was healthy (silent on success)
