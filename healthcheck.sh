#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Health check
#
# Verifies the two layers of the lean DNS-blocker + security box:
#   1. AdGuard Home DNS sinkhole (the ad/tracker/malware blocker)
#   2. ClamAV antivirus daemon
#
# Prints a clear PASS / WARN / FAIL for each check.
# Exit code 0 = all good. Exit code 1 = something needs attention.
# =============================================================================
set -eu

AGH_PORT=3000

PASS=0
WARN=0
FAIL=0

_pass() { printf '\033[1;32m  PASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
_warn() { printf '\033[1;33m  WARN\033[0m  %s\n' "$*"; WARN=$((WARN+1)); }
_fail() { printf '\033[1;31m  FAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
_hdr()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }

# ── Init system detection ──────────────────────────────────────────────────────
INIT_SYS="sysvinit"
if [ -d /run/systemd/system ]; then INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1; then INIT_SYS=openrc
elif [ -f /etc/openwrt_release ]; then INIT_SYS=procd
elif command -v sv >/dev/null 2>&1; then INIT_SYS=runit
fi

service_active() {
    _svc="$1"
    case "$INIT_SYS" in
        systemd) systemctl is-active --quiet "$_svc" 2>/dev/null ;;
        openrc)  rc-service "$_svc" status >/dev/null 2>&1 ;;
        procd)   /etc/init.d/"$_svc" status >/dev/null 2>&1 ;;
        runit)   sv status "$_svc" 2>/dev/null | grep -q '^run:' ;;
        *)       /etc/init.d/"$_svc" status >/dev/null 2>&1 ;;
    esac
}

# =============================================================================
# LAYER 1 — AdGuard Home DNS sinkhole
# =============================================================================
_hdr "Layer 1 — AdGuard Home DNS sinkhole"

AGH_RUNNING=0
if service_active AdGuardHome 2>/dev/null; then
    AGH_RUNNING=1
elif service_active adguardhome 2>/dev/null; then
    AGH_RUNNING=1
fi

if [ "$AGH_RUNNING" = "1" ]; then
    _pass "AdGuardHome service is running"
else
    _fail "AdGuardHome service NOT running"
    printf '        Fix: sudo sh dns_sinkhole.sh\n'
fi

# Check DNS is answering on port 53
if command -v dig >/dev/null 2>&1; then
    RESOLVED="$(dig +short +timeout=3 example.com @127.0.0.1 2>/dev/null | head -1)"
elif command -v nslookup >/dev/null 2>&1; then
    RESOLVED="$(nslookup -timeout=3 example.com 127.0.0.1 2>/dev/null | awk '/^Address/ && NR>2{print $2;exit}')"
else
    RESOLVED=""
fi

if [ -n "$RESOLVED" ]; then
    _pass "DNS resolves example.com → $RESOLVED via 127.0.0.1"
else
    _fail "DNS not answering on 127.0.0.1:53"
    printf '        Fix: Check AdGuard Home is listening on port 53 (Admin UI → DNS settings)\n'
fi

# Check ad blocking is actually working.
# doubleclick.net is on every major blocklist; it should return NXDOMAIN or 0.0.0.0
if command -v dig >/dev/null 2>&1; then
    ADTEST="$(dig +short +timeout=3 stats.g.doubleclick.net @127.0.0.1 2>/dev/null | head -1)"
    if [ -z "$ADTEST" ] || [ "$ADTEST" = "0.0.0.0" ] || [ "$ADTEST" = "::" ]; then
        _pass "Ad domain blocked (stats.g.doubleclick.net → null)"
    else
        _warn "Ad domain NOT blocked → $ADTEST  (check AdGuard blocklists are enabled)"
    fi
fi

# AdGuard Home web UI reachable
if command -v curl >/dev/null 2>&1; then
    HTTP_STATUS="$(curl -so /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${AGH_PORT}/" 2>/dev/null || true)"
    if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "302" ]; then
        _pass "AdGuard Home web UI reachable on :${AGH_PORT}"
    else
        _warn "AdGuard Home web UI returned HTTP $HTTP_STATUS on :${AGH_PORT}"
    fi
fi

# =============================================================================
# LAYER 2 — ClamAV
# =============================================================================
_hdr "Layer 2 — ClamAV malware scanner"

CLAMD_RUNNING=0
for _svc in clamav-daemon clamd; do
    service_active "$_svc" 2>/dev/null && CLAMD_RUNNING=1 && break
done

if [ "$CLAMD_RUNNING" = "1" ]; then
    _pass "clamav-daemon service is running"
else
    _warn "clamav-daemon not running as a service (virus DB may still be downloading)"
fi

# Ping the daemon via socket
CLAMD_SOCK=""
for _s in /run/clamav/clamd.ctl /var/run/clamav/clamd.ctl \
          /run/clamav/clamd.sock /var/run/clamav/clamd.socket; do
    [ -S "$_s" ] && CLAMD_SOCK="$_s" && break
done

if [ -n "$CLAMD_SOCK" ]; then
    if command -v nc >/dev/null 2>&1; then
        PONG="$(printf 'zPING\0' | nc -q1 -U "$CLAMD_SOCK" 2>/dev/null || true)"
        if echo "$PONG" | grep -q 'PONG'; then
            _pass "clamd socket responding (PING→PONG)"
        else
            _warn "clamd socket found but not responding to PING"
        fi
    else
        _pass "clamd socket exists at $CLAMD_SOCK (nc not available for deeper check)"
    fi
else
    _warn "clamd socket not found — ClamAV daemon may still be starting"
    printf '        Fix: sudo sh malware_block.sh\n'
fi

# Check DB age — a DB older than 7 days is stale
DB_AGE_WARN=7
for _dbdir in /var/lib/clamav /var/lib/clamav-data /var/lib/clamavdb; do
    if [ -d "$_dbdir" ]; then
        DAILY_CVD="$(find "$_dbdir" -name 'daily.*' -newer /dev/null 2>/dev/null | head -1)"
        if [ -n "$DAILY_CVD" ]; then
            if find "$_dbdir" -name 'daily.*' -mtime "+${DB_AGE_WARN}" 2>/dev/null | grep -q .; then
                _warn "Virus database is older than ${DB_AGE_WARN} days — run: sudo freshclam"
            else
                _pass "Virus database is fresh"
            fi
        else
            _warn "Cannot find daily.cvd/cld in $_dbdir"
        fi
        break
    fi
done

# =============================================================================
# LAYER 3 — Adult-content filter
# =============================================================================
_hdr "Layer 3 — Adult-content filter"

if command -v dig >/dev/null 2>&1; then
    NSFWTEST="$(dig +short +timeout=3 pornhub.com @127.0.0.1 2>/dev/null | head -1)"
    if [ -z "$NSFWTEST" ] || [ "$NSFWTEST" = "0.0.0.0" ] || [ "$NSFWTEST" = "::" ]; then
        _pass "Adult domain blocked (pornhub.com → null)"
    else
        _warn "Adult domain NOT blocked → $NSFWTEST  (run: sudo sh content_filter.sh)"
    fi
else
    _warn "no dig available — cannot verify adult-content filter"
fi

# =============================================================================
# SUMMARY
# =============================================================================
TOTAL=$((PASS+WARN+FAIL))
printf '\n\033[1;37m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
printf '  Results: '
printf '\033[1;32m%d PASS\033[0m  ' "$PASS"
printf '\033[1;33m%d WARN\033[0m  ' "$WARN"
printf '\033[1;31m%d FAIL\033[0m\n' "$FAIL"
printf '  Total checks: %d\n' "$TOTAL"
printf '\033[1;37m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n\n'

[ "$FAIL" = "0" ]   # exits 0 if all passed/warned, 1 if any failed
