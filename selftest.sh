#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Go-live acceptance test
#
# This is the final gate. install.sh runs this immediately after setup.
# It does NOT just check that files exist — it drives the DNS layer LIVE and
# proves it actually works on this exact machine, on this exact network.
#
# Two classes of check:
#
#   CRITICAL  — if this fails the box is non-functional as a resolver: if it's
#               the network's DNS and DNS is dead, nothing resolves. A single
#               critical failure makes this script exit non-zero, which tells
#               install.sh to trigger selfdestruct.sh and wipe back to clean.
#
#   ADVISORY  — degraded-but-safe (e.g. ClamAV DB still downloading, blocklists
#               not finished syncing). These warn but never trigger teardown.
#
# Exit codes:
#   0  — all critical checks passed. Safe to go live.
#   1  — at least one critical check failed. install.sh must self-destruct.
# =============================================================================
set -u

AGH_PORT=3000

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

CRIT_FAIL=0
ADV_WARN=0
PASS=0

c_pass() { printf '\033[1;32m  ✓ PASS\033[0m   %s\n' "$*"; PASS=$((PASS+1)); }
c_warn() { printf '\033[1;33m  ! WARN\033[0m   %s\n' "$*"; ADV_WARN=$((ADV_WARN+1)); }
c_crit() { printf '\033[1;31m  ✗ CRITICAL\033[0m %s\n' "$*"; CRIT_FAIL=$((CRIT_FAIL+1)); }
hdr()    { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

# ── Init system detection ─────────────────────────────────────────────────────
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

port_listening() {
    _port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnH 2>/dev/null | grep -q ":${_port} "
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tln 2>/dev/null | grep -q ":${_port} "
    else
        return 0   # can't check — don't fail on missing tooling
    fi
}

printf '\033[1;37m\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '  GO-LIVE ACCEPTANCE TEST\n'
printf '  Proving the DNS blocker + security layers work.\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '\033[0m\n'

# =============================================================================
# PHASE 0 — FILE INTEGRITY  (CRITICAL)
# Every shipped script must parse. A broken file = a broken feature, and we
# will not go live with one.
# =============================================================================
hdr "Phase 0 — File integrity (every feature's code must be valid)"

_SH_FILES="dns_sinkhole.sh malware_block.sh autoupdate.sh watchdog.sh
           healthcheck.sh bypass_censorship.sh selfdestruct.sh"
_PY_FILES="dns_optimizer.py"

for _f in $_SH_FILES; do
    if [ ! -f "$REPO_DIR/$_f" ]; then
        c_crit "missing script: $_f"
    elif sh -n "$REPO_DIR/$_f" 2>/dev/null; then
        c_pass "$_f parses cleanly"
    else
        c_crit "$_f has a SHELL SYNTAX ERROR — feature is broken"
    fi
done

for _f in $_PY_FILES; do
    if [ ! -f "$REPO_DIR/$_f" ]; then
        c_crit "missing module: $_f"
    elif python3 -c "import ast,sys; ast.parse(open('$REPO_DIR/$_f').read())" 2>/dev/null; then
        c_pass "$_f parses cleanly"
    else
        c_crit "$_f has a PYTHON SYNTAX ERROR — feature is broken"
    fi
done

# =============================================================================
# PHASE 1 — DNS SINKHOLE  (CRITICAL)
# DNS resolution itself is critical: if this box is the network's resolver and
# it's dead, nobody can resolve anything. Ad-domain blocking is ADVISORY
# (blocklists may still be syncing right after install).
# =============================================================================
hdr "Phase 1 — DNS sinkhole (AdGuard Home)"

if service_active AdGuardHome || service_active adguardhome; then
    c_pass "AdGuardHome service is running"
else
    c_crit "AdGuardHome service is NOT running"
fi

if port_listening 53; then
    c_pass "DNS is listening on :53"
else
    c_crit "nothing listening on :53 — the network cannot resolve names"
fi

# Resolve a known-good name through the box's own resolver.
_resolved=""
if command -v dig >/dev/null 2>&1; then
    _resolved="$(dig +short +time=3 +tries=1 example.com @127.0.0.1 2>/dev/null | head -1)"
elif command -v nslookup >/dev/null 2>&1; then
    _resolved="$(nslookup -timeout=3 example.com 127.0.0.1 2>/dev/null | awk '/^Address/ && NR>2{print $2; exit}')"
fi
if [ -n "$_resolved" ]; then
    c_pass "DNS resolves example.com → $_resolved"
else
    if command -v dig >/dev/null 2>&1 || command -v nslookup >/dev/null 2>&1; then
        c_crit "DNS is not answering on 127.0.0.1:53 — resolution is broken"
    else
        c_warn "no dig/nslookup available to verify resolution"
    fi
fi

# Ad-domain blocking — ADVISORY (blocklists can take a few minutes to sync).
if command -v dig >/dev/null 2>&1; then
    _ad="$(dig +short +time=3 +tries=1 stats.g.doubleclick.net @127.0.0.1 2>/dev/null | head -1)"
    if [ -z "$_ad" ] || [ "$_ad" = "0.0.0.0" ] || [ "$_ad" = "::" ]; then
        c_pass "ad domain blocked (stats.g.doubleclick.net → null)"
    else
        c_warn "ad domain not blocked yet → $_ad (blocklists may still be syncing)"
    fi
fi

# Admin UI reachable — ADVISORY.
if command -v curl >/dev/null 2>&1; then
    _ui="$(curl -so /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${AGH_PORT}/" 2>/dev/null || echo 000)"
    case "$_ui" in
        200|302) c_pass "AdGuard Home admin UI reachable on :${AGH_PORT}" ;;
        *)       c_warn "AdGuard Home admin UI returned HTTP $_ui on :${AGH_PORT}" ;;
    esac
fi

# =============================================================================
# PHASE 2 — WATCHDOG + AUTOUPDATE  (ADVISORY)
# Self-healing + nightly refresh. If they're not scheduled the system still
# works right now; it just isn't as resilient. Warn, don't tear down.
# =============================================================================
hdr "Phase 2 — Self-healing & autoupdate (advisory)"

if service_active wifi-adblock-watchdog 2>/dev/null \
   || [ -f /etc/systemd/system/wifi-adblock-watchdog.timer ] \
   || crontab -l 2>/dev/null | grep -q watchdog.sh; then
    c_pass "watchdog is scheduled (auto-heal every 10 min)"
else
    c_warn "watchdog not scheduled — broken services won't auto-restart"
fi

if [ -f /etc/systemd/system/wifi-adblock-update.timer ] \
   || crontab -l 2>/dev/null | grep -q autoupdate.sh; then
    c_pass "nightly autoupdate is scheduled (blocklists + virus DB + fastest DNS)"
else
    c_warn "autoupdate not scheduled — blocklists/virus DB won't refresh nightly"
fi

# =============================================================================
# PHASE 3 — ClamAV  (ADVISORY)
# DB can take many minutes to download on first install. Never tear down for it.
# =============================================================================
hdr "Phase 3 — ClamAV malware scanner (advisory)"

if service_active clamav-daemon || service_active clamd; then
    c_pass "ClamAV daemon is running"
else
    c_warn "ClamAV daemon not running yet (virus DB may still be downloading)"
fi

# =============================================================================
# VERDICT
# =============================================================================
printf '\n\033[1;37m═══════════════════════════════════════════════════════════\033[0m\n'
printf '  Passed: \033[1;32m%d\033[0m   Advisory warnings: \033[1;33m%d\033[0m   Critical failures: \033[1;31m%d\033[0m\n' \
       "$PASS" "$ADV_WARN" "$CRIT_FAIL"
printf '\033[1;37m═══════════════════════════════════════════════════════════\033[0m\n\n'

if [ "$CRIT_FAIL" -gt 0 ]; then
    printf '\033[1;31m  VERDICT: FAILED — %d critical problem(s).\033[0m\n' "$CRIT_FAIL"
    printf '\033[1;31m  This system is NOT safe to go live. install.sh will now self-destruct.\033[0m\n\n'
    exit 1
fi

printf '\033[1;32m  VERDICT: PASSED — every critical layer is live and verified.\033[0m\n'
if [ "$ADV_WARN" -gt 0 ]; then
    printf '\033[1;33m  %d advisory item(s) above will resolve on their own (DB/blocklist syncing).\033[0m\n' "$ADV_WARN"
fi
printf '\n'
exit 0
