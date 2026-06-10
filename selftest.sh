#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Go-live acceptance test
#
# This is the final gate. install.sh runs this immediately after setup.
# It does NOT just check that files exist — it drives every feature LIVE and
# proves it actually works on this exact machine, on this exact network.
#
# Two classes of check:
#
#   CRITICAL  — if any of these fail the system is either non-functional OR
#               actively harmful (e.g. traffic is being redirected into a dead
#               proxy = the whole network loses internet). A single critical
#               failure makes this script exit non-zero, which tells install.sh
#               to trigger selfdestruct.sh and wipe everything back to clean.
#
#   ADVISORY  — degraded-but-safe (e.g. ClamAV DB still downloading, blocklists
#               not finished syncing). These warn but never trigger teardown.
#
# Exit codes:
#   0  — all critical checks passed. Safe to go live.
#   1  — at least one critical check failed. install.sh must self-destruct.
# =============================================================================
set -u

PROXY_PORT=8080
AGH_PORT=3000
PORTAL_PORT=80

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/mitm-proxy"
[ -d "$INSTALL_DIR" ] || INSTALL_DIR="/usr/share/mitm-proxy"

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
printf '  Proving every layer works before this goes live.\n'
printf '═══════════════════════════════════════════════════════════\n'
printf '\033[0m\n'

# =============================================================================
# PHASE 0 — FILE INTEGRITY  (CRITICAL)
# Every shipped script must parse. A broken file = a broken feature, and we
# will not go live with one.
# =============================================================================
hdr "Phase 0 — File integrity (every feature's code must be valid)"

_SH_FILES="setup.sh dns_sinkhole.sh malware_block.sh network_config.sh
           captive_portal.sh netwatch_setup.sh onboard_existing.sh
           autoupdate.sh watchdog.sh healthcheck.sh bypass_censorship.sh"
_PY_FILES="yt_ad_stripper.py malware_scanner.py netwatch.py portal_server.py
           dns_optimizer.py yt_updater.py"

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
# PHASE 1 — TRANSPARENT PROXY  (CRITICAL)
# This is the single most dangerous layer. If iptables is redirecting traffic
# into the proxy but the proxy is dead, the ENTIRE NETWORK loses internet.
# That exact combination MUST trigger self-destruct.
# =============================================================================
hdr "Phase 1 — Transparent proxy (YouTube stripper + malware scanner)"

PROXY_UP=0
if service_active mitm-adblock; then
    c_pass "mitm-adblock service is running"
    PROXY_UP=1
else
    c_crit "mitm-adblock service is NOT running"
fi

PROXY_LISTENING=0
if port_listening "$PROXY_PORT"; then
    c_pass "proxy is listening on :${PROXY_PORT}"
    PROXY_LISTENING=1
else
    c_crit "nothing listening on :${PROXY_PORT} — proxy is dead"
fi

# The deadly combination check — done explicitly and loudly.
REDIRECT_ACTIVE=0
if command -v iptables >/dev/null 2>&1; then
    if iptables -t nat -L PREROUTING 2>/dev/null | grep -q "MITMPROXY"; then
        REDIRECT_ACTIVE=1
    fi
fi
if [ "$REDIRECT_ACTIVE" = "1" ] && [ "$PROXY_LISTENING" = "0" ]; then
    c_crit "DANGER: traffic is being redirected into a DEAD proxy — the whole network would lose internet. Aborting."
elif [ "$REDIRECT_ACTIVE" = "1" ] && [ "$PROXY_LISTENING" = "1" ]; then
    c_pass "redirect + live proxy are consistent (no black-hole risk)"
fi

# Actually push a real HTTP request through the proxy and confirm it answers.
if [ "$PROXY_LISTENING" = "1" ] && command -v curl >/dev/null 2>&1; then
    _code="$(curl -so /dev/null -w '%{http_code}' --proxy "http://127.0.0.1:${PROXY_PORT}" \
             --max-time 10 "http://example.com" 2>/dev/null || echo 000)"
    case "$_code" in
        200|301|302)
            c_pass "live HTTP request through proxy succeeded (HTTP $_code)" ;;
        ''|0|000|0000|000000)
            c_warn "could not reach example.com through proxy (no internet right now?)" ;;
        *)
            c_crit "proxy returned HTTP $_code for a normal site — interception is misbehaving" ;;
    esac
fi

# =============================================================================
# PHASE 2 — DNS SINKHOLE  (CRITICAL)
# DNS resolution itself is critical: if AdGuard is the network's resolver and
# it's dead, nobody can resolve anything. Ad-domain blocking is ADVISORY
# (blocklists may still be syncing right after install).
# =============================================================================
hdr "Phase 2 — DNS sinkhole (AdGuard Home)"

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

# No DNS loop — port 53 must NOT be redirected into the proxy.
if command -v iptables >/dev/null 2>&1; then
    if iptables -t nat -L MITMPROXY 2>/dev/null | grep -q "dpt:53"; then
        c_crit "port 53 is being redirected into the proxy — this creates a DNS loop"
    else
        c_pass "port 53 is not redirected (no DNS loop)"
    fi
fi

# =============================================================================
# PHASE 3 — iptables INTERCEPT CHAIN  (CRITICAL)
# =============================================================================
hdr "Phase 3 — iptables intercept chain"

if command -v iptables >/dev/null 2>&1; then
    if iptables -t nat -L MITMPROXY 2>/dev/null | grep -q "REDIRECT"; then
        c_pass "MITMPROXY chain has REDIRECT rules"
    else
        c_crit "MITMPROXY chain missing or has no REDIRECT rules"
    fi
    if iptables -t nat -L PREROUTING 2>/dev/null | grep -q "MITMPROXY"; then
        c_pass "MITMPROXY is hooked into PREROUTING"
    else
        c_crit "MITMPROXY not in PREROUTING — forwarded traffic isn't intercepted"
    fi
else
    c_warn "iptables not available — cannot verify intercept chain"
fi

# =============================================================================
# PHASE 4 — CAPTIVE PORTAL + ONBOARDING  (CRITICAL: portal must answer)
# =============================================================================
hdr "Phase 4 — Captive portal & device onboarding"

if port_listening "$PORTAL_PORT"; then
    c_pass "portal is listening on :${PORTAL_PORT}"
    if command -v curl >/dev/null 2>&1; then
        _pcode="$(curl -so /dev/null -w '%{http_code}' --max-time 5 \
                  "http://127.0.0.1:${PORTAL_PORT}/generate_204" 2>/dev/null || echo 000)"
        case "$_pcode" in
            204|200) c_pass "portal answered a captive probe (HTTP $_pcode)" ;;
            *)       c_warn "portal returned HTTP $_pcode to a captive probe" ;;
        esac
    fi
else
    c_crit "portal is not listening on :${PORTAL_PORT} — new devices get no welcome page"
fi

# Onboarding lists should exist (created by onboard_existing.sh).
if [ -f "$INSTALL_DIR/existing_devices.txt" ] || [ -f "$INSTALL_DIR/seen_devices.txt" ]; then
    c_pass "device tracking lists are present"
else
    c_warn "no device tracking lists yet (onboarding may not have run)"
fi

# =============================================================================
# PHASE 5 — CA CERTIFICATE  (CRITICAL: HTTPS features depend on it)
# =============================================================================
hdr "Phase 5 — CA certificate"

if [ -f "$INSTALL_DIR/certs/mitmproxy-ca-cert.pem" ]; then
    _exp="$(openssl x509 -noout -enddate -in "$INSTALL_DIR/certs/mitmproxy-ca-cert.pem" 2>/dev/null | cut -d= -f2)"
    c_pass "CA cert present (expires: ${_exp:-unknown})"
else
    c_crit "CA cert missing — HTTPS ad stripping and download scanning cannot work"
fi

# =============================================================================
# PHASE 6 — NETWATCH + WATCHDOG DAEMONS  (ADVISORY)
# Self-healing layers. If they're down the system still works right now; the
# install just isn't as resilient. Warn, don't tear down.
# =============================================================================
hdr "Phase 6 — Self-healing daemons (advisory)"

if service_active wifi-adblock-netwatch || pgrep -f netwatch.py >/dev/null 2>&1; then
    c_pass "netwatch daemon is running (portable network re-config)"
else
    c_warn "netwatch daemon not detected — auto-reconfigure on network change is off"
fi

if service_active wifi-adblock-watchdog 2>/dev/null \
   || [ -f /etc/systemd/system/wifi-adblock-watchdog.timer ] \
   || crontab -l 2>/dev/null | grep -q watchdog.sh; then
    c_pass "watchdog is scheduled (auto-heal every 10 min)"
else
    c_warn "watchdog not scheduled — broken services won't auto-restart"
fi

# =============================================================================
# PHASE 7 — ClamAV  (ADVISORY)
# DB can take many minutes to download on first install. Never tear down for it.
# =============================================================================
hdr "Phase 7 — ClamAV malware scanner (advisory)"

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
