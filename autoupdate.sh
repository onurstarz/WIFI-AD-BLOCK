#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Nightly autoupdate
#
# Scheduled by install.sh to run nightly within the 1–7 AM window.
# Safe to run manually at any time: sudo sh autoupdate.sh
#
# Updates (in order):
#   1. ClamAV virus signatures (freshclam)
#   2. AdGuard Home blocklists (API refresh)
#   3. Adaptive DNS optimizer — re-benchmark and switch to the fastest server
#   4. AdGuard Home binary (if a new version is available)
#   5. Security-only system package updates
#   6. Restart services if anything changed
#   7. Run healthcheck — alert if broken
# =============================================================================
set -eu

LOCK_FILE="/var/run/wifi-adblock-update.lock"
LOG_HEADER="[autoupdate $(date '+%Y-%m-%d %H:%M:%S')]"

REPO_DIR="$(cat /etc/wifi-adblock-installed 2>/dev/null | grep REPO_DIR | cut -d= -f2)"
[ -z "$REPO_DIR" ] && REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

log()  { printf '%s %s\n' "$LOG_HEADER" "$*"; }
warn() { printf '%s WARN: %s\n' "$LOG_HEADER" "$*"; }

# =============================================================================
# LOCK — prevent concurrent runs
# =============================================================================
if [ -f "$LOCK_FILE" ]; then
    OLD_PID="$(cat "$LOCK_FILE" 2>/dev/null || echo 0)"
    if kill -0 "$OLD_PID" 2>/dev/null; then
        log "Another update is running (PID $OLD_PID). Exiting."
        exit 0
    fi
    rm -f "$LOCK_FILE"
fi
printf '%d\n' "$$" > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT INT TERM

log "=== Update started ==="
CHANGED=0

# =============================================================================
# 1. CLAMAV SIGNATURES
# =============================================================================
log "Updating ClamAV signatures..."
if command -v freshclam >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop clamav-freshclam 2>/dev/null || true
    fi
    if freshclam --quiet 2>/dev/null; then
        log "ClamAV signatures updated."
        CHANGED=1
    else
        warn "freshclam returned non-zero (may already be current)."
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start clamav-freshclam 2>/dev/null || true
    fi
else
    warn "freshclam not found — skipping AV signature update."
fi

# =============================================================================
# 2. ADGUARD HOME BLOCKLISTS
# =============================================================================
log "Refreshing AdGuard Home blocklists..."
if command -v curl >/dev/null 2>&1; then
    REFRESH_STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
        --max-time 30 \
        -X POST "http://127.0.0.1:3000/control/filtering/refresh" \
        -H "Content-Type: application/json" \
        -d '{"whitelist":false}' 2>/dev/null || echo "0")"
    if [ "$REFRESH_STATUS" = "200" ]; then
        log "AdGuard Home blocklists refreshed."
        CHANGED=1
    elif [ "$REFRESH_STATUS" = "401" ]; then
        warn "AdGuard Home requires auth for API — blocklists will auto-refresh via AGH's own schedule."
    else
        warn "AdGuard Home refresh returned HTTP $REFRESH_STATUS — may not be running yet."
    fi
fi

# =============================================================================
# 3. ADAPTIVE DNS OPTIMIZER — re-benchmark and switch to fastest server
# =============================================================================
log "Re-benchmarking DNS servers (location-aware adaptive selection)..."

PY3_BIN=""
for _py in python3 python; do
    if command -v "$_py" >/dev/null 2>&1; then
        PY3_BIN="$(command -v "$_py")"
        break
    fi
done

DNS_OPT="$REPO_DIR/dns_optimizer.py"
if [ -n "$PY3_BIN" ] && [ -f "$DNS_OPT" ]; then
    _DNS_RESULT=0
    "$PY3_BIN" "$DNS_OPT" \
        >> /var/log/wifi-adblock-dns-optimizer.log 2>&1 || _DNS_RESULT=$?
    if [ "$_DNS_RESULT" = "1" ]; then
        log "DNS optimizer: switched to a faster server."
        CHANGED=1
    else
        log "DNS optimizer: current server still optimal — no change."
    fi
else
    warn "dns_optimizer.py or Python not found — skipping DNS optimization."
fi

# =============================================================================
# 4. ADGUARD HOME BINARY UPDATE
# =============================================================================
log "Checking for AdGuard Home updates..."
if command -v curl >/dev/null 2>&1; then
    UPDATE_STATUS="$(curl -s --max-time 15 \
        "http://127.0.0.1:3000/control/version.json" 2>/dev/null || echo '{}')"
    if printf '%s' "$UPDATE_STATUS" | grep -q '"new_version"'; then
        NEW_VER="$(printf '%s' "$UPDATE_STATUS" | grep -o '"new_version":"[^"]*"' | cut -d'"' -f4)"
        log "AdGuard Home update available: $NEW_VER — triggering built-in updater."
        curl -s -X POST "http://127.0.0.1:3000/control/update" \
            --max-time 120 >/dev/null 2>&1 || \
            warn "AGH self-update request failed (may require re-authentication in UI)."
        CHANGED=1
    else
        log "AdGuard Home is up to date."
    fi
fi

# =============================================================================
# 5. SECURITY SYSTEM UPDATES
# =============================================================================
log "Applying security system updates..."

if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null
    if command -v unattended-upgrade >/dev/null 2>&1; then
        unattended-upgrade --quiet 2>/dev/null && log "unattended-upgrade complete." || true
    else
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            --only-upgrade 2>/dev/null | grep -c 'upgraded' | \
            xargs -I{} log "{} packages upgraded." 2>/dev/null || true
    fi
elif command -v dnf >/dev/null 2>&1; then
    dnf upgrade --security -y --quiet 2>/dev/null && log "dnf security update complete." || true
elif command -v yum >/dev/null 2>&1; then
    yum update --security -y --quiet 2>/dev/null && log "yum security update complete." || true
elif command -v apk >/dev/null 2>&1; then
    apk upgrade --quiet 2>/dev/null && log "apk upgrade complete." || true
elif command -v pacman >/dev/null 2>&1; then
    pacman -Su --noconfirm --quiet 2>/dev/null && log "pacman upgrade complete." || true
fi

# =============================================================================
# 6. RESTART SERVICES IF CHANGED
# =============================================================================
if [ "$CHANGED" = "1" ]; then
    log "Changes detected — restarting services..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart clamav-daemon   2>/dev/null || \
            systemctl restart clamd       2>/dev/null || true
        systemctl restart AdGuardHome     2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service clamd restart          2>/dev/null || true
        rc-service AdGuardHome restart    2>/dev/null || true
    fi
    log "Services restarted."
else
    log "Nothing changed — no restarts needed."
fi

# =============================================================================
# 7. POST-UPDATE HEALTH CHECK
# =============================================================================
log "Running post-update health check..."
sleep 5
if sh "$REPO_DIR/healthcheck.sh" -q 2>/dev/null; then
    log "Health check PASSED — all layers operational."
else
    warn "Health check found issues after update — watchdog will auto-heal."
    sh "$REPO_DIR/watchdog.sh" 2>/dev/null || true
fi

log "=== Update complete ==="
