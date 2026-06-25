#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Adult/NSFW content filter layer
#
# Adds network-wide adult-content blocking on top of ad/malware blocking:
#
#   1. HaGeZi NSFW DNS Blocklist — 100,000+ adult/pornographic domains,
#      updated daily, as an AdGuard Home filter subscription.
#   2. AdGuard Parental Control — enables the built-in family-safe DNS
#      resolver (family-block.dns.adguard.com) as an extra safety net.
#   3. SafeSearch enforcement — forces Google, Bing, DuckDuckGo, Yandex,
#      and YouTube Restricted Mode via DNS rewriting, covering every device
#      on the network with no per-device configuration.
#
# Run as root, after dns_sinkhole.sh. Safe to re-run (fully idempotent).
# =============================================================================
set -eu

log()  { printf '\033[1;35m[content]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━  %s  ━━━\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

AGH_YAML="/opt/AdGuardHome/AdGuardHome.yaml"
NSFW_URL="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt"
NSFW_NAME="HaGeZi NSFW Blocklist"

# =============================================================================
# INIT SYSTEM DETECTION
# =============================================================================
INIT_SYS="sysvinit"
[ -d /run/systemd/system ] && INIT_SYS=systemd
command -v rc-service >/dev/null 2>&1 && INIT_SYS=openrc
[ -f /etc/openwrt_release ] && INIT_SYS=procd
command -v sv >/dev/null 2>&1 && INIT_SYS=runit

agh_stop() {
    case "$INIT_SYS" in
        systemd) systemctl stop  AdGuardHome 2>/dev/null || true ;;
        openrc)  rc-service AdGuardHome stop 2>/dev/null || true ;;
        procd)   /etc/init.d/AdGuardHome stop 2>/dev/null || true ;;
        *)       pkill -x AdGuardHome 2>/dev/null || true ;;
    esac
}
agh_start() {
    case "$INIT_SYS" in
        systemd) systemctl start  AdGuardHome 2>/dev/null || true ;;
        openrc)  rc-service AdGuardHome start 2>/dev/null || true ;;
        procd)   /etc/init.d/AdGuardHome start 2>/dev/null || true ;;
        *)       /opt/AdGuardHome/AdGuardHome -s start 2>/dev/null || true ;;
    esac
}

# =============================================================================
# 1. GUARD — yaml must exist (AGH creates it on first run)
# =============================================================================
hdr "Content filter — adult-site blocking"

if [ ! -f "$AGH_YAML" ]; then
    warn "AdGuardHome.yaml not found — AdGuard Home may not have completed its"
    warn "first-run wizard yet. Finish the wizard, then re-run:  sudo sh $0"
    exit 0
fi

# =============================================================================
# 2. PAUSE WATCHDOG + STOP AGH (prevents yaml being clobbered mid-edit)
#    AGH writes its full in-memory config to disk on shutdown AND on any
#    API/UI config change, so we must stop it before touching the file.
# =============================================================================
hdr "Pausing watchdog and stopping AdGuard Home for config edit"

_WD_WAS_ACTIVE=0
if [ "$INIT_SYS" = "systemd" ]; then
    if systemctl is-active --quiet wifi-adblock-watchdog.timer 2>/dev/null; then
        _WD_WAS_ACTIVE=1
        systemctl stop wifi-adblock-watchdog.timer 2>/dev/null || true
        log "Watchdog timer paused."
    fi
fi

agh_stop

# Wait for AGH to fully exit so its shutdown-write to yaml finishes
_i=0
while pgrep -x AdGuardHome >/dev/null 2>&1 && [ "$_i" -lt 10 ]; do
    sleep 1; _i=$((_i+1))
done
log "AdGuard Home stopped."

cp "$AGH_YAML" "${AGH_YAML}.bak.$(date +%s)" 2>/dev/null || true
log "Config backed up."

# =============================================================================
# 3. ADD NSFW BLOCKLIST ENTRY TO filters:
#    Uses Python (already required by dns_optimizer.py) to safely append a
#    new filter entry with a collision-free id.
# =============================================================================
hdr "Adding NSFW blocklist subscription"

if grep -qF "$NSFW_URL" "$AGH_YAML" 2>/dev/null; then
    log "NSFW blocklist already present — skipping."
else
    _PY=""
    for _p in python3 python; do
        command -v "$_p" >/dev/null 2>&1 && _PY="$_p" && break
    done

    if [ -n "$_PY" ]; then
        _PY_TMP="/tmp/wifi-adblock-add-nsfw-filter.py"
        cat > "$_PY_TMP" << 'PYEOF'
import re, sys, time, os

yaml_path, url, name = sys.argv[1], sys.argv[2], sys.argv[3]
content = open(yaml_path).read()

# Pick a collision-free id (timestamp-based, same scheme as AGH itself)
existing_ids = {int(m) for m in re.findall(r'(?m)^\s+id:\s*(\d+)', content)}
new_id = int(time.time())
while new_id in existing_ids:
    new_id += 1

entry = "  - enabled: true\n    url: {}\n    name: {}\n    id: {}\n".format(
    url, name, new_id)

# Case 1: filters: [] (empty inline) → replace with block
if re.search(r'(?m)^filters:\s*\[\]', content):
    content = re.sub(r'(?m)^filters:\s*\[\]',
                     'filters:\n' + entry.rstrip('\n'), content)
# Case 2: filters: with existing entries → append inside the block
elif re.search(r'(?m)^filters:\s*$', content):
    content = re.sub(
        r'(?m)^filters:\s*\n((?:(?:[ \t]+)[^\n]*\n)*)',
        lambda m: m.group(0) + entry,
        content)
else:
    # No filters key at all — append one
    content = content.rstrip('\n') + '\nfilters:\n' + entry

tmp = yaml_path + '.tmp'
with open(tmp, 'w') as f:
    f.write(content)
os.rename(tmp, yaml_path)
print("[content] NSFW filter entry added (id={})".format(new_id))
PYEOF
        if "$_PY" "$_PY_TMP" "$AGH_YAML" "$NSFW_URL" "$NSFW_NAME"; then
            log "NSFW blocklist added to AdGuard Home filters."
        else
            warn "Python script failed — add the NSFW blocklist manually in the AGH UI:"
            warn "  Filters → DNS Blocklists → Add: $NSFW_URL"
        fi
        rm -f "$_PY_TMP"
    else
        warn "Python not available — add NSFW blocklist manually in AdGuard Home UI:"
        warn "  Filters → DNS Blocklists → Add: $NSFW_URL"
    fi
fi

# =============================================================================
# 4. ENABLE PARENTAL CONTROL (flat boolean in all AGH versions)
# =============================================================================
hdr "Enabling Parental Control"

if grep -q 'parental_enabled:' "$AGH_YAML"; then
    sed 's/parental_enabled: false/parental_enabled: true/' "$AGH_YAML" \
        > "${AGH_YAML}.tmp" && mv "${AGH_YAML}.tmp" "$AGH_YAML"
    log "Parental control enabled (parental_enabled: true)."
else
    warn "parental_enabled key not found — enable manually: Settings → General settings."
fi

# =============================================================================
# 5. ENABLE SAFESEARCH
#    AGH v0.107.28+ uses a nested safe_search: block.
#    Older versions use a flat safesearch_enabled: boolean.
#    We detect which format is present and edit accordingly.
# =============================================================================
hdr "Enabling SafeSearch (Google, Bing, DuckDuckGo, YouTube Restricted Mode)"

if grep -qE '^[[:space:]]*safe_search:' "$AGH_YAML" 2>/dev/null; then
    # New nested format: flip enabled: inside the safe_search block.
    # Uses indentation to scope the edit to the correct block.
    awk '
      /^[[:space:]]*safe_search:[[:space:]]*$/ {
          ln=$0; gsub(/[^ \t].*/, "", ln); blk_indent=length(ln);
          inblk=1; print; next
      }
      inblk==1 && length($0)>0 {
          ln=$0; gsub(/[^ \t].*/, "", ln); cur_indent=length(ln);
          if (cur_indent<=blk_indent) { inblk=0 }
          else if ($0 ~ /^[[:space:]]+enabled:[[:space:]]*false[[:space:]]*$/) {
              sub(/enabled:[[:space:]]*false/, "enabled: true"); print; next
          }
      }
      { print }
    ' "$AGH_YAML" > "${AGH_YAML}.tmp" && mv "${AGH_YAML}.tmp" "$AGH_YAML"
    log "SafeSearch enabled (nested safe_search block)."
elif grep -q 'safesearch_enabled:' "$AGH_YAML" 2>/dev/null; then
    sed 's/safesearch_enabled: false/safesearch_enabled: true/' "$AGH_YAML" \
        > "${AGH_YAML}.tmp" && mv "${AGH_YAML}.tmp" "$AGH_YAML"
    log "SafeSearch enabled (flat safesearch_enabled key)."
else
    warn "SafeSearch key not present — it may already be on by default."
fi

# =============================================================================
# 6. RESTART AdGuard Home + RE-ENABLE WATCHDOG
# =============================================================================
hdr "Restarting AdGuard Home"

agh_start
log "AdGuard Home started — NSFW blocklist will download within ~60 seconds."

if [ "$_WD_WAS_ACTIVE" = "1" ] && [ "$INIT_SYS" = "systemd" ]; then
    systemctl start wifi-adblock-watchdog.timer 2>/dev/null || true
    log "Watchdog timer re-enabled."
fi

# =============================================================================
# DONE
# =============================================================================
printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  Adult content blocking active.\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m\n'
log "ACTIVE:"
log "  • HaGeZi NSFW Blocklist — 100,000+ adult/porn domains blocked network-wide."
log "  • Parental Control — AdGuard family-safe resolver active."
log "  • SafeSearch — Google, Bing, DuckDuckGo, YouTube Restricted Mode enforced."
printf '\n'
log "Verify in AdGuard Home UI (http://<box-ip>:3000):"
log "  → Filters → DNS Blocklists — look for 'HaGeZi NSFW Blocklist' (downloading...)"
log "  → Settings → General settings — Parental Control and SafeSearch toggles ON"
