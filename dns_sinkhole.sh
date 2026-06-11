#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — DNS sinkhole layer (AdGuard Home)
#
# This is the workhorse for network-wide ad blocking. It blocks ads that load
# from separate ad-network domains: mobile game ads (AdMob/Unity/AppLovin),
# browser banners/pop-ups, in-app banners, tracking, and telemetry — across
# every device on the network, with nothing sitting in the traffic path.
#
# AdGuard Home is a single static binary. Its own installer registers a
# service on systemd / OpenRC / procd / runit / FreeBSD-rc automatically,
# so this script stays simple and portable.
#
# Run as root. Safe to re-run.
# =============================================================================
set -eu

log()  { printf '\033[1;35m[dns]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━  %s  ━━━\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

AGH_DIR="/opt/AdGuardHome"

# =============================================================================
# 1. ARCHITECTURE DETECTION
# =============================================================================
hdr "Detecting CPU architecture"

RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
    x86_64|amd64)        AGH_ARCH="amd64"   ;;
    aarch64|arm64)       AGH_ARCH="arm64"   ;;   # Amlogic S905X = this one
    armv7l|armv7|armhf)  AGH_ARCH="armv7"   ;;
    armv6l|armv6)        AGH_ARCH="armv6"   ;;
    armv5*)              AGH_ARCH="armv5"   ;;
    i386|i686)           AGH_ARCH="386"     ;;
    mips)                AGH_ARCH="mips"    ;;
    mips64)              AGH_ARCH="mips64"  ;;
    *)                   die "Unknown architecture '$RAW_ARCH' — check AdGuard Home release list." ;;
esac
log "Detected: $RAW_ARCH  →  AdGuard Home build: linux_${AGH_ARCH}"

# =============================================================================
# 2. DOWNLOAD TOOL
# =============================================================================
DL=""
if   command -v curl >/dev/null 2>&1; then DL="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then DL="wget -qO"
else
    # Try to install one
    if   command -v apt-get >/dev/null 2>&1; then apt-get install -y --no-install-recommends curl
    elif command -v apk     >/dev/null 2>&1; then apk add --no-cache curl
    elif command -v opkg    >/dev/null 2>&1; then opkg update && opkg install curl
    fi
    command -v curl >/dev/null 2>&1 && DL="curl -fsSL -o" || die "Need curl or wget."
fi

# =============================================================================
# 3. DOWNLOAD + INSTALL AdGuard Home
# =============================================================================
hdr "Installing AdGuard Home"

if [ -x "$AGH_DIR/AdGuardHome" ]; then
    log "AdGuard Home already present at $AGH_DIR — skipping download."
else
    TARBALL="/tmp/AdGuardHome.tar.gz"
    URL="https://static.adguard.com/adguardhome/release/AdGuardHome_linux_${AGH_ARCH}.tar.gz"
    log "Downloading $URL"
    # shellcheck disable=SC2086
    $DL "$TARBALL" "$URL"
    log "Extracting to /opt..."
    tar -xzf "$TARBALL" -C /opt
    rm -f "$TARBALL"
fi

# Register as a service (AdGuard Home auto-detects the init system).
# If it's already installed as a service this is a no-op error we ignore.
log "Registering AdGuard Home as a system service..."
"$AGH_DIR/AdGuardHome" -s install 2>/dev/null || \
    log "Service already installed (or running) — continuing."

# =============================================================================
# 4. PORT 53 CONFLICT CHECK
# =============================================================================
hdr "Checking for port 53 conflicts"

# AdGuard Home needs UDP/TCP 53. On Debian/Armbian, systemd-resolved often
# squats on it. Free it up.
if [ -d /run/systemd/system ] && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    warn "systemd-resolved is holding port 53 — reconfiguring it to stub-off."
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/adguardhome.conf << 'EOF'
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
EOF
    # Point the system resolver at AdGuard Home
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true
    systemctl restart systemd-resolved || true
    log "systemd-resolved stub listener disabled; port 53 is now free."
fi

# =============================================================================
# 5. START
# =============================================================================
hdr "Starting AdGuard Home"

if   command -v systemctl >/dev/null 2>&1; then systemctl restart AdGuardHome 2>/dev/null || true
elif command -v rc-service >/dev/null 2>&1; then rc-service AdGuardHome restart 2>/dev/null || true
elif [ -x /etc/init.d/AdGuardHome ]; then /etc/init.d/AdGuardHome restart 2>/dev/null || true
fi

BOX_IP_GUESS="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)"
[ -z "$BOX_IP_GUESS" ] && BOX_IP_GUESS="<this-box-ip>"

# =============================================================================
# DONE
# =============================================================================
printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  AdGuard Home installed.\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m\n'
log "FIRST-TIME SETUP (do this once, from any device on the LAN):"
log "  1. Open:  http://${BOX_IP_GUESS}:3000"
log "  2. Set the DNS listen interface to 'All interfaces', port 53."
log "  3. Set the admin web interface to port 3000 (or 80 if free)."
log "  4. Create an admin login."
printf '\n'
log "RECOMMENDED BLOCKLISTS (add under Filters → DNS blocklists):"
log "  • AdGuard DNS filter            (enabled by default)"
log "  • AdAway                        — mobile app/game ads"
log "  • OISD Big                      https://big.oisd.nl"
log "  • HaGeZi Multi PRO              github.com/hagezi/dns-blocklists"
log "  • Peter Lowe's list             — ad servers + tracking"
printf '\n'
log "THEN point your network's DNS at this box:"
log "  • Set your router's DHCP DNS option to ${BOX_IP_GUESS} (primary AND secondary)."
log "  • Reconnect devices so they pick up the new DNS server."
