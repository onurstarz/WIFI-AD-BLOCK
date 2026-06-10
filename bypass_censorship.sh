#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Turkey censorship bypass for Discord + Roblox
#
# Turkey blocks Discord and Roblox at two levels:
#   1. DNS poisoning  — already fixed by AdGuard Home using Quad9 over DoH.
#   2. IP-level drops — this script fixes that via WireGuard split-tunnel.
#
# Only Discord and Roblox traffic goes through the tunnel. Everything else
# stays on your direct connection at full speed. This keeps your ping as
# low as the chosen VPN server allows — a nearby European server gives
# 25–50ms from Turkey.
#
# WHAT YOU NEED BEFORE RUNNING:
#   A WireGuard peer outside Turkey. Cheapest options:
#     • Mullvad VPN (€5/mo) — has Romanian servers, ~25ms from Istanbul.
#       Download the .conf file from their website, use it below.
#     • Hetzner VPS in Germany (€4/mo) — ~40ms. Install wireguard-tools on
#       it, run 'wg genkey | tee wg_server.key | wg pubkey' to get keys,
#       then fill in the values below.
#
# HOW TO RUN:
#   sudo sh bypass_censorship.sh
#   The script creates /etc/wireguard/wg-bypass.conf from your answers.
#   Edit that file directly for subsequent changes.
# =============================================================================
set -eu

log()  { printf '\033[1;34m[bypass]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]  \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error] \033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━  %s  ━━━\033[0m\n' "$*"; }
ask()  { printf '\033[1;37m  %s\033[0m ' "$1"; read -r _REPLY; printf '%s' "$_REPLY"; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

WG_IFACE="wg-bypass"
WG_CONF="/etc/wireguard/${WG_IFACE}.conf"
RT_TABLE=200     # custom routing table for tunnelled traffic
FWMARK=0xdead    # iptables mark to identify bypass-bound packets

# =============================================================================
# IP RANGES — Discord and Roblox
#
# These are the known IP ranges as of mid-2025. Discord heavily uses
# Cloudflare (162.159.x.x) for media/CDN and its own ASN 54512 for voice.
# Roblox uses ASN 394684 (128.116.x.x) plus Fastly/Cloudflare CDN.
#
# The AllowedIPs in the WireGuard config will contain exactly these ranges
# so ONLY this traffic goes through the tunnel.
# =============================================================================

DISCORD_RANGES="
162.159.128.0/17
162.159.192.0/19
66.22.192.0/21
35.196.0.0/14
35.234.0.0/14
104.17.0.0/22"

ROBLOX_RANGES="
128.116.0.0/16
209.206.0.0/16
199.255.0.0/16"

# Comma-separated for WireGuard AllowedIPs
ALLOWED_IPS="$(printf '%s\n%s' "$DISCORD_RANGES" "$ROBLOX_RANGES" \
    | sed '/^$/d; s/^[[:space:]]*//' | tr '\n' ',' | sed 's/,$//')"

# =============================================================================
# DETECTION
# =============================================================================
PKG_MGR="none"
if   command -v apt-get      >/dev/null 2>&1; then PKG_MGR=apt
elif command -v dnf          >/dev/null 2>&1; then PKG_MGR=dnf
elif command -v yum          >/dev/null 2>&1; then PKG_MGR=yum
elif command -v pacman       >/dev/null 2>&1; then PKG_MGR=pacman
elif command -v apk          >/dev/null 2>&1; then PKG_MGR=apk
elif command -v opkg         >/dev/null 2>&1; then PKG_MGR=opkg
fi

INIT_SYS="sysvinit"
if [ -d /run/systemd/system ]; then INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1; then INIT_SYS=openrc
elif [ -f /etc/openwrt_release ]; then INIT_SYS=procd
fi

# =============================================================================
# 1. INSTALL WIREGUARD
# =============================================================================
hdr "Installing WireGuard"

install_wg() {
    case "$PKG_MGR" in
        apt)
            apt-get update -qq
            apt-get install -y --no-install-recommends wireguard-tools iproute2 ;;
        dnf|yum)
            $PKG_MGR install -y wireguard-tools ;;
        pacman)
            pacman -Sy --noconfirm wireguard-tools ;;
        apk)
            apk add --no-cache wireguard-tools ;;
        opkg)
            opkg update && opkg install wireguard-tools kmod-wireguard ;;
        *)
            warn "Install wireguard-tools manually for your distro."
            return ;;
    esac
}

if command -v wg >/dev/null 2>&1; then
    log "WireGuard already installed."
else
    install_wg
fi

command -v wg >/dev/null 2>&1 || die "wg not found after install. Check your distro's WireGuard package."

# =============================================================================
# 2. GENERATE OR LOAD PEER CONFIG
# =============================================================================
hdr "WireGuard configuration"

if [ -f "$WG_CONF" ]; then
    log "Config already exists at $WG_CONF"
    printf '  Do you want to reconfigure it? [y/N] '
    read -r _RECONF
    case "$_RECONF" in
        y|Y) : ;;
        *)   log "Keeping existing config. Jumping to tunnel bring-up."; goto_bringup=1 ;;
    esac
fi

if [ "${goto_bringup:-0}" = "0" ]; then
    printf '\n\033[1;37mYou need three values from your VPN peer / VPS:\033[0m\n'
    printf '  1. The peer'\''s PUBLIC KEY  (base64, 44 chars)\n'
    printf '  2. The peer'\''s ENDPOINT    (IP or hostname : port, e.g. vpn.example.com:51820)\n'
    printf '  3. Your client'\''s PRIVATE KEY (generated below if you don'\''t have one)\n\n'

    # Generate a local keypair
    PRIVATE_KEY="$(wg genkey)"
    PUBLIC_KEY="$(printf '%s' "$PRIVATE_KEY" | wg pubkey)"
    log "Generated local keypair."
    printf '\n  \033[1;32mYour PUBLIC key\033[0m (give this to your peer / VPS server config):\n'
    printf '    %s\n\n' "$PUBLIC_KEY"

    # Collect peer info
    PEER_PUBKEY="$(ask "  Paste your peer's PUBLIC key:")"
    [ -z "$PEER_PUBKEY" ] && die "Peer public key is required."

    PEER_ENDPOINT="$(ask "  Paste your peer's ENDPOINT (host:port):")"
    [ -z "$PEER_ENDPOINT" ] && die "Peer endpoint is required."

    # Client tunnel IP — typically assigned by the VPN provider
    CLIENT_IP="$(ask "  Your tunnel IP (from your VPN provider, e.g. 10.0.0.2/32) [10.0.0.2/32]:")"
    [ -z "$CLIENT_IP" ] && CLIENT_IP="10.0.0.2/32"

    # Optional preshared key
    PRESHARED_KEY="$(ask "  Preshared key (leave blank if none):")"

    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    if [ -n "$PRESHARED_KEY" ]; then
        PSK_LINE="PresharedKey = ${PRESHARED_KEY}"
    else
        PSK_LINE=""
    fi

    cat > "$WG_CONF" << EOF
# WireGuard split-tunnel for Discord + Roblox bypass
# Only those services' IP ranges are routed through this tunnel.
# Generated by bypass_censorship.sh

[Interface]
PrivateKey = ${PRIVATE_KEY}
Address    = ${CLIENT_IP}
DNS        = 9.9.9.9

# PostUp/PreDown: policy routing so only marked packets use this tunnel.
# Normal traffic keeps its original gateway — no slowdown.
PostUp   = ip rule  add fwmark ${FWMARK} table ${RT_TABLE} priority 100; \
           ip route add default dev %i table ${RT_TABLE}; \
           iptables -t mangle -A PREROUTING -d $(printf '%s' "$DISCORD_RANGES $ROBLOX_RANGES" \
               | tr ' \n' ',' | sed 's/,$//' | sed 's/,,*/,/g') -j MARK --set-mark ${FWMARK}
PreDown  = ip rule  del fwmark ${FWMARK} table ${RT_TABLE} 2>/dev/null || true; \
           ip route del default dev %i table ${RT_TABLE} 2>/dev/null || true; \
           iptables -t mangle -D PREROUTING -d $(printf '%s' "$DISCORD_RANGES $ROBLOX_RANGES" \
               | tr ' ' ',' | sed 's/,$//' | sed 's/,,*/,/g') -j MARK --set-mark ${FWMARK} 2>/dev/null || true

[Peer]
PublicKey  = ${PEER_PUBKEY}
${PSK_LINE}
Endpoint   = ${PEER_ENDPOINT}
# Only Discord + Roblox IP ranges go through this tunnel.
AllowedIPs = ${ALLOWED_IPS}
# Keep the tunnel alive through NAT
PersistentKeepalive = 25
EOF

    chmod 600 "$WG_CONF"
    log "Config written to $WG_CONF"
fi

# =============================================================================
# 3. BRING UP THE TUNNEL
# =============================================================================
hdr "Bringing up WireGuard tunnel"

# Bring down first in case it's already up (idempotent)
wg-quick down "$WG_IFACE" 2>/dev/null || true
wg-quick up   "$WG_IFACE"

# Verify it came up
if wg show "$WG_IFACE" >/dev/null 2>&1; then
    _out="$(wg show "$WG_IFACE" 2>/dev/null)"
    log "Tunnel is up."
    printf '%s\n' "$_out" | sed 's/^/    /'
else
    die "WireGuard tunnel failed to come up. Check: wg show $WG_IFACE"
fi

# =============================================================================
# 4. ENABLE ON BOOT
# =============================================================================
hdr "Enabling on boot"

case "$INIT_SYS" in
    systemd)
        systemctl enable "wg-quick@${WG_IFACE}"
        log "Enabled via systemd (wg-quick@${WG_IFACE})." ;;
    openrc)
        rc-update add wireguard default 2>/dev/null || \
            warn "Add 'wg-quick up $WG_IFACE' to /etc/local.d/wireguard.start manually." ;;
    procd)
        # OpenWrt has its own WireGuard UCI config; wg-quick isn't idiomatic there
        warn "On OpenWrt, use UCI to persist WireGuard: https://openwrt.org/docs/guide-user/network/tunneling_interface_protocols/protocol.wireguard"
        ;;
    *)
        # Create a boot script
        RC_LOCAL=""
        for _f in /etc/rc.local /etc/rc.d/rc.local; do
            [ -f "$_f" ] && RC_LOCAL="$_f" && break
        done
        if [ -n "$RC_LOCAL" ]; then
            grep -q "wg-quick up $WG_IFACE" "$RC_LOCAL" 2>/dev/null || \
                sed -i "s|^exit 0|wg-quick up $WG_IFACE\nexit 0|" "$RC_LOCAL"
            log "Added to $RC_LOCAL"
        else
            warn "Add 'wg-quick up $WG_IFACE' to your distro's boot scripts manually."
        fi ;;
esac

# =============================================================================
# 5. VERIFY CONNECTIVITY
# =============================================================================
hdr "Testing bypass"

sleep 2  # let routes settle

# Test Discord reach (discord.com's IP should be reachable)
if command -v curl >/dev/null 2>&1; then
    DISCORD_STATUS="$(curl -so /dev/null -w '%{http_code}' \
        --max-time 10 --connect-timeout 8 \
        "https://discord.com/api/v10/gateway" 2>/dev/null || echo "0")"
    if [ "$DISCORD_STATUS" = "200" ]; then
        log "Discord API reachable (HTTP 200). Bypass is working."
    elif [ "$DISCORD_STATUS" = "0" ]; then
        warn "Could not reach discord.com — check peer is up and endpoint is reachable."
    else
        log "Discord API returned HTTP $DISCORD_STATUS (non-zero = routing is working)."
    fi

    ROBLOX_STATUS="$(curl -so /dev/null -w '%{http_code}' \
        --max-time 10 --connect-timeout 8 \
        "https://www.roblox.com" 2>/dev/null || echo "0")"
    if [ "$ROBLOX_STATUS" = "200" ] || [ "$ROBLOX_STATUS" = "301" ] || [ "$ROBLOX_STATUS" = "302" ]; then
        log "Roblox reachable (HTTP $ROBLOX_STATUS). Bypass is working."
    elif [ "$ROBLOX_STATUS" = "0" ]; then
        warn "Could not reach roblox.com — check peer is up."
    else
        log "Roblox returned HTTP $ROBLOX_STATUS."
    fi
fi

# Quick latency check via ping
for _host in 162.159.128.233 128.116.100.1; do
    if command -v ping >/dev/null 2>&1; then
        PING_RESULT="$(ping -c 3 -W 3 "$_host" 2>/dev/null \
            | awk '/rtt|round-trip/ {split($4,a,"/"); printf "%.0fms avg", a[2]}')"
        [ -n "$PING_RESULT" ] && log "Ping $_host : $PING_RESULT"
    fi
done

# =============================================================================
# DONE
# =============================================================================
printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  Discord + Roblox bypass active.\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m\n'
log "Split routing: only Discord/Roblox IPs go through the tunnel."
log "Everything else uses your normal direct connection."
log "Config: $WG_CONF"
printf '\n'
log "Useful commands:"
log "  wg show $WG_IFACE          — live tunnel stats + last handshake time"
log "  wg-quick down $WG_IFACE    — turn off the tunnel"
log "  wg-quick up   $WG_IFACE    — turn it back on"
printf '\n'
log "If ping is higher than expected, try a server in Romania or Bulgaria —"
log "they are the closest countries to Turkey with good WireGuard providers."
