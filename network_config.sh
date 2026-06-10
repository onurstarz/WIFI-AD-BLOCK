#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Universal network gateway config
#
# Makes this Linux box the default gateway for your LAN so all device traffic
# flows transparently through mitmproxy without per-device proxy settings.
#
# Supported network managers:
#   OpenWrt (UCI)          — detected via /etc/openwrt_release
#   systemd-networkd       — detected via systemd
#   NetworkManager         — detected via nmcli
#   ifupdown (/etc/network/interfaces) — Debian / Ubuntu / Armbian / Alpine
#   busybox ifconfig       — OpenWrt fallback
#   Generic ip-commands    — universal POSIX fallback
#
# EDIT THE VARIABLES SECTION BELOW BEFORE RUNNING.
# Run as root after setup.sh.
# =============================================================================
set -eu

# =============================================================================
# ▼▼▼  EDIT THESE  ▼▼▼
# =============================================================================
LAN_IFACE="eth0"           # NIC connected to your LAN / switch
WAN_IFACE="eth0"           # NIC facing the router (often same single port)
BOX_IP="192.168.1.2"       # static IP to assign to THIS Linux box
SUBNET_PREFIX="24"         # CIDR prefix (24 = /24 = 255.255.255.0)
ROUTER_IP="192.168.1.1"    # your actual upstream router / gateway
DHCP_START="192.168.1.100" # DHCP pool start (handed to your devices)
DHCP_END="192.168.1.200"   # DHCP pool end
DNS_SERVER="9.9.9.9"       # DNS for clients (change to Pi-hole IP if running one)
# =============================================================================
# ▲▲▲  EDIT THESE  ▲▲▲
# =============================================================================

log()  { printf '\033[1;36m[net]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━  %s  ━━━\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

# =============================================================================
# DETECTION
# =============================================================================
IS_OPENWRT=0
[ -f /etc/openwrt_release ] && IS_OPENWRT=1

NET_MGR="generic"
if   [ "$IS_OPENWRT" = "1" ]; then
    NET_MGR=uci
elif command -v nmcli >/dev/null 2>&1 && nmcli -t d >/dev/null 2>&1; then
    NET_MGR=networkmanager
elif [ -d /run/systemd/system ] && command -v networkctl >/dev/null 2>&1; then
    NET_MGR=networkd
elif [ -f /etc/network/interfaces ] || [ -d /etc/network/interfaces.d ]; then
    NET_MGR=ifupdown
fi
log "Network manager : $NET_MGR"

PKG_MGR="none"
if   command -v apt-get      >/dev/null 2>&1; then PKG_MGR=apt
elif command -v dnf          >/dev/null 2>&1; then PKG_MGR=dnf
elif command -v yum          >/dev/null 2>&1; then PKG_MGR=yum
elif command -v pacman       >/dev/null 2>&1; then PKG_MGR=pacman
elif command -v apk          >/dev/null 2>&1; then PKG_MGR=apk
elif command -v opkg         >/dev/null 2>&1; then PKG_MGR=opkg
elif command -v zypper       >/dev/null 2>&1; then PKG_MGR=zypper
elif command -v xbps-install >/dev/null 2>&1; then PKG_MGR=xbps
fi

INIT_SYS="sysvinit"
if [ -d /run/systemd/system ]; then INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1; then INIT_SYS=openrc
elif [ "$IS_OPENWRT" = "1" ]; then INIT_SYS=procd
fi

# =============================================================================
# APPLY STATIC IP
# =============================================================================
hdr "Setting static IP $BOX_IP/$SUBNET_PREFIX on $LAN_IFACE"

apply_ip_generic() {
    # Always works — uses the 'ip' command which is available everywhere.
    ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
    ip addr add "${BOX_IP}/${SUBNET_PREFIX}" dev "$LAN_IFACE" 2>/dev/null || true
    ip link set "$LAN_IFACE" up
    ip route add default via "$ROUTER_IP" metric 100 2>/dev/null || true
    log "IP set via ip-commands (not persistent across reboots — see below)."
}

case "$NET_MGR" in
    uci)
        log "Configuring via OpenWrt UCI..."
        uci set network.lan.proto='static'
        uci set network.lan.ipaddr="$BOX_IP"
        uci set network.lan.netmask="255.255.255.0"
        uci set network.lan.gateway="$ROUTER_IP"
        uci set network.lan.dns="$DNS_SERVER 1.1.1.1"
        uci commit network
        /etc/init.d/network restart || true
        ;;

    networkmanager)
        log "Configuring via NetworkManager (nmcli)..."
        CON_NAME="mitm-adblock-static"
        nmcli con del "$CON_NAME" >/dev/null 2>&1 || true
        nmcli con add type ethernet ifname "$LAN_IFACE" con-name "$CON_NAME" \
            ipv4.method manual \
            ipv4.addresses "${BOX_IP}/${SUBNET_PREFIX}" \
            ipv4.gateway "$ROUTER_IP" \
            ipv4.dns "$DNS_SERVER 1.1.1.1" \
            ipv6.method disabled
        nmcli con up "$CON_NAME"
        ;;

    networkd)
        log "Configuring via systemd-networkd..."
        mkdir -p /etc/systemd/network
        cat > /etc/systemd/network/10-mitm-adblock.network << EOF
[Match]
Name=${LAN_IFACE}

[Network]
Address=${BOX_IP}/${SUBNET_PREFIX}
Gateway=${ROUTER_IP}
DNS=${DNS_SERVER}
DNS=1.1.1.1
EOF
        systemctl restart systemd-networkd
        ;;

    ifupdown)
        log "Configuring via /etc/network/interfaces..."
        # Use interfaces.d drop-in if it exists, else write directly
        if [ -d /etc/network/interfaces.d ]; then
            IFACE_FILE=/etc/network/interfaces.d/mitm-adblock
        else
            IFACE_FILE=/etc/network/interfaces.mitm
            warn "Append the contents of $IFACE_FILE to /etc/network/interfaces manually."
        fi
        cat > "$IFACE_FILE" << EOF
auto ${LAN_IFACE}
iface ${LAN_IFACE} inet static
    address ${BOX_IP}
    netmask 255.255.255.0
    gateway ${ROUTER_IP}
    dns-nameservers ${DNS_SERVER} 1.1.1.1
EOF
        # Bring up now; ifup/ifdown might not be available on Alpine
        if command -v ifdown >/dev/null 2>&1; then
            ifdown "$LAN_IFACE" 2>/dev/null || true
            ifup "$LAN_IFACE" 2>/dev/null || apply_ip_generic
        else
            apply_ip_generic
        fi
        ;;

    generic)
        apply_ip_generic
        warn "No persistent network manager found."
        warn "Add a static IP assignment for $LAN_IFACE to your distro's network config manually."
        ;;
esac

# =============================================================================
# DHCP SERVER (tells clients this box is their gateway)
# =============================================================================
hdr "Configuring DHCP — advertising $BOX_IP as gateway"

setup_dhcp_openwrt() {
    # OpenWrt already runs dnsmasq; configure it via UCI
    log "Configuring OpenWrt dnsmasq via UCI..."

    # Set DHCP range
    uci set dhcp.lan.start="$(echo "$DHCP_START" | awk -F. '{print $4}')"
    uci set dhcp.lan.limit="$(( $(echo "$DHCP_END" | awk -F. '{print $4}') - $(echo "$DHCP_START" | awk -F. '{print $4}') + 1 ))"
    uci set dhcp.lan.leasetime='12h'

    # This makes OpenWrt dnsmasq advertise BOX_IP as the default gateway (option 3)
    # and DNS server (option 6) to every DHCP client.
    uci -q del dhcp.lan.dhcp_option || true
    uci add_list dhcp.lan.dhcp_option="3,${BOX_IP}"
    uci add_list dhcp.lan.dhcp_option="6,${DNS_SERVER},1.1.1.1"

    uci commit dhcp
    /etc/init.d/dnsmasq restart
    log "OpenWrt dnsmasq restarted."
}

setup_dhcp_dnsmasq() {
    # Full dnsmasq install on non-OpenWrt distros
    case "$PKG_MGR" in
        apt)    apt-get install -y --no-install-recommends dnsmasq ;;
        dnf|yum) $PKG_MGR install -y dnsmasq ;;
        pacman) pacman -S --noconfirm dnsmasq ;;
        apk)    apk add --no-cache dnsmasq ;;
        zypper) zypper install -y dnsmasq ;;
        xbps)   xbps-install -Sy dnsmasq ;;
        *)      warn "Install dnsmasq manually for your distro." ;;
    esac

    DNSMASQ_CONF_DIR=""
    if [ -d /etc/dnsmasq.d ]; then
        DNSMASQ_CONF_DIR=/etc/dnsmasq.d
    elif [ -d /etc/dnsmasq.conf.d ]; then
        DNSMASQ_CONF_DIR=/etc/dnsmasq.conf.d
    fi

    DNSMASQ_CONF="${DNSMASQ_CONF_DIR:+${DNSMASQ_CONF_DIR}/mitm-adblock.conf}"
    [ -z "$DNSMASQ_CONF" ] && DNSMASQ_CONF="/etc/dnsmasq.d/mitm-adblock.conf" && mkdir -p /etc/dnsmasq.d

    cat > "$DNSMASQ_CONF" << EOF
# Only serve DHCP on the LAN interface
interface=${LAN_IFACE}
bind-interfaces

# IP pool — 12h lease
dhcp-range=${DHCP_START},${DHCP_END},12h

# Tell all clients to use THIS box as default gateway
dhcp-option=option:router,${BOX_IP}

# DNS
dhcp-option=option:dns-server,${DNS_SERVER},1.1.1.1

# Don't act as a DNS forwarder (port=0 disables DNS, keeps DHCP only)
# Comment this out if you want dnsmasq to also handle DNS.
port=0

no-resolv
EOF

    # Restart dnsmasq via whichever init system is present
    case "$INIT_SYS" in
        systemd)  systemctl enable dnsmasq && systemctl restart dnsmasq ;;
        openrc)   rc-update add dnsmasq default 2>/dev/null || true && rc-service dnsmasq restart ;;
        procd)    /etc/init.d/dnsmasq enable && /etc/init.d/dnsmasq restart ;;
        *)        /etc/init.d/dnsmasq restart 2>/dev/null || service dnsmasq restart ;;
    esac
    log "dnsmasq DHCP server running."
}

if [ "$IS_OPENWRT" = "1" ]; then
    setup_dhcp_openwrt
else
    setup_dhcp_dnsmasq
fi

# =============================================================================
# MASQUERADE (so replies route back through this box to clients)
# =============================================================================
hdr "Enabling NAT masquerade on $WAN_IFACE"

iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
    warn "MASQUERADE rule failed — set WAN_IFACE correctly at the top of this script."

# =============================================================================
# DONE
# =============================================================================
printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  Network configured.\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m'
printf '\n'
log "Next steps:"
log "  1. On your ROUTER: either disable its DHCP server entirely,"
log "     or change its DHCP 'default gateway' option to ${BOX_IP}."
log "  2. On each device: release + renew DHCP (reconnect to Wi-Fi)."
log "  3. Install the mitmproxy CA cert on each device (see README.md)."
log "  4. Verify: watch 'journalctl -fu mitm-adblock | grep YT-AdStrip'."
