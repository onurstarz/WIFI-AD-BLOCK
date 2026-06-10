#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# network_config.sh  —  wires up the Linux box as a forwarding gateway
#
# Run this AFTER setup.sh.  It configures the box to act as the LAN gateway
# so all client devices route through mitmproxy without any per-device proxy
# settings.  Also starts a small DHCP server that hands out this box as the
# default gateway.
#
# Edit the VARIABLES section to match your network before running.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── VARIABLES — edit these ───────────────────────────────────────────────────
LAN_IFACE="eth0"          # interface connected to your LAN/switch
WAN_IFACE="eth0"          # often the same if only one port; set to wlan0 etc if different
BOX_IP="192.168.1.2"      # static IP of this Linux box on the LAN
SUBNET="192.168.1.0/24"
ROUTER_IP="192.168.1.1"   # your actual router/gateway
DHCP_RANGE_START="192.168.1.100"
DHCP_RANGE_END="192.168.1.200"
DNS_SERVER="127.0.0.1"    # point to Pi-hole/AdGuard if running on same box, else 9.9.9.9
# ─────────────────────────────────────────────────────────────────────────────

log()  { echo -e "\033[1;36m[net]\033[0m $*"; }
die()  { echo -e "\033[1;31m[error]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root."

# ─── Static IP for this box ───────────────────────────────────────────────────
log "Setting static IP $BOX_IP on $LAN_IFACE..."
cat > /etc/network/interfaces.d/adblock << EOF
auto ${LAN_IFACE}
iface ${LAN_IFACE} inet static
    address ${BOX_IP}
    netmask 255.255.255.0
    gateway ${ROUTER_IP}
    dns-nameservers ${DNS_SERVER} 1.1.1.1
EOF

# Bring the interface up with the new config
ip addr flush dev "$LAN_IFACE" 2>/dev/null || true
ifup "$LAN_IFACE" 2>/dev/null || ip addr add "$BOX_IP/24" dev "$LAN_IFACE" || true

# ─── dnsmasq as lightweight DHCP (tells clients to use this box as gateway) ───
log "Installing and configuring dnsmasq for DHCP..."
apt-get install -y --no-install-recommends dnsmasq

cat > /etc/dnsmasq.d/adblock-dhcp.conf << EOF
# Only serve DHCP on the LAN interface
interface=${LAN_IFACE}

# Hand out IPs in range; 12h lease
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},12h

# Tell every client to route through THIS box, not the real router
dhcp-option=option:router,${BOX_IP}

# DNS
dhcp-option=option:dns-server,${DNS_SERVER},1.1.1.1

# Don't touch /etc/resolv.conf
no-resolv
EOF

# Disable the default dnsmasq DNS listener so it doesn't conflict with
# Pi-hole/AdGuard if you run one.  DHCP-only mode.
grep -qxF 'port=0' /etc/dnsmasq.conf || echo 'port=0' >> /etc/dnsmasq.conf

systemctl restart dnsmasq
log "dnsmasq DHCP server running."

# ─── Route traffic from clients back to the real router ──────────────────────
log "Adding upstream default route via $ROUTER_IP..."
ip route add default via "$ROUTER_IP" dev "$LAN_IFACE" metric 100 2>/dev/null || \
    log "  Default route already present."

# ─── Masquerade outbound so replies reach clients through this box ────────────
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true

log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "  Network configured.  On your router, either:"
log "  A) Disable the router's built-in DHCP server (clients will"
log "     pick up leases from this box automatically), or"
log "  B) Change the router's DHCP 'default gateway' option to $BOX_IP."
log ""
log "  Once done, reconnect each client device (release/renew DHCP)"
log "  and all traffic will flow through mitmproxy."
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
