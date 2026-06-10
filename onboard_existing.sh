#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Silent onboarding for existing network devices
#
# Run automatically by install.sh. Silently extends all possible protections
# to every device that was already on the network before the box was set up.
#
# What existing devices get silently (zero interaction required):
#   ✓  DNS ad / tracker / malware / phishing blocking
#   ✓  ARP traffic interception (all traffic routed through the box)
#   ✓  WireGuard bypass for Discord / Roblox
#   ✓  Adaptive DNS — fastest server selected for their network
#   ✓  Captive portal permanently suppressed for them
#   ✓  HTTPS pass-through — their HTTPS works normally, no cert errors
#
# What they don't get until they install the CA cert:
#   —  HTTPS deep inspection (YouTube ad stripping, download scanning)
#      Available via:  http://BOX_IP/portal
#
# The moment any existing device installs the CA cert and hits /cert-upgrade,
# their iptables bypass is removed and they get full protection automatically.
# =============================================================================
set -eu

INSTALL_DIR="/opt/mitm-proxy"
[ -d "$INSTALL_DIR" ] || INSTALL_DIR="/usr/share/mitm-proxy"
mkdir -p "$INSTALL_DIR"

SEEN_FILE="$INSTALL_DIR/seen_devices.txt"
EXISTING_IPS="$INSTALL_DIR/existing_ips.txt"
LOG="/var/log/wifi-adblock-install.log"

log()  { printf '\033[1;32m[onboard]\033[0m %s\n' "$*" | tee -a "$LOG"; }

touch "$SEEN_FILE" 2>/dev/null || true
> "${EXISTING_IPS}.new"

FOUND_MACs=0
FOUND_IPs=0

# ── Add a device to both lists ────────────────────────────────────────────────

add_device() {
    _ip="$1"; _mac="$2"
    # Validate IP format
    case "$_ip" in
        ''|169.254.*|255.*|0.*|127.*) return ;;
    esac
    # Validate MAC
    case "$_mac" in
        ''|'00:00:00:00:00:00'|'*') return ;;
    esac
    # Mark as portal-seen so they never get the captive portal
    if ! grep -qF "$_mac" "$SEEN_FILE" 2>/dev/null; then
        printf '%s\n' "$_mac" >> "$SEEN_FILE"
        FOUND_MACs=$((FOUND_MACs + 1))
    fi
    # Add to HTTPS bypass list
    if ! grep -qF "$_ip" "${EXISTING_IPS}.new" 2>/dev/null; then
        printf '%s\n' "$_ip" >> "${EXISTING_IPS}.new"
        FOUND_IPs=$((FOUND_IPs + 1))
    fi
}

# ── Scan /proc/net/arp (devices with active ARP entries) ─────────────────────

if [ -r /proc/net/arp ]; then
    while IFS= read -r line; do
        case "$line" in 'IP address'*) continue ;; esac
        _ip="$(printf '%s' "$line" | awk '{print $1}')"
        _flags="$(printf '%s' "$line" | awk '{print $3}')"
        _mac="$(printf '%s' "$line" | awk '{print $4}')"
        # Skip incomplete ARP entries (0x0 = no response received)
        case "$_flags" in '0x0'|'0x00') continue ;; esac
        add_device "$_ip" "$_mac"
    done < /proc/net/arp
fi

# ── Scan DHCP leases (catches devices not currently active in ARP) ────────────

for _lf in \
    /var/lib/misc/dnsmasq.leases \
    /tmp/dhcp.leases \
    /var/lib/dhcp/dhcpd.leases \
    /var/db/dhcpd.leases \
    /opt/AdGuardHome/data/clients.db; do
    [ -f "$_lf" ] || continue
    while IFS= read -r line; do
        # dnsmasq format: <timestamp> <mac> <ip> <hostname> *
        _ts="$(printf '%s' "$line" | awk '{print $1}')"
        case "$_ts" in ''|*[!0-9]*) continue ;; esac
        _mac="$(printf '%s' "$line" | awk '{print $2}')"
        _ip="$(printf '%s' "$line" | awk '{print $3}')"
        add_device "$_ip" "$_mac"
    done < "$_lf"
done

mv "${EXISTING_IPS}.new" "$EXISTING_IPS"
log "Found $FOUND_MACs existing devices ($FOUND_IPs unique IPs)"

# ── Apply iptables HTTPS pass-through for existing devices ────────────────────
# Rules are inserted BEFORE the REDIRECT rules in the MITMPROXY chain so
# existing devices' port-443 traffic goes straight to the internet — no TLS
# interception, no certificate errors. Everything else is still intercepted.

if ! command -v iptables >/dev/null 2>&1; then
    log "iptables not found — HTTPS bypass rules skipped (will apply when setup.sh runs)"
    exit 0
fi

# Ensure the MITMPROXY chain exists (setup.sh may not have run yet)
iptables -t nat -N MITMPROXY 2>/dev/null || true

_bypass_count=0
if [ -s "$EXISTING_IPS" ]; then
    while IFS= read -r _ip; do
        [ -z "$_ip" ] && continue
        # Check it's not already there
        if ! iptables -t nat -L MITMPROXY -n 2>/dev/null \
                | grep -q "RETURN.*$_ip"; then
            # -I inserts at position 1 = evaluated first, before REDIRECT
            iptables -t nat -I MITMPROXY 1 \
                -s "$_ip" -p tcp --dport 443 -j RETURN 2>/dev/null || true
            _bypass_count=$((_bypass_count + 1))
        fi
    done < "$EXISTING_IPS"
fi
log "HTTPS bypass rules applied for $_bypass_count IPs"
log "Existing devices: full DNS protection active, HTTPS pass-through on"
log "Full HTTPS protection available at: http://\$(hostname -I | awk '{print \$1}')/portal"
