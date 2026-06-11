#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — Universal setup script
#
# Tested distro families:
#   Debian / Ubuntu / Armbian / Raspbian  (apt)
#   Alpine Linux                          (apk + OpenRC)
#   OpenWrt / ophub amlogic-s9xxx-openwrt (opkg + procd)
#   Arch / Manjaro                        (pacman)
#   Fedora / RHEL / CentOS / Rocky        (dnf / yum)
#   openSUSE Leap / Tumbleweed            (zypper)
#   Void Linux                            (xbps)
#   Gentoo                                (emerge — manual steps noted)
#   Any POSIX Linux with Python 3.9+
#
# Run as root.  Safe to re-run — each section is idempotent.
# =============================================================================
set -eu

PROXY_PORT=8080
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Install dir: prefer /opt (writable on most distros including OpenWrt with
# extroot), fall back to /usr/share if /opt doesn't exist or isn't writable.
if [ -d /opt ] && [ -w /opt ]; then
    INSTALL_DIR="/opt/mitm-proxy"
else
    INSTALL_DIR="/usr/share/mitm-proxy"
fi
CERT_DIR="${INSTALL_DIR}/certs"

# ── Colour helpers (printf, not echo -e — POSIX safe) ──────────────────────
log()  { printf '\033[1;32m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn] \033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
hdr()  { printf '\n\033[1;36m━━━  %s  ━━━\033[0m\n' "$*"; }

[ "$(id -u)" = "0" ] || die "Re-run as root: sudo sh $0"

# =============================================================================
# 1. DETECTION
# =============================================================================
hdr "Detecting environment"

# ── Package manager ──────────────────────────────────────────────────────────
PKG_MGR="none"
if   command -v apt-get      >/dev/null 2>&1; then PKG_MGR=apt
elif command -v dnf          >/dev/null 2>&1; then PKG_MGR=dnf
elif command -v yum          >/dev/null 2>&1; then PKG_MGR=yum
elif command -v pacman       >/dev/null 2>&1; then PKG_MGR=pacman
elif command -v apk          >/dev/null 2>&1; then PKG_MGR=apk
elif command -v opkg         >/dev/null 2>&1; then PKG_MGR=opkg
elif command -v zypper       >/dev/null 2>&1; then PKG_MGR=zypper
elif command -v xbps-install >/dev/null 2>&1; then PKG_MGR=xbps
elif command -v emerge       >/dev/null 2>&1; then PKG_MGR=emerge
fi
log "Package manager : $PKG_MGR"

# ── Init system ───────────────────────────────────────────────────────────────
INIT_SYS="sysvinit"
if [ -d /run/systemd/system ]; then
    INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1 || [ -f /sbin/openrc ]; then
    INIT_SYS=openrc
elif [ -f /etc/openwrt_release ] || command -v procd >/dev/null 2>&1; then
    INIT_SYS=procd
elif [ -d /etc/sv ] || command -v runit >/dev/null 2>&1; then
    INIT_SYS=runit
elif [ -d /service ] && command -v s6-svscan >/dev/null 2>&1; then
    INIT_SYS=s6
fi
log "Init system     : $INIT_SYS"

# ── OpenWrt flag ─────────────────────────────────────────────────────────────
IS_OPENWRT=0
[ -f /etc/openwrt_release ] && IS_OPENWRT=1
log "OpenWrt         : $IS_OPENWRT"

# ── User management ───────────────────────────────────────────────────────────
# Busybox uses 'adduser' with different flags; glibc systems use 'useradd'.
# On very stripped systems fall back to 'nobody' (always exists).
PROXY_USER="mitm"
HAS_USERADD=0
HAS_ADDUSER=0
command -v useradd  >/dev/null 2>&1 && HAS_USERADD=1
command -v adduser  >/dev/null 2>&1 && HAS_ADDUSER=1
if [ "$HAS_USERADD" = "0" ] && [ "$HAS_ADDUSER" = "0" ]; then
    warn "Neither useradd nor adduser found — running as 'nobody'."
    PROXY_USER="nobody"
fi

# =============================================================================
# 2. SYSTEM PACKAGES
# =============================================================================
hdr "Installing system dependencies"

pkg_update() {
    case "$PKG_MGR" in
        apt)    apt-get update -qq ;;
        dnf)    dnf check-update -q || true ;;
        yum)    yum check-update -q || true ;;
        pacman) pacman -Sy --noconfirm ;;
        apk)    apk update -q ;;
        opkg)   opkg update ;;
        zypper) zypper refresh -q ;;
        xbps)   xbps-install -Su -y >/dev/null 2>&1 || true ;;
        emerge) emerge --sync -q ;;
        none)   : ;;
    esac
}

# pkg_install <generic-name>  — maps generic names to distro-specific package names
pkg_install() {
    _pkg="$1"
    case "$PKG_MGR" in
        apt)
            case "$_pkg" in
                python3)       apt-get install -y --no-install-recommends python3 ;;
                python3-pip)   apt-get install -y --no-install-recommends python3-pip ;;
                python3-venv)  apt-get install -y --no-install-recommends python3-venv ;;
                iptables)      apt-get install -y --no-install-recommends iptables ;;
                iproute2)      apt-get install -y --no-install-recommends iproute2 ;;
                openssl)       apt-get install -y --no-install-recommends openssl ;;
                curl)          apt-get install -y --no-install-recommends curl ;;
                *)             apt-get install -y --no-install-recommends "$_pkg" ;;
            esac ;;
        dnf|yum)
            case "$_pkg" in
                python3-venv)  $PKG_MGR install -y python3 ;;  # venv bundled on Fedora
                iproute2)      $PKG_MGR install -y iproute ;;
                *)             $PKG_MGR install -y "$_pkg" ;;
            esac ;;
        pacman)
            case "$_pkg" in
                python3)       pacman -S --noconfirm python ;;
                python3-pip)   pacman -S --noconfirm python-pip ;;
                python3-venv)  : ;;  # bundled with python
                iproute2)      pacman -S --noconfirm iproute2 ;;
                *)             pacman -S --noconfirm "$_pkg" ;;
            esac ;;
        apk)
            case "$_pkg" in
                python3)       apk add --no-cache python3 ;;
                python3-pip)   apk add --no-cache py3-pip ;;
                python3-venv)  apk add --no-cache python3 ;;  # venv bundled
                iproute2)      apk add --no-cache iproute2 ;;
                openssl)       apk add --no-cache openssl ;;
                *)             apk add --no-cache "$_pkg" ;;
            esac ;;
        opkg)
            case "$_pkg" in
                python3)       opkg install python3 ;;
                python3-pip)   opkg install python3-pip 2>/dev/null || install_pip_bootstrap ;;
                python3-venv)  : ;;  # handled via pip on OpenWrt
                iproute2)      opkg install ip-full ;;
                openssl)       opkg install libopenssl openssl-util ;;
                curl)          opkg install curl ;;
                *)             opkg install "$_pkg" ;;
            esac ;;
        zypper)
            case "$_pkg" in
                python3)       zypper install -y python3 ;;
                python3-pip)   zypper install -y python3-pip ;;
                python3-venv)  zypper install -y python3 ;;  # bundled
                iproute2)      zypper install -y iproute2 ;;
                *)             zypper install -y "$_pkg" ;;
            esac ;;
        xbps)
            case "$_pkg" in
                python3)       xbps-install -Sy python3 ;;
                python3-pip)   xbps-install -Sy python3-pip ;;
                python3-venv)  : ;;
                iproute2)      xbps-install -Sy iproute2 ;;
                *)             xbps-install -Sy "$_pkg" ;;
            esac ;;
        emerge)
            case "$_pkg" in
                python3|python3-pip|python3-venv) emerge dev-lang/python ;;
                iptables)      emerge net-firewall/iptables ;;
                iproute2)      emerge sys-apps/iproute2 ;;
                openssl)       emerge dev-libs/openssl ;;
                curl)          emerge net-misc/curl ;;
                *)             warn "Gentoo: manually emerge $*" ;;
            esac ;;
        none)
            warn "No package manager — skipping install of: $_pkg" ;;
    esac
}

# Bootstrap pip via ensurepip or get-pip.py when opkg doesn't have it
install_pip_bootstrap() {
    log "Bootstrapping pip via ensurepip..."
    python3 -m ensurepip --upgrade 2>/dev/null && return
    warn "ensurepip failed — trying get-pip.py..."
    if command -v curl >/dev/null 2>&1; then
        curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    elif command -v wget >/dev/null 2>&1; then
        wget -qO /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
    else
        die "Cannot download get-pip.py — install curl or wget first."
    fi
    python3 /tmp/get-pip.py --quiet
    rm -f /tmp/get-pip.py
}

pkg_update
pkg_install python3
pkg_install python3-pip
pkg_install iptables
pkg_install iproute2
pkg_install openssl
pkg_install curl

# =============================================================================
# 3. PYTHON VIRTUALENV + MITMPROXY
# =============================================================================
hdr "Installing mitmproxy"

mkdir -p "$INSTALL_DIR"

# Try venv first; fall back to --user pip install if venv module is missing.
PYTHON_BIN=""
PIP_BIN=""

setup_venv() {
    log "Trying virtualenv at $INSTALL_DIR..."
    pkg_install python3-venv 2>/dev/null || true
    if python3 -m venv "$INSTALL_DIR" 2>/dev/null; then
        PYTHON_BIN="$INSTALL_DIR/bin/python3"
        PIP_BIN="$INSTALL_DIR/bin/pip"
        log "Virtualenv created."
        return 0
    fi
    return 1
}

setup_system_pip() {
    warn "venv not available — installing mitmproxy system-wide via pip."
    # On OpenWrt/musl, some wheels need --break-system-packages (pip 23+) or
    # the flag doesn't exist yet. Handle both.
    if python3 -m pip install mitmproxy blackboxprotobuf --quiet 2>/dev/null; then
        :
    else
        python3 -m pip install mitmproxy blackboxprotobuf \
            --quiet --break-system-packages 2>/dev/null || \
        python3 -m pip install mitmproxy blackboxprotobuf \
            --quiet --user
    fi
    PYTHON_BIN="$(command -v python3)"
    PIP_BIN="$(command -v pip3 || command -v pip)"
}

if ! setup_venv; then
    setup_system_pip
else
    "$PIP_BIN" install --upgrade pip --quiet
    "$PIP_BIN" install mitmproxy blackboxprotobuf --quiet
fi

log "mitmproxy installed: $("$PYTHON_BIN" -m mitmdump --version 2>/dev/null | head -1)"

# Resolve mitmdump path
MITMDUMP_BIN=""
if [ -f "$INSTALL_DIR/bin/mitmdump" ]; then
    MITMDUMP_BIN="$INSTALL_DIR/bin/mitmdump"
elif command -v mitmdump >/dev/null 2>&1; then
    MITMDUMP_BIN="$(command -v mitmdump)"
else
    # Last resort: search $HOME/.local/bin
    if [ -f "$HOME/.local/bin/mitmdump" ]; then
        MITMDUMP_BIN="$HOME/.local/bin/mitmdump"
    fi
fi
[ -n "$MITMDUMP_BIN" ] || die "mitmdump not found after installation. Check pip output above."
log "mitmdump binary : $MITMDUMP_BIN"

# Copy the addon script
cp "$SCRIPT_DIR/yt_ad_stripper.py" "$INSTALL_DIR/yt_ad_stripper.py"
chmod 644 "$INSTALL_DIR/yt_ad_stripper.py"

# =============================================================================
# 4. PROXY USER
# =============================================================================
hdr "Creating proxy user ($PROXY_USER)"

create_user() {
    if id "$PROXY_USER" >/dev/null 2>&1; then
        log "User '$PROXY_USER' already exists."
        return
    fi
    # Find a shell to use as nologin
    NOLOGIN_SHELL=""
    for _s in /sbin/nologin /usr/sbin/nologin /bin/false; do
        [ -f "$_s" ] && NOLOGIN_SHELL="$_s" && break
    done
    [ -z "$NOLOGIN_SHELL" ] && NOLOGIN_SHELL="/bin/false"

    if [ "$HAS_USERADD" = "1" ]; then
        useradd -r -s "$NOLOGIN_SHELL" -d "$INSTALL_DIR" "$PROXY_USER" 2>/dev/null || \
        useradd    -s "$NOLOGIN_SHELL" -d "$INSTALL_DIR" "$PROXY_USER"
    elif [ "$HAS_ADDUSER" = "1" ]; then
        # BusyBox / Alpine adduser syntax
        adduser -S -D -H -s "$NOLOGIN_SHELL" "$PROXY_USER" 2>/dev/null || \
        adduser -S            -s "$NOLOGIN_SHELL" -h "$INSTALL_DIR" "$PROXY_USER"
    fi
    log "User '$PROXY_USER' created."
}

if [ "$PROXY_USER" != "nobody" ]; then
    create_user
fi

chown -R "$PROXY_USER" "$INSTALL_DIR" 2>/dev/null || true

# =============================================================================
# 5. IP FORWARDING
# =============================================================================
hdr "Enabling IP forwarding"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Persist across reboots — sysctl.conf is available on virtually every distro
SYSCTL_CONF=/etc/sysctl.conf
# OpenWrt uses /etc/sysctl.d/ instead
[ -d /etc/sysctl.d ] && SYSCTL_CONF=/etc/sysctl.d/99-mitm-adblock.conf

printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n' > "$SYSCTL_CONF"
log "Sysctl persisted to $SYSCTL_CONF"

# =============================================================================
# 6. IPTABLES TRANSPARENT PROXY RULES
# =============================================================================
hdr "Configuring iptables"

apply_iptables() {
    # Tear down any previous MITMPROXY chain
    iptables -t nat -D PREROUTING -j MITMPROXY >/dev/null 2>&1 || true
    iptables -t nat -D OUTPUT     -j MITMPROXY >/dev/null 2>&1 || true
    iptables -t nat -F MITMPROXY               >/dev/null 2>&1 || true
    iptables -t nat -X MITMPROXY               >/dev/null 2>&1 || true

    iptables -t nat -N MITMPROXY

    # Bypass: RFC-1918 / loopback (only intercept internet-bound traffic)
    for _net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
        iptables -t nat -A MITMPROXY -d "$_net" -j RETURN
    done

    # Redirect HTTP + HTTPS to mitmproxy
    iptables -t nat -A MITMPROXY -p tcp --dport 80  -j REDIRECT --to-port "$PROXY_PORT"
    iptables -t nat -A MITMPROXY -p tcp --dport 443 -j REDIRECT --to-port "$PROXY_PORT"

    # Hook into PREROUTING (forwarded traffic from other devices on the LAN).
    # NOTE: uid-owner match must NOT be inside MITMPROXY chain — it is invalid
    # in prerouting context and causes nftables-backed iptables to reject the
    # PREROUTING jump entirely. The uid-owner exclusion lives in OUTPUT instead.
    iptables -t nat -A PREROUTING -j MITMPROXY 2>/dev/null || \
        warn "PREROUTING hook failed — will be retried by netwatch on next network event"

    # Hook into OUTPUT (traffic from this box itself).
    # Exclude the proxy user's own traffic first to break the redirect loop.
    if iptables -t nat -A OUTPUT -m owner --uid-owner "$PROXY_USER" -j RETURN 2>/dev/null; then
        log "uid-owner match loaded."
    else
        warn "uid-owner not available in nat OUTPUT — loop prevention may be limited"
    fi
    iptables -t nat -A OUTPUT -j MITMPROXY 2>/dev/null || \
        warn "OUTPUT hook failed"

    log "iptables rules applied."
}

apply_iptables

# ── Persist iptables rules ────────────────────────────────────────────────────
persist_iptables() {
    mkdir -p /etc/iptables 2>/dev/null || true
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    elif command -v iptables-save >/dev/null 2>&1; then
        # Where the rules file goes varies by distro
        if [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4
        elif [ -d /var/lib/iptables ]; then
            iptables-save > /var/lib/iptables/rules-save
        else
            iptables-save > /etc/iptables.rules
        fi

        # Alpine / OpenRC: add iptables to default runlevel
        if [ "$INIT_SYS" = "openrc" ]; then
            rc-update add iptables default 2>/dev/null || true
        fi

        # OpenWrt: write rules into /etc/firewall.user (executed on each boot)
        if [ "$IS_OPENWRT" = "1" ]; then
            FWUSER=/etc/firewall.user
            # Remove previous block if present
            if grep -q 'MITMPROXY' "$FWUSER" 2>/dev/null; then
                sed '/# BEGIN MITM-ADBLOCK/,/# END MITM-ADBLOCK/d' "$FWUSER" > "${FWUSER}.tmp"
                mv "${FWUSER}.tmp" "$FWUSER"
            fi
            cat >> "$FWUSER" << FWEOF

# BEGIN MITM-ADBLOCK
iptables -t nat -N MITMPROXY 2>/dev/null || iptables -t nat -F MITMPROXY
for _n in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
    iptables -t nat -A MITMPROXY -d "\$_n" -j RETURN
done
iptables -t nat -A MITMPROXY -p tcp --dport 80  -j REDIRECT --to-port ${PROXY_PORT}
iptables -t nat -A MITMPROXY -p tcp --dport 443 -j REDIRECT --to-port ${PROXY_PORT}
iptables -t nat -A PREROUTING -j MITMPROXY 2>/dev/null || true
iptables -t nat -A OUTPUT     -j MITMPROXY 2>/dev/null || true
# END MITM-ADBLOCK
FWEOF
            log "OpenWrt: firewall rules written to $FWUSER"
        fi

        # Arch Linux: enable iptables.service
        if [ "$PKG_MGR" = "pacman" ] && [ "$INIT_SYS" = "systemd" ]; then
            iptables-save > /etc/iptables/iptables.rules
            systemctl enable iptables >/dev/null 2>&1 || true
        fi

        # RHEL / Fedora: use iptables-services if available
        if [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
                    iptables-save > /etc/iptables/rules.v4
            fi
        fi
    fi
    log "iptables rules persisted."
}

persist_iptables

# =============================================================================
# 7. CA CERTIFICATE GENERATION
# =============================================================================
hdr "Generating mitmproxy root CA"

mkdir -p "$CERT_DIR"
chown "$PROXY_USER" "$CERT_DIR" 2>/dev/null || true
chmod 700 "$CERT_DIR"

gen_certs() {
    # Temporarily remove OUTPUT hook so mitmdump can reach the network without
    # being redirected to itself (proxy isn't running yet = black hole).
    _had_output=0
    if iptables -t nat -L OUTPUT 2>/dev/null | grep -q MITMPROXY; then
        iptables -t nat -D OUTPUT -j MITMPROXY 2>/dev/null && _had_output=1
        iptables -t nat -D OUTPUT -m owner --uid-owner "$PROXY_USER" -j RETURN 2>/dev/null || true
    fi

    # --no-server exits after cert generation (mitmproxy >= 9).
    # Fallback: start in background, wait, kill — cert is written on first run.
    if ! timeout 20 "$MITMDUMP_BIN" --no-server --set confdir="$CERT_DIR" -q >/dev/null 2>&1; then
        warn "--no-server not supported — using background start method"
        "$MITMDUMP_BIN" --set confdir="$CERT_DIR" --listen-port "$PROXY_PORT" -q >/dev/null 2>&1 &
        _cpid=$!
        sleep 8
        kill "$_cpid" 2>/dev/null || true
        wait "$_cpid" 2>/dev/null || true
    fi

    # Restore OUTPUT hook
    if [ "$_had_output" = "1" ]; then
        if iptables -t nat -A OUTPUT -m owner --uid-owner "$PROXY_USER" -j RETURN 2>/dev/null; then :; fi
        iptables -t nat -A OUTPUT -j MITMPROXY 2>/dev/null || true
    fi
    log "Cert generation complete."
}

if [ ! -f "$CERT_DIR/mitmproxy-ca-cert.pem" ]; then
    gen_certs
fi

if [ -f "$CERT_DIR/mitmproxy-ca-cert.pem" ]; then
    # Export DER format for Android
    openssl x509 \
        -in  "$CERT_DIR/mitmproxy-ca-cert.pem" \
        -out "$CERT_DIR/mitmproxy-ca-cert.cer" \
        -outform DER 2>/dev/null || true
    log "CA cert (PEM) : $CERT_DIR/mitmproxy-ca-cert.pem"
    log "CA cert (DER) : $CERT_DIR/mitmproxy-ca-cert.cer"
else
    warn "CA cert not found — it will be auto-generated on first proxy startup."
fi

# =============================================================================
# 8. SERVICE / INIT SCRIPT
# =============================================================================
hdr "Installing service ($INIT_SYS)"

MITM_CMD_ARGS="--mode transparent --listen-port ${PROXY_PORT} --set confdir=${CERT_DIR} --set ssl_insecure=false --set connection_strategy=lazy -s ${INSTALL_DIR}/yt_ad_stripper.py"

install_service_systemd() {
    cat > /etc/systemd/system/mitm-adblock.service << EOF
[Unit]
Description=YouTube Ad Stripping Transparent Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${PROXY_USER}
ExecStart=${MITMDUMP_BIN} ${MITM_CMD_ARGS}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mitm-adblock

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable mitm-adblock
    systemctl restart mitm-adblock
    log "systemd service started."
    log "  Status : systemctl status mitm-adblock"
    log "  Logs   : journalctl -fu mitm-adblock"
}

install_service_openrc() {
    cat > /etc/init.d/mitm-adblock << EOF
#!/sbin/openrc-run
description="YouTube Ad Stripping Transparent Proxy"
command="${MITMDUMP_BIN}"
command_args="${MITM_CMD_ARGS}"
command_user="${PROXY_USER}"
pidfile="/run/mitm-adblock.pid"
command_background=true
depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/mitm-adblock
    rc-update add mitm-adblock default 2>/dev/null || true
    rc-service mitm-adblock restart
    log "OpenRC service started."
    log "  Status : rc-service mitm-adblock status"
    log "  Logs   : /var/log/mitm-adblock.log"
}

install_service_procd() {
    # OpenWrt procd init script
    cat > /etc/init.d/mitm-adblock << EOF
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1
PROG=${MITMDUMP_BIN}

start_service() {
    procd_open_instance
    procd_set_param command \$PROG ${MITM_CMD_ARGS}
    procd_set_param user ${PROXY_USER}
    procd_set_param respawn \${respawn_threshold:-3600} \${respawn_timeout:-5} \${respawn_retry:-5}
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
    chmod +x /etc/init.d/mitm-adblock
    /etc/init.d/mitm-adblock enable
    /etc/init.d/mitm-adblock restart
    log "procd service started."
    log "  Status : /etc/init.d/mitm-adblock status"
    log "  Logs   : logread -e mitm-adblock"
}

install_service_runit() {
    SV_DIR="/etc/sv/mitm-adblock"
    mkdir -p "$SV_DIR/log"
    cat > "$SV_DIR/run" << EOF
#!/bin/sh
exec chpst -u ${PROXY_USER} ${MITMDUMP_BIN} ${MITM_CMD_ARGS}
EOF
    cat > "$SV_DIR/log/run" << EOF
#!/bin/sh
exec svlogd -tt /var/log/mitm-adblock
EOF
    chmod +x "$SV_DIR/run" "$SV_DIR/log/run"
    mkdir -p /var/log/mitm-adblock
    # Link into the active service dir (varies: Void=/var/service, Artix=/run/runit/service)
    for _sdir in /var/service /service /run/runit/service; do
        if [ -d "$_sdir" ]; then
            ln -sf "$SV_DIR" "$_sdir/mitm-adblock" 2>/dev/null || true
            break
        fi
    done
    log "runit service installed at $SV_DIR"
    log "  Status : sv status mitm-adblock"
    log "  Logs   : tail -f /var/log/mitm-adblock/current"
}

install_service_s6() {
    S6_DIR="/etc/s6/sv/mitm-adblock"
    mkdir -p "$S6_DIR"
    cat > "$S6_DIR/run" << EOF
#!/bin/execlineb -P
s6-setuidgid ${PROXY_USER}
${MITMDUMP_BIN} ${MITM_CMD_ARGS}
EOF
    chmod +x "$S6_DIR/run"
    s6-db-reload 2>/dev/null || true
    log "s6 service installed at $S6_DIR"
}

install_service_sysvinit() {
    # LSB-compatible init.d script as universal fallback
    cat > /etc/init.d/mitm-adblock << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          mitm-adblock
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: YouTube Ad Stripping Transparent Proxy
### END INIT INFO
DAEMON=${MITMDUMP_BIN}
DAEMON_ARGS="${MITM_CMD_ARGS}"
PIDFILE=/var/run/mitm-adblock.pid
USER=${PROXY_USER}

case "\$1" in
    start)
        echo "Starting mitm-adblock..."
        start-stop-daemon --start --background --make-pidfile \\
            --pidfile "\$PIDFILE" --chuid "\$USER" \\
            --exec "\$DAEMON" -- \$DAEMON_ARGS
        ;;
    stop)
        echo "Stopping mitm-adblock..."
        start-stop-daemon --stop --pidfile "\$PIDFILE" --retry 10
        rm -f "\$PIDFILE"
        ;;
    restart|force-reload)
        \$0 stop && \$0 start
        ;;
    status)
        if [ -f "\$PIDFILE" ] && kill -0 "\$(cat "\$PIDFILE")" 2>/dev/null; then
            echo "mitm-adblock is running (pid \$(cat "\$PIDFILE"))"
        else
            echo "mitm-adblock is not running"
        fi
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
        ;;
esac
EOF
    chmod +x /etc/init.d/mitm-adblock
    if command -v update-rc.d  >/dev/null 2>&1; then update-rc.d mitm-adblock defaults; fi
    if command -v chkconfig    >/dev/null 2>&1; then chkconfig --add mitm-adblock; fi
    /etc/init.d/mitm-adblock restart
    log "sysvinit service installed."
    log "  Status : /etc/init.d/mitm-adblock status"
}

case "$INIT_SYS" in
    systemd)   install_service_systemd ;;
    openrc)    install_service_openrc  ;;
    procd)     install_service_procd   ;;
    runit)     install_service_runit   ;;
    s6)        install_service_s6      ;;
    sysvinit)  install_service_sysvinit ;;
esac

# =============================================================================
# DONE
# =============================================================================
printf '\n\033[1;32m'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '  Setup complete!\n'
printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
printf '\033[0m'
log "Certs dir : $CERT_DIR"
log "Script    : $INSTALL_DIR/yt_ad_stripper.py"
log "mitmdump  : $MITMDUMP_BIN"
printf '\n'
log "Next: run network_config.sh, then install the CA cert on"
log "each device.  See README.md for per-platform cert install."
