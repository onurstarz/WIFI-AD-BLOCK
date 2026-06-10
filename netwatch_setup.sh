#!/bin/sh
# =============================================================================
# WIFI-AD-BLOCK — NetWatch service installer
#
# Installs netwatch.py as a persistent system daemon across all init systems:
#   systemd / OpenRC / procd (OpenWrt) / runit / sysvinit
#
# netwatch handles:
#   • Network auto-detection (any interface, any subnet, any router)
#   • ARP spoofing — intercepts all device traffic without router changes
#   • Live reconfiguration when the box moves to a different network
#
# Called automatically by install.sh. Also safe to run standalone:
#   sudo sh netwatch_setup.sh
# =============================================================================
set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="/var/log/wifi-adblock-install.log"

log()  { printf '\033[1;32m[netwatch-setup]\033[0m %s\n' "$*" | tee -a "$LOG"; }
warn() { printf '\033[1;33m[warn]           \033[0m %s\n' "$*" | tee -a "$LOG"; }
die()  { printf '\033[1;31m[error]          \033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "Run as root: sudo sh $0"

mkdir -p "$(dirname "$LOG")"

# ── Install directory (matches setup.sh) ─────────────────────────────────────

INSTALL_DIR="/opt/mitm-proxy"
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR" 2>/dev/null || INSTALL_DIR="/usr/share/mitm-proxy"
    mkdir -p "$INSTALL_DIR"
fi
NETWATCH_DEST="$INSTALL_DIR/netwatch.py"

# ── Detect init system ───────────────────────────────────────────────────────

INIT_SYS="sysvinit"
[ -d /run/systemd/system ]            && INIT_SYS=systemd
command -v rc-service >/dev/null 2>&1 && INIT_SYS=openrc
[ -f /etc/openwrt_release ]           && INIT_SYS=procd
command -v sv >/dev/null 2>&1         && INIT_SYS=runit
log "Init system : $INIT_SYS"

# ── Locate Python 3.8+ ──────────────────────────────────────────────────────

PY3=""
for _py in python3 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
    if command -v "$_py" >/dev/null 2>&1; then
        if "$_py" -c \
            'import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)' \
            2>/dev/null; then
            PY3="$(command -v "$_py")"
            break
        fi
    fi
done
[ -z "$PY3" ] && die "Python 3.8+ not found. Run setup.sh first to install it."
log "Python     : $PY3"

# ── Enable IP forwarding (needed for traffic to pass through the box) ────────

if [ -f /proc/sys/net/ipv4/ip_forward ]; then
    printf '1\n' > /proc/sys/net/ipv4/ip_forward
fi
# Persist across reboots
_SYSCTL_CONF="/etc/sysctl.d/99-wifi-adblock.conf"
if [ -d /etc/sysctl.d ]; then
    if ! grep -q 'ip_forward' "$_SYSCTL_CONF" 2>/dev/null; then
        printf 'net.ipv4.ip_forward = 1\n' >> "$_SYSCTL_CONF"
    fi
elif [ -f /etc/sysctl.conf ]; then
    if ! grep -q 'ip_forward' /etc/sysctl.conf; then
        printf 'net.ipv4.ip_forward = 1\n' >> /etc/sysctl.conf
    fi
fi

# ── Copy netwatch.py to install dir ─────────────────────────────────────────

cp "$REPO_DIR/netwatch.py" "$NETWATCH_DEST"
chmod 755 "$NETWATCH_DEST"
log "Installed  : $NETWATCH_DEST"

# ── Install and enable the service ──────────────────────────────────────────

SVC_NAME="wifi-adblock-netwatch"

case "$INIT_SYS" in

# ─── systemd ─────────────────────────────────────────────────────────────────
    systemd)
        cat > /etc/systemd/system/${SVC_NAME}.service << EOF
[Unit]
Description=WiFi AdBlock — Network Monitor + ARP Intercept
Documentation=https://github.com/onurstarz/wifi-ad-block
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PY3} ${NETWATCH_DEST}
Restart=always
RestartSec=10
KillSignal=SIGTERM
TimeoutStopSec=30
StandardOutput=append:/var/log/wifi-adblock-netwatch.log
StandardError=append:/var/log/wifi-adblock-netwatch.log

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$SVC_NAME"
        systemctl restart "$SVC_NAME"
        log "systemd: $SVC_NAME enabled + started."
        ;;

# ─── OpenRC ──────────────────────────────────────────────────────────────────
    openrc)
        cat > /etc/init.d/${SVC_NAME} << EOF
#!/sbin/openrc-run
description="WiFi AdBlock — Network Monitor + ARP Intercept"
command="${PY3}"
command_args="${NETWATCH_DEST}"
pidfile="/run/${SVC_NAME}.pid"
command_background=yes
output_log="/var/log/wifi-adblock-netwatch.log"
error_log="/var/log/wifi-adblock-netwatch.log"

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/${SVC_NAME}
        rc-update add "$SVC_NAME" default
        rc-service "$SVC_NAME" restart
        log "OpenRC: $SVC_NAME enabled + started."
        ;;

# ─── procd (OpenWrt) ─────────────────────────────────────────────────────────
    procd)
        cat > /etc/init.d/${SVC_NAME} << EOF
#!/bin/sh /etc/rc.common
# WiFi AdBlock NetWatch — procd service
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command ${PY3} ${NETWATCH_DEST}
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
        chmod +x /etc/init.d/${SVC_NAME}
        /etc/init.d/${SVC_NAME} enable
        /etc/init.d/${SVC_NAME} restart
        log "procd: $SVC_NAME enabled + started."
        ;;

# ─── runit (Void Linux, Alpine, etc.) ────────────────────────────────────────
    runit)
        SV_DIR="/etc/runit/sv/${SVC_NAME}"
        mkdir -p "${SV_DIR}/log"
        mkdir -p /var/log/wifi-adblock-netwatch

        printf '#!/bin/sh\nexec %s %s 2>&1\n' "$PY3" "$NETWATCH_DEST" \
            > "${SV_DIR}/run"
        chmod +x "${SV_DIR}/run"

        printf '#!/bin/sh\nexec svlogd -tt /var/log/wifi-adblock-netwatch\n' \
            > "${SV_DIR}/log/run"
        chmod +x "${SV_DIR}/log/run"

        # Link into the active services directory (varies by distro)
        _LINKED=0
        for _d in /var/service /service /run/runit/service; do
            if [ -d "$_d" ]; then
                ln -sf "$SV_DIR" "${_d}/${SVC_NAME}" 2>/dev/null || true
                _LINKED=1
                break
            fi
        done
        if [ "$_LINKED" = "0" ]; then
            warn "runit service directory not found — start manually: sv up $SVC_NAME"
        else
            sv up "$SVC_NAME" 2>/dev/null || true
            log "runit: $SVC_NAME created + started."
        fi
        ;;

# ─── sysvinit / generic ───────────────────────────────────────────────────────
    *)
        cat > /etc/init.d/${SVC_NAME} << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          ${SVC_NAME}
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: WiFi AdBlock Network Monitor
### END INIT INFO

PIDFILE="/var/run/${SVC_NAME}.pid"
LOGFILE="/var/log/wifi-adblock-netwatch.log"
DAEMON="${PY3}"
DAEMON_ARGS="${NETWATCH_DEST}"

case "\$1" in
    start)
        printf 'Starting ${SVC_NAME}... '
        \${DAEMON} \${DAEMON_ARGS} >> "\${LOGFILE}" 2>&1 &
        printf '%s\n' "\$!" > "\${PIDFILE}"
        printf 'done.\n'
        ;;
    stop)
        printf 'Stopping ${SVC_NAME}... '
        if [ -f "\${PIDFILE}" ]; then
            kill "\$(cat "\${PIDFILE}")" 2>/dev/null || true
            rm -f "\${PIDFILE}"
        fi
        pkill -f "netwatch.py" 2>/dev/null || true
        printf 'done.\n'
        ;;
    restart)
        \$0 stop
        \$0 start
        ;;
    status)
        if [ -f "\${PIDFILE}" ] && kill -0 "\$(cat "\${PIDFILE}")" 2>/dev/null; then
            printf '${SVC_NAME} is running (pid %s)\n' "\$(cat "\${PIDFILE}")"
        else
            printf '${SVC_NAME} is not running\n'
            exit 1
        fi
        ;;
    *)
        printf 'Usage: %s {start|stop|restart|status}\n' "\$0" >&2
        exit 1
        ;;
esac
EOF
        chmod +x /etc/init.d/${SVC_NAME}

        # Register with init system if tools are available
        if command -v update-rc.d >/dev/null 2>&1; then
            update-rc.d "$SVC_NAME" defaults
        elif command -v chkconfig >/dev/null 2>&1; then
            chkconfig --add "$SVC_NAME"
        fi

        /etc/init.d/${SVC_NAME} start
        log "sysvinit: $SVC_NAME installed + started."
        ;;
esac

# ── Verify the daemon is alive ───────────────────────────────────────────────

sleep 3
_ALIVE=0
case "$INIT_SYS" in
    systemd) systemctl is-active --quiet "$SVC_NAME" 2>/dev/null && _ALIVE=1 ;;
    openrc)  rc-service "$SVC_NAME" status >/dev/null 2>&1       && _ALIVE=1 ;;
    procd)   /etc/init.d/"$SVC_NAME" status >/dev/null 2>&1      && _ALIVE=1 ;;
    runit)   sv status "$SVC_NAME" 2>/dev/null | grep -q '^run:' && _ALIVE=1 ;;
    *)       pgrep -f "netwatch.py" >/dev/null 2>&1               && _ALIVE=1 ;;
esac

if [ "$_ALIVE" = "1" ]; then
    log "netwatch is running — ARP intercept active."
else
    warn "netwatch did not start cleanly."
    warn "Check: /var/log/wifi-adblock-netwatch.log"
    warn "Manual start: $PY3 $NETWATCH_DEST"
fi
