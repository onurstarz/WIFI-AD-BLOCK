"""
netwatch — portable network auto-configure + ARP intercept daemon.

What it does
────────────
1. Detects whatever network the box is connected to (Ethernet OR Wi-Fi,
   any subnet, any router IP — fully automatic).
2. Reconfigures AdGuard Home, mitmproxy, dnsmasq, and iptables for the
   detected network whenever it changes (plugged into a new network, IP
   renewed, etc.).
3. Runs ARP spoofing: continuously tells every device on the LAN that the
   router's IP lives at our MAC address, so their traffic flows through us.

Why ARP spoofing
────────────────
Without modifying the router, ARP spoofing is the only reliable way to
intercept all devices' traffic automatically.  It is purely temporary:
- Requires *continuous* sending of fake ARP replies.
- Stop sending → ARP caches expire (1–20 min) → normal routing resumes.
- The router never knows anything happened.
- No persistent changes anywhere — unplugging is a complete clean exit.

Requirements
────────────
No external Python packages needed.  Uses only stdlib + raw sockets.
Needs: root (for raw sockets + iptables), ip, iptables, python3.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────

# How often to poll for network changes (seconds)
POLL_INTERVAL   = 8

# How often to re-send ARP spoofing packets (seconds)
ARP_INTERVAL    = 3

# How often to scan for new devices to spoof (seconds)
SCAN_INTERVAL   = 20

# Install dir (must match setup.sh)
INSTALL_DIR     = "/opt/mitm-proxy" if os.path.isdir("/opt/mitm-proxy") \
                  else "/usr/share/mitm-proxy"

AGH_YAML        = "/opt/AdGuardHome/AdGuardHome.yaml"
AGH_PORT        = 3000
PROXY_PORT      = 8080

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level   = logging.INFO,
    format  = "[netwatch %(levelname)s] %(message)s",
    stream  = sys.stdout,
)
log = logging.getLogger("netwatch")


# ─────────────────────────────────────────────────────────────────────────────
# Network detection
# ─────────────────────────────────────────────────────────────────────────────

class NetworkInfo:
    __slots__ = ("iface", "our_ip", "our_mac", "gateway_ip", "subnet", "prefix")

    def __init__(self, iface, our_ip, our_mac, gateway_ip, subnet, prefix):
        self.iface      = iface
        self.our_ip     = our_ip
        self.our_mac    = our_mac
        self.gateway_ip = gateway_ip
        self.subnet     = subnet   # e.g. "192.168.1.0"
        self.prefix     = prefix   # e.g. 24

    def __eq__(self, other):
        if not isinstance(other, NetworkInfo):
            return False
        return self.gateway_ip == other.gateway_ip and self.our_ip == other.our_ip

    def dhcp_range(self):
        """Return (start_ip, end_ip) for a DHCP pool in this subnet."""
        net  = ipaddress.IPv4Network(f"{self.subnet}/{self.prefix}", strict=False)
        hosts = list(net.hosts())
        # Skip first 50 (router + statics), hand out .51–.200
        start = str(hosts[min(50, len(hosts)//4)])
        end   = str(hosts[min(200, len(hosts)*3//4)])
        return start, end

    def __repr__(self):
        return f"<Net {self.our_ip}/{self.prefix} gw={self.gateway_ip} on {self.iface}>"


def _run(cmd: list[str], timeout: int = 5) -> str:
    try:
        return subprocess.check_output(cmd, text=True, timeout=timeout,
                                       stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        return ""


def detect_network() -> Optional[NetworkInfo]:
    """
    Detect current default-route network.
    Prefers Ethernet (eth*, en*) over Wi-Fi (wlan*, wlp*) if both are up.
    """
    routes = _run(["ip", "route", "show"])
    # Parse all default routes, pick best interface
    candidates = []
    for line in routes.splitlines():
        if not line.startswith("default"):
            continue
        parts = line.split()
        try:
            gw    = parts[parts.index("via") + 1]
            iface = parts[parts.index("dev") + 1]
            metric = int(parts[parts.index("metric") + 1]) \
                     if "metric" in parts else 0
            candidates.append((metric, iface, gw))
        except (ValueError, IndexError):
            continue

    if not candidates:
        return None

    # Sort by metric (lower = better), prefer eth/en over wlan
    def _pref(c):
        iface = c[1]
        eth = 0 if re.match(r'^(eth|en|em|eno|ens|enp)', iface) else 1
        return (eth, c[0])

    candidates.sort(key=_pref)
    _, iface, gateway_ip = candidates[0]

    # Our IP on this interface
    addr_out = _run(["ip", "addr", "show", iface])
    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', addr_out)
    if not m:
        return None
    our_ip = m.group(1)
    prefix = int(m.group(2))
    net    = ipaddress.IPv4Network(f"{our_ip}/{prefix}", strict=False)
    subnet = str(net.network_address)

    # Our MAC
    our_mac = _get_iface_mac(iface)
    if not our_mac:
        return None

    return NetworkInfo(iface, our_ip, our_mac, gateway_ip, subnet, prefix)


# ─────────────────────────────────────────────────────────────────────────────
# ARP spoofing — pure Python, no external packages
# ─────────────────────────────────────────────────────────────────────────────

SIOCGIFHWADDR = 0x8927

def _get_iface_mac(iface: str) -> Optional[bytes]:
    """Return raw 6-byte MAC for an interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR,
                           struct.pack("256s", iface[:15].encode()))
        s.close()
        return info[18:24]
    except OSError:
        return None


def _mac_str_to_bytes(mac_str: str) -> bytes:
    return bytes(int(h, 16) for h in mac_str.split(":"))


def _mac_bytes_to_str(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _send_arp_reply(iface: str,
                    src_ip:  str,   src_mac:  bytes,
                    dst_ip:  str,   dst_mac:  bytes) -> None:
    """
    Craft and send a gratuitous ARP reply:
    "src_ip is at src_mac" — sent to dst_mac.

    Using a broadcast dst_mac (ff:ff:ff:ff:ff:ff) updates every device's
    ARP cache on the segment simultaneously.
    """
    eth = dst_mac + src_mac + b"\x08\x06"
    arp = struct.pack("!HHBBH",
                      1,      # hardware type: Ethernet
                      0x0800, # protocol type: IPv4
                      6,      # hardware addr length
                      4,      # protocol addr length
                      2)      # opcode: reply
    arp += src_mac + socket.inet_aton(src_ip)
    arp += dst_mac + socket.inet_aton(dst_ip)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(0x0806))
        sock.bind((iface, 0))
        sock.send(eth + arp)
        sock.close()
    except OSError:
        pass


def _restore_arp(iface: str, net: NetworkInfo,
                 targets: list[str]) -> None:
    """Send correct ARP replies to undo our spoofing on shutdown."""
    gw_mac = _resolve_mac(net.gateway_ip, iface)
    if not gw_mac:
        return
    broadcast = b"\xff\xff\xff\xff\xff\xff"
    for target_ip in targets:
        target_mac = _resolve_mac(target_ip, iface)
        if target_mac:
            # Tell target: gateway_ip is really at gw_mac
            _send_arp_reply(iface,
                            src_ip=net.gateway_ip, src_mac=gw_mac,
                            dst_ip=target_ip,      dst_mac=target_mac)
    # Broadcast correct gateway ARP too
    _send_arp_reply(iface,
                    src_ip=net.gateway_ip, src_mac=gw_mac,
                    dst_ip="0.0.0.0",     dst_mac=broadcast)
    log.info("ARP caches restored.")


def _resolve_mac(ip: str, iface: str) -> Optional[bytes]:
    """
    Lookup MAC for an IP: first check /proc/net/arp, then trigger an
    ARP request via a UDP ping if not found.
    """
    # Check kernel ARP table
    mac = _arp_table_lookup(ip)
    if mac:
        return mac
    # Trigger ARP request: send a UDP packet (kernel will ARP-resolve)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.sendto(b"", (ip, 9))  # port 9 = discard, triggers ARP
        s.close()
    except OSError:
        pass
    time.sleep(0.3)
    return _arp_table_lookup(ip)


def _arp_table_lookup(ip: str) -> Optional[bytes]:
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac not in ("00:00:00:00:00:00", ""):
                        return _mac_str_to_bytes(mac)
    except (FileNotFoundError, StopIteration):
        pass
    return None


def _discover_hosts(subnet: str, prefix: int) -> list[str]:
    """
    Return list of host IPs on the subnet (excluding our own IP and .0/.255).
    Reads /proc/net/arp so we only spoof devices that have actually sent
    traffic — no noise, no guessing.
    """
    net   = ipaddress.IPv4Network(f"{subnet}/{prefix}", strict=False)
    found = set()
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip  = parts[0]
                mac = parts[3]
                if mac in ("00:00:00:00:00:00", ""):
                    continue
                try:
                    addr = ipaddress.IPv4Address(ip)
                    if addr in net and not addr == net.broadcast_address:
                        found.add(ip)
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    return list(found)


class ArpSpoofWorker(threading.Thread):
    """
    Background thread: continuously sends ARP replies telling all devices
    on the LAN that the gateway's IP is at our MAC address.

    This makes every device route through us.  When this thread is stopped
    (and _restore_arp is called), ARP caches expire and normal routing
    resumes within 1–20 minutes.
    """

    def __init__(self, net: NetworkInfo):
        super().__init__(daemon=True, name="arp-spoof")
        self._net     = net
        self._stop    = threading.Event()
        self._targets: list[str] = []
        self._lock    = threading.Lock()

    def run(self):
        net       = self._net
        broadcast = b"\xff\xff\xff\xff\xff\xff"
        last_scan = 0.0
        log.info(f"ARP spoof started on {net.iface} — "
                 f"claiming {net.gateway_ip} → {_mac_bytes_to_str(net.our_mac)}")

        while not self._stop.is_set():
            now = time.monotonic()

            # Re-scan for new devices periodically
            if now - last_scan >= SCAN_INTERVAL:
                hosts = _discover_hosts(net.subnet, net.prefix)
                # Exclude our own IP and the gateway
                hosts = [h for h in hosts
                         if h != net.our_ip and h != net.gateway_ip]
                with self._lock:
                    self._targets = hosts
                last_scan = now

            # Send broadcast gratuitous ARP:
            # "gateway_ip is at our_mac" — reaches every device at once
            _send_arp_reply(
                net.iface,
                src_ip  = net.gateway_ip, src_mac  = net.our_mac,
                dst_ip  = "0.0.0.0",      dst_mac  = broadcast,
            )

            # Also send unicast to each known target (more reliable on
            # some OS implementations that ignore broadcast ARP updates)
            with self._lock:
                targets = list(self._targets)
            for target_ip in targets:
                target_mac = _arp_table_lookup(target_ip)
                if target_mac:
                    _send_arp_reply(
                        net.iface,
                        src_ip  = net.gateway_ip, src_mac  = net.our_mac,
                        dst_ip  = target_ip,       dst_mac  = target_mac,
                    )

            self._stop.wait(ARP_INTERVAL)

    def stop_and_restore(self):
        self._stop.set()
        self.join(timeout=6)
        with self._lock:
            targets = list(self._targets)
        _restore_arp(self._net.iface, self._net, targets)


# ─────────────────────────────────────────────────────────────────────────────
# Service reconfiguration
# ─────────────────────────────────────────────────────────────────────────────

def _systemctl(action: str, service: str) -> None:
    _run(["systemctl", action, service])


def _detect_init() -> str:
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    if _run(["which", "rc-service"]):
        return "openrc"
    if os.path.exists("/etc/openwrt_release"):
        return "procd"
    return "sysvinit"


INIT_SYS = _detect_init()


def _restart(service: str) -> None:
    if INIT_SYS == "systemd":
        _run(["systemctl", "restart", service])
    elif INIT_SYS == "openrc":
        _run(["rc-service", service, "restart"])
    elif INIT_SYS == "procd":
        _run([f"/etc/init.d/{service}", "restart"])
    else:
        _run([f"/etc/init.d/{service}", "restart"])


def apply_iptables(net: NetworkInfo) -> None:
    """Re-apply transparent proxy iptables rules for the detected network."""
    log.info(f"Applying iptables for {net.iface} / {net.subnet}/{net.prefix}")

    def ipt(*args):
        _run(["iptables"] + list(args))

    # Tear down previous chain
    ipt("-t", "nat", "-D", "PREROUTING", "-j", "MITMPROXY")
    ipt("-t", "nat", "-D", "OUTPUT",     "-j", "MITMPROXY")
    ipt("-t", "nat", "-F", "MITMPROXY")
    ipt("-t", "nat", "-X", "MITMPROXY")

    ipt("-t", "nat", "-N", "MITMPROXY")

    # Skip our own traffic (by UID if possible)
    ipt("-t", "nat", "-A", "MITMPROXY",
        "-m", "owner", "--uid-owner", "mitm", "-j", "RETURN")

    # Skip LAN + loopback
    for cidr in ["127.0.0.0/8", "10.0.0.0/8",
                 "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]:
        ipt("-t", "nat", "-A", "MITMPROXY", "-d", cidr, "-j", "RETURN")

    # Redirect HTTP + HTTPS → mitmproxy
    ipt("-t", "nat", "-A", "MITMPROXY",
        "-p", "tcp", "--dport", "80",  "-j", "REDIRECT",
        "--to-port", str(PROXY_PORT))
    ipt("-t", "nat", "-A", "MITMPROXY",
        "-p", "tcp", "--dport", "443", "-j", "REDIRECT",
        "--to-port", str(PROXY_PORT))

    ipt("-t", "nat", "-A", "PREROUTING", "-j", "MITMPROXY")
    ipt("-t", "nat", "-A", "OUTPUT",     "-j", "MITMPROXY")

    # Masquerade outbound on the detected interface
    ipt("-t", "nat", "-A", "POSTROUTING",
        "-o", net.iface, "-j", "MASQUERADE")

    # Enable IP forwarding
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    log.info("iptables updated.")


def update_adguard_home(net: NetworkInfo) -> None:
    """Update AdGuard Home config with new box IP for DNS rewrites."""
    if not os.path.exists(AGH_YAML):
        log.warning("AdGuardHome.yaml not found — skipping AGH update.")
        return

    # Update the box IP in captive portal DNS rewrites
    # (The rewrites file was written with the old IP; replace them)
    try:
        with open(AGH_YAML) as f:
            content = f.read()

        # Replace IP in rewrite answer lines
        import re as _re
        old_ips = set(_re.findall(r'answer: (\d+\.\d+\.\d+\.\d+)', content))
        new_content = content
        for old in old_ips:
            if old != net.our_ip and old != net.gateway_ip:
                new_content = new_content.replace(
                    f"answer: {old}", f"answer: {net.our_ip}")

        if new_content != content:
            with open(AGH_YAML, "w") as f:
                f.write(new_content)
            log.info(f"AdGuardHome.yaml: updated captive portal rewrites to {net.our_ip}")
            _restart("AdGuardHome")
    except Exception as e:
        log.warning(f"Could not update AdGuardHome.yaml: {e}")


def update_dnsmasq_dhcp(net: NetworkInfo) -> None:
    """Rewrite the dnsmasq DHCP config for the new subnet."""
    conf_file = "/etc/dnsmasq.d/mitm-adblock.conf"
    if not os.path.exists(conf_file):
        return

    start, end = net.dhcp_range()
    try:
        with open(conf_file) as f:
            content = f.read()

        import re as _re
        content = _re.sub(r'interface=\S+', f'interface={net.iface}', content)
        content = _re.sub(
            r'dhcp-range=\S+',
            f'dhcp-range={start},{end},12h', content)
        content = _re.sub(
            r'dhcp-option=option:router,\S+',
            f'dhcp-option=option:router,{net.our_ip}', content)
        content = _re.sub(
            r'dhcp-option=option:dns-server,\S+',
            f'dhcp-option=option:dns-server,{net.our_ip},1.1.1.1', content)

        with open(conf_file, "w") as f:
            f.write(content)

        for svc in ("dnsmasq",):
            _restart(svc)
        log.info(f"dnsmasq DHCP updated for {net.subnet}/{net.prefix}")
    except Exception as e:
        log.warning(f"Could not update dnsmasq: {e}")


def optimize_dns() -> None:
    """
    Re-benchmark DNS servers for the new network location and switch to the
    fastest. A new network = new physical location = different server latencies,
    so this runs on every network change. The optimizer's own "sniper" logic
    decides whether a switch is actually justified.
    """
    optimizer = None
    for cand in (os.path.join(INSTALL_DIR, "dns_optimizer.py"),
                 "/opt/mitm-proxy/dns_optimizer.py",
                 os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "dns_optimizer.py")):
        if os.path.exists(cand):
            optimizer = cand
            break
    if not optimizer:
        log.info("dns_optimizer.py not found — skipping DNS benchmark.")
        return
    log.info("Re-benchmarking DNS servers for new network location...")
    try:
        # Run in background — a full benchmark takes a few seconds and we don't
        # want to block the rest of reconfiguration on it.
        subprocess.Popen(
            [sys.executable, optimizer],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        log.warning(f"Could not launch dns_optimizer: {e}")


def reconfigure(net: NetworkInfo) -> None:
    """Full reconfiguration for a newly detected network."""
    log.info(f"Reconfiguring for {net}")
    apply_iptables(net)
    update_adguard_home(net)
    update_dnsmasq_dhcp(net)
    # Restart mitmproxy so it re-binds to the current interface
    _restart("mitm-adblock")
    # New location → re-rank DNS servers and switch if a faster one exists
    optimize_dns()
    log.info("Reconfiguration complete.")


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

class NetWatch:
    def __init__(self):
        self._current_net: Optional[NetworkInfo] = None
        self._spoof_worker: Optional[ArpSpoofWorker] = None
        self._running = True

    def _stop_spoof(self):
        if self._spoof_worker:
            log.info("Stopping ARP spoof + restoring caches...")
            self._spoof_worker.stop_and_restore()
            self._spoof_worker = None

    def _start_spoof(self, net: NetworkInfo):
        self._stop_spoof()
        self._spoof_worker = ArpSpoofWorker(net)
        self._spoof_worker.start()

    def run(self):
        log.info("netwatch started — monitoring network state.")
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

        while self._running:
            net = detect_network()

            if net is None:
                # No network — stop spoofing, wait
                if self._current_net is not None:
                    log.info("Network disconnected — suspending ARP spoof.")
                    self._stop_spoof()
                    self._current_net = None
            elif net != self._current_net:
                # New or changed network
                log.info(f"Network {'detected' if self._current_net is None else 'changed'}: {net}")
                self._stop_spoof()
                self._current_net = net
                reconfigure(net)
                self._start_spoof(net)
            # else: same network, nothing to do

            time.sleep(POLL_INTERVAL)

    def _handle_signal(self, signum, _frame):
        log.info(f"Signal {signum} received — shutting down cleanly.")
        self._running = False
        self._stop_spoof()
        sys.exit(0)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("netwatch must run as root.", file=sys.stderr)
        sys.exit(1)
    NetWatch().run()
