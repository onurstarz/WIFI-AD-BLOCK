#!/usr/bin/env python3
"""
WIFI-AD-BLOCK — Visual simulation
Animates 10 real-world scenarios through each protection layer.

Usage:
  python3 simulate.py           normal speed (recommended)
  python3 simulate.py --fast    instant, no delays
"""
from __future__ import annotations
import os, sys, time, shutil

FAST = "--fast" in sys.argv
W    = min(shutil.get_terminal_size((88, 24)).columns, 92)

# ── ANSI ──────────────────────────────────────────────────────────────────────
RST = "\033[0m";  BLD = "\033[1m";  DIM = "\033[2m"
RED = "\033[1;31m"; GRN = "\033[1;32m"; YLW = "\033[1;33m"
BLU = "\033[1;34m"; MAG = "\033[1;35m"; CYN = "\033[1;36m"; WHT = "\033[1;37m"

def c(col, txt):  return f"{col}{txt}{RST}"
def clr():        os.system("clear" if os.name != "nt" else "cls")
def hr(ch="─"):   print(c(DIM, ch * W))
def sl(n):        time.sleep(0.0 if FAST else n)

def type_out(text, color=WHT, char_delay=0.009):
    """Print text character by character (typewriter effect)."""
    if FAST:
        sys.stdout.write(color + text + RST + "\n")
        sys.stdout.flush()
        return
    sys.stdout.write(color)
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        sl(char_delay)
    sys.stdout.write(RST + "\n")


# ── Scenario definitions ─────────────────────────────────────────────────────

SCENARIOS = [

    {
        "n": 1,
        "title": "Ad network DNS query — sinkholed before it leaves your network",
        "device": "iPhone 14",
        "ip":     "192.168.1.5",
        "proto":  "DNS",
        "dest":   "pagead2.googlesyndication.com",
        "steps": [
            (YLW, "AdGuard Home  (port 53)", "DNS query received from 192.168.1.5"),
            (DIM, "Blocklist check         ", "EasyList · 843,200 entries · searching..."),
            (RED, "AdGuard Home            ", "MATCH — ad domain in blocklist"),
            (RED, "AdGuard Home            ", "replying with 0.0.0.0 (sinkhole)"),
            (DIM, "Device                  ", "got NXDOMAIN — app makes no HTTP request"),
        ],
        "result": (RED,  "BLOCKED",      "ad domain sinkholed — network never contacted"),
        "stat":   "dns_blocked",
    },

    {
        "n": 2,
        "title": "YouTube video request — ad payload stripped from encrypted stream",
        "device": "MacBook Pro",
        "ip":     "192.168.1.6",
        "proto":  "HTTPS",
        "dest":   "youtubei.googleapis.com  /youtubei/v1/player",
        "steps": [
            (DIM, "AdGuard Home            ", "DNS: youtubei.googleapis.com → 142.250.80.14  (allowed)"),
            (DIM, "iptables NAT            ", "PREROUTING: TCP :443 → REDIRECT to :8080"),
            (CYN, "mitmproxy               ", "TLS intercept — CA cert trusted by device"),
            (DIM, "mitmproxy               ", "decrypting response body (1.2 MB JSON)..."),
            (YLW, "yt_ad_stripper          ", "target path matched — scanning ad keys..."),
            (RED, "yt_ad_stripper          ", "found: playerAds, adPlacements, adSlots, instreamVideoAdRenderer"),
            (GRN, "yt_ad_stripper          ", "stripped 4 ad keys — body 1.2 MB → 294 KB"),
            (CYN, "mitmproxy               ", "re-encrypting + forwarding clean response"),
        ],
        "result": (GRN,  "ADS STRIPPED",  "video plays — zero ad payloads delivered to device"),
        "stat":   "ads_stripped",
    },

    {
        "n": 3,
        "title": "Malware download — intercepted by ClamAV before reaching the device",
        "device": "MacBook Pro",
        "ip":     "192.168.1.6",
        "proto":  "HTTP",
        "dest":   "downloads.freeware-hub.net  /setup_installer.exe",
        "steps": [
            (DIM, "iptables NAT            ", "PREROUTING: TCP :80 → REDIRECT to :8080"),
            (CYN, "mitmproxy               ", "HTTP response intercepted"),
            (YLW, "malware_scanner         ", "Content-Type: application/octet-stream"),
            (YLW, "malware_scanner         ", "extension .exe matches RISKY_EXTENSIONS — scanning"),
            (DIM, "ClamAV clamd            ", "streaming 2.4 MB to unix socket /run/clamav/clamd.ctl"),
            (RED, "ClamAV clamd            ", "FOUND: Win.Trojan.GenericKD-12345"),
            (RED, "malware_scanner         ", "replacing response with 403 block page"),
        ],
        "result": (RED,  "BLOCKED",       "device sees: 'Download blocked — Win.Trojan.GenericKD-12345'"),
        "stat":   "malware_blocked",
    },

    {
        "n": 4,
        "title": "New device joins WiFi — ARP intercept + captive portal shown",
        "device": "Guest Phone",
        "ip":     "192.168.1.12  (new)",
        "proto":  "ARP + HTTP",
        "dest":   "connectivitycheck.gstatic.com  /generate_204  (Android OS probe)",
        "steps": [
            (MAG, "netwatch                ", "new ARP entry: 192.168.1.12 / MAC aa:bb:cc:dd:ee:ff"),
            (MAG, "ArpSpoofWorker          ", "sending: 'ARP reply: 192.168.1.1 is at OUR MAC'"),
            (MAG, "ArpSpoofWorker          ", "broadcast to ff:ff:ff:ff:ff:ff + unicast to device"),
            (DIM, "Device ARP cache        ", "updated: 192.168.1.1 → [our MAC]  ← all traffic now flows through us"),
            (DIM, "Android OS probe        ", "GET connectivitycheck.gstatic.com/generate_204"),
            (YLW, "AdGuard DNS rewrite     ", "connectivitycheck.gstatic.com → 192.168.1.2 (us)"),
            (CYN, "portal_server (port 80) ", "captive portal triggered — first visit for this MAC"),
            (CYN, "portal_server           ", "serving welcome page: DNS protection + CA cert install"),
        ],
        "result": (CYN,  "PORTAL SHOWN",  "phone browser opens welcome page automatically"),
        "stat":   "portals_shown",
    },

    {
        "n": 5,
        "title": "Phishing site — blocked by Safe Browsing before the page loads",
        "device": "iPhone 14",
        "ip":     "192.168.1.5",
        "proto":  "DNS",
        "dest":   "secure-paypal-login-verify.ru",
        "steps": [
            (YLW, "AdGuard Home            ", "DNS query: secure-paypal-login-verify.ru"),
            (DIM, "Blocklist check         ", "no match in ad/tracker lists"),
            (YLW, "Safe Browsing           ", "checking threat intelligence feed..."),
            (RED, "Safe Browsing           ", "MATCH: phishing / credential harvesting"),
            (RED, "AdGuard Home            ", "blocked — returning 0.0.0.0"),
        ],
        "result": (RED,  "BLOCKED",       "phishing page never loads — DNS returns nothing"),
        "stat":   "dns_blocked",
    },

    {
        "n": 6,
        "title": "Roblox (banned in Turkey) — silently routed through WireGuard tunnel",
        "device": "PS5",
        "ip":     "192.168.1.8",
        "proto":  "TCP",
        "dest":   "128.116.0.1  (Roblox game server)",
        "steps": [
            (DIM, "iptables mangle         ", "PREROUTING: dest 128.116.0.0/16 matches Roblox range"),
            (BLU, "iptables mangle         ", "SET fwmark 0xdead on packet"),
            (BLU, "ip rule                 ", "fwmark 0xdead → lookup RT_TABLE 200"),
            (BLU, "ip route table 200      ", "default via wg-bypass tunnel"),
            (MAG, "WireGuard wg-bypass     ", "packet encrypted, sent to VPN peer"),
            (GRN, "VPN peer (non-TR exit)  ", "packet exits — Roblox sees foreign IP, allows connection"),
            (DIM, "ISP (Turkey)            ", "sees only: encrypted WireGuard UDP to peer endpoint"),
        ],
        "result": (BLU,  "TUNNELED",      "Roblox connects at full speed — ban bypassed invisibly"),
        "stat":   "tunneled",
    },

    {
        "n": 7,
        "title": "Mobile game ad SDK — DNS killed, ad never loads",
        "device": "Android Tab",
        "ip":     "192.168.1.9",
        "proto":  "DNS",
        "dest":   "sdk.mintegral.com",
        "steps": [
            (YLW, "AdGuard Home            ", "DNS query: sdk.mintegral.com"),
            (DIM, "Blocklist check         ", "AdGuard Mobile Ads filter — match found"),
            (RED, "AdGuard Home            ", "SINKHOLE: 0.0.0.0"),
            (DIM, "Mobile game             ", "SDK gets no response — silent fail, no ad rendered"),
        ],
        "result": (RED,  "BLOCKED",       "in-app ad SDK silenced — game continues ad-free"),
        "stat":   "dns_blocked",
    },

    {
        "n": 8,
        "title": "Normal HTTPS browsing — passes through every layer untouched",
        "device": "MacBook Pro",
        "ip":     "192.168.1.6",
        "proto":  "HTTPS",
        "dest":   "github.com  /torvalds/linux",
        "steps": [
            (DIM, "AdGuard Home            ", "DNS: github.com → 140.82.112.3  (not blocked)"),
            (DIM, "iptables NAT            ", "REDIRECT :443 → :8080"),
            (CYN, "mitmproxy               ", "TLS intercept — checking host"),
            (DIM, "yt_ad_stripper          ", "host not in TARGET_PATHS — skip"),
            (DIM, "malware_scanner         ", "Content-Type: text/html — not a download, skip"),
            (GRN, "mitmproxy               ", "forwarding response unmodified"),
        ],
        "result": (GRN,  "PASS",          "page loads normally — no modification, full speed"),
        "stat":   "passed",
    },

    {
        "n": 9,
        "title": "Legitimate .iso download — scanned and cleared by ClamAV",
        "device": "MacBook Pro",
        "ip":     "192.168.1.6",
        "proto":  "HTTPS",
        "dest":   "releases.ubuntu.com  /ubuntu-24.04-desktop-amd64.iso",
        "steps": [
            (CYN, "mitmproxy               ", "response intercepted"),
            (YLW, "malware_scanner         ", "Content-Type: application/octet-stream — .iso extension"),
            (YLW, "malware_scanner         ", "file in RISKY_EXTENSIONS — streaming to ClamAV (25 MB cap)"),
            (DIM, "ClamAV clamd            ", "scanning 25.0 MB chunk via unix socket..."),
            (GRN, "ClamAV clamd            ", "OK — no threats found"),
            (GRN, "mitmproxy               ", "forwarding full response to device"),
        ],
        "result": (GRN,  "CLEAN",         "download proceeds — file is legitimate"),
        "stat":   "passed",
    },

    {
        "n": 10,
        "title": "Box moved to a new network — everything reconfigures automatically",
        "device": "The box itself",
        "ip":     "10.0.0.5  (new network)",
        "proto":  "SYSTEM EVENT",
        "dest":   "new router: 10.0.0.1  /  old router was: 192.168.1.1",
        "steps": [
            (MAG, "netwatch  (8s poll)      ", "ip route show → default via 10.0.0.1 dev eth0"),
            (MAG, "netwatch                ", "CHANGE DETECTED: 192.168.1.0/24 → 10.0.0.0/24"),
            (YLW, "ArpSpoofWorker          ", "sending STOP signal to ARP thread"),
            (YLW, "_restore_arp            ", "sending real gateway ARP to all known hosts on old net"),
            (DIM, "Old devices             ", "ARP caches will expire to normal in < 20 min"),
            (YLW, "apply_iptables          ", "flushing MITMPROXY chain — rebuilding for 10.0.0.0/24"),
            (YLW, "update_adguard_home     ", "patching captive portal DNS rewrites: answer → 10.0.0.5"),
            (YLW, "update_dnsmasq_dhcp     ", "rewriting DHCP range for 10.0.0.0/24  (10.0.0.51–200)"),
            (MAG, "netwatch                ", "restarting mitm-adblock service"),
            (MAG, "ArpSpoofWorker          ", "new thread: broadcasting 'gateway 10.0.0.1 → our MAC'"),
        ],
        "result": (MAG,  "RECONFIGURED",  "fully operational on new network — took 8 seconds, zero manual steps"),
        "stat":   "reconfigured",
    },
]

# ── Stats ─────────────────────────────────────────────────────────────────────

counts = {k: 0 for k in
          ("dns_blocked", "ads_stripped", "malware_blocked",
           "portals_shown", "tunneled", "passed", "reconfigured")}

STAT_DISPLAY = [
    ("dns_blocked",    RED, "DNS blocked"),
    ("ads_stripped",   GRN, "Ads stripped"),
    ("malware_blocked",RED, "Malware blocked"),
    ("portals_shown",  CYN, "Portals"),
    ("tunneled",       BLU, "Tunneled"),
    ("passed",         GRN, "Passed clean"),
    ("reconfigured",   MAG, "Reconfig"),
]

def print_stats():
    parts = [f"{c(col, str(counts[k]))} {c(DIM, lbl)}"
             for k, col, lbl in STAT_DISPLAY if counts[k] > 0]
    if parts:
        print("  " + c(DIM, "│  ").join(parts))


# ── Views ─────────────────────────────────────────────────────────────────────

def print_banner():
    clr()
    print()
    lines = [
        " ██╗    ██╗██╗███████╗██╗      █████╗ ██████╗ ",
        " ██║    ██║██║██╔════╝██║     ██╔══██╗██╔══██╗",
        " ██║ █╗ ██║██║█████╗  ██║     ███████║██║  ██║",
        " ██║███╗██║██║██╔══╝  ██║     ██╔══██║██║  ██║",
        " ╚███╔███╔╝██║██║     ██║████╗██║  ██║██████╔╝",
        "  ╚══╝╚══╝ ╚═╝╚═╝     ╚═════╝╚═╝  ╚═╝╚═════╝ ",
    ]
    for line in lines:
        print(c(GRN, line))
    print(c(DIM, "  Network Shield  ·  10 real-world scenarios  ·  watch every packet"))
    print()


def print_topology():
    hr("═")
    print(c(WHT + BLD, "  NETWORK TOPOLOGY" + RST))
    hr("═")
    print()
    box_col = YLW
    print(f"  {c(CYN,'Devices')}                           "
          f"{c(box_col,'YOUR BOX (Armbian S905X)')}                    {c(DIM,'Internet')}")
    print()
    print(f"  {c(CYN,'iPhone 14    192.168.1.5')}  ──►  "
          f"┌──────────────────────────────┐  ──►  {c(DIM,'youtube.com, google.com')}")
    print(f"  {c(CYN,'MacBook Pro  192.168.1.6')}  ──►  "
          f"│  {c(YLW,'1')}  AdGuard DNS      port 53   │  ──►  {c(DIM,'github.com, etc.')}")
    print(f"  {c(CYN,'Samsung TV   192.168.1.7')}  ──►  "
          f"│  {c(YLW,'2')}  mitmproxy         port 8080 │   {c(RED,'✗')}   {c(DIM,'ad networks')}")
    print(f"  {c(CYN,'PS5          192.168.1.8')}  ──►  "
          f"│  {c(YLW,'3')}  ClamAV scanner            │   {c(RED,'✗')}   {c(DIM,'malware / phishing')}")
    print(f"  {c(CYN,'Android Tab  192.168.1.9')}  ──►  "
          f"│  {c(YLW,'4')}  WireGuard tunnel          │  ──►  {c(BLU,'Discord / Roblox (Turkey)')}")
    print(f"  {c(MAG,'[new device joins]')}         ──►  "
          f"└──────────────────────────────┘")
    print()
    _gw_claim = '"gateway IP = our MAC"'
    print(f"  {c(MAG, '▲ ARP spoofing')}  {c(DIM,'— box broadcasts')}"
          f" {c(MAG, _gw_claim)}"
          f" {c(DIM,'every 3 s')}")
    print(f"  {c(DIM,'   All devices route through us.  Unplug → ARP expires → router takes over.')}")
    print()
    hr("═")
    print()


def run_scenario(sc):
    hr("─")
    print(f"  {c(DIM,'scenario')} {c(WHT + BLD, str(sc['n']) + '/10' + RST)}"
          f"  {c(BLD, sc['title'])}")
    hr("─")
    print()
    print(f"  {c(DIM,'device  :')}  {c(CYN, sc['device'])}  {c(DIM, sc['ip'])}")
    print(f"  {c(DIM,'protocol:')}  {c(WHT, sc['proto'])}")
    print(f"  {c(DIM,'target  :')}  {c(WHT, sc['dest'])}")
    print()

    for col, layer, detail in sc["steps"]:
        prefix = f"  {c(DIM, '▸')} {c(col, layer)}  "
        sys.stdout.write(prefix)
        sys.stdout.flush()
        sl(0.08)
        type_out(detail, col if col != DIM else WHT, char_delay=0.009)
        sl(0.18)

    print()
    rcol, rlabel, rdesc = sc["result"]
    pad = " " * max(0, 14 - len(rlabel))
    print(f"  {c(rcol, BLD + '► ' + rlabel + RST)}{pad}  {c(DIM, rdesc)}")
    print()

    counts[sc["stat"]] += 1
    print_stats()

    sl(1.5)
    print()


def print_final():
    hr("═")
    print(c(GRN + BLD, "  ALL 10 SCENARIOS DONE — WHAT THIS MEANS IN PRACTICE" + RST))
    hr("═")
    print()
    rows = [
        (GRN, "YouTube on any device",    "no ads — stripped from the encrypted stream in real-time"),
        (GRN, "Browser pop-up ads",       "dead — DNS kills the ad domain before any request is made"),
        (GRN, "Mobile game ads",          "dead — ad SDK DNS queries return nothing"),
        (RED, "TikTok / Instagram ads",   "NOT blocked — same server as content + cert pinning (impossible)"),
        (GRN, "Malware links",            "download intercepted, ClamAV scans it, blocked if infected"),
        (GRN, "Phishing sites",           "DNS blocked — page never loads"),
        (BLU, "Discord / Roblox (TR ban)","tunneled through WireGuard — works at full speed"),
        (CYN, "New device joins WiFi",    "instant ARP intercept + captive portal welcome page"),
        (MAG, "Box moved to new network", "auto-detects in 8 s, ARP spoof starts, everything reconfigures"),
        (GRN, "Unplug the box",           "ARP caches expire in < 20 min — router takes over, no trace"),
    ]
    for col, label, desc in rows:
        mark = c(col, "✓") if col != RED else c(RED, "✗")
        print(f"  {mark}  {c(WHT, label.ljust(28))}  {c(DIM, desc)}")

    print()
    print(c(DIM, "  Stats from this session:"))
    print("  ", end="")
    print_stats()
    print()
    hr("─")
    print()
    print(f"  {c(DIM, 'Install  :')}  {c(WHT, 'sudo sh install.sh')}")
    print(f"  {c(DIM, 'Health   :')}  {c(WHT, 'sudo sh healthcheck.sh')}")
    print(f"  {c(DIM, 'Log      :')}  {c(WHT, 'tail -f /var/log/wifi-adblock-netwatch.log')}")
    print()


def main():
    print_banner()
    sl(0.8)
    print_topology()
    try:
        input(c(DIM, "  Press ENTER to start the simulation..."))
    except EOFError:
        pass
    print()

    for sc in SCENARIOS:
        run_scenario(sc)

    print_final()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c(DIM, "\n\n  Simulation stopped.\n"))
        sys.exit(0)
