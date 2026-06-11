# WIFI-AD-BLOCK

Network-wide ad blocking **and malware protection** for every device on your Wi-Fi — with **nothing sitting in the traffic path**. This box is a lean DNS resolver + security appliance: your router points its DNS at it, and it filters ads, trackers, and malicious domains for the whole network. No proxy, no certificates on any device, no slowdown.

Layers working together:

1. **DNS sinkhole (AdGuard Home)** — blocks ads delivered from dedicated ad-network domains: mobile game ads (AdMob/Unity/AppLovin), browser banners/pop-ups, in-app banners, tracking, telemetry, and known malware/phishing domains. The workhorse.
2. **ClamAV** — an on-box antivirus engine, kept running and auto-updated, for scanning files on demand (`clamdscan`).
3. **Adaptive DNS optimizer** — benchmarks the major public resolvers from your exact location every night and switches AdGuard Home to whichever is provably fastest, so DNS lookups (and page loads) stay snappy.

**Stack:** `AdGuard Home` (DNS + malware domains + Safe Browsing) → `Quad9` security upstream · `ClamAV` daemon · `dns_optimizer.py` (fastest-resolver selection) · self-healing `watchdog` + nightly `autoupdate`.

---

## What actually gets blocked (read this first)

This project is **DNS-only by design** — it never decrypts traffic. That keeps it fast, private, and zero-maintenance, but it means ads fall into two buckets:

| Ad type | Blocked? | Why |
|---|---|---|
| Browser pop-up / banner ads | ✅ | Served from ad-network domains |
| Most mobile game ads (AdMob, Unity, AppLovin) | ✅ | Served from ad domains |
| Most in-app banner / interstitial ads | ✅ | Served from ad domains |
| Tracking / telemetry | ✅ | Blocked at the resolver |
| Known malware / phishing domains | ✅ | AdGuard Safe Browsing + Quad9 + blocklists |
| YouTube ads (browser **and** app) | ⚠️ partial | Served from the *same* servers as the video — DNS can't separate them |
| TikTok / Instagram / Spotify feed ads | ❌ | Same-server delivery; not router-blockable |

**Why YouTube-app and in-feed ads aren't fully blocked:** those ads arrive from the identical servers (and often the identical API calls) as the real content, so a DNS resolver can't tell an ad apart from a video or a post without blocking the whole service. Removing them would require decrypting traffic and installing a certificate on every device — which this project deliberately does **not** do. Everything served from a dedicated ad domain (the large majority of ads) is blocked network-wide with zero per-device setup.

---

## Quick start

One command, run as root:

```sh
sudo sh install.sh
```

It auto-detects your network, installs AdGuard Home + ClamAV, schedules the nightly autoupdate and the 10-minute self-healing watchdog, then runs a live acceptance test. If the critical DNS layer isn't working it automatically tears everything back down to a clean machine (`selfdestruct.sh`) rather than leaving your network broken.

### Two one-time manual steps

1. **AdGuard Home wizard** — open `http://<BOX_IP>:3000` from any device on the LAN and finish the first-run wizard:
   - DNS listen interface: **All interfaces**, port **53**
   - Admin web interface: port **3000**
   - Create an admin login
   - (Recommended) Settings → DNS → Upstream: `https://dns.quad9.net/dns-query`
   - (Recommended) Filters → DNS blocklists: add OISD Big, HaGeZi, AdAway, URLhaus, Phishing Army

2. **Point your router's DNS at the box** — in your router admin (usually `192.168.1.1`), set the DHCP **DNS server** to `<BOX_IP>` for **both** primary and secondary. This is what makes ad blocking cover the entire network automatically. Then reconnect devices (toggle Wi-Fi off/on) so they pick up the new DNS.

> Use the box IP for *both* DNS slots. If you leave a public DNS (e.g. 8.8.8.8) as secondary, devices will round-robin to it and bypass filtering half the time.

---

## Supported distros

| Distro family | Package manager | Init system | Notes |
|---|---|---|---|
| Debian / Ubuntu / Armbian / Raspbian | apt | systemd | Primary target |
| Alpine Linux | apk | OpenRC | Minimal footprint |
| OpenWrt (ophub/amlogic-s9xxx) | opkg | procd | TX3 / Amlogic S905X3 |
| Arch / Manjaro | pacman | systemd | |
| Fedora / RHEL / CentOS / Rocky | dnf / yum | systemd | |
| openSUSE Leap / Tumbleweed | zypper | systemd | |
| Void Linux | xbps | runit | |
| Any POSIX Linux with Python 3.9+ | any | sysvinit fallback | LSB init.d script |

All scripts are written in POSIX `/bin/sh` — no bash, no bashisms. They auto-detect package manager and init system at runtime.

---

## Architecture

```
Your devices
    │  (router hands out BOX_IP as the DNS server via DHCP)
    ▼
Linux Box  :53
┌────────────────────────────────────────────────────┐
│  AdGuard Home                                        │
│  • blocks ad / tracker / malware domains             │
│  • Safe Browsing (malware + phishing)                │
│  • upstream → Quad9 (security-filtering resolver)    │
│  • upstream auto-tuned nightly by dns_optimizer.py   │
└────────────────────────────────────────────────────┘
    │  (clean DNS answers; ads return null)
    ▼
Router → Internet     (all actual traffic flows straight
                       through the router — the box is never
                       in the data path)
```

ClamAV runs alongside as an on-demand scanner. The watchdog restarts any layer that dies; the nightly autoupdate refreshes blocklists, virus signatures, the fastest-DNS choice, and security patches.

---

## Operations

### Verify everything is live

```sh
sudo sh healthcheck.sh
```

### Service management (systemd)

| What | Command |
|---|---|
| AdGuard Home status | `systemctl status AdGuardHome` |
| AdGuard Home logs | `journalctl -fu AdGuardHome` |
| ClamAV status | `systemctl status clamav-daemon` |
| Watchdog timer | `systemctl list-timers wifi-adblock-watchdog.timer` |
| Autoupdate timer | `systemctl list-timers wifi-adblock-update.timer` |

### Confirm a device is using the box

Open the AdGuard Home dashboard (`http://<BOX_IP>:3000`) and watch the **Query Log** — if a device's lookups appear there, it's being filtered. The dashboard's "blocked" counter climbs as ads are refused.

### Manual update

```sh
sudo sh autoupdate.sh
```

### Scan a file with ClamAV

```sh
clamdscan /path/to/file
```

---

## Optional — Discord + Roblox bypass (Turkey)

`bypass_censorship.sh` sets up a WireGuard tunnel for services blocked by ISP-level censorship. It's **not** run by `install.sh` because it needs your VPN peer keys. Run it once you have them:

```sh
sudo sh bypass_censorship.sh
```

---

## Uninstall

Full teardown back to a clean machine (stops + removes every component, restores normal DNS, keeps logs for reference):

```sh
sudo sh selfdestruct.sh
```

---

## Limitations

| | Notes |
|---|---|
| YouTube-app / in-feed ads | Same-server delivery — not blockable without decrypting traffic (out of scope by design). |
| Same-server ads (TikTok, Instagram, some Spotify) | Can't be separated from content at the DNS layer. |
| Per-device DNS override | A device manually set to use 8.8.8.8 bypasses filtering. Block outbound DNS (port 53/853) at the router to enforce, if desired. |
| DNS-over-HTTPS in browsers | Browsers with DoH enabled may bypass the box. Disable DoH or block known DoH endpoints to enforce. |
