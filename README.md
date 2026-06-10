# WIFI-AD-BLOCK

Network-wide ad blocking **and malware protection** for every device on your Wi-Fi. Layers working together:

1. **DNS sinkhole (AdGuard Home)** — blocks ads delivered from dedicated ad-network domains: mobile game ads, browser banners/pop-ups, in-app banners, tracking, telemetry. Also blocks known malware/phishing domains. The broad workhorse.
2. **Transparent HTTPS proxy (mitmproxy)** — strips YouTube ads served from the *same* servers as the video, which DNS alone can't touch.
3. **ClamAV download scanner** — scans files crossing the proxy and blocks infected downloads before they reach any device.

**Stack:** `AdGuard Home` (DNS + malware domains) + `mitmproxy` (`yt_ad_stripper.py` + `malware_scanner.py`) → `ClamAV` → `iptables` (traffic redirect) → `dnsmasq` / UCI (DHCP gateway announcement)

---

## What actually gets blocked (read this first)

Ads come in two kinds, and only one is fully beatable at the router:

| | DNS sinkhole | + mitmproxy | Notes |
|---|---|---|---|
| Browser pop-up / banner ads | ✅ | ✅ | |
| Most mobile game ads (AdMob, Unity, AppLovin) | ✅ | ✅ | Served from ad domains |
| Most in-app banner / interstitial ads | ✅ | ✅ | |
| Tracking / telemetry | ✅ | ✅ | |
| Spotify ads | ⚠️ partial | ⚠️ partial | Some served from content servers |
| YouTube (browser + app) | ⚠️ partial | ✅ **full** | mitmproxy strips same-server ads |
| **TikTok / Instagram feed ads** | ❌ | ❌ | See below — not router-blockable |

**Why TikTok and Instagram feed ads can't be blocked router-side:**

1. **Certificate pinning** — these apps reject any TLS connection not signed by their exact certificate, so mitmproxy can't decrypt their traffic at all (the app just shows "no connection").
2. **Same-server delivery** — feed ads arrive through the identical API call as your normal content, so DNS can't distinguish ad from post.

Blocking those would require **rooting/jailbreaking each phone** and patching the app per-device — fragile, breaks on every update, and not "connect to Wi-Fi and it works." This project deliberately stays router-only, so those feed ads are out of scope. Everything else in the table above is covered.

---

## Supported distros

| Distro family | Package manager | Init system | Notes |
|---|---|---|---|
| Debian / Ubuntu / Armbian / Raspbian | apt | systemd | Primary target |
| Alpine Linux | apk | OpenRC | Minimal footprint |
| **OpenWrt** (ophub/amlogic-s9xxx-openwrt) | opkg | **procd** | TX3 / Amlogic S905X3 |
| Arch / Manjaro | pacman | systemd | |
| Fedora / RHEL / CentOS / Rocky | dnf / yum | systemd | |
| openSUSE Leap / Tumbleweed | zypper | systemd | |
| Void Linux | xbps | runit | |
| Gentoo | emerge | OpenRC / systemd | Manual notes in script |
| Any POSIX Linux with Python 3.9+ | any | sysvinit fallback | LSB init.d script |

All scripts are written in POSIX `/bin/sh` — no bash, no bashisms.  
They auto-detect package manager, init system, and network manager at runtime.

---

## Architecture

```
Your devices
    │  (default gateway = Linux box via DHCP)
    ▼
Linux Box  :8080
┌─────────────────────────────────────────────────────┐
│  iptables PREROUTING                                 │
│  • skip LAN / RFC-1918 ranges                       │
│  • TCP port 80/443 → REDIRECT :8080                 │
│                                                     │
│  mitmdump (transparent mode)                        │
│  • terminates TLS using local root CA               │
│  • calls yt_ad_stripper.py on every response        │
│    ├─ JSON path:  strip AD_JSON_KEYS recursively    │
│    └─ Proto path: strip AD_PROTO_FIELDS (bbpb)      │
│                                                     │
│  Re-encrypts with real server cert + local CA chain │
└─────────────────────────────────────────────────────┘
    │
    ▼
Router → Internet
```

---

## Quick start

### 1. Edit network variables

Open `network_config.sh` and set the five variables at the top:

```sh
LAN_IFACE="eth0"         # your NIC name (check: ip link)
BOX_IP="192.168.1.2"     # the static IP for this box
ROUTER_IP="192.168.1.1"  # your actual router
DHCP_START="192.168.1.100"
DHCP_END="192.168.1.200"
```

### 2. Run setup (as root, in this order)

```sh
sudo sh setup.sh          # mitmproxy YouTube stripper + iptables + service
sudo sh dns_sinkhole.sh   # AdGuard Home DNS sinkhole (the broad ad blocker)
sudo sh malware_block.sh  # ClamAV download scanner + DNS malware blocking
sudo sh network_config.sh # static IP + DHCP advertising this box as gateway+DNS
```

All scripts are safe to re-run. Run `malware_block.sh` *after* `setup.sh`
(it patches the proxy service to load the scanner) and after AdGuard Home's
first-run wizard (so it can enable Safe Browsing).

After `dns_sinkhole.sh`, open `http://<BOX_IP>:3000` once to finish AdGuard
Home's first-run wizard (set DNS to listen on all interfaces / port 53, create
an admin login, add blocklists). Then set `DNS_SERVER="<BOX_IP>"` in
`network_config.sh` so your devices use AdGuard Home for DNS.

### 3. Configure your router

Do **one** of these:

- **Option A (recommended):** Disable the DHCP server in your router's admin panel.  
  The Linux box will handle DHCP and advertise itself as the gateway.

- **Option B:** In your router's DHCP settings, change "Default Gateway" to `BOX_IP`.  
  Leave the router's DHCP running.

### 4. Reconnect devices

On each device, release and renew the DHCP lease (toggle Wi-Fi off/on, or
`ipconfig /release && ipconfig /renew` on Windows).  The device will now
route through the Linux box.

### 5. Install the CA cert

Serve the cert over HTTP so devices can fetch it easily:

```sh
cd /opt/mitm-proxy/certs   # or /usr/share/mitm-proxy/certs
python3 -m http.server 8888
```

Browse to `http://<BOX_IP>:8888` from each device and download the cert.

| Platform | File | Where to install |
|---|---|---|
| Android | `mitmproxy-ca-cert.cer` | Settings → Security → Install CA certificate |
| iOS / iPadOS | `mitmproxy-ca-cert.pem` | Download → Settings → General → VPN & Device Management → install profile, then Settings → General → About → Certificate Trust Settings → enable |
| macOS | `mitmproxy-ca-cert.pem` | Keychain Access → File → Import → set to "Always Trust" |
| Windows | `mitmproxy-ca-cert.pem` | certmgr.msc → Trusted Root CAs → right-click → All Tasks → Import |
| Linux (Debian/Ubuntu/Armbian) | `mitmproxy-ca-cert.pem` | `sudo cp cert.pem /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates` |
| Linux (Alpine / OpenWrt) | `mitmproxy-ca-cert.pem` | `cp cert.pem /etc/ssl/certs/ && update-ca-certificates` |

---

## Operations

### Service management

| Init system | Status | Logs | Restart |
|---|---|---|---|
| **systemd** | `systemctl status mitm-adblock` | `journalctl -fu mitm-adblock` | `systemctl restart mitm-adblock` |
| **OpenRC** | `rc-service mitm-adblock status` | `/var/log/mitm-adblock.log` | `rc-service mitm-adblock restart` |
| **procd (OpenWrt)** | `/etc/init.d/mitm-adblock status` | `logread -e mitm-adblock` | `/etc/init.d/mitm-adblock restart` |
| **runit (Void)** | `sv status mitm-adblock` | `tail -f /var/log/mitm-adblock/current` | `sv restart mitm-adblock` |
| **sysvinit** | `/etc/init.d/mitm-adblock status` | `/var/log/syslog` | `/etc/init.d/mitm-adblock restart` |

### Verify it's working

Watch for stripped-field log lines in real time:

```sh
# systemd
journalctl -fu mitm-adblock | grep YT-AdStrip

# OpenWrt
logread -f | grep YT-AdStrip
```

You should see:

```
[YT-AdStrip] JSON  stripped  4 ad fields  <- /youtubei/v1/player
[YT-AdStrip] JSON  stripped  2 ad fields  <- /youtubei/v1/next
```

### Interactive debug (mitmweb UI)

```sh
# Replace the init service with the web UI temporarily
mitmdump_bin="$(command -v mitmdump || echo /opt/mitm-proxy/bin/mitmdump)"
"$mitmdump_bin" \
    --mode transparent \
    --listen-port 8080 \
    --web-port 8081 \
    --set confdir=/opt/mitm-proxy/certs \
    -s /opt/mitm-proxy/yt_ad_stripper.py
```

Open `http://<BOX_IP>:8081` in a browser to inspect live traffic.

### Reload the addon script without a service restart

mitmproxy watches the script file for changes and hot-reloads it:

```sh
cp yt_ad_stripper.py /opt/mitm-proxy/yt_ad_stripper.py
# No restart needed — mitmproxy picks up the change automatically
```

---

## OpenWrt-specific notes (TX3 / Amlogic S905X3)

The setup script detects OpenWrt by checking for `/etc/openwrt_release` and
switches to procd-compatible behaviour throughout:

- **Python/mitmproxy:** installed via `opkg` + `pip`.  The S905X3 is `aarch64`,
  which has prebuilt pip wheels for mitmproxy and all its dependencies
  (including the `cryptography` Rust extension).  Installation should complete
  without needing a compiler.

- **iptables persistence:** rules are written to `/etc/firewall.user`, which
  OpenWrt's firewall init script executes on every boot.

- **DHCP:** configured via UCI (`uci set dhcp.lan.*`) rather than installing a
  second dnsmasq.  OpenWrt's built-in dnsmasq already handles DHCP; the script
  just adds `dhcp-option=3,<BOX_IP>` to make it advertise this box as the
  gateway.

- **Static IP:** configured via `uci set network.lan.*`.

If `pip install mitmproxy` fails due to a missing musl wheel, install Entware
first (`/opt/entware`) which provides a glibc environment:

```sh
# Entware bootstrap for Amlogic (run once, requires internet)
wget -O - https://raw.githubusercontent.com/Entware/Entware/master/setup/setup.sh | sh
/opt/bin/opkg update
/opt/bin/opkg install python3 python3-pip
/opt/bin/pip3 install mitmproxy blackboxprotobuf
```

Then edit `MITMDUMP_BIN` in the service init file to point at `/opt/bin/mitmdump`.

---

## Malware protection

Three layers, installed by `malware_block.sh`:

1. **ClamAV live download scanning.** `malware_scanner.py` hooks the mitmproxy
   response loop. When a device downloads a file (detected by content-type,
   `Content-Disposition: attachment`, or a risky extension), the bytes are
   streamed to the ClamAV daemon *before* reaching the device. Infected →
   the download is replaced with a block page. Fail-open by design: if the AV
   daemon is down, traffic passes through rather than taking your network
   offline (a warning is logged instead).

2. **DNS malware/phishing blocking.** AdGuard Home's Safe Browsing is enabled
   and you add threat-intelligence blocklists (URLhaus, Phishing Army, HaGeZi).
   Clicking a known-malicious link fails to resolve — the connection never
   opens.

3. **Security-filtering upstream DNS (Quad9).** Set AdGuard Home's upstream to
   `https://dns.quad9.net/dns-query`. Quad9 refuses malicious domains at the
   resolver, so even brand-new threats not yet in your local blocklists get
   caught.

**Test it** with the harmless EICAR test signature (the industry-standard AV
test file — not real malware):

```sh
curl http://www.eicar.org/download/eicar.com
# Expect: the "Malware Blocked" page instead of the file
```

Watch the scanner work:

```sh
journalctl -fu mitm-adblock | grep Malware   # systemd
logread -f | grep Malware                    # OpenWrt
```

**What this does and doesn't do:**

- ✅ Blocks **navigation** to known-malicious domains (DNS) — a clicked malware
  link won't open.
- ✅ Blocks **infected file downloads** over HTTP and decryptable HTTPS (ClamAV).
- ⚠️ It does **not** delete the link out of a search-results page. Google's
  results page is HTTPS from Google's own servers; the link may still be listed,
  but clicking it is blocked. Functionally you're protected; the text isn't erased.
- ⚠️ Downloads inside **certificate-pinned** apps (the same ones that bypass ad
  stripping) aren't scanned, because the proxy can't see inside them.

## QUIC / HTTP3 workaround

YouTube aggressively uses QUIC (UDP 443).  mitmproxy only handles TCP.
Block QUIC to force fallback to TCP/HTTPS:

```sh
iptables -I FORWARD -p udp --dport 443 -j DROP
iptables -I OUTPUT  -p udp --dport 443 -j DROP
```

YouTube clients retry over TCP within ~1 second.

---

## Updating the ad field list

YouTube occasionally adds new ad-delivery JSON keys.

1. Open mitmweb (see above) and watch a `/youtubei/v1/player` response.
2. Search the body for `ad`, `ads`, `interstitial`, `bumper`.
3. Add new key names to `AD_JSON_KEYS` in `yt_ad_stripper.py`.
4. Copy the updated file to the install dir — the service hot-reloads it.

---

## Limitations

| | Notes |
|---|---|
| Certificate-pinned apps | Banking apps, some streaming services. Passed through untouched — these connections are safe. |
| QUIC / HTTP3 | Block with iptables rule above to force TCP fallback. |
| Smart TVs with pinned certs | Install the CA into the TV's system trust store if accessible, or block ads at DNS level instead. |
| OpenWrt + musl wheels | Use Entware if pip wheels fail to install (see section above). |
