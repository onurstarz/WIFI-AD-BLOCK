# WIFI-AD-BLOCK

A transparent HTTPS interception pipeline that strips YouTube ad payloads at the network level — before they ever reach your devices.

**Stack:** `mitmproxy` (transparent mode) → `yt_ad_stripper.py` (Python addon) → `iptables` (traffic redirect) → `dnsmasq` (DHCP gateway announcement)

---

## Architecture

```
Your devices
    │  (default gateway = Linux box)
    ▼
Linux Box  :8080
┌─────────────────────────────────────────────────────┐
│  iptables PREROUTING                                 │
│  • port 80/443 → REDIRECT :8080                     │
│                                                     │
│  mitmdump (transparent mode)                        │
│  • terminates TLS with local CA                     │
│  • calls yt_ad_stripper.py on each response         │
│    ├─ JSON:     strip AD_JSON_KEYS recursively      │
│    └─ Protobuf: strip AD_PROTO_FIELDS via bbpb      │
│                                                     │
│  Re-encrypts with real server cert + local CA chain │
└─────────────────────────────────────────────────────┘
    │
    ▼
Router → Internet
```

---

## Quick Start

### 1. Clone and install

```bash
git clone <this-repo> /opt/wifi-ad-block
cd /opt/wifi-ad-block

# Edit network_config.sh first — set your IPs and interface names
nano network_config.sh

# Run setup (installs packages, iptables rules, systemd service)
sudo bash setup.sh

# Run network config (configures static IP + DHCP gateway)
sudo bash network_config.sh
```

### 2. Install the CA certificate on each device

The CA cert is generated at `/opt/mitm-proxy/certs/` on first run.

Serve it over HTTP so devices can grab it easily:

```bash
# Serve the cert directory on port 8888 (run once)
cd /opt/mitm-proxy/certs
python3 -m http.server 8888 &
```

Then on each device navigate to `http://<BOX_IP>:8888` and download:

| Device | File to download | Where to install |
|---|---|---|
| Android 7+ | `mitmproxy-ca-cert.cer` | Settings → Security → Install CA cert |
| iOS / iPadOS | `mitmproxy-ca-cert.pem` | Download → Settings → Profile → Install, then Settings → About → Cert Trust → enable |
| macOS | `mitmproxy-ca-cert.pem` | Keychain Access → import → set "Always Trust" |
| Windows | `mitmproxy-ca-cert.pem` | certmgr.msc → Trusted Root CAs → import |
| Linux (system-wide) | see below | — |

**Linux (Debian/Ubuntu) cert install:**

```bash
sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

**Android user-space apps that pin certificates** (banking apps, some streaming apps) will not trust user-installed CAs.  That is expected and correct — those apps protect their own traffic.  YouTube's app and browser YouTube both work with a user-installed CA.

---

## Operations

### Service management

```bash
systemctl status  mitm-adblock   # live status
journalctl -fu    mitm-adblock   # follow logs in real time
systemctl restart mitm-adblock   # apply script changes
systemctl stop    mitm-adblock   # disable temporarily
```

### Verify it's working

```bash
# Watch the stripped-field log in real time
journalctl -fu mitm-adblock | grep YT-AdStrip
```

You should see lines like:

```
[YT-AdStrip] JSON  stripped  4 ad fields  ← /youtubei/v1/player
[YT-AdStrip] JSON  stripped  2 ad fields  ← /youtubei/v1/next
```

### Manual run (dev/debug)

```bash
# Run interactively with the mitmweb UI on port 8081
sudo -u mitm /opt/mitm-proxy/bin/mitmweb \
    --mode transparent \
    --listen-port 8080 \
    --web-port 8081 \
    --set confdir=/opt/mitm-proxy/certs \
    -s /opt/mitm-proxy/yt_ad_stripper.py
```

Then open `http://<BOX_IP>:8081` in a browser to watch live traffic.

### Reload script without restart

```bash
# mitmproxy reloads addon scripts automatically on file change.
# Just edit yt_ad_stripper.py and save — the service picks it up.
install -m 644 yt_ad_stripper.py /opt/mitm-proxy/yt_ad_stripper.py
```

---

## iptables rules explained

```
PREROUTING chain → MITMPROXY chain
  RETURN if traffic is from the 'mitm' user        # break redirect loop
  RETURN if dst is 127/8, 10/8, 172.16/12, 192.168/16  # keep LAN local
  TCP dport 80  → REDIRECT :8080
  TCP dport 443 → REDIRECT :8080

OUTPUT chain → MITMPROXY chain   (catches traffic from this box itself)
```

Flush and reapply at any time:

```bash
sudo bash setup.sh   # idempotent — flushes and rebuilds the chain
```

---

## How the ad stripping works

YouTube's app and web player communicate with `youtubei.googleapis.com`.  
The `/youtubei/v1/player` endpoint returns a large JSON object (or Protobuf for mobile) that contains **both** the video stream manifests and the full ad schedule embedded in the same response.

**JSON responses** are the common case for Chrome and mobile browsers.  
The script parses the response body, walks the object tree recursively, and deletes any key that matches the `AD_JSON_KEYS` set — things like `playerAds`, `adSlots`, `adPlacements`, `adBreakParams`.  The cleaned object is re-serialized and handed to the client.

**Protobuf responses** come from the native YouTube app on Android/iOS.  
The script uses `blackboxprotobuf` to decode the binary payload without a `.proto` schema, drops known ad field numbers (`12`, `13`, `46` etc.), and re-encodes.  Because Protobuf fields are identified by number rather than name, this is robust to YouTube adding new ad-delivery field names.

---

## Updating the ad field list

YouTube occasionally adds new ad-delivery keys.  To add one:

1. Open `mitmweb` (see above) and watch a `/youtubei/v1/player` response.
2. Copy the response body into a JSON viewer.
3. Search for `ad`, `ads`, `interstitial`, or `bumper`.
4. Add any new key names to `AD_JSON_KEYS` in `yt_ad_stripper.py`.
5. Copy the updated script to `/opt/mitm-proxy/` — the service reloads it automatically.

---

## Limitations

| Limitation | Notes |
|---|---|
| Certificate-pinned apps | Banking apps and some streaming services pin their certs. These connections are passed through untouched. |
| QUIC / HTTP3 | YouTube sometimes uses QUIC (UDP). mitmproxy only handles TCP. Block QUIC at the firewall to force fallback to TCP/HTTPS: `iptables -I FORWARD -p udp --dport 443 -j DROP` |
| YouTube TV / Smart TV | Some TV clients use certificate pinning and will refuse. Install the CA cert in the TV's system store if accessible, or use DNS-level blocking as a secondary layer. |
| Ad-free YouTube Premium | The cleanest solution. This script is for users who want ad-free without a subscription. |
