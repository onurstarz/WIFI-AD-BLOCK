"""
Captive portal server — WIFI-AD-BLOCK.

Runs on port 80 of the box. When a device connects to Wi-Fi its OS
automatically makes an HTTP probe to a known URL (different per OS).
We intercept those probes via DNS rewrites in AdGuard Home:
  captive.apple.com          → BOX_IP  (iOS / macOS)
  connectivitycheck.gstatic  → BOX_IP  (Android)
  www.msftconnecttest.com    → BOX_IP  (Windows)

New device  → gets the portal welcome page (shows network protections,
              optional cert install button, "Got it" dismiss).
Seen device → gets the expected OS response (Success / 204 / etc.) so
              the "Sign in to Wi-Fi" popup never appears again.

Seen devices are tracked by MAC address (read from /proc/net/arp).
MAC is more stable than IP — survives DHCP renewals.

Also serves the mitmproxy CA cert files directly so users don't need
a separate HTTP server for cert installation.
"""
from __future__ import annotations

import http.server
import os
import re
import subprocess
import threading
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────
PORTAL_PORT     = 80
SEEN_FILE       = "/opt/mitm-proxy/seen_devices.txt"
EXISTING_FILE   = "/opt/mitm-proxy/existing_devices.txt"
CERT_DIR        = "/opt/mitm-proxy/certs"
NETWORK_NAME    = "Protected Network"

# ── OS captive-portal detection paths + expected responses ────────────────────
# Each entry: path → (os_hint, content_type, body)
# body=None means respond with HTTP 204 No Content (Android)
CAPTIVE_PATHS: dict[str, tuple[str, Optional[str], Optional[str]]] = {
    # Apple (iOS, macOS, tvOS)
    "/hotspot-detect.html":           ("apple",   "text/html",  "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "/library/test/success.html":     ("apple",   "text/html",  "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    # Android / ChromeOS
    "/generate_204":                  ("android", None,         None),
    "/gen_204":                       ("android", None,         None),
    "/connectcheck.html":             ("android", "text/html",  ""),
    # Windows
    "/connecttest.txt":               ("windows", "text/plain", "Microsoft Connect Test"),
    "/ncsi.txt":                      ("windows", "text/plain", "Microsoft NCSI"),
    "/redirect":                      ("windows", "text/html",  ""),
    # Firefox
    "/success.txt":                   ("firefox", "text/plain", "success\n"),
    "/canonical.html":                ("firefox", "text/html",  "<HTML>"),
    # Ubuntu
    "/ubuntu/ubuntulink.php":         ("ubuntu",  "text/plain", ""),
}

_seen_lock   = threading.Lock()
_box_ip_cache: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_box_ip() -> str:
    global _box_ip_cache
    if _box_ip_cache:
        return _box_ip_cache
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "1.1.1.1"], text=True, timeout=3
        )
        parts = out.split()
        if "src" in parts:
            _box_ip_cache = parts[parts.index("src") + 1]
            return _box_ip_cache
    except Exception:
        pass
    _box_ip_cache = "192.168.1.2"
    return _box_ip_cache


def _mac_for_ip(ip: str) -> Optional[str]:
    """Read MAC from /proc/net/arp — no external commands needed."""
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac not in ("00:00:00:00:00:00", ""):
                        return mac.lower()
    except Exception:
        pass
    return None


def _is_seen(ip: str) -> bool:
    mac = _mac_for_ip(ip)
    if not mac:
        return False
    with _seen_lock:
        if not os.path.exists(SEEN_FILE):
            return False
        with open(SEEN_FILE) as f:
            return mac in f.read()


def _is_existing_device(ip: str) -> bool:
    """True if this IP was on the network before the box was installed."""
    mac = _mac_for_ip(ip)
    if not mac:
        return False
    with _seen_lock:
        if not os.path.exists(EXISTING_FILE):
            return False
        with open(EXISTING_FILE) as f:
            return mac in f.read()


def _mark_seen(ip: str) -> None:
    mac = _mac_for_ip(ip)
    if not mac:
        return
    with _seen_lock:
        os.makedirs(os.path.dirname(SEEN_FILE), exist_ok=True)
        if os.path.exists(SEEN_FILE):
            with open(SEEN_FILE) as f:
                if mac in f.read():
                    return
        with open(SEEN_FILE, "a") as f:
            f.write(mac + "\n")


def _remove_https_bypass(ip: str) -> None:
    """
    Remove the HTTPS pass-through rule for this device so mitmproxy
    intercepts their HTTPS from now on (requires CA cert to be installed).
    Also removes their IP from existing_ips.txt so the rule stays gone
    after a netwatch iptables rebuild.
    """
    existing_ips = os.path.join(os.path.dirname(SEEN_FILE), "existing_ips.txt")
    if os.path.exists(existing_ips):
        try:
            with open(existing_ips) as f:
                lines = f.read().splitlines()
            lines = [l for l in lines if l.strip() != ip]
            with open(existing_ips, "w") as f:
                f.write("\n".join(lines) + ("\n" if lines else ""))
        except OSError:
            pass

    # Remove live iptables rule (best-effort; netwatch will not re-add it
    # because the IP is now gone from existing_ips.txt)
    try:
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "MITMPROXY",
             "-s", ip, "-p", "tcp", "--dport", "443", "-j", "RETURN"],
            capture_output=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _upgrade_done_html() -> str:
    return """<!DOCTYPE html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
  body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .box{text-align:center;padding:2rem}
  h2{color:#3fb950;font-size:1.6rem}
  p{color:#8b949e;max-width:320px;margin:.8rem auto}
</style></head><body>
<div class=box>
  <h2>&#10003; Full protection enabled</h2>
  <p>HTTPS inspection is now active for your device.</p>
  <p>YouTube ads, malware download scanning, and HTTPS ad stripping are all on.</p>
</div></body></html>"""


# ── Universal one-tap cert install ────────────────────────────────────────────
# Fixed UUIDs so re-installing the profile REPLACES the old one instead of
# stacking duplicates in Settings.
_PROFILE_UUID = "2f1c9e10-3b4a-4c5d-8e6f-a1b2c3d4e5f6"
_PAYLOAD_UUID = "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d"


def _read_cert_b64_der() -> Optional[str]:
    """Return the CA cert as base64 DER (the body of the PEM, markers stripped)."""
    pem = os.path.join(CERT_DIR, "mitmproxy-ca-cert.pem")
    if not os.path.exists(pem):
        return None
    try:
        with open(pem) as f:
            content = f.read()
    except OSError:
        return None
    m = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        content, re.S,
    )
    if not m:
        return None
    return "".join(m.group(1).split())


def _mobileconfig() -> Optional[str]:
    """
    Build an Apple configuration profile (.mobileconfig) that installs the CA
    cert as a trusted root. Tapping a link to this in Safari triggers the
    native 'Profile Downloaded' install flow — the same mechanism used by
    sideloading / MDM enrolment.
    """
    b64 = _read_cert_b64_der()
    if not b64:
        return None
    wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>wifi-adblock-ca.cer</string>
      <key>PayloadContent</key>
      <data>
{wrapped}
      </data>
      <key>PayloadDescription</key>
      <string>Installs the WiFi AdBlock root certificate.</string>
      <key>PayloadDisplayName</key>
      <string>WiFi AdBlock Root Certificate</string>
      <key>PayloadIdentifier</key>
      <string>com.wifiadblock.ca</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{_PAYLOAD_UUID}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Removes ads, trackers and malware from encrypted traffic while you are on this Wi-Fi. Remove anytime under Settings &gt; General &gt; VPN &amp; Device Management.</string>
  <key>PayloadDisplayName</key>
  <string>WiFi AdBlock Protection</string>
  <key>PayloadIdentifier</key>
  <string>com.wifiadblock.profile</string>
  <key>PayloadOrganization</key>
  <string>WiFi AdBlock</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{_PROFILE_UUID}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""


def _detect_os(ua: str) -> str:
    ua = (ua or "").lower()
    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        return "ios"
    if "macintosh" in ua or "mac os x" in ua:
        return "macos"
    if "android" in ua:
        return "android"
    if "windows" in ua:
        return "windows"
    if "cros" in ua:
        return "chromeos"
    if "linux" in ua:
        return "linux"
    return "other"


# ── Request handler ───────────────────────────────────────────────────────────

class PortalHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress default noisy logs

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        client_ip = self.client_address[0]
        path      = self.path.split("?")[0].rstrip("/") or "/"

        # ── Cert downloads ────────────────────────────────────────────────────
        if path == "/mitmproxy-ca-cert.pem":
            self._serve_file(
                os.path.join(CERT_DIR, "mitmproxy-ca-cert.pem"),
                "application/x-pem-file",
                "mitmproxy-ca-cert.pem",
            )
            return
        if path in ("/mitmproxy-ca-cert.cer", "/mitmproxy-ca-cert.der"):
            self._serve_file(
                os.path.join(CERT_DIR, "mitmproxy-ca-cert.cer"),
                "application/x-x509-ca-cert",
                "mitmproxy-ca-cert.cer",
            )
            return

        # ── Universal one-tap installer ───────────────────────────────────────
        # A single page any device can open. Detects the OS and serves the
        # native install flow (Apple config profile / Android CA import /
        # Windows cert wizard).
        if path == "/install":
            ua = self.headers.get("User-Agent", "")
            self._send(200, "text/html; charset=utf-8",
                       _install_landing_html(_detect_box_ip(), _detect_os(ua)))
            return

        # ── Apple configuration profile ───────────────────────────────────────
        # Tapping a link to this in Safari triggers the native profile-install
        # prompt (the "iOS profile" mechanism). MIME must be aspen-config.
        if path in ("/wifi-adblock.mobileconfig", "/profile.mobileconfig"):
            cfg = _mobileconfig()
            if cfg is None:
                self._send(404, "text/plain",
                           "Certificate not found. Run setup.sh first.\n")
                return
            data = cfg.encode()
            self.send_response(200)
            self.send_header("Content-Type",
                             "application/x-apple-aspen-config; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="wifi-adblock.mobileconfig"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # ── Captive-portal detection probes ───────────────────────────────────
        if path in CAPTIVE_PATHS:
            if _is_seen(client_ip):
                # Returning device — satisfy the OS probe so popup never shows
                _, ctype, body = CAPTIVE_PATHS[path]
                if body is None:
                    self._send(204)
                else:
                    self._send(200, ctype, body)
            elif _is_existing_device(client_ip):
                # Pre-existing device — show one-time upgrade notice
                self._serve_upgrade_notice(client_ip)
            else:
                # New device — show the portal page
                self._serve_portal(client_ip)
            return

        # ── "Got it" action ───────────────────────────────────────────────────
        if path == "/portal-accept":
            _mark_seen(client_ip)
            self._send(302, headers={"Location": "/portal-done"})
            return

        # ── Existing device: "Maybe Later" dismiss ────────────────────────────
        # Marks them as fully seen so the upgrade notice never appears again.
        # Their HTTPS bypass stays in place — they just don't get prompted again.
        if path == "/upgrade-accept":
            _mark_seen(client_ip)
            self._send(302, headers={"Location": "/portal-done"})
            return

        # ── Cert installed → upgrade to full HTTPS protection ─────────────────
        # Existing devices have a HTTPS pass-through rule so their traffic is
        # never intercepted (no cert errors). When they install the CA cert and
        # hit this endpoint, we remove that bypass rule — from that point their
        # HTTPS traffic goes through mitmproxy like any new device.
        if path == "/cert-upgrade":
            _remove_https_bypass(client_ip)
            _mark_seen(client_ip)
            self._send(200, "text/html; charset=utf-8", _upgrade_done_html())
            return

        if path == "/portal-done":
            self._send(200, "text/html; charset=utf-8", _done_html())
            return

        # ── Default: show portal ──────────────────────────────────────────────
        self._serve_portal(client_ip)

    def _serve_portal(self, client_ip: str):
        self._send(200, "text/html; charset=utf-8",
                   _portal_html(_detect_box_ip(), NETWORK_NAME))

    def _serve_upgrade_notice(self, client_ip: str):
        self._send(200, "text/html; charset=utf-8",
                   _upgrade_notice_html(_detect_box_ip()))

    def _serve_file(self, path: str, ctype: str, filename: str):
        if not os.path.exists(path):
            self._send(404, "text/plain", "Certificate not found. Run setup.sh first.\n")
            return
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send(self, code: int, ctype: str = "", body: str = "",
              headers: dict | None = None):
        self.send_response(code)
        if ctype:
            self.send_header("Content-Type", ctype)
        if body:
            encoded = body.encode()
            self.send_header("Content-Length", str(len(encoded)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body.encode())


# ── HTML pages ────────────────────────────────────────────────────────────────

def _upgrade_notice_html(box_ip: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unlock Full Protection</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#0d0d0d;color:#e0e0e0;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:1rem}}
.card{{max-width:420px;width:100%;background:#181818;border-radius:18px;
       border:1px solid #262626;overflow:hidden;
       box-shadow:0 20px 60px rgba(0,0,0,.6)}}
.header{{background:linear-gradient(150deg,#1a1400 0%,#1a1100 100%);
         padding:2rem 1.5rem;text-align:center;
         border-bottom:1px solid #332800}}
.icon{{font-size:2.8rem;margin-bottom:.6rem}}
h1{{font-size:1.2rem;font-weight:700;color:#f0c040;letter-spacing:-.01em}}
.sub{{font-size:.78rem;color:#8a7040;margin-top:.3rem}}
.body{{padding:1.4rem}}
.section{{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;
          color:#555;margin:.9rem 0 .4rem}}
.row{{display:flex;align-items:center;gap:.6rem;padding:.55rem .7rem;
      border-radius:8px;margin-bottom:.3rem;font-size:.82rem}}
.row-on{{background:#0d1a0d;color:#6ddf6d;border:1px solid #1e3a1e}}
.row-off{{background:#1a1400;color:#f0c040;border:1px solid #332800}}
.row .mark{{font-size:1rem;flex-shrink:0}}
.cert-box{{background:#111;border:1px solid #2a2a2a;border-radius:10px;
           padding:.9rem;margin:1rem 0}}
.cert-box h3{{font-size:.82rem;color:#c9d1d9;margin-bottom:.3rem;font-weight:600}}
.cert-box p{{font-size:.73rem;color:#666;line-height:1.4;margin-bottom:.55rem}}
.btn{{display:block;width:100%;text-align:center;padding:.6rem .8rem;
      border-radius:8px;font-size:.8rem;font-weight:500;text-decoration:none;
      margin-bottom:.4rem;cursor:pointer;border:none;transition:opacity .15s}}
.btn:hover{{opacity:.85}}
.btn-pem{{background:#1e1e2a;color:#a0a0f0;border:1px solid #2a2a44}}
.btn-cer{{background:#1a1e2a;color:#80b0f0;border:1px solid #222a44}}
.btn-activated{{background:#1a3a1a;color:#7dff7d;border:1px solid #2a5a2a;
                font-weight:600;padding:.7rem}}
.btn-later{{background:#1a1a1a;color:#666;border:1px solid #2a2a2a;
            font-size:.78rem;margin-top:.2rem}}
.note{{font-size:.67rem;color:#444;text-align:center;margin-top:.7rem;line-height:1.5}}
</style>
</head><body>
<div class="card">
  <div class="header">
    <div class="icon">⚡</div>
    <h1>One step to unlock full protection</h1>
    <div class="sub">You're already on this protected network</div>
  </div>
  <div class="body">

    <div class="section">Already active on your device</div>
    <div class="row row-on"><span class="mark">✓</span> DNS ad &amp; tracker blocking</div>
    <div class="row row-on"><span class="mark">✓</span> Malware &amp; phishing shield</div>
    <div class="row row-on"><span class="mark">✓</span> Discord &amp; Roblox tunnel</div>
    <div class="row row-on"><span class="mark">✓</span> Browser YouTube ads blocked</div>

    <div class="section">Unlocked by installing the certificate</div>
    <div class="row row-off"><span class="mark">→</span> YouTube <em>app</em> ad stripping</div>
    <div class="row row-off"><span class="mark">→</span> HTTPS malware download scanning</div>

    <div class="cert-box">
      <h3>Install the security certificate</h3>
      <p>One tap — we detect your device and walk you through it.
         Works like a corporate CA, fully removable at any time.</p>
      <a class="btn btn-pem" href="http://{box_ip}/install">
        ✨ &nbsp;One-Tap Install — Set Up My Device
      </a>
      <a class="btn btn-activated" href="/cert-upgrade">
        ✓ &nbsp;I've installed it — enable full protection
      </a>
    </div>

    <a class="btn btn-later" href="/upgrade-accept">
      Maybe Later — Continue Browsing &rsaquo;
    </a>
    <p class="note">This notice won't appear again on this device.</p>

  </div>
</div>
</body></html>"""


def _portal_html(box_ip: str, network_name: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome — {network_name}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#0d0d0d;color:#e0e0e0;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:1rem}}
.card{{max-width:420px;width:100%;background:#181818;border-radius:18px;
       border:1px solid #262626;overflow:hidden;
       box-shadow:0 20px 60px rgba(0,0,0,.6)}}
.header{{background:linear-gradient(150deg,#0d2b0d 0%,#111e11 100%);
         padding:2rem 1.5rem;text-align:center;
         border-bottom:1px solid #1e3a1e}}
.shield{{font-size:2.8rem;margin-bottom:.6rem}}
h1{{font-size:1.25rem;font-weight:700;color:#6ddf6d;letter-spacing:-.01em}}
.sub{{font-size:.8rem;color:#5a7a5a;margin-top:.3rem}}
.body{{padding:1.4rem}}
.feat{{display:flex;align-items:flex-start;gap:.7rem;margin-bottom:.8rem;
       padding:.8rem;background:#1e1e1e;border-radius:10px;
       border-left:3px solid #2a5a2a}}
.feat .icon{{font-size:1.3rem;flex-shrink:0;line-height:1}}
.feat h3{{font-size:.85rem;color:#d0d0d0;margin-bottom:.15rem;font-weight:600}}
.feat p{{font-size:.75rem;color:#777;line-height:1.45}}
.divider{{height:1px;background:#222;margin:.8rem 0}}
.dns-wrap{{text-align:center;margin:.9rem 0}}
.dns-label{{font-size:.68rem;color:#555;text-transform:uppercase;
            letter-spacing:.05em;margin-bottom:.3rem}}
.dns-val{{font-family:"SF Mono",Consolas,monospace;font-size:.9rem;
          color:#6ddf6d;background:#0d1a0d;border:1px solid #1e3a1e;
          border-radius:8px;padding:.45rem .8rem;display:inline-block}}
.cert-box{{background:#1a1600;border:1px solid #332a00;border-radius:10px;
           padding:.9rem;margin:.9rem 0}}
.cert-box h3{{font-size:.82rem;color:#f0c040;margin-bottom:.35rem;font-weight:600}}
.cert-box p{{font-size:.73rem;color:#888;line-height:1.4;margin-bottom:.55rem}}
.btn{{display:block;width:100%;text-align:center;padding:.6rem .8rem;
      border-radius:8px;font-size:.8rem;font-weight:500;text-decoration:none;
      margin-bottom:.4rem;cursor:pointer;border:none;transition:opacity .15s}}
.btn:hover{{opacity:.85}}
.btn-cert-ios{{background:#2a2000;color:#f0c040;border:1px solid #443200}}
.btn-cert-and{{background:#1e1e2a;color:#a0a0f0;border:1px solid #2a2a44}}
.btn-accept{{background:#1a4a1a;color:#7dff7d;border:1px solid #2a6a2a;
             font-size:.95rem;padding:.85rem;margin-top:.4rem;font-weight:600}}
.note{{font-size:.67rem;color:#444;text-align:center;margin-top:.7rem;
       line-height:1.55}}
</style>
</head><body>
<div class="card">
  <div class="header">
    <div class="shield">🛡️</div>
    <h1>Protected Network</h1>
    <div class="sub">Ad blocking · Malware shield · Always on</div>
  </div>
  <div class="body">
    <div class="feat">
      <div class="icon">🚫</div>
      <div><h3>Ads Blocked</h3>
      <p>Browser pop-ups, mobile game ads, in-app banners, and YouTube ads
         stripped network-wide.</p></div>
    </div>
    <div class="feat">
      <div class="icon">🦠</div>
      <div><h3>Malware Shield</h3>
      <p>Malicious downloads blocked before they reach your device.
         Phishing and malware domains sinkholes.</p></div>
    </div>
    <div class="feat">
      <div class="icon">🔄</div>
      <div><h3>Auto-Detaches When You Leave</h3>
      <p>DNS filtering is assigned via DHCP — scoped to this network only.
         It stops the moment you switch to another Wi-Fi or mobile data.</p></div>
    </div>
    <div class="divider"></div>
    <div class="dns-wrap">
      <div class="dns-label">Your DNS on this network</div>
      <div class="dns-val">{box_ip}</div>
    </div>
    <div class="cert-box">
      <h3>⚡ Optional: Full YouTube App Ad Blocking</h3>
      <p>The certificate lets the network also remove YouTube ads inside the
         YouTube app. One tap — we detect your device and guide you.</p>
      <a class="btn btn-cert-ios"
         href="http://{box_ip}/install">
        ✨ &nbsp;One-Tap Install — Set Up My Device
      </a>
    </div>
    <a class="btn btn-accept" href="/portal-accept">
      Got it — Continue to Internet &rsaquo;
    </a>
    <p class="note">
      Ad blocking is already active without the certificate.<br>
      This notice won't appear again on this device.
    </p>
  </div>
</div>
</body></html>"""


def _install_landing_html(box_ip: str, os_name: str) -> str:
    """
    Universal cert-install landing page. Detects the device's OS server-side
    and shows the matching one-tap method as the hero, with every other
    platform tucked into an expandable section below.
    """
    base = f"http://{box_ip}"

    # Per-OS hero blocks ------------------------------------------------------
    ios_hero = f"""
      <div class="hero">
        <div class="big">📱</div>
        <h2>Install on iPhone / iPad</h2>
        <p>One tap. Opens Apple's built-in profile installer.</p>
        <a class="cta" href="{base}/wifi-adblock.mobileconfig">Install Profile</a>
        <ol class="steps">
          <li>Tap <b>Install Profile</b> above — Safari shows
              “Profile Downloaded”.</li>
          <li>Open <b>Settings</b> → tap <b>Profile Downloaded</b> →
              <b>Install</b> (top-right), enter your passcode.</li>
          <li><b>Important:</b> go to <b>Settings → General → About →
              Certificate Trust Settings</b> and turn <b>ON</b> the switch for
              “WiFi AdBlock”.</li>
        </ol>
        <p class="warn">Step 3 is required — without it iOS won't fully trust
           the certificate and YouTube-app ad stripping stays off.</p>
      </div>"""

    macos_hero = f"""
      <div class="hero">
        <div class="big">💻</div>
        <h2>Install on Mac</h2>
        <p>Downloads a configuration profile.</p>
        <a class="cta" href="{base}/wifi-adblock.mobileconfig">Download Profile</a>
        <ol class="steps">
          <li>Open the downloaded <b>.mobileconfig</b> file.</li>
          <li><b>System Settings → General → VPN &amp; Device Management</b> →
              double-click the profile → <b>Install</b>.</li>
          <li>It's added as a trusted root automatically.</li>
        </ol>
      </div>"""

    android_hero = f"""
      <div class="hero">
        <div class="big">🤖</div>
        <h2>Install on Android</h2>
        <a class="cta" href="{base}/mitmproxy-ca-cert.cer">Download Certificate</a>
        <ol class="steps">
          <li>Tap <b>Download Certificate</b> above.</li>
          <li>Open <b>Settings</b>, search <b>“CA certificate”</b> (or
              Security → Encryption &amp; credentials → Install a certificate →
              <b>CA certificate</b>).</li>
          <li>Choose the downloaded file → confirm <b>Install anyway</b>.</li>
        </ol>
        <p class="warn">Android note: the certificate goes into the user store,
           which browsers trust but most apps (incl. the YouTube app) do not.
           DNS-level ad blocking is already protecting this device regardless —
           the cert mainly adds browser HTTPS coverage unless the phone is
           rooted.</p>
      </div>"""

    windows_hero = f"""
      <div class="hero">
        <div class="big">🪟</div>
        <h2>Install on Windows</h2>
        <a class="cta" href="{base}/mitmproxy-ca-cert.pem">Download Certificate</a>
        <ol class="steps">
          <li>Tap <b>Download Certificate</b>, then open the file.</li>
          <li>Click <b>Install Certificate</b> → <b>Local Machine</b> →
              <b>Place all certificates in the following store</b> →
              <b>Trusted Root Certification Authorities</b>.</li>
          <li>Finish → <b>Yes</b> on the security prompt.</li>
        </ol>
      </div>"""

    linux_hero = f"""
      <div class="hero">
        <div class="big">🐧</div>
        <h2>Install on Linux</h2>
        <a class="cta" href="{base}/mitmproxy-ca-cert.pem">Download Certificate</a>
        <ol class="steps">
          <li><code>sudo cp mitmproxy-ca-cert.pem
              /usr/local/share/ca-certificates/wifi-adblock.crt</code></li>
          <li><code>sudo update-ca-certificates</code></li>
        </ol>
      </div>"""

    heroes = {
        "ios": ios_hero, "macos": macos_hero, "android": android_hero,
        "windows": windows_hero, "linux": linux_hero, "chromeos": android_hero,
    }
    hero = heroes.get(os_name)
    if hero is None:
        # Unknown device — show iOS + Android + Windows together as the hero.
        hero = ios_hero + android_hero + windows_hero

    # Every platform NOT shown as the hero goes in the "other devices" drawer.
    others_order = ["ios", "macos", "android", "windows", "linux"]
    other_blocks = "".join(
        heroes[o] for o in others_order if o != os_name and o in heroes
    )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Install Protection Certificate</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#0d0d0d;color:#e0e0e0;min-height:100vh;
     display:flex;align-items:flex-start;justify-content:center;padding:1rem}}
.card{{max-width:440px;width:100%;background:#181818;border-radius:18px;
       border:1px solid #262626;overflow:hidden;margin:1rem 0;
       box-shadow:0 20px 60px rgba(0,0,0,.6)}}
.top{{background:linear-gradient(150deg,#0d2b0d 0%,#111e11 100%);
      padding:1.6rem 1.5rem;text-align:center;border-bottom:1px solid #1e3a1e}}
.top h1{{font-size:1.2rem;color:#6ddf6d;font-weight:700}}
.top p{{font-size:.78rem;color:#5a7a5a;margin-top:.3rem}}
.body{{padding:1.3rem}}
.hero{{background:#1e1e1e;border:1px solid #2a2a2a;border-radius:12px;
       padding:1.2rem;margin-bottom:1rem;text-align:center}}
.hero .big{{font-size:2.4rem;margin-bottom:.4rem}}
.hero h2{{font-size:1.05rem;color:#e8e8e8;margin-bottom:.3rem}}
.hero>p{{font-size:.78rem;color:#888;margin-bottom:.9rem}}
.cta{{display:block;width:100%;text-align:center;padding:.85rem;
      background:#1a4a1a;color:#7dff7d;border:1px solid #2a6a2a;
      border-radius:10px;font-size:.95rem;font-weight:600;text-decoration:none;
      margin-bottom:.9rem}}
.cta:hover{{opacity:.88}}
.steps{{text-align:left;margin:.4rem 0 0 1.1rem;color:#bbb}}
.steps li{{font-size:.8rem;line-height:1.5;margin-bottom:.45rem}}
.steps b{{color:#e0e0e0}}
.steps code{{background:#111;border:1px solid #2a2a2a;border-radius:5px;
             padding:.05rem .3rem;font-size:.74rem;color:#9ad}}
.warn{{font-size:.72rem;color:#d0a040;background:#1a1400;border:1px solid #332800;
       border-radius:8px;padding:.6rem;margin-top:.8rem;line-height:1.45;
       text-align:left}}
details{{margin-top:.6rem;border-top:1px solid #222;padding-top:.8rem}}
summary{{font-size:.82rem;color:#888;cursor:pointer;list-style:none}}
summary::-webkit-details-marker{{display:none}}
summary:before{{content:"▸ ";color:#555}}
details[open] summary:before{{content:"▾ "}}
.done{{margin-top:1rem}}
.done a{{display:block;text-align:center;padding:.7rem;background:#1a1a1a;
         color:#7dff7d;border:1px solid #2a5a2a;border-radius:9px;
         font-size:.82rem;font-weight:600;text-decoration:none}}
.note{{font-size:.68rem;color:#555;text-align:center;margin-top:.9rem;
       line-height:1.55}}
</style>
</head><body>
<div class="card">
  <div class="top">
    <h1>🔒 Install Protection Certificate</h1>
    <p>Unlocks YouTube-app ad removal &amp; encrypted-download scanning</p>
  </div>
  <div class="body">
    {hero}

    <div class="done">
      <a href="{base}/cert-upgrade">✓ I've installed it — enable full protection</a>
    </div>

    <details>
      <summary>Installing on a different device?</summary>
      {other_blocks}
    </details>

    <p class="note">
      This certificate only inspects traffic while you're on this Wi-Fi and is
      removable anytime. Ad blocking already works without it.
    </p>
  </div>
</div>
</body></html>"""


def _done_html() -> str:
    return """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>All Set</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0d0d0d;
     color:#e0e0e0;display:flex;align-items:center;justify-content:center;
     min-height:100vh;text-align:center;padding:1.5rem}
.card{max-width:320px;background:#181818;border-radius:18px;padding:2.5rem 2rem;
      border:1px solid #262626}
.icon{font-size:3rem;margin-bottom:1rem}
h1{color:#6ddf6d;font-size:1.3rem;margin-bottom:.6rem;font-weight:700}
p{color:#666;font-size:.82rem;line-height:1.6}
</style>
</head><body>
<div class="card">
  <div class="icon">✅</div>
  <h1>You're protected.</h1>
  <p>Ad blocking and malware shield are active.</p>
  <p style="margin-top:.8rem;font-size:.72rem;color:#444">
    Close this window and browse normally.<br>
    This notice won't appear on this device again.
  </p>
</div>
</body></html>"""


if __name__ == "__main__":
    import sys
    import socket

    box = _detect_box_ip()
    print(f"[captive-portal] Starting on 0.0.0.0:{PORTAL_PORT}  (box={box})", flush=True)

    # Warn if port 80 is already occupied
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("0.0.0.0", PORTAL_PORT))
        probe.close()
    except OSError:
        print(f"[captive-portal] ERROR: port {PORTAL_PORT} already in use.", file=sys.stderr)
        sys.exit(1)

    server = http.server.HTTPServer(("0.0.0.0", PORTAL_PORT), PortalHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
