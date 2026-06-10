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
import subprocess
import threading
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────
PORTAL_PORT  = 80
SEEN_FILE    = "/opt/mitm-proxy/seen_devices.txt"
CERT_DIR     = "/opt/mitm-proxy/certs"
NETWORK_NAME = "Protected Network"

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

        # ── Captive-portal detection probes ───────────────────────────────────
        if path in CAPTIVE_PATHS:
            if _is_seen(client_ip):
                # Returning device — satisfy the OS probe so popup never shows
                _, ctype, body = CAPTIVE_PATHS[path]
                if body is None:
                    self._send(204)
                else:
                    self._send(200, ctype, body)
            else:
                # New device — show the portal page
                self._serve_portal(client_ip)
            return

        # ── "Got it" action ───────────────────────────────────────────────────
        if path == "/portal-accept":
            _mark_seen(client_ip)
            self._send(302, headers={"Location": "/portal-done"})
            return

        if path == "/portal-done":
            self._send(200, "text/html; charset=utf-8", _done_html())
            return

        # ── Default: show portal ──────────────────────────────────────────────
        self._serve_portal(client_ip)

    def _serve_portal(self, client_ip: str):
        self._send(200, "text/html; charset=utf-8",
                   _portal_html(_detect_box_ip(), NETWORK_NAME))

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
         YouTube app. Skip this if you only use YouTube in a browser.</p>
      <a class="btn btn-cert-ios"
         href="http://{box_ip}/mitmproxy-ca-cert.pem">
        Install Certificate &nbsp;—&nbsp; iOS / macOS / Windows
      </a>
      <a class="btn btn-cert-and"
         href="http://{box_ip}/mitmproxy-ca-cert.cer">
        Install Certificate &nbsp;—&nbsp; Android (.cer)
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
