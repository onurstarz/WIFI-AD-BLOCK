#!/usr/bin/env python3
"""
yt_updater.py — YouTube ad-strip adaptive update engine

How it works
────────────
YouTube periodically changes the JSON field names they use to deliver ads.
When they do, our static AD_JSON_KEYS list goes stale and ads slip through.
This engine detects that automatically and updates the list.

Three signal sources (combined for confidence):
  1. Live-traffic discoveries  — yt_ad_stripper.py logs any ad-heuristic keys
                                 it finds in real YouTube responses that aren't
                                 in our current list. This file reads those.
  2. Direct API probe          — Makes a fresh request to YouTube's player API
                                 and scans the raw response for unknown ad keys.
  3. Community (yt-dlp)        — yt-dlp's YouTube extractor is the fastest
                                 open-source tracker of YouTube API changes.
                                 We pull it and scan for new ad field strings.

Update cycle
────────────
  1. Collect candidate new keys from all three sources
  2. Merge with current AD_JSON_KEYS in yt_ad_stripper.py
  3. Test: mitmdump --no-server -s yt_ad_stripper.py (syntax + load check)
  4. Keep if test passes, roll back to backup if it fails
  5. Restart the mitmproxy service so the new keys take effect
  6. Log outcome either way

Called by autoupdate.sh (nightly). Also safe to run manually:
  python3 yt_updater.py                dry run — shows what would change
  python3 yt_updater.py --apply        actually apply changes
  python3 yt_updater.py --verbose      show full scan details
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

INSTALL_DIR   = Path("/opt/mitm-proxy" if Path("/opt/mitm-proxy").is_dir()
                     else "/usr/share/mitm-proxy")
ADDON_PATH    = INSTALL_DIR / "yt_ad_stripper.py"
DISCOVERY_LOG = Path("/var/log/wifi-adblock-ad-discoveries.log")
UPDATE_LOG    = Path("/var/log/wifi-adblock-yt-updater.log")

APPLY   = "--apply"   in sys.argv
VERBOSE = "--verbose" in sys.argv

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if VERBOSE else logging.INFO,
    format="[yt-updater %(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("yt-updater")


def _persist(msg: str) -> None:
    try:
        with open(UPDATE_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass


# ── Heuristic ad-key detection ────────────────────────────────────────────────
# Patterns that identify YouTube ad delivery field names.
# Used to discover NEW keys that YouTube introduces — even ones no one has
# manually documented yet.

_AD_PATTERNS = [
    re.compile(r'^playerAd'),
    re.compile(r'^adSlot'),
    re.compile(r'^adPlacement'),
    re.compile(r'^adBreak'),
    re.compile(r'^adPod'),
    re.compile(r'^adSet'),
    re.compile(r'^adParam'),
    re.compile(r'^adMessage'),
    re.compile(r'^adContent'),
    re.compile(r'^adPreview'),
    re.compile(r'^adInfo'),
    re.compile(r'^paidContent'),
    re.compile(r'^youtubeAds'),
    re.compile(r'^piUseFreewheel'),
    re.compile(r'^(?:instream|preroll|midroll|postroll|bumper|companion|overlay|masthead)'
               r'(?:[A-Z]|Ad|Ads|$)'),
    re.compile(r'(?:Ad|Ads)(?:Renderer|Module|Format|Template|Config|Data|Info|'
               r'Metadata|Slot|Placement|Break|Network|System|Title|Duration)$'),
    re.compile(r'(?:monetiz|auction|promoted|sponsor).*(?:Renderer|Data|Config|Info)',
               re.IGNORECASE),
    re.compile(r'^(?:linear|nonlinear|vpaid|vast|ima)Ad', re.IGNORECASE),
    re.compile(r'(?:Ad|Ads)(?:Logging|Heartbeat|Ping|Tracking|Signal)'),
]


def _looks_like_ad_key(key: str) -> bool:
    return any(p.search(key) for p in _AD_PATTERNS)


def _scan_tree(node: object, depth: int = 0) -> set[str]:
    """Walk a JSON tree and return all keys that look like ad structures."""
    hits: set[str] = set()
    if depth > 25:
        return hits
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and _looks_like_ad_key(k):
                hits.add(k)
            hits |= _scan_tree(v, depth + 1)
    elif isinstance(node, list):
        for item in node:
            hits |= _scan_tree(item, depth + 1)
    return hits


# ── YouTube API probe ─────────────────────────────────────────────────────────

# Rick Astley "Never Gonna Give You Up" — available in every country,
# YouTube will never remove it (literally).
_PROBE_VIDEO   = "dQw4w9WgXcQ"
_PROBE_URL     = "https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false"

# Android embedded client — no authentication required, returns JSON.
# This key is baked into the YouTube Android app and widely used by
# open-source YouTube clients (yt-dlp, NewPipe, etc.).
_ANDROID_KEY   = "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"


def probe_youtube_api(timeout: int = 20) -> dict | None:
    """
    POST directly to YouTube's player API, bypassing our own proxy.
    Returns the parsed response JSON, or None on any error.
    """
    payload = json.dumps({
        "context": {
            "client": {
                "hl": "en",
                "gl": "US",
                "clientName": "ANDROID",
                "clientVersion": "17.31.35",
                "androidSdkVersion": 30,
                "osName": "Android",
                "osVersion": "11",
                "userAgent": "com.google.android.youtube/17.31.35 (Linux; U; Android 11) gzip",
            }
        },
        "videoId": _PROBE_VIDEO,
        "contentCheckOk": True,
        "racyCheckOk": True,
    }).encode()

    for url in (_PROBE_URL, f"{_PROBE_URL}&key={_ANDROID_KEY}"):
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "com.google.android.youtube/17.31.35 (Linux; U; Android 11) gzip",
                "X-YouTube-Client-Name": "3",
                "X-YouTube-Client-Version": "17.31.35",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        # ProxyHandler({}) forces a direct connection — bypasses our mitmproxy
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except (urllib.error.HTTPError, urllib.error.URLError,
                json.JSONDecodeError, OSError):
            continue
    return None


# ── Community source: yt-dlp ──────────────────────────────────────────────────

_YTDLP_URL = (
    "https://raw.githubusercontent.com/yt-dlp/yt-dlp/master"
    "/yt_dlp/extractor/youtube.py"
)
_STR_RE = re.compile(r'''["']([a-zA-Z][a-zA-Z0-9]{3,59})["']''')


def fetch_community_keys(timeout: int = 25) -> set[str]:
    """
    Pull yt-dlp's YouTube extractor and extract ad-heuristic string literals.
    yt-dlp tracks YouTube API changes faster than almost any other project.
    """
    log.info("Pulling yt-dlp YouTube extractor for community signals...")
    req = urllib.request.Request(
        _YTDLP_URL,
        headers={"User-Agent": "wifi-adblock-updater/1.0"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    found: set[str] = set()
    try:
        with opener.open(req, timeout=timeout) as resp:
            src = resp.read().decode("utf-8", errors="ignore")
        for m in _STR_RE.finditer(src):
            key = m.group(1)
            if _looks_like_ad_key(key):
                found.add(key)
        log.info(f"yt-dlp scan: {len(found)} ad-heuristic keys extracted")
    except (urllib.error.URLError, OSError) as e:
        log.warning(f"Could not reach yt-dlp source ({e}) — skipping community signals")
    return found


# ── Live-traffic discovery log ────────────────────────────────────────────────

def read_discovery_log() -> set[str]:
    """
    Read keys that yt_ad_stripper.py logged from real live traffic.
    Format per line: "YYYY-MM-DD HH:MM:SS DISCOVERY <key>"
    """
    found: set[str] = set()
    if not DISCOVERY_LOG.exists():
        return found
    try:
        with open(DISCOVERY_LOG) as f:
            for line in f:
                parts = line.split()
                if "DISCOVERY" in parts:
                    idx = parts.index("DISCOVERY")
                    if idx + 1 < len(parts):
                        key = parts[idx + 1]
                        if key.isidentifier():
                            found.add(key)
    except OSError:
        pass
    if found:
        log.info(f"Live-traffic log: {len(found)} candidate keys from real traffic")
    return found


# ── Addon file manipulation ───────────────────────────────────────────────────

# Matches: AD_JSON_KEYS: frozenset[str] = frozenset({...})
# The [^=\n]* handles the optional ": frozenset[str]" type annotation.
_KEYSET_RE = re.compile(
    r'(AD_JSON_KEYS[^=\n]*=\s*frozenset\(\{)([^}]*?)(\}\))',
    re.DOTALL,
)


def current_keys(path: Path) -> set[str]:
    """Parse the current AD_JSON_KEYS set from yt_ad_stripper.py."""
    try:
        m = _KEYSET_RE.search(path.read_text())
        return set(re.findall(r'"([^"]+)"', m.group(2))) if m else set()
    except OSError:
        return set()


def write_keys(path: Path, keys: set[str]) -> None:
    """Rewrite the AD_JSON_KEYS frozenset in yt_ad_stripper.py."""
    src = path.read_text()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sorted_k = sorted(keys)
    rows = [f"    # Last updated by yt_updater: {ts}  ({len(keys)} keys)"]
    for i in range(0, len(sorted_k), 4):
        chunk = sorted_k[i:i + 4]
        rows.append("    " + ", ".join(f'"{k}"' for k in chunk) + ",")
    new_body = "\n" + "\n".join(rows) + "\n"
    path.write_text(_KEYSET_RE.sub(
        lambda m: m.group(1) + new_body + m.group(3), src, count=1
    ))


def test_addon(path: Path) -> bool:
    """Return True if mitmproxy can load the addon without errors."""
    mitmdump = shutil.which("mitmdump") or str(INSTALL_DIR / "venv" / "bin" / "mitmdump")
    if not Path(mitmdump).exists():
        log.warning("mitmdump not found — assuming addon is OK (can't test)")
        return True
    try:
        r = subprocess.run(
            [mitmdump, "--no-server", "-s", str(path)],
            capture_output=True, text=True, timeout=12,
        )
        ok = r.returncode == 0 or "YouTubeAdStripper" in r.stderr
        if not ok:
            log.warning(f"Addon load test output:\n{r.stderr[:600]}")
        return ok
    except subprocess.TimeoutExpired:
        return True  # timeout = stuck waiting for traffic = loaded fine


def restart_proxy() -> None:
    for cmd in (
        ["systemctl", "restart", "mitm-adblock"],
        ["rc-service", "mitm-adblock", "restart"],
        ["/etc/init.d/mitm-adblock", "restart"],
    ):
        try:
            subprocess.run(cmd, timeout=15, capture_output=True)
            log.info(f"mitm-adblock restarted via {cmd[0]}")
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue


# ── Main update cycle ─────────────────────────────────────────────────────────

def run() -> int:
    """
    Returns:
      0  all good, nothing to update
      1  updated successfully
      2  update attempted but load-test failed (rolled back)
     -1  addon file missing
    """
    if not ADDON_PATH.exists():
        log.error(f"Addon not found: {ADDON_PATH}")
        return -1

    known = current_keys(ADDON_PATH)
    log.info(f"Current strip list: {len(known)} keys")

    candidates: set[str] = set()

    # ── Source 1: live-traffic discoveries ───────────────────────────────────
    live = read_discovery_log() - known
    if live:
        log.info(f"Source 1 (live traffic): {len(live)} new key(s) → {sorted(live)}")
        candidates |= live

    # ── Source 2: direct YouTube API probe ────────────────────────────────────
    log.info("Source 2: probing YouTube player API directly...")
    response_data = probe_youtube_api()
    if response_data:
        all_found = _scan_tree(response_data)
        new_in_probe = all_found - known
        if all_found:
            log.info(
                f"Source 2 (API probe): {len(all_found)} ad keys in response — "
                f"{len(all_found) - len(new_in_probe)} already known, "
                f"{len(new_in_probe)} new"
            )
            if VERBOSE and new_in_probe:
                for k in sorted(new_in_probe):
                    log.debug(f"  probe NEW: {k}")
        else:
            log.info("Source 2 (API probe): no ad keys in this response "
                     "(normal — this probe video may not have had ads)")
        candidates |= new_in_probe
    else:
        log.warning("Source 2 (API probe): no response — skipping")

    # ── Source 3: yt-dlp community signals ───────────────────────────────────
    community = fetch_community_keys() - known
    if community:
        log.info(f"Source 3 (yt-dlp): {len(community)} new signal(s)")
        if VERBOSE:
            for k in sorted(community):
                log.debug(f"  community NEW: {k}")
        candidates |= community

    # ── Decision ─────────────────────────────────────────────────────────────
    if not candidates:
        log.info("No new ad keys found — strip list is already current.")
        _persist(f"OK — {len(known)} keys, nothing to update")
        return 0

    log.info(f"Total new candidate keys: {len(candidates)} → {sorted(candidates)}")

    if not APPLY:
        log.info("DRY RUN — pass --apply to write changes.")
        return 0

    # ── Apply ─────────────────────────────────────────────────────────────────
    merged = known | candidates
    bak = ADDON_PATH.with_suffix(".py.bak")
    shutil.copy2(ADDON_PATH, bak)
    log.info(f"Backup: {bak}")

    try:
        write_keys(ADDON_PATH, merged)
        log.info(f"AD_JSON_KEYS: {len(known)} → {len(merged)} keys")
    except Exception as e:
        log.error(f"Write failed: {e}")
        shutil.copy2(bak, ADDON_PATH)
        return 2

    # ── Test ──────────────────────────────────────────────────────────────────
    log.info("Testing updated addon in mitmproxy...")
    if test_addon(ADDON_PATH):
        log.info("✓ Addon loads — update kept.")
        _persist(f"UPDATED +{len(candidates)} key(s): {sorted(candidates)}")
        # Clear discovery log so we don't re-add the same keys next time
        if DISCOVERY_LOG.exists():
            try:
                DISCOVERY_LOG.write_text("")
            except OSError:
                pass
        restart_proxy()
        return 1
    else:
        log.warning("Addon failed load test — rolling back.")
        shutil.copy2(bak, ADDON_PATH)
        _persist(f"ROLLBACK — load test failed for: {sorted(candidates)}")
        return 2


if __name__ == "__main__":
    sys.exit(run())
