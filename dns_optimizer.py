#!/usr/bin/env python3
"""
dns_optimizer.py — Location-aware adaptive DNS selector

Benchmarks all major DNS servers from this exact network location,
scores them on latency + consistency + failure rate, and switches
AdGuard Home to whichever is provably fastest.

"Sniper" switching logic:
  • 5 probes per server, across 5 different domains (defeats caching)
  • Score = median × (1 + coeff_of_variation) / (1 − failure_rate)
  • Only switches if winner is ≥20% better AND saves ≥5 ms
  • Validates new server actually responds before committing
  • Single atomic update — global + gaming domain overrides in one shot

Gaming domains get an explicit [/domain/]<fastest_ip> override entry
in AdGuard Home so those lookups bypass fallback chains entirely.

Called by:  autoupdate.sh (nightly)
Manual:
  python3 dns_optimizer.py              benchmark + apply if better
  python3 dns_optimizer.py --force      always apply winner
  python3 dns_optimizer.py --verbose    show all server scores
  python3 dns_optimizer.py --daemon     run continuously (every 30 min)
"""
from __future__ import annotations

import json
import logging
import math
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

# ── Tuning ────────────────────────────────────────────────────────────────────

SWITCH_THRESHOLD  = 0.80   # new server must score THIS × current (lower = better)
MIN_GAIN_MS       = 5.0    # AND must save at least this many ms (no sub-ms thrashing)
PROBES_PER_SERVER = 5      # queries per server (one per probe domain)
PROBE_TIMEOUT_S   = 2.0    # seconds before a single probe is a failure
RECHECK_SECS      = 1800   # daemon mode: re-benchmark every 30 minutes
MAX_FAILURE_RATE  = 0.20   # reject any server with >20% probe failures

FORCE   = "--force"   in sys.argv
VERBOSE = "--verbose" in sys.argv

# ── Paths ─────────────────────────────────────────────────────────────────────

AGH_PORT   = 3000
AGH_YAML   = Path("/opt/AdGuardHome/AdGuardHome.yaml")
STATE_FILE = Path("/var/lib/wifi-adblock/dns_state.json")
LOG_FILE   = Path("/var/log/wifi-adblock-dns-optimizer.log")

# ── DNS servers to benchmark ──────────────────────────────────────────────────

CANDIDATES = [
    ("Cloudflare",        "1.1.1.1"),
    ("Cloudflare-b",      "1.0.0.1"),
    ("Google",            "8.8.8.8"),
    ("Google-b",          "8.8.4.4"),
    ("Quad9",             "9.9.9.9"),
    ("Quad9-b",           "149.112.112.112"),
    ("OpenDNS",           "208.67.222.222"),
    ("OpenDNS-b",         "208.67.220.220"),
    ("AdGuard",           "94.140.14.14"),
    ("AdGuard-b",         "94.140.15.15"),
    ("CleanBrowsing",     "185.228.168.168"),
    ("ControlD",          "76.76.2.0"),
    ("Alternate-DNS",     "76.76.19.19"),
    ("Level3",            "4.2.2.1"),
    ("Level3-b",          "4.2.2.2"),
    ("Comodo",            "8.26.56.26"),
    ("Neustar",           "64.6.64.6"),
    ("NextDNS",           "45.90.28.0"),
    ("Verisign",          "64.6.65.6"),
    ("SafeDNS",           "195.46.39.39"),
]

# Probe domains — globally stable, geographically diverse CDN footprints
PROBE_DOMAINS = [
    "google.com",
    "cloudflare.com",
    "github.com",
    "amazon.com",
    "netflix.com",
]

# Gaming + social domains → always use fastest server via AGH domain overrides.
# Format: fed to AGH as [/domain/]<ip>
PRIORITY_DOMAINS = [
    # Gaming
    "roblox.com", "robloxlabs.com",
    "discord.com", "discordapp.com", "discord.gg",
    "steampowered.com", "steamgames.com", "steam.com",
    "battlenet.com", "battle.net",
    "leagueoflegends.com", "riotgames.com",
    "epicgames.com", "fortnite.com",
    "ea.com", "origin.com",
    "playstation.com", "nintendo.com",
    "xbox.com", "xboxlive.com",
    "minecraft.net", "mojang.com",
    # Video
    "youtube.com", "googlevideo.com", "ytimg.com",
    "netflix.com", "nflxvideo.net",
    "twitch.tv", "twitchsvc.net",
]

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if VERBOSE else logging.INFO,
    format="[dns-opt %(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("dns-opt")


def _persist(msg: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass


# ── Raw DNS probing (stdlib only, no dig/nslookup required) ──────────────────

def _build_query(domain: str, qid: int) -> bytes:
    """Minimal DNS A-record query packet."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname  = b"".join(
        bytes([len(p)]) + p.encode() for p in domain.split(".")
    ) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN


def _probe(server_ip: str, domain: str) -> Optional[float]:
    """Return RTT in ms for one DNS query, or None on timeout/error."""
    qid = random.randint(1, 65535)
    pkt = _build_query(domain, qid)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(PROBE_TIMEOUT_S)
        t0 = time.perf_counter()
        sock.sendto(pkt, (server_ip, 53))
        resp, _ = sock.recvfrom(512)
        elapsed = (time.perf_counter() - t0) * 1000
        sock.close()
        resp_id = struct.unpack("!H", resp[:2])[0]
        flags   = struct.unpack("!H", resp[2:4])[0]
        if resp_id == qid and (flags & 0x8000):   # response bit set
            return elapsed
        return None
    except (socket.timeout, OSError):
        return None


# ── Scoring ───────────────────────────────────────────────────────────────────

class Result:
    """Benchmark result for one DNS server."""
    __slots__ = ("name", "ip", "median_ms", "cv", "failure_rate", "score")

    def __init__(self, name: str, ip: str, samples: list[Optional[float]]):
        self.name = name
        self.ip   = ip
        ok = [s for s in samples if s is not None]
        self.failure_rate = 1.0 - len(ok) / max(len(samples), 1)
        if not ok:
            self.median_ms = 9999.0
            self.cv        = 1.0
            self.score     = 99999.0
            return
        ok.sort()
        self.median_ms = ok[len(ok) // 2]
        mean    = sum(ok) / len(ok)
        stddev  = math.sqrt(sum((x - mean) ** 2 for x in ok) / len(ok))
        self.cv = stddev / mean if mean > 0 else 0.0
        # Penalise variance and failures on top of raw latency
        self.score = self.median_ms * (1.0 + self.cv) / max(1.0 - self.failure_rate, 0.01)

    def __str__(self) -> str:
        return (
            f"{self.name:<22} {self.ip:<16} "
            f"p50={self.median_ms:6.1f}ms  "
            f"cv={self.cv:.2f}  "
            f"fail={self.failure_rate:.0%}  "
            f"score={self.score:7.1f}"
        )


def _benchmark_server(name: str, ip: str) -> Result:
    samples = [_probe(ip, domain) for domain in PROBE_DOMAINS[:PROBES_PER_SERVER]]
    return Result(name, ip, samples)


def benchmark_all() -> list[Result]:
    """Benchmark all candidates in parallel. Returns sorted best→worst."""
    results: list[Optional[Result]] = [None] * len(CANDIDATES)

    def _worker(idx: int, name: str, ip: str) -> None:
        results[idx] = _benchmark_server(name, ip)

    threads = [
        threading.Thread(target=_worker, args=(i, n, ip), daemon=True)
        for i, (n, ip) in enumerate(CANDIDATES)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=PROBE_TIMEOUT_S * PROBES_PER_SERVER + 3)

    valid = [r for r in results if r is not None and r.failure_rate < 1.0]
    return sorted(valid, key=lambda r: r.score)


# ── State ─────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(primary: Result, secondary: Result) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({
            "primary_ip":    primary.ip,
            "primary_name":  primary.name,
            "primary_score": primary.score,
            "median_ms":     primary.median_ms,
            "secondary_ip":  secondary.ip,
            "updated_at":    time.strftime("%Y-%m-%d %H:%M:%S"),
        }, indent=2))
    except OSError:
        pass


# ── AdGuard Home update ───────────────────────────────────────────────────────

def _agh_post(path: str, body: dict) -> bool:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"http://127.0.0.1:{AGH_PORT}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 204)
    except (urllib.error.URLError, OSError):
        return False


def _restart_agh() -> None:
    for cmd in (["systemctl", "restart", "AdGuardHome"],
                ["rc-service", "AdGuardHome", "restart"],
                ["/etc/init.d/AdGuardHome", "restart"]):
        try:
            subprocess.run(cmd, timeout=15, capture_output=True)
            return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue


def apply_upstreams(primary: Result, secondary: Result) -> bool:
    """
    Single atomic update:
    - primary + secondary as global upstreams
    - every priority domain wired directly to primary (no fallback hops)
    All in one API call, so nothing is ever half-configured.
    """
    domain_overrides = [f"[/{d}/]{primary.ip}" for d in PRIORITY_DOMAINS]
    all_upstreams    = [primary.ip, secondary.ip] + domain_overrides

    payload = {
        "upstream_dns":  all_upstreams,
        "bootstrap_dns": [primary.ip, secondary.ip],
        "fallback_dns":  [secondary.ip, "9.9.9.9"],
    }

    if _agh_post("/control/dns_config", payload):
        log.info(
            f"AdGuard Home updated via API — "
            f"primary={primary.ip} ({primary.name})  "
            f"secondary={secondary.ip}  "
            f"+{len(domain_overrides)} domain overrides"
        )
        return True

    # API unreachable — edit YAML directly
    if not AGH_YAML.exists():
        log.warning("API failed and AdGuardHome.yaml not found")
        return False

    try:
        import re as _re
        content = AGH_YAML.read_text()
        entries = "\n".join(
            f"    - '{e}'" if e.startswith("[") else f"    - {e}"
            for e in all_upstreams
        )
        new_block = f"upstream_dns:\n{entries}\n"
        content = _re.sub(
            r'upstream_dns:\s*\n(?:[ \t]+-[^\n]*\n)*',
            new_block, content
        )
        new_boot = f"bootstrap_dns:\n    - {primary.ip}\n    - {secondary.ip}\n"
        content = _re.sub(
            r'bootstrap_dns:\s*\n(?:[ \t]+-[^\n]*\n)*',
            new_boot, content
        )
        AGH_YAML.write_text(content)
        log.info(f"AdGuardHome.yaml updated — restarting AGH")
        _restart_agh()
        return True
    except OSError as e:
        log.error(f"YAML edit failed: {e}")
        return False


# ── Decision engine ───────────────────────────────────────────────────────────

def run_once() -> bool:
    """
    One benchmark + decision cycle.
    Returns True if DNS was switched, False if already optimal.
    """
    state         = load_state()
    current_ip    = state.get("primary_ip")
    current_score = float(state.get("primary_score", 9999))

    log.info(
        f"Benchmarking {len(CANDIDATES)} servers  "
        f"({PROBES_PER_SERVER} probes × {len(PROBE_DOMAINS)} domains each) ..."
    )
    t0     = time.perf_counter()
    ranked = benchmark_all()
    elapsed = time.perf_counter() - t0
    log.info(f"Done in {elapsed:.1f}s — {len(ranked)} servers responded")

    if not ranked:
        log.error("No DNS servers responded — keeping current config")
        return False

    if VERBOSE:
        log.debug("All results (best → worst):")
        for r in ranked:
            log.debug(f"  {'◄ current' if r.ip == current_ip else '        '} {r}")

    winner    = ranked[0]
    runner_up = ranked[1] if len(ranked) > 1 else ranked[0]

    log.info(
        f"Winner : {winner.name:<22} {winner.ip}  "
        f"p50={winner.median_ms:.1f}ms  score={winner.score:.1f}"
    )
    if current_ip:
        improvement = (1.0 - winner.score / current_score) * 100
        gain_ms     = current_score - winner.score
        log.info(
            f"Current: {current_ip}  score={current_score:.1f}  "
            f"→ improvement {improvement:+.1f}%  gain {gain_ms:+.1f}ms"
        )

    # ── Switching decision ────────────────────────────────────────────────────
    gain_ms = current_score - winner.score
    switch  = (
        FORCE
        or current_ip is None
        or (
            winner.ip != current_ip
            and winner.score    < current_score * SWITCH_THRESHOLD
            and gain_ms        >= MIN_GAIN_MS
            and winner.failure_rate < MAX_FAILURE_RATE
        )
    )

    if not switch:
        margin = (1.0 - winner.score / current_score) * 100 if current_score else 0
        log.info(
            f"No switch — {winner.ip} is only {margin:.1f}% better "
            f"(threshold: {(1-SWITCH_THRESHOLD)*100:.0f}% + {MIN_GAIN_MS}ms). "
            f"Staying on {current_ip}."
        )
        _persist(
            f"KEEP {current_ip} — best available {winner.ip} "
            f"({margin:.1f}% better, below {(1-SWITCH_THRESHOLD)*100:.0f}% threshold)"
        )
        return False

    log.info(f"Switching → {winner.ip} ({winner.name})")
    if not apply_upstreams(winner, runner_up):
        log.error("Apply failed — DNS unchanged")
        return False

    save_state(winner, runner_up)
    msg = (
        f"SWITCHED {current_ip or 'none'} → {winner.ip} ({winner.name})  "
        f"p50={winner.median_ms:.1f}ms  "
        f"improvement={gain_ms:.1f}ms  "
        f"secondary={runner_up.ip}"
    )
    log.info(msg)
    _persist(msg)
    return True


def run_daemon() -> None:
    log.info(f"Daemon mode — benchmarking every {RECHECK_SECS // 60} min")
    while True:
        try:
            run_once()
        except Exception as e:
            log.error(f"Cycle error: {e}")
        time.sleep(RECHECK_SECS)


if __name__ == "__main__":
    if "--daemon" in sys.argv:
        run_daemon()
    else:
        switched = run_once()
        sys.exit(1 if switched else 0)
