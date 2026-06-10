"""
YouTube Ad Stripping addon for mitmproxy.

Intercepts responses from youtubei.googleapis.com, parses both JSON and
Protobuf payloads, and surgically removes ad-related fields before the
data reaches client devices.

Requires: Python >= 3.9 (mitmproxy constraint), blackboxprotobuf (optional,
          needed only for native YouTube Android/iOS app Protobuf responses).
"""

from __future__ import annotations  # makes generic aliases (tuple[], frozenset[]) work on 3.9

import json
from typing import Any

from mitmproxy import ctx, http

# ── JSON field names YouTube uses for ad delivery ────────────────────────────
AD_JSON_KEYS: frozenset[str] = frozenset({
    # Player-level ad containers
    "playerAds",
    "adSlots",
    "adBreakParams",
    "adBreakHeartbeatParams",
    "adBreaks",
    "adPlacements",
    "adSettings",
    "adMessages",
    "adPlaybackContext",
    "adPinType",
    # Companion / overlay ads
    "auxiliaryUi",
    "companionData",
    "externalVideoId",
    "engagementPanels",
    # Bumper / skip metadata
    "bumperParams",
    "skippableRenderer",
    # Ad renderer types
    "instreamVideoAdRenderer",
    "linearAdSequenceRenderer",
    "adBreakServiceRenderer",
    "adBreakHeartbeatRenderer",
    "adInfoRenderer",
    "adHoverTextButtonRenderer",
    "adPreviewRenderer",
    "confirmDialogRenderer",
    "adsConfig",
    "interstitialConfig",
    "adSlotLoggingData",
})

# ── Known Protobuf field numbers for ad data in PlayerResponse ───────────────
# Field 12 = playerAds, 13 = adSlots, 46 = adBreakParams.
# Reverse-engineered from YouTube mobile client binary + community research.
AD_PROTO_FIELDS: frozenset[int] = frozenset({12, 13, 21, 46, 58, 102})

# ── Endpoints to intercept ───────────────────────────────────────────────────
TARGET_HOST = "youtubei.googleapis.com"
TARGET_PATHS = (
    "/youtubei/v1/player",
    "/youtubei/v1/next",
    "/youtubei/v1/browse",
    "/youtubei/v1/reel/reel_watch_sequence",
)


# ─────────────────────────────────────────────────────────────────────────────
# JSON stripping
# ─────────────────────────────────────────────────────────────────────────────

def _strip_json(node: Any, depth: int = 0) -> tuple[Any, int]:
    """Recursively remove ad keys from a deserialised JSON object."""
    if depth > 40:
        return node, 0

    removed = 0

    if isinstance(node, dict):
        keys_to_drop = [k for k in node if k in AD_JSON_KEYS]
        removed += len(keys_to_drop)
        for k in keys_to_drop:
            del node[k]
        for v in node.values():
            _, n = _strip_json(v, depth + 1)
            removed += n

    elif isinstance(node, list):
        for item in node:
            _, n = _strip_json(item, depth + 1)
            removed += n

    return node, removed


# ─────────────────────────────────────────────────────────────────────────────
# Protobuf stripping
# ─────────────────────────────────────────────────────────────────────────────

def _strip_proto(message: dict, depth: int = 0) -> tuple[dict, int]:
    """Drop known ad field numbers from a blackboxprotobuf-decoded message."""
    if depth > 30:
        return message, 0

    removed = 0
    result: dict = {}

    for raw_key, value in message.items():
        field_num = int(raw_key) if isinstance(raw_key, str) and raw_key.isdigit() else raw_key
        if field_num in AD_PROTO_FIELDS:
            removed += 1
            continue

        if isinstance(value, dict):
            value, n = _strip_proto(value, depth + 1)
            removed += n
        elif isinstance(value, list):
            cleaned = []
            for item in value:
                if isinstance(item, dict):
                    item, n = _strip_proto(item, depth + 1)
                    removed += n
                cleaned.append(item)
            value = cleaned

        result[raw_key] = value

    return result, removed


def _process_protobuf(body: bytes) -> tuple[bytes, int]:
    try:
        import blackboxprotobuf  # type: ignore[import]
    except ImportError:
        ctx.log.warn("[YT-AdStrip] blackboxprotobuf not installed — protobuf stripping disabled")
        return body, 0

    try:
        message, typedef = blackboxprotobuf.decode_message(body)
        message, removed = _strip_proto(message)
        return blackboxprotobuf.encode_message(message, typedef), removed
    except Exception as exc:
        ctx.log.warn(f"[YT-AdStrip] Protobuf decode/encode failed: {exc}")
        return body, 0


# ─────────────────────────────────────────────────────────────────────────────
# mitmproxy addon
# ─────────────────────────────────────────────────────────────────────────────

class YouTubeAdStripper:
    def response(self, flow: http.HTTPFlow) -> None:
        if TARGET_HOST not in flow.request.pretty_host:
            return
        if not any(flow.request.path.startswith(p) for p in TARGET_PATHS):
            return
        if flow.response is None or flow.response.content is None:
            return

        ct = flow.response.headers.get("content-type", "").lower()

        if "json" in ct or "javascript" in ct:
            self._handle_json(flow)
        elif "protobuf" in ct or "octet-stream" in ct:
            self._handle_protobuf(flow)
        else:
            self._handle_json(flow, silent_fail=True)

    def _handle_json(self, flow: http.HTTPFlow, silent_fail: bool = False) -> None:
        try:
            data = json.loads(flow.response.content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            if not silent_fail:
                ctx.log.warn(f"[YT-AdStrip] JSON decode failed: {flow.request.pretty_url}")
            return

        data, removed = _strip_json(data)
        if removed:
            flow.response.text = json.dumps(data, separators=(",", ":"))
            ctx.log.info(
                f"[YT-AdStrip] JSON  stripped {removed:2d} ad fields  "
                f"<- {flow.request.path.split('?')[0]}"
            )

    def _handle_protobuf(self, flow: http.HTTPFlow) -> None:
        cleaned, removed = _process_protobuf(flow.response.content)
        flow.response.content = cleaned
        if removed:
            ctx.log.info(
                f"[YT-AdStrip] Proto stripped {removed:2d} ad fields  "
                f"<- {flow.request.path.split('?')[0]}"
            )


addons = [YouTubeAdStripper()]
