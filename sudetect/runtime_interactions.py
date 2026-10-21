"""Strict declarations and value-free observations for offline UI actions."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
import zlib


_ID = re.compile(r"[A-Za-z][A-Za-z0-9_:.-]{0,99}\Z")
_BUTTON_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,99}\Z")
_SYNTHETIC = re.compile(r"TEST_[A-Za-z0-9_-]{1,32}\Z")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_PNG_BYTES = 8 * 1024 * 1024


def validate_steps(authorization: dict):
    steps = authorization.get("ui_steps", [])
    if not isinstance(steps, list) or len(steps) > 12:
        return "invalid_ui_steps", None
    normalized = []
    assertions = {"expect_visible_ids", "expect_png_download", "expect_dom_change"}
    fields = {"click": {"action", "target_id", "target_button_class"} | assertions,
              "select": {"action", "target_id", "index"} | assertions,
              "check": {"action", "target_id", "checked"} | assertions,
              "fill": {"action", "target_id", "value"} | assertions,
              "wait": {"action", "milliseconds"} | assertions}
    for row in steps:
        if not isinstance(row, dict) or row.get("action") not in fields:
            return "invalid_ui_steps", None
        action = row["action"]
        required = {"action", "milliseconds"} if action == "wait" else {"action"}
        if action != "wait" and action != "click": required.add("target_id")
        if action == "select": required.add("index")
        if action == "check": required.add("checked")
        if action == "fill": required.add("value")
        if not required <= row.keys() or not set(row) <= fields[action]:
            return "invalid_ui_steps", None
        if action == "click" and (("target_id" in row) == ("target_button_class" in row)):
            return "invalid_ui_steps", None
        expected = row.get("expect_visible_ids", [])
        if (not isinstance(expected, list) or len(expected) > 4
                or any(not isinstance(item, str) or not _ID.fullmatch(item)
                       for item in expected) or len(set(expected)) != len(expected)):
            return "invalid_ui_steps", None
        if (not isinstance(row.get("expect_png_download", False), bool)
                or not isinstance(row.get("expect_dom_change", False), bool)):
            return "invalid_ui_steps", None
        if action == "wait":
            value = row["milliseconds"]
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2000:
                return "invalid_ui_steps", None
        else:
            target_name = row.get("target_id", row.get("target_button_class"))
            pattern = _BUTTON_CLASS if "target_button_class" in row else _ID
            if not isinstance(target_name, str) or not pattern.fullmatch(target_name):
                return "invalid_ui_steps", None
            if re.search(r"login|log-in|signin|sign-in|password|passwd|credential|auth|submit",
                         target_name, re.IGNORECASE):
                return "prohibited_ui_target", None
        if action == "select" and (isinstance(row["index"], bool)
                                   or not isinstance(row["index"], int)
                                   or not 0 <= row["index"] <= 100):
            return "invalid_ui_steps", None
        if action == "check" and not isinstance(row["checked"], bool):
            return "invalid_ui_steps", None
        if action == "fill" and (not isinstance(row["value"], str)
                                 or not _SYNTHETIC.fullmatch(row["value"])):
            return "prohibited_ui_value", None
        normalized.append({**row, "expect_visible_ids": expected.copy(),
                           "expect_png_download": row.get("expect_png_download", False),
                           "expect_dom_change": row.get("expect_dom_change", False)})
    observe = authorization.get("observe_png_download", False)
    if not isinstance(observe, bool):
        return "invalid_png_observation", None
    if any(row["expect_png_download"] for row in normalized) and not observe:
        return "png_observation_not_authorized", None
    return None, (normalized, observe)


def inspect_png_download(download, download_dir: str):
    """Read only a local browser download; never return URL, filename, or bytes."""
    url = download.url
    if not (url.startswith("blob:https://captured.invalid/")
            or url.startswith("data:image/png;base64,")):
        return {"status": "external_or_unsupported_download"}
    path = None
    try:
        path = Path(download.path())
        if not path.resolve().is_relative_to(Path(download_dir).resolve()):
            path = None
            return {"status": "png_path_outside_private_dir"}
        if path.stat().st_size > _MAX_PNG_BYTES:
            return {"status": "png_byte_limit"}
        data = path.read_bytes()
        if len(data) < 45 or data[:8] != _PNG_SIGNATURE or data[12:16] != b"IHDR":
            return {"status": "invalid_png"}
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        if not (0 < width <= 32768 and 0 < height <= 32768
                and width * height <= 100_000_000):
            return {"status": "invalid_png"}
        offset = 8
        chunks = []
        for _ in range(512):
            if offset + 12 > len(data):
                return {"status": "invalid_png"}
            length = int.from_bytes(data[offset:offset + 4], "big")
            end = offset + 12 + length
            if end > len(data):
                return {"status": "invalid_png"}
            kind = data[offset + 4:offset + 8]
            payload = data[offset + 8:end - 4]
            crc = int.from_bytes(data[end - 4:end], "big")
            if zlib.crc32(kind + payload) & 0xffffffff != crc:
                return {"status": "invalid_png"}
            chunks.append(kind)
            offset = end
            if kind == b"IEND":
                break
        if (chunks[0] != b"IHDR" or int.from_bytes(data[8:12], "big") != 13
                or b"IDAT" not in chunks or chunks[-1] != b"IEND"
                or offset != len(data)):
            return {"status": "invalid_png"}
        return {"status": "verified_png", "sha256": hashlib.sha256(data).hexdigest(),
                "byte_count": len(data), "width": width, "height": height,
                "visual_content_verified": False}
    except Exception:
        return {"status": "png_read_failed"}
    finally:
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
