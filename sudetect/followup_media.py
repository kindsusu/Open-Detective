"""Bounded continuation of OCR on already captured inline image bytes.

Only value-free counts and signal codes leave this module. A completed OCR
pass does not certify visual content, barcodes or image metadata.
"""
from __future__ import annotations

import math
import time

from .media_review import _INLINE_IMAGE, analyze_inline_images

MAX_FOLLOWUP_BODY_BYTES = 128 * 1024 * 1024
MAX_FOLLOWUP_DECODED_BYTES = 512 * 1024 * 1024


def review_inline_media(body: bytes, *, max_seconds: float = 300.0,
                        max_total_decoded_bytes: int = MAX_FOLLOWUP_DECODED_BYTES,
                        max_pixels: int = 40_000_000) -> dict:
    """Resume every inline image within an explicit time and aggregate budget.

    ``next_index`` is an exact ordinal in this captured body, so a partial
    result can be distinguished from full OCR coverage. Image visual review
    remains pending even when every OCR call completed.
    """
    if not isinstance(body, bytes):
        raise TypeError("inline media body must be bytes")
    if type(max_total_decoded_bytes) is not int or not 1 <= max_total_decoded_bytes <= MAX_FOLLOWUP_DECODED_BYTES:
        raise ValueError("invalid aggregate decoded byte limit")
    if type(max_pixels) is not int or not 1 <= max_pixels <= 100_000_000:
        raise ValueError("invalid followup pixel limit")
    if not isinstance(max_seconds, (float, int)) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError("invalid followup time limit")
    if len(body) > MAX_FOLLOWUP_BODY_BYTES:
        return {"inline_images_found": None, "inline_images_examined": 0,
                "inline_images_remaining": None, "next_index": 0,
                "ocr_completed": 0, "decoded_bytes_examined": 0,
                "signal_counts": {}, "pending_reviews": ["followup_inline_body_byte_limit"],
                "ocr_coverage_complete": False, "visual_review_complete": False}
    deadline = time.monotonic() + max_seconds
    found = sum(1 for _ in _INLINE_IMAGE.finditer(body))
    next_index = completed = decoded = 0
    signals: dict[str, int] = {}
    pending: set[str] = set()
    while True:
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            pending.add("inline_image_time_limit")
            break
        remaining_bytes = max_total_decoded_bytes - decoded
        if remaining_bytes <= 0:
            pending.add("inline_image_byte_limit")
            break
        batch = analyze_inline_images(
            body, start_index=next_index, max_images=4096,
            max_total_decoded_bytes=remaining_bytes,
            max_seconds=min(remaining_time, 300.0), max_pixels=max_pixels,
            continue_sensitive_review=True)
        found = batch["inline_images_found"]
        previous = next_index
        next_index = batch["inline_images_next_index"]
        completed += batch["ocr_completed"]
        decoded += batch["inline_decoded_bytes_examined"]
        for code, count in batch["signal_counts"].items():
            signals[code] = signals.get(code, 0) + count
        pending.update(reason for reason in batch["pending_reviews"]
                       if reason != "inline_image_count_or_budget_limit")
        if next_index >= found:
            pending.discard("inline_image_time_limit")
            break
        if next_index == previous or "inline_image_byte_limit" in pending:
            break
    remaining = max(0, found - next_index)
    if remaining:
        pending.add("inline_image_ocr_unexamined")
    if completed < found:
        pending.add("inline_image_ocr_incomplete")
    if found:
        pending.add("image_visual_and_metadata_review_required")
    return {"inline_images_found": found, "inline_images_examined": next_index,
            "inline_images_remaining": remaining, "next_index": next_index,
            "ocr_completed": completed, "decoded_bytes_examined": decoded,
            "signal_counts": dict(sorted(signals.items())),
            "pending_reviews": sorted(pending),
            "ocr_coverage_complete": completed == found and remaining == 0,
            "visual_review_complete": not bool(found)}
