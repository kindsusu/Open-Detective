"""Bounded, offline raster-image OCR with value-free classifier output.

OCR is an optional aid to image review. A successful OCR pass cannot establish
that every visible symbol, diagram, barcode, or embedded metadata was understood.
No source pixels or recognized text are written to disk or returned to callers.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
import copy
import hashlib
import importlib.util
import math
import re
import shutil
import subprocess
import sys
import time

from .classifiers import analyze


def analyze_svg(body: bytes, *, capture_complete: bool = True, max_bytes: int = 8_388_608) -> dict:
    """Inspect vector source without rendering, resolving entities, or running scripts."""
    import xml.etree.ElementTree as ET
    report = {"media_type": "svg", "content": "NOT_INSPECTED", "signals": [],
              "analysis_complete": False, "text_analysis_complete": False,
              "image_review_complete": False, "ocr_state": "not_applicable_vector_source",
              "pending_reviews": []}
    if not capture_complete or len(body) > max_bytes:
        report["pending_reviews"].append("svg_capture_or_byte_limit")
        return report
    try:
        source = body.decode("utf-8", "strict")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", source, re.I):
            raise ValueError("entity declarations not inspected")
        root = ET.fromstring(source)
        if root.tag.rsplit("}", 1)[-1].lower() != "svg":
            raise ValueError("not SVG")
    except (ValueError, UnicodeError, ET.ParseError, RecursionError):
        report["pending_reviews"].append("svg_parse_or_entity_review")
        return report
    classification = analyze(body, "text/plain", max_bytes=max_bytes).report
    report.update(content=classification["content"], signals=classification["signals"],
                  text_analysis_complete=classification["text_analysis_complete"])
    report["pending_reviews"].extend(classification.get("pending_reviews", []))
    report["pending_reviews"].append("svg_visual_review_required")
    if re.search(r"(?:\bhref\s*=|<\s*(?:script|foreignObject)\b)", source, re.I):
        report["pending_reviews"].append("svg_active_or_linked_content_unexamined")
    return report

DEFAULT_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_BYTES = 32 * 1024 * 1024
DEFAULT_PIXELS = 25_000_000
MAX_OCR_TEXT_BYTES = 262_144
_OCR_CACHE: OrderedDict[tuple, dict] = OrderedDict()
_OCR_CACHE_LIMIT = 2048
_INLINE_IMAGE = re.compile(rb"data:image/(?:png|jpe?g|webp|gif|avif|bmp|tiff?|x-icon|vnd\.microsoft\.icon);base64,", re.I)
_BASE64_PAYLOAD = re.compile(rb"[A-Za-z0-9+/=]+")


def _image_header(body: bytes) -> tuple[str, int, int] | None:
    """Identify supported formats and dimensions without decoding image pixels."""
    if len(body) >= 24 and body.startswith(b"\x89PNG\r\n\x1a\n") and body[12:16] == b"IHDR":
        return "png", int.from_bytes(body[16:20], "big"), int.from_bytes(body[20:24], "big")
    if len(body) >= 10 and body[:6] in (b"GIF87a", b"GIF89a"):
        return "gif", int.from_bytes(body[6:8], "little"), int.from_bytes(body[8:10], "little")
    if len(body) >= 20 and body.startswith(b"RIFF") and body[8:12] == b"WEBP":
        chunk = body[12:16]
        if chunk == b"VP8X" and len(body) >= 30:
            return "webp", 1 + int.from_bytes(body[24:27], "little"), 1 + int.from_bytes(body[27:30], "little")
        if chunk == b"VP8 " and len(body) >= 30 and body[23:26] == b"\x9d\x01\x2a":
            return "webp", int.from_bytes(body[26:28], "little") & 0x3fff, int.from_bytes(body[28:30], "little") & 0x3fff
        if chunk == b"VP8L" and len(body) >= 25 and body[20] == 0x2f:
            bits = int.from_bytes(body[21:25], "little")
            return "webp", 1 + (bits & 0x3fff), 1 + ((bits >> 14) & 0x3fff)
    if not body.startswith(b"\xff\xd8"):
        return None
    offset = 2
    # JPEG can carry large EXIF blocks. Bounds are checked before every read.
    while offset + 4 <= len(body):
        if body[offset] != 0xff:
            return None
        while offset < len(body) and body[offset] == 0xff:
            offset += 1
        if offset >= len(body):
            return None
        marker = body[offset]
        offset += 1
        if marker in {0xd9, 0xda}:
            return None
        if marker in {0x01, *range(0xd0, 0xd8)}:
            continue
        if offset + 2 > len(body):
            return None
        length = int.from_bytes(body[offset:offset + 2], "big")
        if length < 2 or offset + length > len(body):
            return None
        if marker in {0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf}:
            if length < 7:
                return None
            return "jpeg", int.from_bytes(body[offset + 5:offset + 7], "big"), int.from_bytes(body[offset + 3:offset + 5], "big")
        offset += length
    return None


def analyze_image(body: bytes, content_type: str = "", *, capture_complete: bool = True,
                  max_bytes: int = DEFAULT_IMAGE_BYTES, max_pixels: int = DEFAULT_PIXELS,
                  max_seconds: float = 45.0, tesseract_path: str | None = None,
                  language: str = "eng+kor") -> dict:
    """Run optional local OCR; return only sanitized signals and coverage states.

``tesseract_path`` must name a trusted local executable; callers may omit it to
use an executable already on PATH. The OCR subprocess receives bytes on stdin,
has a deadline, and may make no HTTP requests through this module. Missing OCR
dependencies, size limits and extraction failures stay explicitly incomplete.
"""
    if not isinstance(body, bytes):
        raise TypeError("image body must be bytes")
    if not 1 <= max_bytes <= MAX_IMAGE_BYTES or not 1 <= max_pixels <= 100_000_000:
        raise ValueError("invalid image analysis limit")
    if not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError("invalid image OCR timeout")
    if not language or len(language) > 64 or not all(ch.isascii() and (ch.isalnum() or ch in "_+-") for ch in language):
        raise ValueError("invalid OCR language")
    started = time.monotonic()
    header = _image_header(body)
    report = {
        "media_type": header[0] if header else "unknown",
        "dimensions": {"width": header[1], "height": header[2]} if header else None,
        "capture_input_complete": bool(capture_complete),
        "bytes_examined": min(len(body), max_bytes),
        "content": "NOT_INSPECTED", "signals": [], "ocr_state": "not_run",
        "ocr_text_bytes": None, "ocr_language_requested": language,
        "text_analysis_complete": False, "image_review_complete": False,
        "analysis_complete": False, "pending_reviews": [],
        "automated_sensitivity_is_provisional": True,
    }
    pending = report["pending_reviews"]
    if not capture_complete:
        pending.append("capture_incomplete")
    if len(body) > max_bytes:
        pending.append("image_byte_limit")
    if header is not None and (header[1] < 1 or header[2] < 1 or header[1] * header[2] > max_pixels):
        pending.append("image_pixel_limit")
    if pending:
        return report
    windows_available = tesseract_path is None and _windows_ocr_available()
    rapidocr_available = (tesseract_path is None and not windows_available and
                          importlib.util.find_spec("rapidocr_onnxruntime") is not None)
    executable = None if windows_available or rapidocr_available else tesseract_path or shutil.which("tesseract")
    backend = ("windows_ocr" if windows_available else "rapidocr_onnxruntime" if rapidocr_available
               else "tesseract" if executable else "unavailable")
    cache_key = (hashlib.sha256(body).digest(), backend, executable, language,
                 max_bytes, max_pixels, bool(capture_complete))
    cached = _OCR_CACHE.get(cache_key)
    if cached is not None:
        _OCR_CACHE.move_to_end(cache_key)
        return copy.deepcopy(cached)
    ocr_body = body
    needs_decoder = (header is None or header[0] == "gif" or
                     (header[0] == "webp" and len(body) > 20 and body[12:16] == b"VP8X" and body[20] & 0x02))
    if needs_decoder:
        if importlib.util.find_spec("PIL") is None:
            pending.append("image_decoder_unavailable")
            return report
        from .documents import _run_isolated
        status, prepared = _run_isolated(_pillow_prepare_worker,
            (body, max_pixels, max_bytes), min(max_seconds, 15.0), redact_result=False)
        if status != "ok" or not prepared or not prepared.get("valid"):
            pending.append("image_decode_time_limit" if status == "timeout" else "unsupported_or_invalid_image")
            return report
        report["media_type"] = prepared["media_type"]
        report["dimensions"] = prepared["dimensions"]
        report["image_frames_total"] = prepared["frames_total"]
        report["image_frames_examined"] = 0
        if prepared.get("limit"):
            pending.append(prepared["limit"])
            return report
        ocr_body = prepared["ocr_body"]
        if prepared["frames_total"] > 1:
            pending.append("image_unexamined_frames")
        if prepared["media_type"] == "ico":
            pending.append("image_multi_resolution_unexamined")
    elif header[0] == "png" and b"acTL" in body[:min(len(body), 1_048_576)]:
        pending.append("image_animation_frames_unexamined")
    remaining = max_seconds - (time.monotonic() - started)
    if remaining <= 0:
        pending.append("image_decode_time_limit")
        return report
    if windows_available or rapidocr_available:
        from .documents import _run_isolated
        worker = _windows_ocr_worker if windows_available else _rapidocr_worker
        args = (ocr_body, language) if windows_available else (ocr_body,)
        status, extracted = _run_isolated(worker, args, remaining)
        report["ocr_backend"] = backend
        if status == "ok" and extracted and extracted.get("ocr_state") == "completed":
            report.update(extracted)
            if "image_frames_examined" in report:
                report["image_frames_examined"] = 1
            pending.extend(extracted.get("pending_reviews", []))
            if rapidocr_available and "kor" in language.casefold().split("+"):
                pending.append("ocr_requested_language_not_covered")
            pending.append("image_visual_and_metadata_review_required")
            report["pending_reviews"] = sorted(set(pending))
            _cache_completed(cache_key, report)
            return report
        report["ocr_state"] = "timeout" if status == "timeout" else "failed"
        pending.append("ocr_time_limit" if status == "timeout" else "ocr_worker_failed")
        return report
    if not executable:
        pending.append("ocr_engine_unavailable")
        return report
    report["ocr_backend"] = "tesseract"
    try:
        completed = subprocess.run(
            [executable, "stdin", "stdout", "-l", language],
            input=ocr_body, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=remaining, check=False,
        )
    except subprocess.TimeoutExpired:
        report["ocr_state"] = "timeout"
        pending.append("ocr_time_limit")
        return report
    except (OSError, ValueError):
        report["ocr_state"] = "failed"
        pending.append("ocr_worker_failed")
        return report
    if completed.returncode:
        report["ocr_state"] = "failed"
        pending.append("ocr_worker_failed_or_language_unavailable")
        return report
    report["ocr_state"] = "completed"
    if "image_frames_examined" in report:
        report["image_frames_examined"] = 1
    report["ocr_text_bytes"] = len(completed.stdout)
    if len(completed.stdout) > MAX_OCR_TEXT_BYTES:
        pending.append("ocr_text_byte_limit")
        return report
    classification = analyze(completed.stdout, "text/plain", max_bytes=MAX_OCR_TEXT_BYTES).report
    report["content"] = classification["content"]
    report["signals"] = classification["signals"]
    report["text_analysis_complete"] = bool(classification["analysis_complete"])
    pending.extend(classification.get("pending_reviews", []))
    # OCR is only a text recognition pass. Even perfect OCR cannot certify visual
    # content, QR codes, all text, or embedded metadata in a public image.
    pending.append("image_visual_and_metadata_review_required")
    _cache_completed(cache_key, report)
    return report


def _cache_completed(key: tuple, report: dict) -> None:
    if report.get("ocr_state") != "completed" or not report.get("text_analysis_complete"):
        return
    _OCR_CACHE[key] = copy.deepcopy(report)
    _OCR_CACHE.move_to_end(key)
    if len(_OCR_CACHE) > _OCR_CACHE_LIMIT:
        _OCR_CACHE.popitem(last=False)


def _pillow_prepare_worker(body: bytes, max_pixels: int, max_bytes: int) -> dict:
    """Decode metadata and the first frame in a time-limited process."""
    from io import BytesIO
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = max_pixels
    with Image.open(BytesIO(body)) as picture:
        width, height = picture.size
        media_type = (picture.format or "unknown").casefold()
        frames = int(getattr(picture, "n_frames", 1))
        result = {"valid": True, "media_type": media_type,
                  "dimensions": {"width": width, "height": height},
                  "frames_total": frames, "ocr_body": None, "limit": None}
        if width < 1 or height < 1 or width * height > max_pixels:
            result["limit"] = "image_pixel_limit"
            return result
        picture.seek(0)
        projection = picture.convert("RGB")
        output = BytesIO()
        projection.save(output, format="PNG")
        if output.tell() > max_bytes:
            result["limit"] = "image_conversion_byte_limit"
            return result
        result["ocr_body"] = output.getvalue()
        return result


def _rapidocr_worker(body: bytes) -> dict:
    """Isolated worker: raw recognized text is confined to this process."""
    from rapidocr_onnxruntime import RapidOCR

    rows, _ = RapidOCR()(body)
    text = "\n".join(str(row[1]) for row in (rows or []) if len(row) >= 2)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_OCR_TEXT_BYTES:
        return {"ocr_state": "completed", "ocr_text_bytes": len(encoded),
                "pending_reviews": ["ocr_text_byte_limit"]}
    classified = analyze(encoded, "text/plain", max_bytes=MAX_OCR_TEXT_BYTES).report
    return {"ocr_state": "completed", "ocr_text_bytes": len(encoded),
            "content": classified["content"], "signals": classified["signals"],
            "text_analysis_complete": bool(classified["analysis_complete"]),
            "pending_reviews": classified.get("pending_reviews", [])}


def _windows_ocr_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return importlib.util.find_spec("winrt.windows.media.ocr") is not None
    except (ImportError, ModuleNotFoundError):
        return False


def _windows_ocr_worker(body: bytes, language: str) -> dict:
    """Use installed Windows OCR language packs in an isolated process."""
    import asyncio
    from winrt.windows.globalization import Language
    from winrt.windows.graphics.imaging import BitmapDecoder
    from winrt.windows.media.ocr import OcrEngine
    from winrt.windows.storage.streams import DataWriter, InMemoryRandomAccessStream

    async def recognize():
        stream = InMemoryRandomAccessStream()
        writer = DataWriter(stream)
        writer.write_bytes(body)
        await writer.store_async()
        writer.detach_stream()
        stream.seek(0)
        decoder = await BitmapDecoder.create_async(stream)
        bitmap = await decoder.get_software_bitmap_async()
        available = {item.language_tag.casefold(): item.language_tag
                     for item in OcrEngine.available_recognizer_languages}
        requested = ["en-US" if item == "eng" else "ko" if item == "kor" else item
                     for item in language.casefold().split("+")]
        texts = []
        used = []
        for tag in requested:
            actual = available.get(tag.casefold())
            if not actual:
                continue
            engine = OcrEngine.try_create_from_language(Language(actual))
            if engine is None:
                continue
            observed = await engine.recognize_async(bitmap)
            texts.extend(line.text for line in observed.lines)
            used.append(actual)
        bitmap.close()
        writer.close()
        stream.close()
        return texts, requested, used

    texts, requested, used = asyncio.run(recognize())
    if not used:
        return {"ocr_state": "failed", "pending_reviews": ["ocr_requested_language_not_covered"]}
    # Multiple language engines may read the same visible line. Count a line
    # once, without exposing its value or retaining it beyond this worker.
    encoded = "\n".join(dict.fromkeys(texts)).encode("utf-8")
    pending = [] if len(used) == len(requested) else ["ocr_requested_language_not_covered"]
    if len(encoded) > MAX_OCR_TEXT_BYTES:
        return {"ocr_state": "completed", "ocr_text_bytes": len(encoded),
                "ocr_languages_used": used,
                "pending_reviews": pending + ["ocr_text_byte_limit"]}
    classified = analyze(encoded, "text/plain", max_bytes=MAX_OCR_TEXT_BYTES).report
    return {"ocr_state": "completed", "ocr_text_bytes": len(encoded),
            "ocr_languages_used": used,
            "content": classified["content"], "signals": classified["signals"],
            "text_analysis_complete": bool(classified["analysis_complete"]),
            "pending_reviews": pending + classified.get("pending_reviews", [])}


def analyze_inline_images(body: bytes, *, max_images: int = 128,
                          max_total_decoded_bytes: int = 32 * 1024 * 1024,
                          max_seconds: float = 30.0,
                          tesseract_path: str | None = None,
                          language: str = "eng+kor") -> dict:
    """Inspect bounded data-URL images without returning decoded data or OCR text."""
    if not 1 <= max_images <= 4096 or not 1 <= max_total_decoded_bytes <= 512 * 1024 * 1024:
        raise ValueError("invalid inline image limit")
    if not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError("invalid inline image timeout")
    found = sum(1 for _ in _INLINE_IMAGE.finditer(body))
    result = {"inline_images_found": found, "inline_images_examined": 0,
              "inline_images_unexamined": found,
              "ocr_completed": 0, "signal_counts": {}, "signals": [],
              "content": "NOT_INSPECTED", "pending_reviews": [],
              "analysis_complete": not found}
    if not found:
        return result
    pending = result["pending_reviews"]
    deadline = time.monotonic() + max_seconds
    consumed = 0
    for count, match in enumerate(_INLINE_IMAGE.finditer(body)):
        if count >= max_images:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pending.append("inline_image_time_limit")
            break
        payload = _BASE64_PAYLOAD.match(body, match.end())
        end = payload.end() if payload else match.end()
        encoded = body[match.end():end]
        if not encoded or len(encoded) > (max_total_decoded_bytes - consumed) * 4 // 3 + 4:
            pending.append("inline_image_byte_limit")
            break
        try:
            image = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            pending.append("inline_image_invalid_base64")
            result["inline_images_examined"] += 1
            continue
        consumed += len(image)
        if consumed > max_total_decoded_bytes:
            pending.append("inline_image_byte_limit")
            break
        review = analyze_image(image, max_bytes=min(MAX_IMAGE_BYTES, max_total_decoded_bytes),
                               max_seconds=min(remaining, 30.0), tesseract_path=tesseract_path,
                               language=language)
        result["inline_images_examined"] += 1
        result["ocr_completed"] += review["ocr_state"] == "completed"
        pending.extend(review["pending_reviews"])
        if review["content"] == "SENSITIVE_CANDIDATE":
            result["content"] = "SENSITIVE_CANDIDATE"
        for signal in review["signals"]:
            code = signal["code"]
            result["signal_counts"][code] = result["signal_counts"].get(code, 0) + 1
        if review["content"] == "SENSITIVE_CANDIDATE":
            pending.append("inline_image_sensitive_candidate_stop")
            break
    result["signals"] = [{"code": code, "images": count}
                         for code, count in sorted(result["signal_counts"].items())]
    if result["inline_images_examined"] < found:
        pending.append("inline_image_count_or_budget_limit")
    result["inline_images_unexamined"] = found - result["inline_images_examined"]
    result["pending_reviews"] = sorted(set(pending))
    return result
