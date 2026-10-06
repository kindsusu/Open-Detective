"""Offline, bounded document inspection. No active document content is executed."""
from __future__ import annotations

from io import BytesIO
import contextlib
import logging
import math
import multiprocessing
import os
import re
import sys
import time
import warnings

from .classifiers import analyze

DEFAULT_DOCUMENT_BYTES = 8 * 1024 * 1024
DEFAULT_DOCUMENT_PAGES = 32
MAX_DOCUMENT_ANNOTATIONS = 256
MAX_EXTRACTED_TEXT_BYTES = 4 * 1024 * 1024
_INLINE_IMAGE = re.compile(rb"(?<!\S)BI(?=\s)")
_XOBJECT_DRAW = re.compile(rb"(?<!\S)/[^\s/<>]+\s+Do(?=\s|$)")


class _DropPdfLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return False


@contextlib.contextmanager
def _quiet_pdf_parser():
    # pypdf can log malformed input fragments, including user-supplied bytes.
    # Filter its loaded module loggers as well as process streams for the parse.
    blocker = _DropPdfLogs()
    loggers = [logging.getLogger(name) for name in sys.modules if name == "pypdf" or name.startswith("pypdf.")]
    for logger in loggers: logger.addFilter(blocker)
    try:
        with warnings.catch_warnings(), contextlib.redirect_stdout(BytesIOTextSink()), contextlib.redirect_stderr(BytesIOTextSink()):
            warnings.simplefilter("ignore")
            yield
    finally:
        for logger in loggers: logger.removeFilter(blocker)


class BytesIOTextSink:
    """Discard untrusted parser diagnostics without retaining their values."""
    def write(self, value): return len(value)
    def flush(self): pass


def analyze_document(body: bytes, content_type: str, *, max_bytes: int = DEFAULT_DOCUMENT_BYTES,
                     max_pages: int = DEFAULT_DOCUMENT_PAGES, capture_complete: bool = True,
                     max_seconds: float = 10.0) -> dict:
    """Return a sanitized PDF analysis and explicit extraction/OCR gaps.

    Page text is transient. Missing optional pypdf, encrypted documents and image
    pages remain pending; no claim about accessibility or publication is made.
    """
    if not 1 <= max_bytes <= 32 * 1024 * 1024 or not 1 <= max_pages <= 256 or not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError("invalid document analysis budget")
    report = {"document_type": "pdf" if "pdf" in content_type.casefold() or body.startswith(b"%PDF-") else "unsupported",
              "content": "NOT_INSPECTED", "time_limit_enforced": False,
              "capture_input_complete": bool(capture_complete), "text_analysis_complete": False,
              "structure_analysis_complete": False, "image_review_complete": False,
              "dependency_review_complete": False, "analysis_complete": False,
              "pages_total": None, "pages_examined": 0, "pages_unexamined": None,
              "page_coverage": [], "bytes_examined": min(len(body), max_bytes),
              "pending_reviews": [], "signals": [], "automated_sensitivity_is_provisional": True}
    pending = report["pending_reviews"]
    if not capture_complete: pending.append("capture_incomplete")
    if len(body) > max_bytes:
        pending.append("document_byte_limit")
        return report
    if report["document_type"] != "pdf":
        pending.append("unsupported_document_format")
        return report
    status, result = _run_isolated(_in_process_analyze_document,
                                   (body, content_type, max_bytes, max_pages, capture_complete), max_seconds)
    if status == "ok" and isinstance(result, dict):
        result["time_limit_enforced"] = True
        return result
    report["time_limit_enforced"] = status != "isolation_unavailable"
    pending.append({"timeout": "pdf_time_limit", "isolation_unavailable": "pdf_isolation_unavailable"}
                   .get(status, "pdf_worker_failed"))
    return report


def _run_isolated(worker, args: tuple, max_seconds: float, *, redact_result: bool = True) -> tuple[str, dict | None]:
    """Run a trusted top-level worker under a wall-clock deadline.

    Only worker-produced sanitized dictionaries cross the pipe. Exceptions and
    parser diagnostics never cross it. This helper also supports deadline tests.
    """
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_worker_entry, args=(child, worker, args, redact_result))
    process.daemon = True
    started = time.monotonic()
    try:
        process.start()
        child.close()
        remaining = max(0.0, max_seconds - (time.monotonic() - started))
        if not parent.poll(remaining): return "timeout", None
        try:
            packet = parent.recv()
        except (EOFError, OSError):
            return "worker_failed", None
        return ("ok", packet) if isinstance(packet, dict) else ("worker_failed", None)
    except (OSError, RuntimeError, ValueError):
        return "isolation_unavailable", None
    finally:
        parent.close()
        child.close()
        if process.pid is not None:
            if process.is_alive(): process.terminate()
            process.join(timeout=0.2)
            if process.is_alive():
                process.kill()
                process.join(timeout=0.2)


def _worker_entry(pipe, worker, args, redact_result=True):
    # Spawned children have fresh descriptors on Windows. Discard both Python
    # streams and native file-descriptor output before importing PDF code.
    try:
        sink = os.open(os.devnull, os.O_WRONLY)
        for fd in (1, 2):
            try: os.dup2(sink, fd)
            except OSError: pass
        os.close(sink)
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
        logging.disable(logging.CRITICAL)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = worker(*args)
        from .evidence_redaction import redact_mapping
        pipe.send(redact_mapping(result) if redact_result and isinstance(result, dict) else result if isinstance(result, dict) else {})
    except BaseException:
        try: pipe.send({})
        except (OSError, BrokenPipeError): pass
    finally:
        pipe.close()


def _in_process_analyze_document(body: bytes, content_type: str, max_bytes: int,
                                 max_pages: int, capture_complete: bool) -> dict:
    """Private parser for the isolated worker and deterministic parser tests."""
    report = {"document_type": "pdf", "content": "NOT_INSPECTED", "time_limit_enforced": True,
              "capture_input_complete": bool(capture_complete), "text_analysis_complete": False,
              "structure_analysis_complete": False, "image_review_complete": False,
              "dependency_review_complete": False, "analysis_complete": False,
              "pages_total": None, "pages_examined": 0, "pages_unexamined": None,
              "page_coverage": [], "bytes_examined": min(len(body), max_bytes),
              "pending_reviews": [], "signals": [], "automated_sensitivity_is_provisional": True}
    pending = report["pending_reviews"]
    if not capture_complete: pending.append("capture_incomplete")
    try:
        from pypdf import PdfReader
    except ImportError:
        pending.append("pdf_text_dependency_missing")
        return report
    report["dependency_review_complete"] = True
    try:
        with _quiet_pdf_parser():
            return _parse_pdf(body, PdfReader, report, pending, max_pages, capture_complete)
    except Exception:
        # Parser exception strings may contain document content or paths.
        pending.append("pdf_parse_failed")
    return report


def _parse_pdf(body, PdfReader, report, pending, max_pages, capture_complete):
        reader = PdfReader(BytesIO(body), strict=False)
        if reader.is_encrypted:
            pending.append("encrypted_pdf_requires_authorized_key")
            return report
        total = len(reader.pages)
        report["pages_total"] = total
        if total > max_pages: pending.append("pdf_page_limit")
        text_parts = []
        extracted_bytes = 0
        image_pages = 0
        uncertain_image_pages = 0
        for index, page in enumerate(reader.pages[:max_pages], start=1):
            try:
                page_text = page.extract_text() or ""
                text_state = "extracted" if page_text.strip() else "empty"
            except Exception:
                page_text = ""
                text_state = "failed"
                if "pdf_page_text_failed" not in pending: pending.append("pdf_page_text_failed")
            encoded = page_text.encode("utf-8")
            if extracted_bytes + len(encoded) > MAX_EXTRACTED_TEXT_BYTES:
                pending.append("pdf_extracted_text_limit")
                break
            text_parts.append(page_text)
            extracted_bytes += len(encoded)
            report["pages_examined"] += 1
            try:
                image_state = _page_image_state(page)
            except Exception:
                image_state = "unknown"
            ocr_needed = image_state != "clear" or text_state != "extracted"
            if ocr_needed: image_pages += 1
            if image_state in {"unknown", "image_and_unknown"}: uncertain_image_pages += 1
            report["page_coverage"].append({"page": index, "text_state": text_state,
                                            "image_state": image_state,
                                            "ocr_state": "not_run" if ocr_needed else "not_applicable"})
        if image_pages:
            pending.append("ocr_not_run")
        if uncertain_image_pages:
            pending.append("image_or_structure_review")
        if not image_pages and not uncertain_image_pages:
            report["image_review_complete"] = "not_applicable_for_text_pages" if report["pages_examined"] == total else False
        if text_parts:
            classification = analyze("\n".join(text_parts).encode("utf-8"), "text/plain",
                                     max_bytes=MAX_EXTRACTED_TEXT_BYTES,
                                     capture_complete=not any(x in pending for x in ("pdf_page_limit", "pdf_extracted_text_limit")))
            report["signals"] = classification.report["signals"]
            report["content"] = classification.report["content"]
            report["asset_profile"] = classification.report["asset_profile"]
        report["text_analysis_complete"] = report["pages_examined"] == total and not any(
            x in pending for x in ("pdf_extracted_text_limit", "ocr_not_run", "image_or_structure_review"))
        report["pages_unexamined"] = total - report["pages_examined"]
        report["structure_analysis_complete"] = report["pages_examined"] == total and not uncertain_image_pages
        report["analysis_complete"] = bool(capture_complete and not pending and report["text_analysis_complete"])
        return report


def extract_document_references(body: bytes, content_type: str, *,
                                max_bytes: int = DEFAULT_DOCUMENT_BYTES,
                                max_pages: int = DEFAULT_DOCUMENT_PAGES,
                                max_annotations: int = MAX_DOCUMENT_ANNOTATIONS,
                                max_seconds: float = 10.0) -> tuple[list[tuple[str, str]], list[str]]:
    """Return exact PDF annotation document URLs transiently for scoped queueing.

    Callers must store approved URLs in a private locator store, not a report.
    No PDF action is executed and no URL is guessed from a neighboring ID.
    """
    if not 1 <= max_bytes <= 32 * 1024 * 1024 or not 1 <= max_pages <= 256 or not 1 <= max_annotations <= MAX_DOCUMENT_ANNOTATIONS or not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError("invalid document reference budget")
    if len(body) > max_bytes: return [], ["document_byte_limit"]
    if "pdf" not in content_type.casefold() and not body.startswith(b"%PDF-"):
        return [], ["unsupported_document_format"]
    status, result = _run_isolated(_in_process_document_references,
                                   (body, max_pages, max_annotations), max_seconds,
                                   redact_result=False)
    if status == "ok" and result:
        return result["references"], result["gaps"]
    return [], [{"timeout": "pdf_time_limit", "isolation_unavailable": "pdf_isolation_unavailable"}.get(status, "pdf_worker_failed")]


def _in_process_document_references(body: bytes, max_pages: int, max_annotations: int) -> dict:
    references: list[tuple[str, str]] = []
    gaps: list[str] = []
    try:
        from pypdf import PdfReader
    except ImportError:
        return {"references": references, "gaps": ["pdf_text_dependency_missing"]}
    try:
        with _quiet_pdf_parser():
            reader = PdfReader(BytesIO(body), strict=False)
            if reader.is_encrypted:
                return {"references": references, "gaps": ["encrypted_pdf_requires_authorized_key"]}
            if len(reader.pages) > max_pages: gaps.append("pdf_page_limit")
            annotations_seen = 0
            for page in reader.pages[:max_pages]:
                for reference in page.get("/Annots", []) or []:
                    annotations_seen += 1
                    if annotations_seen > max_annotations:
                        gaps.append("pdf_annotation_limit")
                        return {"references": references, "gaps": gaps}
                    item = reference.get_object()
                    if not hasattr(item, "get"):
                        gaps.append("pdf_annotation_structure_unresolved")
                        continue
                    if item.get("/Subtype") != "/Link":
                        continue
                    action = item.get("/A")
                    if not action:
                        if item.get("/Dest") is None:
                            gaps.append("pdf_annotation_structure_unresolved")
                        continue
                    action = action.get_object()
                    if not hasattr(action, "get"):
                        gaps.append("pdf_annotation_structure_unresolved")
                        continue
                    if action.get("/S") == "/GoTo":
                        continue
                    if action.get("/S") != "/URI":
                        gaps.append("pdf_annotation_structure_unresolved")
                        continue
                    value = action.get("/URI")
                    if not isinstance(value, str) or len(value) > 2048 or not value.lower().startswith("https://"):
                        gaps.append("pdf_annotation_uri_unusable")
                        continue
                    from .asset_trace import _is_document_reference
                    if _is_document_reference(value): references.append(("document_annotation", value))
    except Exception:
        gaps.append("pdf_annotation_parse_failed")
    return {"references": references, "gaps": gaps}


def _page_image_state(page) -> str:
    """Return clear, image, or unknown without decoding image streams.

    Filtered content and Form XObjects can hide inline or nested images. Only
    small, unfiltered content streams with no image operators are declared clear.
    """
    resources = page.get("/Resources")
    xobjects = resources.get_object().get("/XObject") if resources else None
    image_found = False
    unknown_found = False
    if xobjects:
        objects = xobjects.get_object()
        if len(objects) > 128: return "unknown"
        for ref in objects.values():
            subtype = ref.get_object().get("/Subtype")
            if subtype == "/Image": image_found = True
            else: unknown_found = True
    contents = page.get("/Contents")
    if contents is None:
        return "image_and_unknown" if image_found and unknown_found else "image" if image_found else "unknown" if unknown_found else "clear"
    contents = contents.get_object()
    streams = contents if isinstance(contents, list) else [contents]
    if len(streams) > 128: unknown_found = True
    for ref in streams[:128]:
        stream = ref.get_object()
        raw = getattr(stream, "_data", None)
        if not isinstance(raw, bytes) or len(raw) > 1_048_576 or stream.get("/Filter"):
            unknown_found = True
            continue
        if _INLINE_IMAGE.search(raw): image_found = True
        if _XOBJECT_DRAW.search(raw): unknown_found = True
    return "image_and_unknown" if image_found and unknown_found else "image" if image_found else "unknown" if unknown_found else "clear"
