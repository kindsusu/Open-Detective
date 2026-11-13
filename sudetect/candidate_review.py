"""Value-free, offline triage of bytes already captured in an authorized case.

This module never tests whether credentials work or asserts the identity of a
person. Its output contains only controlled labels, counts and coverage.
"""
from __future__ import annotations

import re
import time

from .classifiers import (CLIENT_PASSWORD_ASSIGNMENT, CLIENT_PASSWORD_COMPARISON,
                          EMAIL, PHONE, PLATE, RESIDENT, SENSITIVE_FIELDS, analyze)
from .media_projection import project_inline_images

MAX_CANDIDATE_BYTES = 128 * 1024 * 1024
_CHUNK = 240_000
_OVERLAP = 4096
_TEMPLATE = re.compile(r"(?i)(?:\{\{[^}\r\n]{1,80}\}\}|\$\{[^}\r\n]{1,80}\}|"
                       r"\b(?:example|sample|placeholder|dummy|fixture|test|예시|샘플)\b)")
_JSON_FIELD = re.compile(r'''["']([A-Za-z_가-힣][\w가-힣]{0,80})["']\s*:\s*''')
_PATCH_ENVELOPE = re.compile(rb"\AFrom [0-9a-f]{40} [^\r\n]*\r?\n")
_PATCH_HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def _changed_patch_text(body: bytes) -> bytes:
    """Project changed hunk lines; exclude mail headers, paths and context.

    The repository patch parser independently validates provenance and hunk
    structure. This projection only bounds candidate classification to source
    content, so it never establishes patch validity on its own.
    """
    lines = []
    in_hunk = False
    for line in body.splitlines():
        if line.startswith(b"diff --git "):
            in_hunk = False
        elif _PATCH_HUNK.match(line):
            in_hunk = True
        elif in_hunk and line[:1] in (b"+", b"-"):
            lines.append(line[1:])
    return b"\n".join(lines)


def review_candidate_bytes(body: bytes, *, content_type: str = "text/plain",
                           max_bytes: int = 8 * 1024 * 1024,
                           max_seconds: float = 120.0) -> dict:
    """Classify covered bytes without emitting source, values, or value hashes.

    `analysis_complete` includes structural completeness. Sources within the
    classifier's full-input bound are parsed once; chunk boundaries never
    manufacture syntax errors. Larger sources retain a structure gap.
    """
    if not isinstance(body, bytes):
        raise TypeError("candidate body must be bytes")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_CANDIDATE_BYTES:
        raise ValueError("invalid candidate byte limit")
    if not isinstance(max_seconds, (float, int)) or not 0 < max_seconds <= 300:
        raise ValueError("invalid candidate timeout")
    deadline = time.monotonic() + max_seconds
    limit = min(len(body), max_bytes)
    is_patch = bool(_PATCH_ENVELOPE.match(body[:limit]))
    selected = _changed_patch_text(body[:limit]) if is_patch else body[:limit]
    # Image base64 is opaque pixel data. Its alphabet can accidentally resemble
    # phone or plate formats, so classify only the projected surrounding text.
    if re.search(br"data:image/", selected, re.I):
        projection = project_inline_images(
            (selected[index:index + 65_536] for index in range(0, len(selected), 65_536)),
            max_wire_bytes=len(selected), max_projected_bytes=len(selected) + 1_048_576)
        source = projection.projected
        media_skipped = projection.skipped_images
        projection_truncated = projection.wire_truncated or projection.projected_truncated
    else:
        source = selected
        media_skipped = 0
        projection_truncated = False
    source_examined = limit
    codes: set[str] = set()
    literal = template = field_label = False
    phone = plate = email = resident = False
    examined = 0
    pending = set()
    if media_skipped:
        pending.add("inline_image_ocr_unexamined")
    if projection_truncated:
        pending.add("candidate_projection_incomplete")
    full_report = None
    if not is_patch and len(source) <= 32 * 1024 * 1024 and time.monotonic() < deadline:
        full_report = analyze(source, content_type, max_bytes=max(1, len(source))).report
        codes.update(item["code"] for item in full_report["signals"])
        structure_complete = bool(full_report["structure_analysis_complete"])
    elif is_patch:
        # Diff syntax is verified by the dedicated patch parser. Changed lines
        # are intentionally not a complete JSON, HTML or JS document.
        structure_complete = True
    else:
        structure_complete = False
    while examined < len(source):
        if time.monotonic() >= deadline:
            pending.add("candidate_review_time_limit")
            break
        end = min(examined + _CHUNK, len(source))
        fragment = source[max(0, examined - _OVERLAP):end]
        text = fragment.decode("utf-8", "replace")
        if full_report is None:
            # The prefix prevents a JSON fragment from masquerading as a full
            # malformed JSON document. Chunk signals are lexical only here.
            lexical = b"// lexical fragment\n" + fragment
            classified = analyze(lexical, "text/plain", max_bytes=len(lexical)).report
            codes.update(item["code"] for item in classified["signals"])
        literal |= bool(CLIENT_PASSWORD_ASSIGNMENT.search(text) or CLIENT_PASSWORD_COMPARISON.search(text))
        template |= bool(_TEMPLATE.search(text))
        field_label |= any(match.group(1).casefold() in SENSITIVE_FIELDS
                           for match in _JSON_FIELD.finditer(text))
        phone |= bool(PHONE.search(text))
        plate |= bool(PLATE.search(text))
        email |= bool(EMAIL.search(text))
        resident |= bool(RESIDENT.search(text))
        examined = end
    if source_examined < len(body) or examined < len(source):
        pending.add("candidate_review_byte_or_time_limit")
    if not structure_complete:
        pending.add("candidate_structure_review_pending")
    value_codes = {"SENSITIVE_VALUES_CANDIDATE", "BUSINESS_DATA_VALUE_CANDIDATE",
                   "CONTACT_VALUE_CANDIDATE", "CUSTOMER_RECORD_CANDIDATE",
                   "PERSON_LIST_CANDIDATE"}
    findings = []
    if field_label or "SENSITIVE_FIELD_NAMES" in codes:
        findings.append({"kind": "sensitive_field_label", "evidence": "field_name_only"})
    if template:
        findings.append({"kind": "template_or_example", "evidence": "literal_marker"})
    if codes & value_codes:
        findings.append({"kind": "filled_structured_value", "evidence": "classifier_candidate"})
    if literal or "CLIENT_PASSWORD_CANDIDATE" in codes:
        findings.append({"kind": "client_password_source_literal", "evidence": "source_literal",
                         "credential_validity": "not_tested"})
    for present, kind in ((phone, "phone_format"), (plate, "vehicle_plate_format"),
                          (email, "email_format"), (resident, "resident_number_format")):
        if present:
            findings.append({"kind": kind, "evidence": "format_candidate",
                             "identity": "not_verified"})
    secret_codes = {"PRIVATE_KEY_CANDIDATE", "SERVER_SECRET_CANDIDATE", "GITHUB_SECRET_CANDIDATE"}
    if codes & secret_codes:
        findings.append({"kind": "secret_pattern", "evidence": "source_pattern",
                         "credential_validity": "not_tested"})
    if "CONFIDENTIAL_MARKER_CANDIDATE" in codes:
        findings.append({"kind": "confidentiality_label", "evidence": "label_only"})
    if "KR_BUSINESS_NUMBER_CANDIDATE" in codes:
        findings.append({"kind": "business_number_format", "evidence": "format_candidate",
                         "personal_information": "not_inferred"})
    if "RUNTIME_ENDPOINT_CANDIDATE" in codes:
        findings.append({"kind": "runtime_endpoint_reference", "evidence": "source_reference"})
    mapped_codes = (value_codes | secret_codes | {"CLIENT_PASSWORD_CANDIDATE",
        "KR_PHONE_VALUE_CANDIDATE", "KR_VEHICLE_PLATE_CANDIDATE", "EMAIL_VALUE_CANDIDATE",
        "KR_RESIDENT_VALUE_CANDIDATE", "CONFIDENTIAL_MARKER_CANDIDATE",
        "KR_BUSINESS_NUMBER_CANDIDATE", "RUNTIME_ENDPOINT_CANDIDATE"})
    for code in sorted(code for code in codes if code.endswith("_CANDIDATE") and code not in mapped_codes):
        findings.append({"kind": "classifier_candidate", "code": code,
                         "evidence": "classifier_signal", "validity": "not_tested"})
    text_complete = (source_examined == len(body) and examined == len(source)
                     and not projection_truncated)
    return {"document_type": "candidate_review", "bytes_available": len(body),
            "bytes_examined": source_examined, "text_bytes_examined": examined,
            "source_format": "patch_changed_lines" if is_patch else "document",
            "inline_images_excluded_from_text": media_skipped,
            "image_analysis_complete": media_skipped == 0,
            "text_analysis_complete": text_complete,
            "structure_analysis_complete": structure_complete,
            "structure_incomplete_reasons": (full_report.get("asset_profile", {}).get(
                "structure_incomplete_reasons", []) if full_report is not None else
                ([] if structure_complete else ["candidate_structure_input_or_time_limit"])),
            "analysis_complete": text_complete and not pending,
            "candidate_signal_codes": sorted(codes), "findings": findings,
            "pending_reviews": sorted(pending), "sensitivity": "candidate_only",
            "review_authorization": "explicit_followup"}
