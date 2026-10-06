"""Bounded, analysis-only projection of inline base64 images in captured bytes.

The projected bytes are untrusted text for analysis. They are never a substitute
for the original response, its DOM, or a gate decision. No data is persisted.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass


_START = b"data:image/"
_ENCODING = b";base64,"
_PLACEHOLDER = b"[inline-image-omitted]"
_SUBTYPE = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+_-")
_BASE64 = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]*")
_START_LEAD = re.compile(rb"[dD]")
_MAX_SUBTYPE = 64


@dataclass(frozen=True)
class MediaProjection:
    """Projected text plus safe, content-free accounting metadata.

    Hashes and byte counts cover only the consumed wire prefix and returned
    projection. ``wire_truncated`` means available input exceeded the wire cap.
    ``media_ocr_gap`` is true whenever any image payload was skipped.
    """

    projected: bytes
    original_sha256: str
    original_bytes: int
    projected_sha256: str
    projected_bytes: int
    skipped_images: int
    media_ocr_gap: bool
    wire_truncated: bool
    projected_truncated: bool


def project_inline_images(
    chunks: Iterable[bytes], *, max_wire_bytes: int, max_projected_bytes: int
) -> MediaProjection:
    """Replace inline ``data:image/<subtype>;base64,`` payloads in a byte stream.

    Only standard base64 runs with a valid first quartet are removed. Quotes,
    whitespace, CSS ``)`` and other non-base64 bytes end the run and are kept.
    The fixed-size candidate buffer and output cap bound auxiliary memory even
    when markers cross chunk boundaries. Chunk objects themselves are caller-owned.
    """
    if not isinstance(max_wire_bytes, int) or isinstance(max_wire_bytes, bool) or max_wire_bytes < 0:
        raise ValueError("max_wire_bytes must be a nonnegative integer")
    if not isinstance(max_projected_bytes, int) or isinstance(max_projected_bytes, bool) or max_projected_bytes < 0:
        raise ValueError("max_projected_bytes must be a nonnegative integer")

    original_hash = hashlib.sha256()
    projected_hash = hashlib.sha256()
    projected = bytearray()
    original_bytes = 0
    skipped = 0
    wire_truncated = False
    projected_truncated = False
    state = "search"
    pending = bytearray()
    subtype_len = 0
    encoding_len = 0
    padding = 0

    def emit(data: bytes | bytearray | memoryview) -> None:
        nonlocal projected_truncated
        room = max_projected_bytes - len(projected)
        if len(data) > room:
            projected_truncated = True
        if room > 0:
            part = data[:room]
            projected.extend(part)
            projected_hash.update(part)

    def feed(value: int) -> None:
        nonlocal state, subtype_len, encoding_len, padding, skipped
        queue = deque((value,))
        while queue:
            char = queue.popleft()
            if state == "skip":
                if char in _BASE64 and padding == 0:
                    continue
                if char == ord("=") and padding < 2:
                    padding += 1
                    continue
                state = "search"
                queue.appendleft(char)
                continue

            if state == "search":
                expected = _START[len(pending)]
                if char | 32 == expected:
                    pending.append(char)
                    if len(pending) == len(_START):
                        state = "subtype"
                        subtype_len = 0
                    continue
            elif state == "subtype":
                if char in _SUBTYPE and subtype_len < _MAX_SUBTYPE:
                    pending.append(char)
                    subtype_len += 1
                    continue
                if char == ord(";") and subtype_len:
                    pending.append(char)
                    state = "encoding"
                    encoding_len = 1
                    continue
            elif state == "encoding":
                if char | 32 == _ENCODING[encoding_len]:
                    pending.append(char)
                    encoding_len += 1
                    if encoding_len == len(_ENCODING):
                        state = "quartet"
                    continue
            elif state == "quartet":
                # Hold four bytes before committing to removal. Invalid or
                # incomplete payloads pass through unchanged.
                position = len(pending) - len(_START) - subtype_len - len(_ENCODING)
                valid = (char in _BASE64 if position < 2 else char in _BASE64 or char == ord("="))
                if valid and position == 3:
                    third = pending[-1]
                    valid = third != ord("=") or char == ord("=")
                if valid:
                    pending.append(char)
                    if position == 3:
                        emit(pending[:-4])
                        emit(_PLACEHOLDER)
                        skipped += 1
                        padding = 2 if pending[-2:] == b"==" else 1 if pending[-1] == ord("=") else 0
                        pending.clear()
                        state = "skip"
                    continue

            if not pending:
                emit(bytes((char,)))
                continue
            # Candidate failed. Emit its first byte and reprocess the bounded
            # remainder to recognize overlapping markers.
            queue.extendleft(reversed(bytes(pending[1:]) + bytes((char,))))
            emit(pending[:1])
            pending.clear()
            state = "search"

    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("chunks must yield bytes")
        remaining = max_wire_bytes - original_bytes
        if remaining <= 0:
            if chunk:
                wire_truncated = True
                break
            continue
        view = memoryview(chunk)[:remaining]
        original_hash.update(view)
        original_bytes += len(view)
        index = 0
        end = len(view)
        while index < end:
            if state == "search" and not pending:
                lead = _START_LEAD.search(chunk, index, end)
                next_index = lead.start() if lead else end
                if next_index > index:
                    emit(view[index:next_index])
                    index = next_index
                if index == end:
                    break
            if state == "skip" and padding == 0:
                # The payload dominates large responses. Scan its run in C,
                # leaving only the first terminator to the state machine.
                index = _BASE64_RUN.match(chunk, index, end).end()
                if index == end:
                    break
            feed(chunk[index])
            index += 1
        if len(chunk) > remaining:
            wire_truncated = True
            break
    if pending:
        emit(pending)

    return MediaProjection(
        projected=bytes(projected),
        original_sha256=original_hash.hexdigest(),
        original_bytes=original_bytes,
        projected_sha256=projected_hash.hexdigest(),
        projected_bytes=len(projected),
        skipped_images=skipped,
        media_ocr_gap=skipped > 0,
        wire_truncated=wire_truncated,
        projected_truncated=projected_truncated,
    )
