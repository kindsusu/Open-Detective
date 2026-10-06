"""Conservative output redaction; original evidence belongs in a protected store."""
from __future__ import annotations

import re
from collections.abc import Mapping

from .classifiers import BUSINESS_NUMBER, EMAIL, PHONE, PLATE, RESIDENT, SECRET_PATTERNS

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S)
_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b\s*[:=]\s*([\"']?)[^\s,;<>\"']{4,}\2")
_QUERY = re.compile(r"(?i)([?&](?:token|key|secret|password|code|session|auth)=)[^&#\s]+")
_SENSITIVE_KEYS = re.compile(r"(?i)(?:password|passwd|secret|token|api.?key|authorization|cookie|email|phone|mobile|resident|business.?number|vehicle.?plate|customer.?name|employee.?name|address|account.?number|raw.?body|html|screenshot)")


def redact_text(value: str, *, canaries=()) -> str:
    """Mask recognized values in text destined for logs or human output."""
    if not isinstance(value, str): raise TypeError("redact_text expects str")
    result = value
    for canary in canaries:
        if isinstance(canary, str) and canary: result = result.replace(canary, "[REDACTED_CANARY]")
    result = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", result)
    for name, pattern in SECRET_PATTERNS:
        result = pattern.sub("[REDACTED_" + name + "]", result)
    result = _ASSIGNMENT.sub(lambda match: match.group(1) + "=[REDACTED]", result)
    result = _QUERY.sub(lambda match: match.group(1) + "[REDACTED]", result)
    for label, pattern in (("EMAIL", EMAIL), ("PHONE", PHONE), ("RESIDENT", RESIDENT),
                           ("BUSINESS_NUMBER", BUSINESS_NUMBER), ("VEHICLE_PLATE", PLATE)):
        result = pattern.sub("[REDACTED_" + label + "]", result)
    return result


def redact_mapping(value, *, canaries=()):
    """Recursively sanitize a report/log object without mutating the source."""
    if isinstance(value, Mapping):
        return {redact_text(str(key), canaries=canaries):
                ("[REDACTED_FIELD]" if _SENSITIVE_KEYS.search(str(key)) else redact_mapping(item, canaries=canaries))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)): return [redact_mapping(item, canaries=canaries) for item in value]
    if isinstance(value, str): return redact_text(value, canaries=canaries)
    if isinstance(value, (int, float, bool)) or value is None: return value
    return "[UNSUPPORTED_VALUE]"


def safe_error_code(_error: BaseException, *, code: str = "analysis_error") -> str:
    """Never serialize exception text; callers choose a constrained reason code."""
    return code if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "analysis_error"


def redact_screenshot(_image: bytes) -> dict:
    """Fail closed until an OCR or pixel redactor can establish safe output."""
    return {"image": None, "image_review_complete": False,
            "pending_reviews": ["screenshot_redaction_required"]}
