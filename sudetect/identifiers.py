"""Company-name variants used by discovery planning.

Platform account guesses remain separate from free-form search phrases.  The
implementation is packaged with the runtime; ``tools.idgen`` remains a thin
compatibility entry point for existing operator scripts.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Iterable

from .idgen import (FUNCTION, TARGET_PATTERNS, TAILS_KO, generate, initials, main,
                         normalize_term, positive_int, romanize, selftest, stems,
                         validate_target_candidate, _strip_korean_legal_boundary)


def generate_identifiers(*, ko: str = "", en: str = "", aliases: Iterable[str] = (),
                         industry: Iterable[str] = (), functions: Iterable[str] = ()) -> list[dict[str, object]]:
    rows = generate(ko, en, list(aliases), list(functions) or None, list(industry))
    return [{"identifier": value, "tier": tier, "rationale": rationale}
            for value, tier, rationale in rows]


def generate_search_queries(*, ko: str = "", en: str = "", aliases: Iterable[str] = (),
                            industry: Iterable[str] = (), functions: Iterable[str] = ()) -> list[dict[str, str]]:
    """Return human-readable search queries without platform-name filtering."""
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    def add(value: str, rationale: str) -> None:
        value = " ".join(unicodedata.normalize("NFKC", value).split())
        key = value.casefold()
        if value and key not in seen:
            seen.add(key); rows.append({"query": value, "rationale": rationale})
    if ko:
        add(ko, "korean-original")
        add(_strip_korean_legal_boundary(ko), "korean-legal-boundary-stripped")
    name_rows = [(en, "official-english")] + [(value, "operator-alias") for value in aliases]
    brands: list[str] = []
    for value, rationale in name_rows:
        if not value: continue
        add(value, rationale)
        parts = re.findall(r"[A-Za-z0-9가-힣]+", unicodedata.normalize("NFKC", value))
        if parts:
            add(" ".join(parts), rationale + "-spaced")
            add("".join(parts), rationale + "-joined")
            brands.append(parts[0])
    for brand in dict.fromkeys(brands):
        for term in industry: add(f"{brand} {term}", "brand+industry")
        for term in functions: add(f"{brand} {term}", "brand+function")
    # Preserve broad brand/industry searches as explicit lower-priority work.
    # They are search phrases, never proof of ownership or permission to probe.
    if ko:
        clean = _strip_korean_legal_boundary(ko)
        for tail in TAILS_KO:
            if clean.endswith(tail) and len(clean) > len(tail):
                head = clean[:-len(tail)].strip()
                add(head, "korean-brand-token")
                add(f"{head} {tail}", "korean-compound-spaced")
                add(tail, "broad-korean-industry-token")
                break
    for value, rationale in name_rows:
        parts = re.findall(r"[A-Za-z0-9가-힣]+", unicodedata.normalize("NFKC", value))
        if len(parts) > 1:
            add(parts[0], rationale + "-brand-token")
            add(" ".join(parts[1:]), "broad-english-industry-spaced")
            add("".join(parts[1:]), "broad-english-industry-joined")
    for term in industry:
        add(term, "broad-operator-industry")
    return rows


__all__ = ["FUNCTION", "TARGET_PATTERNS", "generate", "generate_identifiers",
           "generate_search_queries", "initials", "main", "normalize_term",
           "positive_int", "romanize", "selftest", "stems", "validate_target_candidate"]
