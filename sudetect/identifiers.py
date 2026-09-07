"""Company-name variants used by discovery planning.

Platform account guesses remain separate from free-form search phrases.  The
implementation is packaged with the runtime; ``tools.idgen`` remains a thin
compatibility entry point for existing operator scripts.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Iterable, Mapping, TypeVar

from .idgen import (FUNCTION, TARGET_PATTERNS, TAILS_KO, generate, initials, main,
                         normalize_term, positive_int, romanize, selftest, stems,
                         validate_target_candidate, _strip_korean_legal_boundary)


_QueryRow = TypeVar("_QueryRow", bound=Mapping[str, object])


def round_robin_narrow_queries(rows: Iterable[_QueryRow]) -> list[_QueryRow]:
    """Keep full identity first while giving each narrow family an early turn.

    This is only an ordering operation: rows, their exact query text, and their
    within-family order are retained.  Short and broad work remains after the
    full/narrow sequence.
    """
    full: list[_QueryRow] = []
    industry: list[_QueryRow] = []
    function: list[_QueryRow] = []
    tail: list[_QueryRow] = []
    for row in rows:
        rationale = row.get("rationale", row.get("generation_rationale", ""))
        if not isinstance(rationale, str):
            tail.append(row)
        elif rationale.startswith("full-name:"):
            full.append(row)
        elif rationale in {"narrow:brand+industry", "narrow:korean-brand+compound-industry"}:
            industry.append(row)
        elif rationale == "narrow:brand+function":
            function.append(row)
        else:
            tail.append(row)
    ordered: list[_QueryRow] = []
    for index in range(max(len(full), len(industry), len(function))):
        for family in (full, industry, function):
            if index < len(family): ordered.append(family[index])
    return ordered + tail


def generate_identifiers(*, ko: str = "", en: str = "", aliases: Iterable[str] = (),
                         industry: Iterable[str] = (), functions: Iterable[str] = ()) -> list[dict[str, object]]:
    rows = generate(ko, en, list(aliases), list(functions) or None, list(industry))
    return [{"identifier": value, "tier": tier, "rationale": rationale}
            for value, tier, rationale in rows]


def generate_search_queries(*, ko: str = "", en: str = "", aliases: Iterable[str] = (),
                            industry: Iterable[str] = (), functions: Iterable[str] = ()) -> list[dict[str, str]]:
    """Return full/narrow round-robin, then short-name and broad search phrases.

    ``rationale`` is intentionally an explicit query-classification field.  Search
    planners preserve its order, so a small budget rotates available full-name,
    industry, and function context work before generic brand or industry terms.
    """
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    def add(value: str, rationale: str) -> None:
        value = " ".join(unicodedata.normalize("NFKC", value).split())
        key = value.casefold()
        if value and key not in seen:
            seen.add(key); rows.append({"query": value, "rationale": rationale})
    korean_brands: list[str] = []
    if ko:
        add(ko, "full-name:korean-original")
        clean = _strip_korean_legal_boundary(ko)
        if clean != ko:
            add(clean, "full-name:korean-legal-boundary-stripped")
        for tail in TAILS_KO:
            if clean.endswith(tail) and len(clean) > len(tail):
                korean_brands.append(clean[:-len(tail)].strip())
                break
    name_rows = [(en, "official-english")] + [(value, "operator-alias") for value in aliases]
    brands: list[str] = []
    deferred_short_aliases: list[str] = []
    full_identity_keys = {
        "".join(re.findall(r"[A-Za-z0-9가-힣]+", unicodedata.normalize("NFKC", value))).casefold()
        for value in (ko, en) if value
    }
    for value, rationale in name_rows:
        if not value:
            continue
        parts = re.findall(r"[A-Za-z0-9가-힣]+", unicodedata.normalize("NFKC", value))
        compact = "".join(parts).casefold()
        # A one-token alias is a useful operator provenance record, but it is only
        # a brand search when it repeats a token from the supplied full identity.
        # Keep it behind narrow combinations instead of spending a name-only budget.
        is_brand_only_alias = (rationale == "operator-alias" and len(parts) == 1
                               and compact not in full_identity_keys)
        if is_brand_only_alias:
            deferred_short_aliases.append(value)
            brands.append(parts[0])
            continue
        add(value, "full-name:" + rationale)
        if parts:
            add(" ".join(parts), "full-name:" + rationale + "-spaced")
            add("".join(parts), "full-name:" + rationale + "-joined")
            brands.append(parts[0])
    # Narrow combinations are evidence-oriented: their two terms come from the
    # supplied identity/context rather than an unqualified generic word.  Interleave
    # brands by term so aliases cannot consume the front of a bounded query budget.
    query_industry = list(dict.fromkeys(str(term) for term in industry if str(term).strip()))
    query_functions = list(dict.fromkeys(str(term) for term in functions if str(term).strip()))
    all_brands = list(dict.fromkeys(korean_brands + brands))
    for term in query_industry:
        for brand in all_brands:
            add(f"{brand} {term}", "narrow:brand+industry")
    for term in query_functions:
        for brand in all_brands:
            add(f"{brand} {term}", "narrow:brand+function")

    for value in deferred_short_aliases:
        add(value, "short-name:operator-alias-brand-token")

    # Preserve short and broad work explicitly at the end.  These phrases are never
    # proof of ownership or permission to probe.
    if ko:
        for tail in TAILS_KO:
            if clean.endswith(tail) and len(clean) > len(tail):
                head = clean[:-len(tail)].strip()
                add(f"{head} {tail}", "narrow:korean-brand+compound-industry")
                add(head, "short-name:korean-brand-token")
                add(tail, "broad:korean-industry-token")
                break
    for value, rationale in name_rows:
        parts = re.findall(r"[A-Za-z0-9가-힣]+", unicodedata.normalize("NFKC", value))
        if len(parts) > 1:
            add(parts[0], "short-name:" + rationale + "-brand-token")
            add(" ".join(parts[1:]), "broad:english-industry-spaced")
            add("".join(parts[1:]), "broad:english-industry-joined")
    for term in query_industry:
        add(term, "broad:operator-industry")
    return round_robin_narrow_queries(rows)


__all__ = ["FUNCTION", "TARGET_PATTERNS", "generate", "generate_identifiers",
           "generate_search_queries", "round_robin_narrow_queries", "initials", "main", "normalize_term",
           "positive_int", "romanize", "selftest", "stems", "validate_target_candidate"]
