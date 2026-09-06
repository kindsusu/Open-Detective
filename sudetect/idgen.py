#!/usr/bin/env python3
"""su-detect / idgen.py - candidate identifier generator.

The account that hosts a leak is almost never the registered company name. It is a
coinage an employee invented at signup, under namespace rules (no spaces, lowercase,
ASCII) and uniqueness pressure. Searching the company name alone does not reach it.

This generates the search space instead: stems x transliterations x joiners x affixes.
It makes no network requests. It writes candidates; the policy-bound probe measures them.

  python3 tools/idgen.py --ko "<korean name>" --en "<english name>"
  python3 tools/idgen.py --ko "<name>" --en "<name>" --targets github --limit 120
  python3 tools/idgen.py --selftest

No company values live in this file - everything distinctive comes in as an argument.
The lexicons below are generic business vocabulary, deliberately not tied to any firm.

Rules (see ops/identifiers.md)
  - Generation is for finding the FIRST entry point. After one hit, pivoting
    (commit authors, org membership, reverse IP, CT) outyields more generation.
  - A candidate is a guess, never an asset. Confirm ownership before probing
    (`SUD-R04`) - a generic coinage may belong to someone else.
  - Ranked output exists because anonymous rate limits are real: probe the top of
    the list, not all of it.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import unicodedata

# --------------------------------------------------------------------- lexicons
# Generic. Extend at runtime with --function / --industry, not by editing this file.

# Business-function words that get appended to a company stem. The leak in the
# precedent behind this tool sat on stem+function, where the function word appears
# nowhere in the company name.
FUNCTION = [
    "sales", "partners", "partner", "dashboard", "dev", "admin", "team", "official", "corp",
    "group", "service", "support", "cs", "hr", "ops", "lab", "labs", "biz",
    "tech", "data", "api", "web", "app", "mall", "shop", "store", "media",
    "marketing", "solution", "system", "network", "digital", "global", "korea",
]

# Legal-form and geography tails to strip before splitting: they carry no identity.
STRIP_TAILS_KO = ["주식회사", "㈜", "(주)", "유한회사", "그룹", "홀딩스", "코리아", "컴퍼니"]
LEGAL_PREFIXES_KO = ["주식회사", "㈜", "(주)", "유한회사"]
LEGAL_SUFFIXES_KO = ["주식회사", "㈜", "(주)", "유한회사", "그룹", "홀딩스", "코리아", "컴퍼니"]
STRIP_TAILS_EN = ["inc", "llc", "ltd", "co", "corp", "corporation", "company", "group", "holdings"]

# Common compound tails in Korean names. Stripping one exposes the distinctive stem;
# the tail itself is also a searchable unit on its own.
TAILS_KO = [
    "렌트카", "렌터카", "모빌리티", "시스템즈", "시스템", "테크놀로지", "테크",
    "솔루션", "네트웍스", "네트워크", "파트너스", "물류", "유통", "산업", "건설",
    "전자", "화학", "제약", "식품", "미디어", "커머스", "에너지", "바이오",
]

JOINERS = ["", "-", "_"]
NUMERIC = ["1", "2", "01", "02", "24", "2024", "2025", "1234"]

# --------------------------------------------------------------- hangul handling

CHO = ["g", "kk", "n", "d", "tt", "r", "m", "b", "pp", "s", "ss", "", "j", "jj",
       "ch", "k", "t", "p", "h"]
JUNG = ["a", "ae", "ya", "yae", "eo", "e", "yeo", "ye", "o", "wa", "wae", "oe",
        "yo", "u", "wo", "we", "wi", "yu", "eu", "ui", "i"]
JONG = ["", "k", "k", "k", "n", "n", "n", "t", "l", "l", "l", "l", "l", "l", "l",
        "l", "m", "p", "p", "t", "t", "ng", "t", "t", "k", "t", "p", "t"]

SBASE, LCOUNT, VCOUNT, TCOUNT = 0xAC00, 19, 21, 28


def _syllables(text: str):
    """Yield (cho, jung, jong) index triples for each Hangul syllable."""
    for ch in text:
        code = ord(ch) - SBASE
        if 0 <= code < LCOUNT * VCOUNT * TCOUNT:
            yield (code // (VCOUNT * TCOUNT),
                   (code % (VCOUNT * TCOUNT)) // TCOUNT,
                   code % TCOUNT)


def romanize(text: str) -> str:
    """Revised-Romanization-ish transliteration. Good enough for candidate names."""
    out = []
    for c, v, t in _syllables(text):
        out.append(CHO[c] + JUNG[v] + JONG[t])
    return "".join(out)


def initials(text: str) -> str:
    """Syllable-initial abbreviation - the Korean way of shortening a name.

    This is NOT English vowel-dropping, and tools that only do the latter miss it
    entirely. A three-syllable stem routinely becomes a three-letter tag.

    One letter per syllable, always. The null initial has no romanization of its
    own, so a syllable carrying it contributes its vowel instead - otherwise every
    vowel-initial syllable would vanish and a three-syllable stem could collapse to
    a single letter, losing the candidate entirely.
    """
    out = []
    for c, v, _ in _syllables(text):
        out.append(CHO[c] or JUNG[v][0])
    return "".join(out)


# ------------------------------------------------------------------- generation

def normalize_term(value: str) -> str:
    """Normalize an operator-supplied affix to the generator's ASCII alphabet.

    Platform identifiers are not free-form text.  NFKC closes easy Unicode lookalike
    and full-width surprises; the explicit ASCII filter keeps generated target names
    reproducible across Python and operating-system locale versions.
    """
    value = unicodedata.normalize("NFKC", value).casefold().strip()
    return "".join(ch for ch in value if ch in "abcdefghijklmnopqrstuvwxyz0123456789")


def _clean(s: str) -> str:
    return normalize_term(s)


def _english_name_parts(value: str) -> list[str]:
    """Return English name tokens after removing exact legal-form suffix tokens."""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    parts = re.findall(r"[a-z0-9]+", normalized)
    while parts and parts[-1] in STRIP_TAILS_EN:
        parts.pop()
    return parts


def _english_compound_stems(parts: list[str]) -> list[str]:
    """Keep explicit word boundaries in a multiword Latin company name.

    Registrants commonly retain one boundary between a distinctive leading word
    and a descriptive compound tail (``brand-industryword``).  The unjoined
    version is already the ordinary English-name stem; this produces only the
    bounded, source-word-derived join variants and never invents vocabulary.
    """
    if len(parts) < 2:
        return []
    return ["-".join(("".join(parts[:split]), "".join(parts[split:])))
            for split in range(1, len(parts))]


def _english_initialism(parts: list[str]) -> str:
    """Return the explicit first-letter abbreviation of a multiword input."""
    return "".join(part[0] for part in parts) if len(parts) >= 2 else ""


def _english_brand_compound(parts: list[str], industry: list[str]) -> str:
    """Preserve a hyphenated multiword brand only before a supplied industry tail."""
    if len(parts) >= 3 and parts[-1] in industry:
        return "-".join(parts[:-1])
    return ""


def _strip_korean_legal_boundary(value: str) -> str:
    """Remove a legal/geographic form once, only at a name boundary."""
    compact = re.sub(r"\s+", "", unicodedata.normalize("NFKC", value).strip())
    for prefix in sorted(LEGAL_PREFIXES_KO, key=len, reverse=True):
        prefix = re.sub(r"\s+", "", unicodedata.normalize("NFKC", prefix))
        if compact.startswith(prefix) and len(compact) > len(prefix):
            compact = compact[len(prefix):]
            break
    for suffix in sorted(LEGAL_SUFFIXES_KO, key=len, reverse=True):
        suffix = re.sub(r"\s+", "", unicodedata.normalize("NFKC", suffix))
        if compact.endswith(suffix) and len(compact) > len(suffix):
            compact = compact[:-len(suffix)]
            break
    return compact


def stems(ko: str = "", en: str = "", extra: list[str] | None = None,
          industry: list[str] | None = None) -> list[tuple[str, str]]:
    """Return [(stem, how-it-was-derived)], deduped, order preserved."""
    found: list[tuple[str, str]] = []

    def add(value: str, why: str, *, preserve_hyphen: bool = False) -> None:
        # Compound stems are assembled from already-normalized English tokens;
        # retain their one intentional boundary while ordinary operator terms
        # remain in the strict ASCII-alphanumeric stem alphabet.
        v = value if preserve_hyphen else _clean(value)
        if not v or len(v) < 2:
            return
        existing = next((index for index, (stem, _) in enumerate(found) if stem == v), None)
        if existing is None:
            found.append((v, why))
        elif found[existing][1].endswith("initialism") and why in {"operator-supplied", "english-name"}:
            # A later literal seed has stronger provenance than a shorthand we
            # derived from earlier words.  Replace it in place to preserve the
            # source order without carrying the bare-only initialism restriction.
            found[existing] = (v, why)

    industry = industry or []
    for raw in (extra or []):
        # An operator may intentionally supply a legal-looking or otherwise
        # compact account spelling.  Preserve that literal normalized seed before
        # using tokenization only for additional, lower-confidence derivatives.
        add(raw, "operator-supplied")
        parts = _english_name_parts(raw)
        for compound in _english_compound_stems(parts):
            add(compound, "operator-supplied-compound", preserve_hyphen=True)
        add(_english_initialism(parts), "operator-supplied-initialism")
        add(_english_brand_compound(parts, industry), "operator-supplied-brand-compound",
            preserve_hyphen=True)

    if en:
        parts = _english_name_parts(en)
        add("".join(parts), "english-name")
        for compound in _english_compound_stems(parts):
            add(compound, "english-compound-joined", preserve_hyphen=True)
        add(_english_brand_compound(parts, industry), "english-brand-compound",
            preserve_hyphen=True)
        add(_english_initialism(parts), "english-initialism")
        for index, part in enumerate(parts):
            # The first word of a multiword official spelling is often the
            # distinctive brand.  Treat it as an operator-supplied-quality stem;
            # later descriptive words remain lower priority.
            add(part, "english-leading-token" if index == 0 else "english-token")

    if ko:
        original = re.sub(r"\s+", "", unicodedata.normalize("NFKC", ko).strip())
        body = _strip_korean_legal_boundary(ko)

        # A lexical occurrence such as 코리아별빛 is identity, not a removable
        # suffix.  Preserve the original even where boundary stripping applies.
        add(romanize(original), "korean-original-romanized")
        add(initials(original), "korean-original-initials")

        for tail in TAILS_KO:                      # split a compound at a known tail
            if body.endswith(tail) and len(body) > len(tail):
                head = body[: -len(tail)]
                add(romanize(head), "korean-stem-romanized")
                add(initials(head), "korean-stem-initials")
                add(romanize(tail), "korean-tail-romanized")
                break
        add(romanize(body), "korean-whole-romanized")
        add(initials(body), "korean-whole-initials")

    # English-side abbreviations of whatever stems we have so far
    for value, why in list(found):
        if why.endswith("initialism"):
            continue
        if value.isascii() and len(value) >= 5:
            devoweled = value[0] + "".join(c for c in value[1:] if c not in "aeiou")
            if 2 < len(devoweled) < len(value):
                add(devoweled, "devowelled")
            add(value[:4], "truncated")

    return found


# How much to trust a stem. A name the company actually writes beats one this script
# invented by chopping letters off.  Within a quality group, generation is deliberately
# interleaved: a finite probe budget needs one name, one business combination, and one
# numeric variation from each spelling before it needs every suffix on one long stem.
STEM_WEIGHT = {
    "operator-supplied": 0, "operator-supplied-compound": 0,
    "operator-supplied-brand-compound": 0, "english-name": 0,
    "english-compound-joined": 0, "english-brand-compound": 0,
    "english-leading-token": 0, "english-token": 1,
    "operator-supplied-initialism": 1, "english-initialism": 1,
    "korean-original-romanized": 1, "korean-original-initials": 2,
    "korean-stem-romanized": 1, "korean-stem-initials": 2,
    "korean-whole-romanized": 2, "korean-tail-romanized": 3,
    "korean-whole-initials": 3, "devowelled": 4, "truncated": 4,
}


def generate(ko: str = "", en: str = "", extra: list[str] | None = None,
             functions: list[str] | None = None,
             industry: list[str] | None = None) -> list[tuple[str, int, str]]:
    """Return [(candidate, tier, rationale)] ranked by stem quality, then tier.

    Ranking matters because anonymous rate limits cap how many candidates ever get
    measured. Sorting by length instead of stem quality floats junk abbreviations
    above the company's actual name - measured, and fixed.
    """
    funcs = [normalize_term(f) for f in (functions or FUNCTION)]
    funcs = [f for f in funcs if f]
    inds = [normalize_term(i) for i in (industry or [])]
    inds = [i for i in inds if i]
    base = stems(ko, en, extra, inds)
    seen: set[str] = set()
    out: list[tuple[str, int, str, int, int, int, int, int]] = []

    def emit(value: str, tier: int, why: str, weight: int, round_: int,
             kind: int, stem_order: int, joiner: int) -> None:
        if value and value not in seen and 2 <= len(value) <= 39:
            seen.add(value)
            out.append((value, tier, why, weight, round_, kind, stem_order, joiner))

    def affixes(stem: str, words: list[str], tier: int, kind: str, weight: int,
                kind_order: int, stem_order: int) -> None:
        for word_order, word in enumerate(words):
            if word in stem or stem in word:      # 'rent' + 'rent' is not a name
                continue
            for ji, j in enumerate(JOINERS):
                # Each word gets a round.  A separator is a spelling variation inside
                # that round, after the compact form, rather than a reason to bury the
                # next stem's brand+role candidate.
                emit(f"{stem}{j}{word}", tier, f"stem+{kind}:{word}", weight,
                     word_order + 1, kind_order, stem_order, ji)

    for stem_order, (stem, why) in enumerate(base):
        w = STEM_WEIGHT.get(why, 4)
        emit(stem, 1, f"stem:{why}", w, 0, 0, stem_order, 0)  # bare name
        if why.endswith("initialism"):
            # Acronyms are a bounded, source-derived shorthand.  Do not multiply
            # this weaker guess by roles, separators, or numeric suffixes.
            continue
        affixes(stem, inds, 2, "industry", w, 1, stem_order)
        affixes(stem, funcs, 3, "function", w, 2, stem_order)
        for number_order, num in enumerate(NUMERIC):           # uniqueness suffix
            emit(f"{stem}{num}", 4, f"stem+numeric:{num}", w,
                 number_order + 1, 3, stem_order, 0)

    # Generic round-robin over each quality group: bare names first, then the first
    # requested industry, function, and numeric form for every spelling.  This keeps
    # a long official stem or a large FUNCTION lexicon from monopolizing a bounded
    # batch.  Tier still describes how a candidate was derived; it is not its queue
    # position.
    # Separator choices are spelling variants, so the compact form for every stem
    # is useful sooner than hyphen/underscore spellings of the first long stem.
    out.sort(key=lambda r: (r[3], r[4], r[7], r[5], r[6], len(r[0]), r[0]))
    return [(v, t, why) for v, t, why, *_ in out]


TARGET_PATTERNS = {
    "github": "https://api.github.com/users/{c}",
    "pages": "https://{c}.github.io/",
    "gitlab": "https://gitlab.com/{c}",
    "vercel": "https://{c}.vercel.app/",
    "netlify": "https://{c}.netlify.app/",
    "pagesdev": "https://{c}.pages.dev/",
    "s3": "https://{c}.s3.amazonaws.com/",
    "gcs": "https://storage.googleapis.com/{c}/",
}


def validate_target_candidate(target: str, candidate: str) -> bool:
    """Validate a candidate against the namespace used by a target URL template."""
    if target not in TARGET_PATTERNS or not candidate.isascii():
        return False

    dns_label = re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", candidate)
    if target in {"vercel", "netlify", "pagesdev"}:
        return dns_label is not None
    if target in {"github", "pages"}:
        return (
            len(candidate) <= 39
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", candidate) is not None
            and "--" not in candidate
        )
    if target == "gitlab":
        return (
            2 <= len(candidate) <= 255
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?", candidate) is not None
            and ".." not in candidate
        )
    if target == "s3":
        if not 3 <= len(candidate) <= 63 or candidate.startswith("xn--"):
            return False
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", candidate) is None:
            return False
        if ".." in candidate or ".-" in candidate or "-." in candidate:
            return False
        try:
            ipaddress.ip_address(candidate)
            return False
        except ValueError:
            return True
    if target == "gcs":
        return (
            3 <= len(candidate) <= 63
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", candidate) is not None
            and ".." not in candidate
        )
    return False


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate candidate identifiers for exposure discovery.")
    p.add_argument("--ko", default="", help="company name in Korean")
    p.add_argument("--en", default="", help="company name in Latin script, as the company writes it")
    p.add_argument("--stem", action="append", default=[], help="extra stem (repeatable)")
    p.add_argument("--industry", action="append", default=[], help="industry word, e.g. a line of business (repeatable)")
    p.add_argument("--function", action="append", default=[], help="extra business-function word (repeatable)")
    p.add_argument("--targets", choices=sorted(TARGET_PATTERNS), help="emit probe batch URL<TAB>label rows")
    p.add_argument("--limit", type=positive_int, default=200, help="max candidates (default 200)")
    p.add_argument("--tier", type=int, choices=range(1, 5), help="only this tier")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args(argv)

    if args.selftest:
        return selftest()
    if not (args.ko or args.en or args.stem):
        p.error("give at least one of --ko / --en / --stem")

    # Output is documented as feeding `python -m sudetect probe --batch`, which reads tab-separated
    # lines. On Windows, text-mode stdout would emit CRLF and put a stray CR at the
    # end of the last field. Pin LF so the handoff is identical on every platform.
    try:
        sys.stdout.reconfigure(newline="\n")
    except (AttributeError, ValueError):
        pass

    rows = generate(args.ko, args.en, args.stem,
                    functions=(FUNCTION + args.function) if args.function else None,
                    industry=args.industry)
    if args.tier is not None:
        rows = [r for r in rows if r[1] == args.tier]

    if args.targets:
        rows = [r for r in rows if validate_target_candidate(args.targets, r[0])]
    rows = rows[: args.limit]

    if args.targets:
        pattern = TARGET_PATTERNS[args.targets]
        for cand, tier, why in rows:
            print(f"{pattern.format(c=cand)}\tt{tier} {cand} ({why})")
    else:
        print("CANDIDATE\tTIER\tRATIONALE")
        for cand, tier, why in rows:
            print(f"{cand}\t{tier}\t{why}")

    print(f"\n# {len(rows)} candidates. A candidate is a guess, not an asset -",
          "confirm ownership before probing (SUD-R04).", file=sys.stderr)
    return 0


# ------------------------------------------------------------------- self-check

def selftest() -> int:
    """The transformations that a name-only search misses. Neutral inputs."""
    fails = []

    def check(label, got, want):
        if got != want:
            fails.append(f"{label}: got {got!r}, want {want!r}")

    # Hangul arithmetic. Neutral, well-known words only - never a real company's name.
    check("romanize/vowel", romanize("서울"), "seoul")
    check("romanize/jong", romanize("한국"), "hanguk")
    check("romanize/4syl", romanize("대한민국"), "daehanminguk")
    check("initials", initials("대한민국"), "dhmg")
    # One letter per syllable even when the initial is the null consonant, otherwise a
    # vowel-initial stem collapses and its candidates are never generated at all.
    check("initials/null-initial", initials("에이스"), "eis")
    check("initials/mixed", initials("우리은행"), "ureh")
    assert all(len(initials(w)) == len(w) for w in ("에이스", "우리은행", "대한민국")), \
        "initials must emit exactly one letter per syllable"

    # A compound Korean name splits at a known tail, and BOTH halves survive.
    got = dict((s, w) for s, w in stems(ko="코스모스렌트카"))
    assert "koseumoseu" in got, got     # 코스모스 romanized
    assert "ksms" in got, got           # syllable-initial abbreviation, one letter per syllable
    assert "renteuka" in got, got       # the tail is searchable on its own

    # The decisive case: stem + a business-function word absent from the name.
    cands = [c for c, _, _ in generate(en="cosmos", industry=["rentcar"])]
    assert "cosmossales" in cands, "stem+function not generated"
    assert "cosmos-sales" in cands, "joiner variant not generated"
    assert "cosmosrentcar" in cands, "stem+industry not generated"

    # Preserve a semantic word boundary before a compound tail and apply the
    # usual uniqueness suffix.  These are neutral fixtures, not company seeds.
    compound = [c for c, _, _ in generate(en="melody rent car")]
    assert "melodyrentcar1" in compound, "compound numeric variant not generated"
    assert "melody-rentcar1" in compound, "joined compound numeric variant not generated"
    assert "melodysales" in compound, "leading brand function variant not generated"

    # Loanword stems: romanization and origin spelling differ, so both must be present
    # when the operator supplies the origin spelling alongside the Korean name.
    both = [c for c, _, _ in generate(ko="코스모스렌트카", en="cosmos")]
    assert "koseumoseu" in both and "cosmos" in both, "romanized and origin must coexist"

    # Ranking: the name the company actually writes must come first, and every affix
    # on it must be tried before a stem this script invented by chopping letters.
    rows = generate(ko="코스모스렌트카", en="cosmos", industry=["rentcar"])
    assert rows[0][0] == "cosmos", f"real name must rank first, got {rows[0][0]!r}"
    pos = {c: i for i, (c, _, _) in enumerate(rows)}
    assert pos["cosmossales"] < pos["koseumoseu"], "affixed real stem beats weaker stem"
    assert pos["cosmossales"] < 60, f"stem+function buried at {pos['cosmossales']}"
    assert "rentcarrentcar" not in pos and "rentcar-rentcar" not in pos, "self-affix must be skipped"

    # Hygiene
    assert all(2 <= len(c) <= 39 for c, _, _ in rows), "length bounds"
    assert len({c for c, _, _ in rows}) == len(rows), "candidates must be unique"

    if fails:
        print("FAIL\n  " + "\n  ".join(fails))
        return 1
    print(f"PASS  idgen selftest ({len(rows)} candidates from one seed pair)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
