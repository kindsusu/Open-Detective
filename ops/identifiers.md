# Offline identifier candidates

`tools/idgen.py` expands operator-supplied Korean and English name seeds into ranked account/project/bucket candidates without making network requests. This is a recall aid, not an ownership classifier.

Provide the official Latin spelling when known; romanization and the spelling used at signup can differ. Legal-form tails are removed only as normalized trailing tokens. Runtime function/industry terms use NFKC, lowercase, and the generator's ASCII alphabet. Platform output applies namespace-specific character and length validation. `--limit` must be positive and `--tier` is 1–4.

```bash
python tools/idgen.py --ko "<name>" --en "<official spelling>" --function ops --limit 100
python tools/idgen.py --en "<name>" --targets vercel --tier 3
python tools/idgen.py --selftest
```

Tier 1 contains direct stems, tier 2 industry affixes, tier 3 generic function affixes, and tier 4 numeric suffixes. For a multiword official Latin spelling, the generator also keeps bounded source-word compound boundaries (for example, `brand-industryword`) and tests their numeric variants. Ranking is a deterministic search order, not a probability or confidence score: direct stems and compact numeric uniqueness variants are placed before the wider function-word fan-out so a finite `--limit` reaches them.

Every output remains a candidate. Confirm it through an owner API, verified DNS/control-plane relation, repository deployment metadata, or another accountable owner record. Similarity, a 403/404, an existing account, or a public page is insufficient. After a confirmed entry point, prefer exact relation edges such as team/project/deployment/alias over more guessing.

Do not place real company seeds in this repository, probe every generated value, infer employee personal accounts, or persist secret-bearing target URLs. The generator has no network dependency; unit tests must stay offline.
