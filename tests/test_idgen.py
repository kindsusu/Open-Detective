import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tools import idgen


class IdgenTests(unittest.TestCase):
    def test_search_phrases_include_brand_industry_and_korean_compounds(self):
        from sudetect.identifiers import generate_search_queries
        rows = generate_search_queries(ko="멜로디렌트카", en="Melody Rent Car", industry=["rentcar"])
        values = {row["query"].casefold() for row in rows}
        self.assertTrue({"멜로디렌트카", "멜로디 렌트카", "멜로디", "렌트카",
                         "melody rent car", "melodyrentcar", "melody", "rentcar"}.issubset(values))
        self.assertLess(next(i for i, r in enumerate(rows) if r["query"] == "Melody Rent Car"),
                        next(i for i, r in enumerate(rows) if r["query"].casefold() == "rentcar"))

    def test_korean_legal_forms_only_strip_at_boundaries_and_original_survives(self):
        lexical = dict(idgen.stems(ko="코리아별빛"))
        self.assertIn("koriabyeolbit", lexical)
        self.assertNotIn("byeolbit", lexical)
        self.assertIn("byeolbit", dict(idgen.stems(ko="(주)별빛")))
        self.assertIn("byeolbit", dict(idgen.stems(ko="별빛 주식회사")))
        middle = dict(idgen.stems(ko="별빛그룹연구소"))
        self.assertIn("byeolbitgeurupyeonguso", middle)
    def test_legal_tail_is_case_insensitive_and_boundary_aware(self):
        values = dict(idgen.stems(en="A.B-C_D, Inc."))
        self.assertIn("abcd", values)
        self.assertNotIn("abcdinc", values)
        self.assertIn("coin", dict(idgen.stems(en="Coin")))

    def test_runtime_terms_are_normalized(self):
        candidates = [row[0] for row in idgen.generate(en="Acme", functions=["  SALES & Ops  "])]
        self.assertIn("acmesalesops", candidates)
        self.assertTrue(all(value.isascii() and value == value.lower() for value in candidates))

    def test_unicode_extra_stem_is_not_emitted_as_ascii_platform_name(self):
        self.assertEqual(idgen.stems(extra=["회사"]), [])
        self.assertFalse(idgen.validate_target_candidate("github", "회사"))

    def test_target_specific_validation(self):
        self.assertTrue(idgen.validate_target_candidate("github", "acme-team"))
        self.assertFalse(idgen.validate_target_candidate("github", "acme_team"))
        self.assertFalse(idgen.validate_target_candidate("github", "a" * 40))
        self.assertTrue(idgen.validate_target_candidate("gitlab", "acme_team"))
        self.assertTrue(idgen.validate_target_candidate("s3", "acme.assets"))
        self.assertFalse(idgen.validate_target_candidate("s3", "192.0.2.1"))
        self.assertFalse(idgen.validate_target_candidate("vercel", "-acme"))

    def test_cli_rejects_non_positive_limit_and_invalid_tier(self):
        for argv in (["--en", "acme", "--limit", "0"], ["--en", "acme", "--limit", "-1"],
                     ["--en", "acme", "--tier", "0"], ["--en", "acme", "--tier", "5"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    idgen.main(argv)

    def test_target_output_filters_invalid_names_and_stays_offline(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = idgen.main(["--stem", "acme_team", "--targets", "github", "--limit", "10"])
        self.assertEqual(result, 0)
        self.assertNotIn("acme_team", stdout.getvalue())
        self.assertIn("https://api.github.com/users/", stdout.getvalue())

    def test_compound_brand_candidates_are_ranked_inside_bounded_github_batch(self):
        # Synthetic multword name: no organization-specific naming map belongs
        # in public fixtures.  Keep a compound-tail separator and a numeric
        # uniqueness suffix without putting either behind the default limit.
        rows = [row for row in idgen.generate(en="Melody Rent Car")
                if idgen.validate_target_candidate("github", row[0])]
        rank = {candidate: index + 1 for index, (candidate, _, _) in enumerate(rows)}
        self.assertLessEqual(rank["melodyrentcar1"], 100)
        self.assertLessEqual(rank["melody-rentcar1"], 100)
        self.assertLessEqual(rank["melodysales"], 100)

        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            result = idgen.main(["--en", "Melody Rent Car", "--targets", "github", "--limit", "100"])
        self.assertEqual(result, 0)
        emitted = stdout.getvalue()
        for candidate in ("melodyrentcar1", "melody-rentcar1", "melodysales"):
            self.assertIn(f"/users/{candidate}\t", emitted)


if __name__ == "__main__":
    unittest.main()
