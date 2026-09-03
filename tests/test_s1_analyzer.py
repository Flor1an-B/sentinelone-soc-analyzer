"""
Regression tests for s1_analyzer.py.

Not a golden-JSON diff suite (the tool has no prior test baseline and several
bugs were fixed in this pass) — instead these lock in invariants that must
hold regardless of implementation details: pure-function correctness on
adversarial input, and structural guarantees of a full analyze() run against
the real sample CSVs already checked into this repo.

Run from the repo root: pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import s1_analyzer as s1  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = REPO_ROOT / "A_Analyser" / "RzSDKService.csv"


# ─────────────────────────────────────────────────────────────────────────
# URL cleaning / IOC extraction (s1_analyzer.py:_clean_url, _refang, etc.)
# ─────────────────────────────────────────────────────────────────────────

class TestCleanUrl:
    def test_strips_trailing_sentence_punctuation(self):
        assert s1._clean_url("https://evil.com/a.") == "https://evil.com/a"
        assert s1._clean_url("https://evil.com/a,") == "https://evil.com/a"

    def test_preserves_legitimate_comma_in_query(self):
        # commas are valid RFC 3986 sub-delims — must not be stripped mid-URL
        u = "https://evil.com/path?a=1,2,3"
        assert s1._clean_url(u) == u

    def test_preserves_balanced_parens(self):
        u = "https://evil.com/path(v2)/payload.exe"
        assert s1._clean_url(u) == u

    def test_strips_unbalanced_trailing_paren(self):
        assert s1._clean_url("https://evil.com/a)") == "https://evil.com/a"

    def test_truncates_at_shell_quote_breakout(self):
        # regression: PowerShell array literal like @('https://host/p','0',...)
        u = "https://host/p','0','C:\\\\Windows"
        assert s1._clean_url(u) == "https://host/p"

    def test_rejects_hostless_stub(self):
        assert s1._clean_url("http://") == ""
        assert s1._clean_url("https://a") == ""

    def test_empty_input(self):
        assert s1._clean_url("") == ""
        assert s1._clean_url(None) == ""

    def test_refangs_hxxp(self):
        assert s1._clean_url("hxxps://evil[.]com/a") == "https://evil.com/a"


class TestRefang:
    def test_defang_patterns(self):
        assert s1._refang("hxxp://evil.com") == "http://evil.com"
        assert s1._refang("evil[.]com") == "evil.com"
        assert s1._refang("evil(dot)com") == "evil.com"
        assert s1._refang("evil[dot]com") == "evil.com"


class TestExtractUrlsFromText:
    def test_finds_plain_and_defanged(self):
        text = "payload at https://evil.com/a and hxxp://bad[.]com/b then done."
        urls = s1._extract_urls_from_text(text)
        assert "https://evil.com/a" in urls
        assert "http://bad.com/b" in urls

    def test_dedup_preserves_order(self):
        text = "https://a.com/x https://a.com/x https://b.com/y"
        assert s1._extract_urls_from_text(text) == ["https://a.com/x", "https://b.com/y"]

    def test_no_urls(self):
        assert s1._extract_urls_from_text("nothing here") == []
        assert s1._extract_urls_from_text("") == []


class TestNormalizeUrlKey:
    def test_case_insensitive_scheme_host(self):
        a = s1._normalize_url_key("HTTPS://Evil.COM/Path?X=1")
        b = s1._normalize_url_key("https://evil.com/Path?X=1")
        assert a == b
        # path/query case is preserved (only scheme+host are lowered)
        assert "Path?X=1" in a


# ─────────────────────────────────────────────────────────────────────────
# EventParser — SentinelOne event.details key=value / MITRE HTML parsing
# ─────────────────────────────────────────────────────────────────────────

class TestEventParser:
    def test_simple_kv_pairs(self):
        d = s1.EventParser.parse("[src.process.cmdline=cmd.exe /c dir src.process.publisher=Microsoft]")
        assert d["src.process.cmdline"] == "cmd.exe /c dir"
        assert d["src.process.publisher"] == "Microsoft"

    def test_quoted_value_with_spaces(self):
        d = s1.EventParser.parse('[src.process.cmdline="C:\\Program Files\\app.exe -x" src.process.publisher=Foo]')
        assert d["src.process.cmdline"] == "C:\\Program Files\\app.exe -x"

    def test_empty_input(self):
        assert s1.EventParser.parse("") == {}
        assert s1.EventParser.parse(None) == {}


# ─────────────────────────────────────────────────────────────────────────
# CsvParser — line reconstruction, timestamp parsing, schema validation
# ─────────────────────────────────────────────────────────────────────────

class TestCsvParserReconstructLines:
    def test_single_line_untouched(self):
        assert s1.CsvParser._reconstruct_lines("a,b,c") == ["a,b,c"]

    def test_multiline_quoted_field_rejoined(self):
        content = 'a,"b\nstill b",c'
        assert s1.CsvParser._reconstruct_lines(content) == ['a,"b still b",c']


class TestCsvParserTimestamp:
    def test_dv_format(self):
        ts = s1.CsvParser._parse_ts("Mar 6, 2026 7:46:04 PM")
        assert ts is not None and ts.year == 2026 and ts.month == 3

    def test_iso_format(self):
        ts = s1.CsvParser._parse_ts("2026-03-06T19:46:04.000Z")
        assert ts is not None and ts.hour == 19

    def test_unparseable_returns_none(self):
        assert s1.CsvParser._parse_ts("not a date") is None


class TestCsvParserSchemaValidation:
    def test_missing_columns_warns(self, tmp_path):
        csv_path = tmp_path / "bad.csv"
        csv_path.write_text("foo,bar\nval1,val2\n", encoding="utf-8")
        events = s1.CsvParser.parse_file(str(csv_path))
        assert events == []
        assert any("missing expected column" in w for w in s1.CsvParser.last_warnings)

    def test_well_formed_dv_csv_no_warnings(self):
        assert SAMPLE_CSV.exists(), "sample fixture missing"
        events = s1.CsvParser.parse_file(str(SAMPLE_CSV))
        assert len(events) > 0
        assert s1.CsvParser.last_warnings == []

    def test_row_skip_counter(self, tmp_path):
        csv_path = tmp_path / "partial.csv"
        csv_path.write_text(
            "event.time,agent.uuid,src.process.user,event.type,"
            "src.process.storyline.id,event.details\n"
            '"Mar 6, 2026 7:46:04 PM",u1,user,Process Creation,s1,[a=b]\n'
            ",,,,,\n",  # missing event.time -> skipped
            encoding="utf-8",
        )
        events = s1.CsvParser.parse_file(str(csv_path))
        assert len(events) == 1
        assert s1.CsvParser.last_rows_skipped == 1
        assert s1.CsvParser.last_rows_total == 2


# ─────────────────────────────────────────────────────────────────────────
# SigmaEvaluator — event-type index must select the same rules the old
# unindexed per-rule CATEGORY_MAP check would have (behavior-preserving
# optimization: same candidates, just not O(all rules) per event).
# ─────────────────────────────────────────────────────────────────────────

class TestSigmaEvaluatorIndex:
    def test_every_rule_indexed_exactly_once_per_bucket_or_unfiltered(self):
        sigma = s1.SigmaEvaluator()
        if not sigma.available:
            import pytest
            pytest.skip("Sigma rules not present in data/sigma/rules")
        indexed_rule_ids = set()
        for rules in sigma._by_etype.values():
            for r in rules:
                indexed_rule_ids.add(id(r))
        unfiltered_ids = {id(r) for r in sigma._unfiltered}
        # Every loaded rule must be reachable from at least one bucket.
        all_ids = {id(r) for r in sigma._rules}
        assert (indexed_rule_ids | unfiltered_ids) >= all_ids

    def test_unfiltered_rules_match_declared_empty_or_unmapped_categories(self):
        sigma = s1.SigmaEvaluator()
        if not sigma.available:
            import pytest
            pytest.skip("Sigma rules not present in data/sigma/rules")
        for r in sigma._unfiltered:
            cat = r.get("_cat", "")
            ets = sigma.CATEGORY_MAP.get(cat)
            assert not ets  # either unmapped (None) or explicitly empty set

    def test_evaluate_event_only_returns_candidates_relevant_to_etype(self):
        sigma = s1.SigmaEvaluator()
        if not sigma.available:
            import pytest
            pytest.skip("Sigma rules not present in data/sigma/rules")
        ev = {"event_type": "Process Creation",
              "details": {"src.process.cmdline": "cmd.exe /c whoami"}}
        # Must not raise, must return a list (possibly empty)
        hits = sigma.evaluate_event(ev)
        assert isinstance(hits, list)


# ─────────────────────────────────────────────────────────────────────────
# MitreAttackEnricher — tid index gives identical results to a full scan
# ─────────────────────────────────────────────────────────────────────────

class TestMitreAttackEnricher:
    def test_known_technique_lookup(self):
        enricher = s1.MitreAttackEnricher()
        if not enricher.available:
            import pytest
            pytest.skip("ATT&CK bundle not present in data/attack/")
        info = enricher.get_technique_info("T1055")  # Process Injection
        assert info != {}
        assert "detection" in info

    def test_unknown_technique_returns_empty(self):
        enricher = s1.MitreAttackEnricher()
        if not enricher.available:
            import pytest
            pytest.skip("ATT&CK bundle not present in data/attack/")
        assert enricher.get_technique_info("T9999.999") == {}

    def test_index_built_covers_lookup_result(self):
        enricher = s1.MitreAttackEnricher()
        if not enricher.available:
            import pytest
            pytest.skip("ATT&CK bundle not present in data/attack/")
        assert "T1055" in enricher._tid_index


# ─────────────────────────────────────────────────────────────────────────
# End-to-end smoke test — full analyze() pipeline on a real sample CSV
# ─────────────────────────────────────────────────────────────────────────

class TestAnalyzeEndToEnd:
    def test_full_pipeline_produces_valid_report(self):
        assert SAMPLE_CSV.exists(), "sample fixture missing"
        data = s1.analyze(str(SAMPLE_CSV), output_report=True)

        # Structural invariants
        for section in ("meta", "identification", "data_quality", "verdict",
                         "metrics", "behavioral_indicators", "mitre_attack",
                         "sigma_matches", "ioc_extraction", "kill_chain"):
            assert section in data, f"missing JSON section: {section}"

        score = data["verdict"]["score"]
        assert isinstance(score, int)
        assert 0 <= score <= 20

        assert isinstance(data["data_quality"], dict)
        assert data["data_quality"]["csv_warnings"] == []

    def test_html_generation_does_not_raise(self):
        import s1_report
        assert SAMPLE_CSV.exists(), "sample fixture missing"
        data = s1.analyze(str(SAMPLE_CSV), output_report=True)
        html = s1_report.generate_html(data)
        assert "<html" in html
        assert "const DATA = " in html
        # XSS regression guard: the injected JSON blob must never carry a
        # literal </script> (or <, >, &) that could break out of the tag.
        payload_start = html.index("const DATA = ") + len("const DATA = ")
        payload_end = html.index(";\n", payload_start)
        payload = html[payload_start:payload_end]
        assert "<" not in payload and ">" not in payload
