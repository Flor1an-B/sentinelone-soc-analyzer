# Changelog

## [3.7.0] - 2026-09-15

### Added — plain-language summary and less clutter for non-expert readers

Direct response to user feedback after live testing: the report was hard to read for someone who isn't a SOC analyst, and the sheer number of sections showing "nothing found" made it feel noisy/unclear even when that emptiness was legitimate (verified separately: on a real test CSV, ~2/3 of empty sections were empty because that CSV simply didn't contain that event type, not a detection bug).

- **Executive summary panel** (`renderExecutiveSummary` in `s1_report.py`) — a plain-language panel shown above the technical verdict hero: what happened (from the independent scenario narrative, falling back to the strongest evidence line), how many SentinelOne vs. independent findings support the conclusion, the verdict in one plain word (Likely malicious / Suspicious / Undetermined / Probably benign / Benign), and the top actionable recommendation. Built entirely from data already computed elsewhere (`scenario_reconstruction`, `verdict.recommendations`, `verdict.evidence_tp_sources`) — no new analysis, purely a simpler restatement.
- **Auto-collapsed empty sections + counter** — a section whose body is just the standard "No X detected/available" empty-state message (used consistently by ~25 render functions already) is now auto-collapsed by default, and a "N of M sections have findings" line is shown above the section list so a reader isn't stuck scrolling past a dozen empty panels to find the ones with actual content.

**Verification note**: an earlier pass of manual browser-less verification for this and the previous (v3.6.1) fix used a Node.js DOM mock whose `textContent` setter didn't update `innerHTML` the way real browsers do — since the report's `esc()` helper works by setting `textContent` then reading back `innerHTML`, every `esc()`-escaped value silently came back empty, and a check for "any French text present" trivially passed on blank output. Caught by testing the executive summary panel's own actual content (found it empty) rather than only checking for the *absence* of a specific bad string. Fixed the mock to properly escape text on `textContent` assignment (matching real DOM behavior) and re-ran full verification: 112,500+ real rendered characters across all panels, zero French leaks, executive summary confirmed populated with correct real content. 51/51 tests still passing.

## [3.6.1] - 2026-09-15

### Fixed — French text leaking into the (English-only) report

Root-caused from live user testing: internal severity levels are French strings (`CRITIQUE`/`ELEVE`/`MOYEN`/`FAIBLE`/`INFO`, used pervasively as VerdictEngine scoring-logic keys) and 8 evidence-text f-strings across `_check_execution_context`/`_check_indicators`/`_check_script_content`/`_check_suspicious_modules`/`_check_process_graph`/`_check_yara`/`_check_cmdline`/`_check_user_agents` interpolated that raw value directly into user-facing text (e.g. `[SCRIPT CRITIQUE] ...`, `[YARA ELEVE] ...`) instead of translating it — while a few other sites in the same file already correctly translated (e.g. `MOYEN` → `"[MEDIUM] ..."`), confirming the inconsistency was accidental, not by design.

- Added `SEVERITY_EN` translation map + `_sev_en()` helper; applied at all 8 live leak sites. Internal severity keys are intentionally left French everywhere else (used as scoring-logic dict keys throughout `VerdictEngine`/`INDICATOR_DB`; changing them would be high-risk for zero behavior change) — only the text actually shown to the user goes through translation.
- Translated two knowledge-base dicts that were entirely in French and feed evidence text: `ATTACK_VECTOR_PARENTS` (17 entries, e.g. *"Webshell ou RCE via IIS"* → *"Webshell or RCE via IIS"*) and `PERSISTENCE_REG_PATTERNS` (13 entries, e.g. *"Cle Run : execution automatique a chaque logon"* → *"Run key: automatic execution on every logon"*).
- `s1_report.py`'s YARA section built its own severity badge manually instead of going through the existing (correctly-translating) `sevBadge()` helper — fixed to reuse it.
- One remaining site is inside `ReportGenerator.generate()`/`generate_html()`, which are dead code never called by `main()` (see the `s1_analyzer.py` audit in project history) — left as-is, no user-facing impact.

**Verification**: rather than trust static code reading, actually executed the report's JS against a real generated dataset (`bypass.csv`) in a Node VM context with DOM stubs, calling all 23 section-render functions plus the 4 direct-DOM-write functions (verdict hero, bento grid, data-quality banner, MITRE heatmap) and inspecting their real rendered HTML output (65,000+ characters) for any of the 4 French severity words — confirmed zero occurrences. 51/51 tests still passing.

## [3.6.0] - 2026-09-15

### Added — independent scenario reconstruction

- **`ScenarioNarrator`** (new analyzer) and JSON section **`scenario_reconstruction`** (`narrative` + `timeline`) — reconstructs a chronological attack-scenario story built **only** from raw telemetry already gathered by the independent analyzers (process tree/attack-vector, network/beacon/UA, files, registry persistence, scheduled tasks, script content, cmdline/LOLBins findings, direct LSASS access). Deliberately never touches `BehaviorAnalyzer`/SentinelOne's own indicators — contrast with the existing `kill_chain` section, which is built entirely from S1's own indicator→MITRE-tactic mapping. Groups findings into 6 phases (Initial Execution, Script & Payload Activity, Persistence, Credential Access, Command & Control, Data & Impact), each phase is chronologically bounded by its own earliest/latest observed timestamp, and every sentence of the generated prose narrative traces back to a specific listed fact (template-based, not free-form generation) so nothing in the narrative is unaccountable to the underlying data.
- **HTML report** — new section "7. Scenario Reconstruction (independent)" (existing sections 7-27 renumbered to 8-28): the prose narrative in a highlighted panel, followed by the phase-by-phase fact list with per-phase timestamps.
- **Tests** — `TestScenarioNarrator` (empty-input fallback, LOLBin cmdline correctly routed to the right phase, structural validation against a real sample CSV, narrative content sanity) plus an end-to-end structural check that `scenario_reconstruction` is present and well-formed. 51/51 tests passing.

## [3.5.0] - 2026-09-15

### Added — evidentiary provenance & independent-analysis strengthening

Design constraint driving this release: the tool must never read SentinelOne's own verdict/classification as input (would create anchoring bias and defeat its purpose as an independent second opinion). Instead, this release makes the tool's *own* analysis verifiably independent and transparent about where each piece of evidence actually came from.

- **`VerdictEngine` evidentiary-source tracking** — every scoring check now tags its findings as `s1_indicators` (derived from SentinelOne's own "Behavioral Indicators"/attack-chain/temporal-sequence engine — `BehaviorAnalyzer` only ever reads events SentinelOne itself generated) or `independent` (derived from raw telemetry via our own Sigma/YARA/process-graph/network/file/registry/cmdline heuristics). New `verdict.contribution_breakdown` in the JSON exposes `s1_indicators_points` vs `independent_points` and critical/high finding counts per source; `verdict.evidence_tp_sources`/`evidence_fp_sources` tag each evidence line individually. Surfaced in the HTML report (source badges on each evidence line, an "Evidentiary basis" panel with a visual S1-vs-independent score bar).
- **`verdict.confidence_basis`** — a plain-English explanation of whether the verdict's confidence rests on independent corroboration, SentinelOne's own detections alone, or neither, with finding counts (e.g. *"corroborated by both SentinelOne's own detections (2 strong finding(s)) and independent raw-telemetry analysis (4 strong finding(s))"*). Lets an analyst write a defensible "our tool says X because [evidence Y]" justification without the tool ever having seen S1's own classification.
- **Fixed: independent-only strong evidence could never reach high-confidence verdicts** — `has_critical`/`has_multiple_high` (the gates for "High confidence TRUE POSITIVE") previously pattern-matched evidence text for exactly two hardcoded English strings (`"[CRITICAL]"`, `"[HIGH]"`), which only ever came from S1-derived checks. Every independent check's severity is rendered in French (`CRITIQUE`/`ELEVE`) or with a different prefix (`[SIGMA CRITICAL]`, `[YARA CRITIQUE]`, `[GRAPH CRITIQUE]`, etc.) and silently never matched — meaning a case with zero SentinelOne behavioral indicators but multiple independent CRITICAL findings (Sigma + YARA + script) was permanently capped at "SUSPICIOUS", never able to independently reach "TRUE POSITIVE — High confidence" on its own merits. Replaced with explicit severity tracking (`_tp(..., severity="critical"|"high")`) counted across all sources. Also newly recognizes direct LSASS access and C2 beacon detection as critical-severity independent findings (previously uncounted for confidence gating, though always scored).
- **LOLBins catalog** (`CmdlineAnalyzer.LOLBINS_DB`) — contextual detection of 11 commonly-abused Windows binaries (rundll32, regsvr32, mshta, certutil, bitsadmin, wmic, msbuild, installutil, regasm, regsvcs, forfiles, odbcconf) against documented real-world abuse patterns (Squiblydoo, Squiblytwo, HTA/JS droppers, BITS download, XSL injection, etc.), each mapped to its MITRE technique. Only the specific argument patterns are scored — invoking any of these binaries alone is normal, ubiquitous, legitimate Windows behavior and is never flagged.
- **Sigma score cap raised 6 → 15** — `evaluate_all()` already dedupes by rule title across all events, so a single noisy rule can never inflate the score; the cap only ever limited how many *distinct* CRITICAL-level community rules (curated for high precision) could count. Several independent CRITICAL Sigma matches on the same storyline is strong corroboration, not FP volume, and was undervalued relative to YARA's uncapped scoring for an equivalent signal.

### Tests
Added `tests/test_s1_analyzer.py::TestVerdictEngineProvenance` (severity/source tracking correctness, including a regression for the confidence_basis contradiction found live on `bypass.csv`) and `TestCmdlineAnalyzerLolbins` (benign LOLBin usage never flagged, malicious patterns correctly flagged and flow into the verdict as independently-sourced evidence). 47/47 tests passing.

## [3.4.1] - 2026-09-15

### Fixed
- **`YaraAnalyzer` individual-rule fallback dropped `private rule` dependencies** — root-caused from a real production report showing "31 YARA rule(s) failed to compile": several failures were `undefined identifier "<X>_PRIVATE"` for public rules referencing a `private rule` helper defined elsewhere in the same monolithic file (e.g. `TRELLIX_ARC_Ransom_Xinof` needs `TRELLIX_ARC_Ransom_Xinof_Chunk_PRIVATE`, `AVASTTI_Manjusaka_Payload_*` need `AVASTTI_*_PRIVATE`). When a batch compile fails and `_load_monolithic` falls back to compiling each rule chunk on its own, the private helper's chunk wasn't included, so any public rule depending on one failed even though the rule itself was fine. Fixed by indexing every `private rule` chunk by name and, when compiling a public rule individually, textually scanning its source for references to those names and prepending only the ones actually used (deliberately not *every* private rule — an unrelated private rule that's itself uncompilable would otherwise poison rules that don't even need it). Verified against a real report: 31 → 28 failures, with the 3 resolved being exactly the `_PRIVATE` ones.

### Added
- **`data_quality.yara_rule_error_samples`** — `yara_rule_errors` previously only exposed a count, giving no way to diagnose which rules failed or why. `YaraAnalyzer` now records up to 10 `"rule_name: exception"` samples during the monolithic fallback's per-rule compile, surfaced in the JSON and as a sub-list under the YARA warning in the HTML data-quality banner. This is what made the private-rule bug above diagnosable in the first place, and also surfaced a separate, non-fixable issue: the remaining ~28 failures are all `invalid field name "number_of_signatures"` — a known Windows-specific `yara-python` limitation ([VirusTotal/yara-python#246](https://github.com/VirusTotal/yara-python/issues/246)) where the PE module's Authenticode signature fields aren't available even on the latest PyPI release (4.5.4), unrelated to this project's code.
- **`s1_update.py --deps` (v2.1.0)** — upgrades the optional Python packages `s1_analyzer.py` uses (`pyyaml`, `networkx`, `pyod`, `yara-python`, `iocextract`, `mitreattack-python`, `certifi`) to their latest PyPI version via `pip`, so a single `s1_update.py` run keeps application files, detection rules, *and* the Python environment reproducibly up to date. Runs as part of the default no-argument full update alongside `--app`/`--rules`; supports `--check` (dry run via `pip install --upgrade --dry-run`) and `--force` (also attempts install of packages not currently present). A package that isn't installed is left alone otherwise, not treated as an error.

## [3.4.0] - 2026-09-03

### Security
- **XSS in `report.html`** — `s1_report.generate_html` injected raw `json.dumps()` output into `const DATA = /* JSON_INJECT */;` via string replace. `json.dumps` does not escape `</script>`, so a `</script>` substring anywhere in analyzed CSV content (e.g. a decoded payload or `event.details` field) would close the script tag early and let attacker-controlled HTML/JS execute when the analyst opens the report. Fixed by escaping `<`, `>`, `&` to `\uXXXX` in the injected blob (the OWASP-recommended technique for embedding JSON in a `<script>` context) — verified end-to-end with Node that the escaped blob still evaluates to the exact original string.

### Fixed
- **Progress bar never reached 100%** — `total_steps` was computed from optional Phase 2/3 module counts (Sigma/YARA/graph/stats/ATT&CK, IP enrichment) that the Phase 1 progress bar never actually increments for (those phases use spinners instead). The bar's real ceiling was the 15 Phase-1 steps, so with all modules enabled it stalled around 60%. `total_steps` is now fixed at 15, matching the real step count; the now-dead `step += 1` increments inside Phase 2-4 were removed.
- **YARA rule count under-reported (e.g. "1 YARA rule loaded" instead of ~4965)** — on yara-python versions that can compile the whole YARA Forge monolithic file directly (the fast path), `YaraAnalyzer._load` counted it as 1 *file* instead of counting the individual `rule NAME` definitions inside it. Matching only happened through the slower per-batch fallback path before, which is why this wasn't caught earlier. Now counts `rule` definitions in both the fast path and the batch/monolithic fallback.
- **`s1_update.py` YARA rule count** — `_update_yara` reassigned (`=`) the rule count inside the zip-member loop instead of accumulating (`+=`), so a release package containing more than one `.yar`/`.yara` file would report only the last file's count. No observed impact today (YARA Forge Core ships a single monolithic file) but fixed for robustness.
- **`IndicatorContextualizer.analyze()` dead `occurrences` field** — always returned `0` with a comment claiming it would be filled elsewhere; nothing ever did. Traced all 6 call sites — every one already recomputes the real count via `BehaviorAnalyzer.get_occurrence_count()` independently, so `report.json`'s actual `behavioral_indicators[].occurrences` was never affected. Removed the dead field.
- **stderr not forced to UTF-8** — only `sys.stdout` was reconfigured; the banner/spinners print Unicode (`✓ ✗ ⚠ ─ ═ →`) to `sys.stderr`, risking `UnicodeEncodeError` on Windows consoles using cp1252. `sys.stderr` now gets the same UTF-8 reconfiguration as `sys.stdout`.

### Added
- **`data_quality` JSON section (31st section)** — surfaces CSV schema warnings (missing expected DV/SDL columns), CSV rows skipped during parsing, Sigma/YARA rule load-error counts, and ATT&CK bundle load failures, so an analyst can tell when a verdict may be based on incomplete detection coverage instead of a silently degraded run. `CsvParser` now validates the header row against the columns each format actually needs and warns (both on stderr and in this section) when they're missing.
- **HTML data-quality banner** — `report.html` shows a warning banner above the verdict hero when `data_quality` has any warnings/errors; renders nothing on a clean run.
- **`--fail-threshold N`** — exit code 1 if the normalized verdict score (0-20) is `>= N`, for CI/automation gates.
- **VirusTotal wait-time estimate** — prints "Checking N hash(es)/URL(s) against VirusTotal (~Xs)..." before the rate-limited lookups start, so the "Generating report..." step no longer sits silently for minutes with no explanation.

### Improved
- **Sigma evaluation performance** — `SigmaEvaluator` now builds a `event_type → rules` index once at load instead of checking each rule's category against every event during `evaluate_all`. Rules with an unmapped or intentionally empty category (e.g. `sysmon`/`wmi_event`/`builtin`, which have no direct S1 event equivalent) still evaluate against every event, exactly matching prior behavior — this is a behavior-preserving optimization, not a detection-coverage change (verified: every loaded rule is still reachable via the index or the unfiltered fallback).
- **MITRE ATT&CK lookup performance** — `MitreAttackEnricher.get_technique_info` did a full linear scan of every technique in the ~48MB STIX bundle on every call. Now builds a `tid → technique` index once at load; lookups are O(1).
- **IsolationForest on large CSVs** — `StatisticalAnalyzer` now caps `max_samples` at 50,000 for tree-building on very large event sets; `predict()`/`decision_function()` still score every event.
- **Sigma/YARA/ATT&CK load errors are now counted** (`SigmaEvaluator.load_errors`, `YaraAnalyzer.rule_errors`, `MitreAttackEnricher.load_error`) instead of being silently swallowed, feeding into `data_quality`.

### Tests
- Added `tests/test_s1_analyzer.py` (pytest, 32 tests): pure-function coverage for URL cleaning/defanging/extraction, `EventParser`, `CsvParser` (line reconstruction, timestamp parsing, schema validation), correctness of the new Sigma event-type index against the full rule set, MITRE index lookups, and an end-to-end `analyze()` + `generate_html()` smoke test against a real sample CSV (`A_Analyser/RzSDKService.csv`) including an XSS regression guard. Run with `pytest tests/ -v` from the repo root.

## [3.3.2] - 2026-04-21

### Fixed
- **IOC URL truncation (stubs)** — `IocExtractAnalyzer` previously called `iocextract.extract_urls`, which internally invokes `extract_encoded_urls` and synthesizes truncated URL fragments from base64/hex blobs (e.g. `http://www.micro`, `http://crl.microsoft.co`, `http://www.microsoft.com/pki/certs/MicRooCe`). Now uses `extract_unencoded_urls` only — encoded payloads are already handled by `ScriptAnalyzer.decode_payloads`, which decodes the full payload first and then extracts URLs from the plaintext.
- **IOC URL over-extension past shell delimiters** — `iocextract.extract_unencoded_urls` returned URLs that continued past surrounding single quotes in PowerShell array literals like `@('https://host/p','0','C:\\...')`. `_clean_url` now truncates at the first interior character that cannot appear unencoded in an RFC 3986 URL (whitespace, `"`, `'`, `` ` ``, `<`, `>`, `\`, `|`, control chars).
- **Aggressive URL trimming on commas** — the previous cleaner split URLs on any comma (`re.split(r"[',\s]", u)[0]`), destroying legitimate commas that are valid RFC 3986 sub-delims in paths and query strings. Replaced with a structured cleaner that strips only trailing unbalanced brackets and sentence punctuation (`.,;!?`), preserving commas embedded in the URL body.
- **C2 Infrastructure mutated `ioc_data["urls"]`** — correlation logic appended decoded-payload URLs directly onto the shared IOC list, silently growing the JSON output's URL array on every run. Now works on a local clone (`list(ioc_data.get("urls", []))`).
- **Windows-path basename on non-Windows hosts** — `Path(name).name` returned the full Windows path when the analyzer runs on macOS/Linux. Replaced with `re.split(r'[\\/]', raw)[-1]` for cross-platform behavior.
- **VirusTotal "0/0 clean" on every row** — the VT results renderer fell through to the "clean" branch when the API returned a 404 or a transport error (empty `last_analysis_stats` → `total=0` → displayed as `0/0 clean`), masking real states. Now distinguishes: *No result* (empty dict), *Error: HTTP X* (transport error), *Unknown to VT (not analysed)* (`found: false`), *No analysis stats* (`found: true` but empty stats), and the real *N/M engines* or *0/M clean* for populated responses.
- **VirusTotal deep-links broken for URLs and hashes** — IOC Extraction "VT↗" links used `/gui/search/<encoded>`, which for full URLs does not resolve to the URL detail page and for hashes loads a search view instead of the file page. Now uses `/gui/file/<hash>` for SHA-1/SHA-256 (direct file page) and `/gui/url/<sha256(url)>` for URLs (VT's canonical URL-detail identifier). The SHA-256 of each URL is precomputed server-side and shipped in the JSON as `ioc_extraction.url_vt_ids`.
- **SSL `CERTIFICATE_VERIFY_FAILED` on macOS / bare Python** — every outbound call (VirusTotal, MalwareBazaar, OTX, Shodan, GitHub) failed with *unable to get local issuer certificate* on macOS python.org installers that hadn't run the separate `Install Certificates.command` post-install step. The analyzer now installs a global `urllib` opener using the `certifi` CA bundle at import time, so all `urlopen` calls pick it up transparently without threading an `ssl.SSLContext` through each call site.

### Added
- **Centralized URL helpers** — `_URL_RE`, `_refang`, `_clean_url`, `_extract_urls_from_text`, `_normalize_url_key`. Handles defanging (`hxxp://`, `[.]`, `(dot)`, `[:]`), order-preserving dedup via `dict.fromkeys`, and case-insensitive scheme+host normalization.
- **Extended IOC source fields** — `IocExtractAnalyzer` now scans 11 fields instead of 4: `cmdScript.content`, `src/tgt/src.parent.process.cmdline`, `event.dns.request`, `event.dns.response`, `url.address`, `event.url.action`, `tgt.file.path`, `indicator.description`, `indicator.metadata`.
- **Raised IOC caps + totals** — display limits increased to `urls=100`, `ips=100`, `hashes=200`, `emails=50`. JSON now exposes `urls_total`, `ips_total`, `hashes_total`, `emails_total` alongside the (capped) displayed lists, so downstream consumers can see when totals exceed what's shown.
- **Regex fallback when `iocextract` missing** — IOC extraction now degrades gracefully: URL/IP/hash/email regexes kick in when the optional dependency isn't installed.
- **Safe-domain suffix allowlist** — C2 correlation uses exact suffix matching (`domain == s or domain.endswith("." + s)`) to avoid e.g. `notmicrosoft.com.evil.tld` being accidentally whitelisted. Added `apache.org` and `mozilla.org` to the list.

### Improved
- **`ScriptAnalyzer.decode_payloads`** — URL slice raised from 10 to 25, decoded-text slice from 5000 to 20000 chars. Uses the centralized `_extract_urls_from_text` and exposes `urls_total`/`paths_total`. File-path regex moved to a class-level constant with broader character support.
- **HTML IOC section (`renderIOC`)** — display caps raised to 50 per kind (URLs/IPs/hashes) and 25 for emails; shows `count / total` labels when the underlying total exceeds the displayed slice.
- **HTML Decoded Payloads (`renderDecodedPayloads`)** — URL and file-path blocks now show `count / total` labels from `urls_total`/`paths_total`.

## [3.3.1] - 2026-03-17

### Fixed
- **C2 Infrastructure — "Unknown" label** — IP-only entries (external connections without a resolved domain) now display the destination IP instead of "Unknown". Root cause: the entry dict used `"ips"` (list) while the renderer read `"ip"` (singular key, undefined); added `"ip": dst` to the entry.
- **C2 Infrastructure — URL truncation** — URLs extracted via `iocextract` were split at the first `]`, `)`, `}`, or `>` character anywhere in the URL, truncating legitimate paths (e.g. `https://evil.com/path(v2)/payload.exe` → `https://evil.com/path(v2`). Fix: split only on `'`, `,`, and whitespace (true trailing noise), then `rstrip` bracket characters from the tail only.

## [3.3.0] - 2026-03-16

### Added
- **Enriched Execution Chain** — downstream actions now visible directly in the chain: child processes (with signing status), network connections (protocol, IP, port, domain, originating process), and file creations (with SHA1 hash). Chronologically sorted, capped at 10 per type with overflow indicator linking to detailed sections.
- **Target file SHA1** — new `target_file_sha1` field in identification attempts to resolve the hash of the script/file being executed (e.g., a `.vbs` or `.ps1`) from File Creation/Modification/Deletion telemetry. When unavailable (pre-existing file), the HTML clearly indicates "not captured in telemetry".
- **SHA1 label disambiguation** — when a target script is identified, the process SHA1 row is labeled with the process name (e.g., `SHA1 (WScript.exe)`) to avoid confusion with the target file hash.
- **File SHA1 cross-lookup** — execution chain file entries are enriched via a path→SHA1 map built from all file operations (Creation, Modification, Deletion), not just Creation events.
- **Payload decoding** — ScriptAnalyzer `decode_payloads()` automatically decodes hex-encoded and base64 (PowerShell `-EncodedCommand`) payloads, extracting embedded URLs and file paths. Rendered in a dedicated "Decoded Payloads" HTML section.
- **C2 Infrastructure correlation** — new section correlates IOC URLs, decoded payload URLs, DNS queries, and network connections into a unified C2 view grouped by domain/IP. Shows DNS resolution status, connection evidence, port, and protocol.
- **Kill Chain visualization** — ATT&CK techniques from behavioral indicators are ordered by MITRE kill chain phase (Reconnaissance → Impact), displayed as a visual flow with tactic-colored cards and arrow connectors.
- **Analyst Notes** — automated detection of persistence/registry discrepancies, artifact gaps (intended file paths vs observed operations), and unsigned child processes. Surfaced as actionable alerts.
- **Gauge color zones** — verdict gauge SVG now shows colored background arcs (green 0-7, yellow 8-11, orange 12-15, red 16-20) for instant visual scoring context.
- **IOC bulk export** — "Copy All IOCs" button copies all extracted IOCs (hashes, IPs, URLs, emails) to clipboard in a categorized text format.
- **TI external links** — IOC items now include clickable links to VirusTotal, AbuseIPDB (IPs), and URLhaus (URLs) for one-click threat intelligence lookup.
- **Global search (Ctrl+K)** — full-text search across all report sections with instant results, click-to-navigate, and section auto-expand.
- **Table sorting** — all table headers are clickable for ascending/descending sort (numeric and alphabetical).
- **Event distribution bar** — Timeline section shows a colored horizontal bar chart of event type distribution with legend.
- **Mobile responsive** — improved CSS for 768px and 480px breakpoints: smaller fonts, compact spacing, hidden gauge on very small screens.

### Fixed
- **Malicious Patterns truncation** — ScriptAnalyzer context window increased from `500+2000` to `1000+8000` chars around the match, revealing full decoded payloads instead of hex gibberish.
- **CmdlineAnalyzer context** — widened from `20+40` to `40+120` chars around the match, and full command line (up to 5000 chars) now stored and rendered in scrollable code blocks.

### Improved
- **Execution Chain overflow** — child processes, network connections, and file creations each capped at 10 entries with "... +N more (see Process Tree section)" overflow message to keep the chain readable on large storylines (100+ children).
- **HTML dashboard** — 27 sections expanded to 31 sections (added Kill Chain, Decoded Payloads, C2 Infrastructure, Analyst Notes). Section numbering updated throughout.

## [3.2.0] - 2026-03-10

### Added
- **VirusTotal URL scanning** — extracted URLs (non-safe domains) are checked via VT `/urls/` API
- **Target Script/File** field in identification — surfaces VBS/JS/PS1 filenames from script host cmdlines (e.g. `ZAMoWIENIE_Luber SpZoo.vbs`)
- **Section badges** — IOC Extraction, ATT&CK Enrichment, Command Line Analysis, Temporal Sequences, Process Tree now show counts
- **`_vt_enabled` flag** — HTML differentiates "VT not enabled" vs "VT enabled, no hashes"

### Fixed
- **Script content truncation** — context window increased from 500 to 2500 chars, previews from 300 to 5000 chars; full malicious payloads now visible
- **EventParser cmdline parsing** — multi-word quoted cmdlines (e.g. `wscript.exe "file with spaces.vbs"`) now fully captured
- **Root cmdline enrichment** (Passe 4) — script hosts with short cmdlines enriched from behavioral indicator events
- **IOC hash labels** — show executable name (wscript.exe) instead of Windows displayName (Microsoft Windows Based Script Host)
- **URL cleanup** — `iocextract` trailing garbage (quotes, commas, brackets) trimmed from extracted URLs
- **Score floor** — clamped to 0 (was allowing negative scores, inconsistent with 0-20 scale)
- **pyod false warning** — "not installed" message no longer shown when stats are disabled

## [3.1.0] - 2026-03-10

### Added
- **HTML dashboard** auto-generated alongside JSON on every analysis
- **Attack Chains** section (section 5) rendered in HTML report
- **MITRE ATT&CK heatmap** data (tactic → technique mapping) in JSON output
- **HTTP requests** included in network JSON section
- **DNS domain correlation** injected into external connections
- **`meta.frameworks`** field listing active optional libraries
- **Clickable bento cards** — click any metric card to jump to its section
- **Score legend** in Diagnosis section (0-3 Benign → 16-20 Malicious)
- **Threat Score thresholds** displayed in `--help`
- **Full TI enrichment example** (`--vt-key KEY --mb --enrich-ips`) in help

### Fixed
- **Process identification** — paths with spaces (e.g. `C:\Program Files\...`) no longer truncated to folder name
- **IsolationForest outlier detection** — pyod returns `1` for outliers, not `-1`
- **Score normalization** — raw unbounded score now mapped to 0-20 scale (logarithmic compression)
- **Verdict thresholds recalibrated** — legitimate software no longer flagged as SUSPICIOUS
- **Severity labels** — `sevBadge()` now displays English labels (High, Critical) instead of French (ELEVE, CRITIQUE)
- **Section numbering** — fixed duplicate section 13, all sections correctly numbered 1-23
- **TI badge count** — now includes `otx_ips` and `otx_domains` in total
- **`html_content` undefined** — safe fallback if `s1_report.py` import fails
- **`after_hours` JSON bloat** — only exports `timestamp_raw`, `event_type`, `process` (not full event objects)
- **f-string backslash** — compatible with Python < 3.12
- **CSS `.alert-box.warn`** — added missing style rule
- **Dark mode IOC items** — use CSS variable instead of hardcoded `#fef2f2`
- **`meta.version` in footer** — reads `analyzer_version` with fallback

### Improved
- **`CorrelationEngine`** reused from VerdictEngine instead of re-instantiated
- **Script deduplication** — hash over 2000 chars instead of 200
- **YARA deduplication** — key over 200 chars instead of 40
- **File read robustness** — fallback to latin-1 encoding if UTF-8 fails
- **Path parsing** — protected against empty/whitespace strings in parent/target cmdlines
- Removed dead code (`bonus += 0`)

## [3.0.0] - 2026-03-09

### Added
- Initial public release
- 22+ analyzers: Process, Behavior, Network, Files, Registry, Scripts, Modules, Tasks, LSASS, Cmdline, Temporal, Sigma, YARA, Process Graph, Statistical, MITRE enrichment, IOC extraction, VirusTotal, MalwareBazaar, OTX, Shodan
- Self-contained HTML dashboard with dark/light theme
- DV and SDL CSV format support
- 27-section JSON report
