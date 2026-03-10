# Changelog

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
