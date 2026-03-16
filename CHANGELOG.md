# Changelog

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
