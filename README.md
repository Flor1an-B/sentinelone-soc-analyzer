# S1 Analyzer

**SentinelOne Deep Visibility Forensic Analyzer** — Automated SOC triage tool for SentinelOne CSV exports.

Analyzes Deep Visibility (DV) and Scalable Data Lake (SDL) CSV exports through 22+ specialized analyzers, producing a threat score, verdict, and a self-contained HTML dashboard for SOC L1/L2 analysts.

![Python](https://img.shields.io/badge/python-3.10--3.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.2.0-orange)

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Process Analysis** | Root process identification, execution chain, parent/child tree, Electron detection |
| **Behavioral Indicators** | 60+ indicator patterns with contextual false-positive detection |
| **Network** | External connections, DNS correlation, C2 beacon detection, suspicious user agents, HTTP requests |
| **Scripts** | PowerShell/CMD/VBS content analysis, obfuscation detection, encoded payload extraction |
| **MITRE ATT&CK** | Tactic/technique mapping, heatmap, enrichment with groups & mitigations |
| **Sigma Rules** | 2000+ community rules evaluated against S1 events |
| **YARA** | 700+ signature-base rules scanned against command lines and scripts |
| **Statistical** | IsolationForest anomaly detection, after-hours activity, entropy analysis |
| **Threat Intelligence** | VirusTotal, MalwareBazaar, AlienVault OTX, Shodan lookups |
| **Verdict Engine** | Normalized threat score (0-20), calibrated thresholds, evidence-based verdict |

## Threat Score

The analyzer produces a **normalized score on a 0-20 scale** with calibrated thresholds:

```
 0 -  3 : FALSE POSITIVE / Benign      — No malicious indicators
 4 -  7 : LIKELY FALSE POSITIVE         — Low risk, mostly benign context
 8 - 11 : UNDETERMINED                  — Needs analyst investigation
12 - 15 : SUSPICIOUS                    — Likely malicious, investigate urgently
16 - 20 : TRUE POSITIVE / Malicious     — Confirmed threat, requires action
```

The score combines behavioral indicators, attack chain correlation, script analysis, MITRE technique coverage, and contextual false-positive mitigation to provide an actionable assessment for SOC analysts.

## Getting a CSV from SentinelOne

1. In the **SentinelOne Management Console**, navigate to an alert you want to investigate
2. Click **Threat Actions** > **Event Search** (or go to **Visibility > Deep Visibility**)
3. Review the events displayed for the selected alert
4. Click **Export** > **Download as CSV**
5. Save the CSV file locally

> **Important:** Before your first analysis, run `--update` to download the latest detection rules.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Flor1an-B/s1-analyzer.git
cd s1-analyzer

# 2. Install optional dependencies (for full analysis capabilities)
pip install -r requirements.txt
# Note: Python 3.10-3.13 recommended (yara-python has prebuilt wheels)

# 3. Download detection rule databases (ATT&CK, Sigma, YARA) — essential first step
python s1_analyzer.py --update

# 4. Analyze your SentinelOne CSV export
python s1_analyzer.py alert.csv
```

A folder is created with both `report.json` and `report.html`. The HTML dashboard is self-contained and can be opened in any browser.

## Usage

```
python s1_analyzer.py [OPTIONS] <csv_file>
```

### Options

| Flag | Description |
|------|-------------|
| `--update` | Download/update ATT&CK bundle, Sigma rules, YARA signature-base |
| `--vt-key KEY` | VirusTotal v3 API key ([free](https://virustotal.com)) |
| `--mb` | Enable MalwareBazaar hash lookups (no key required) |
| `--otx-key KEY` | AlienVault OTX API key ([free](https://otx.alienvault.com)) |
| `--shodan-key KEY` | Shodan API key ([shodan.io](https://shodan.io)) |
| `--enrich-ips` | Enrich external IPs via ip-api.com (geo/ASN) |
| `--json` | Print raw JSON to stdout |
| `--html` | Print HTML to stdout (or use with `-o`) |
| `-o FILE` | Save text/HTML/JSON to file |
| `--no-sigma` | Disable Sigma rule evaluation |
| `--no-yara` | Disable YARA scanning |
| `--no-graph` | Disable NetworkX process graph analysis |
| `--no-stats` | Disable statistical anomaly detection |
| `--no-attack` | Disable ATT&CK enrichment |
| `--no-color` | Disable ANSI colors |

### Examples

```bash
# Download/update rules (essential first step)
python s1_analyzer.py --update

# Basic analysis — generates JSON + HTML dashboard automatically
python s1_analyzer.py alert.csv

# Full threat intelligence enrichment (VirusTotal + MalwareBazaar + IP geolocation)
python s1_analyzer.py alert.csv --vt-key YOUR_VT_API_KEY --mb --enrich-ips

# Save text report to file
python s1_analyzer.py alert.csv -o report.txt

# Skip heavy analysis for faster results
python s1_analyzer.py alert.csv --no-sigma --no-yara
```

## HTML Dashboard

The self-contained HTML report includes:

- **Verdict hero** with gauge, score, and confidence level
- **Clickable metric cards** — jump directly to any section
- **Interactive sections** — collapsible, with badge counts
- **MITRE ATT&CK heatmap** — tactic/technique coverage
- **Process tree** visualization
- **Dark/light theme** — toggle with `T` key
- **Print-friendly** — `Ctrl+P` for clean output
- **Copyable values** — click any hash, IP, or command line to copy

## CSV Formats

### Deep Visibility (DV)
Columns: `event.time`, `agent.uuid`, `src.process.user`, `event.type`, `src.process.storyline.id`, `event.details`

### Scalable Data Lake (SDL)
Columns: `dataSource.name`, `event.time`, `event.type`, `updated_at`, `event.source`, `event.target`, `event.details`, `primary_description`

## Architecture

```
CSV file
  |
  +-- CsvParser ------------ Normalize DV/SDL -> unified event list
  |
  +-- ProcessAnalyzer ------ Root identification, parent chain, children
  +-- BehaviorAnalyzer ----- 60+ behavioral indicator patterns
  +-- NetworkAnalyzer ------ Connections, DNS, beacons, user agents
  +-- FileAnalyzer --------- File operations, suspicious paths
  +-- RegistryAnalyzer ----- Persistence keys, run keys
  +-- ScriptAnalyzer ------- Script content, obfuscation, encodings
  +-- ModuleAnalyzer ------- DLL loads, suspicious modules
  +-- TaskAnalyzer --------- Scheduled tasks
  +-- LsassAnalyzer -------- LSASS access detection
  +-- CmdlineAnalyzer ------ Command line heuristics, entropy
  +-- TemporalCorrelation -- Attack sequence timing
  +-- SigmaEvaluator ------- Sigma community rules
  +-- YaraAnalyzer --------- YARA signature matching
  +-- ProcessGraphAnalyzer - NetworkX graph analysis
  +-- StatisticalAnalyzer -- IsolationForest outlier detection
  +-- MitreAttackEnricher -- ATT&CK groups & mitigations
  +-- IocExtractAnalyzer --- IOC extraction (URLs, IPs, hashes)
  |
  +-- CorrelationEngine ---- Attack chain detection
  +-- FPContextualizer ----- False positive contextual analysis
  +-- VerdictEngine -------- Score normalization & verdict
  |
  +-- ReportGenerator ------ JSON output (27 sections)
  +-- s1_report.py --------- HTML dashboard generation
```

## Output Structure

Each analysis creates a timestamped folder:

```
alert_20260310_143000/
+-- report.json     # Full structured data (27 sections)
+-- report.html     # Self-contained interactive dashboard
```

### JSON Sections (27)

`meta` - `identification` - `verdict` - `metrics` - `timeline` - `behavioral_indicators` - `severity_distribution` - `attack_chains` - `mitre_attack` - `scripts` - `modules` - `network` - `process_tree` - `files` - `registry` - `tasks` - `lsass` - `cmdline_analysis` - `temporal_sequences` - `sigma_matches` - `process_graph` - `statistical_analysis` - `yara_matches` - `mitre_enrichment` - `ioc_extraction` - `virustotal` - `threat_intelligence`

## Dependencies

**Zero dependencies** for basic analysis. Optional packages enable advanced features:

| Package | Feature | Required |
|---------|---------|----------|
| `pyyaml` | Sigma rule loading | No |
| `networkx` | Process graph analysis | No |
| `pyod` | Statistical anomaly detection | No |
| `yara-python` | YARA pattern matching | No |
| `iocextract` | IOC extraction | No |
| `mitreattack-python` | ATT&CK enrichment | No |

```bash
pip install -r requirements.txt
```

### Note on yara-python (Windows)

Prebuilt wheels are available for **Python 3.10 to 3.13**. With Python 3.14+, `yara-python` must compile from source which requires **Microsoft Visual C++ Build Tools**.

<details>
<summary><strong>Installing Visual C++ Build Tools for Python 3.14+</strong></summary>

1. Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
2. Run the installer and select **"Desktop development with C++"**
3. In the right panel, ensure the following are checked:
   - **MSVC v143 - VS 2022 C++ x64/x86 build tools** (or latest version)
   - **Windows 11 SDK** (or Windows 10 SDK)
   - **C++ CMake tools for Windows**
4. Click **Install** (approximately 2-4 GB)
5. After installation, **restart your terminal** then run:

```bash
pip install yara-python
```

</details>

If you don't want to install the build tools, the analyzer works without YARA — all other features remain fully functional. Use `--no-yara` to suppress the warning.

## Keeping Up to Date

### Project files

Sync local files with the latest GitHub release — no git required:

```bash
python s1_update.py              # Check & download updates
python s1_update.py --check      # Dry run — see what would change
python s1_update.py --force      # Re-download all project files
```

### Detection rules

Download the latest community rules:

```bash
python s1_analyzer.py --update
```

This downloads:
- **MITRE ATT&CK** Enterprise bundle (`data/attack/`)
- **Sigma** community rules (`data/sigma/rules/`)
- **YARA** Neo23x0 signature-base (`data/yara/rules/`)

## License

[MIT](LICENSE) — Florian Bertaux
