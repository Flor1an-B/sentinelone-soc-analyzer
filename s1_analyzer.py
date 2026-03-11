#!/usr/bin/env python3
"""
S1 Analyzer — SentinelOne Deep Visibility Forensic Analyzer
============================================================
Author  : Florian Bertaux
Version : 3.2.0

Analyse forensique comportementale pure.
Le verdict repose exclusivement sur les ACTIONS observees.
L'identite de l'application est une observation, jamais un facteur de confiance.

Formats supportes : Deep Visibility (DV) et Singularity Data Lake (SDL/STAR)

Frameworks integres (optionnels) :
  - MITRE ATT&CK enrichment  (pip install mitreattack-python)
  - Sigma rules evaluation    (pip install pyyaml  + --update)
  - NetworkX process graph    (pip install networkx)
  - IsolationForest anomalies (pip install pyod)
  - YARA pattern matching     (pip install yara-python + --update)
  - IOC extraction            (pip install iocextract)

Usage :
  python s1_analyzer.py --update              # Download ATT&CK + Sigma + YARA
  python s1_analyzer.py <fichier.csv>         # Full analysis
  python s1_analyzer.py <fichier.csv> --html  # HTML report
"""
import csv, re, sys, json, argparse, io, time, threading, urllib.request, urllib.error, socket
import zipfile, shutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from io import StringIO

# ---------------------------------------------------------------------------
# OPTIONAL FRAMEWORK IMPORTS (graceful degradation if not installed)
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import networkx as _nx
    HAS_NX = True
except ImportError:
    HAS_NX = False

try:
    from pyod.models.iforest import IForest as _IForest
    HAS_PYOD = True
except ImportError:
    HAS_PYOD = False

try:
    import yara as _yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import iocextract as _iocextract
    HAS_IOC = True
except ImportError:
    HAS_IOC = False

try:
    from mitreattack.stix20 import MitreAttackData as _MitreData
    HAS_MITRE_LIB = True
except ImportError:
    HAS_MITRE_LIB = False

# ---------------------------------------------------------------------------
# VERSION & METADATA
# ---------------------------------------------------------------------------
__version__  = "3.2.0"
__author__   = "Florian Bertaux"
__tool__     = "S1 Analyzer"

# ---------------------------------------------------------------------------
# DATA DIRECTORY — stores downloaded ATT&CK bundle, Sigma rules, YARA rules
# ---------------------------------------------------------------------------
DATA_DIR      = Path(__file__).parent / "data"
ATTACK_BUNDLE = DATA_DIR / "attack" / "enterprise-attack.json"
SIGMA_DIR     = DATA_DIR / "sigma" / "rules"
YARA_DIR      = DATA_DIR / "yara" / "rules"

# Forcer UTF-8 sur la sortie standard Windows (évite UnicodeEncodeError cp1252)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Activer les séquences ANSI sur Windows (Windows 10 1511+)
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# COULEURS ET FORMATAGE TERMINAL
# ---------------------------------------------------------------------------
_USE_COLOR = True  # peut être désactivé par --no-color

ANSI_STRIP = re.compile(r'\x1b\[[0-9;]*m')

def _strip_ansi(text: str) -> str:
    return ANSI_STRIP.sub('', text)


class C:
    """Codes ANSI — appliqués seulement si _USE_COLOR est vrai."""
    R      = '\033[0m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RED    = '\033[31m'
    LRED   = '\033[91m'
    GREEN  = '\033[32m'
    LGREEN = '\033[92m'
    YELLOW = '\033[33m'
    LYELLOW= '\033[93m'
    BLUE   = '\033[34m'
    LBLUE  = '\033[94m'
    CYAN   = '\033[36m'
    LCYAN  = '\033[96m'
    MAGENTA= '\033[35m'
    WHITE  = '\033[97m'

    @staticmethod
    def wrap(code: str, text: str) -> str:
        if not _USE_COLOR:
            return text
        return f"{code}{text}\033[0m"

    # Raccourcis sémantiques
    @staticmethod
    def crit(t):   return C.wrap(C.BOLD + C.LRED,    t)
    @staticmethod
    def high(t):   return C.wrap(C.LRED,              t)
    @staticmethod
    def med(t):    return C.wrap(C.LYELLOW,            t)
    @staticmethod
    def low(t):    return C.wrap(C.DIM,                t)
    @staticmethod
    def ok(t):     return C.wrap(C.LGREEN,             t)
    @staticmethod
    def info(t):   return C.wrap(C.LCYAN,              t)
    @staticmethod
    def bold(t):   return C.wrap(C.BOLD,               t)
    @staticmethod
    def dim(t):    return C.wrap(C.DIM,                t)
    @staticmethod
    def header(t): return C.wrap(C.BOLD + C.LBLUE,     t)
    @staticmethod
    def sep(t):    return C.wrap(C.BLUE,               t)
    @staticmethod
    def sep2(t):   return C.wrap(C.DIM,                t)


def _sev_color(sev: str, text: str) -> str:
    if sev == "CRITIQUE": return C.crit(text)
    if sev == "ELEVE":    return C.high(text)
    if sev == "MOYEN":    return C.med(text)
    return C.dim(text)


# ---------------------------------------------------------------------------
# CLIENT VIRUSTOTAL (API v3)
# ---------------------------------------------------------------------------
class VirusTotalClient:
    """Interroge l'API VirusTotal v3 pour les hashes SHA1/SHA256."""
    BASE = "https://www.virustotal.com/api/v3/files"

    def __init__(self, api_key: str):
        self.api_key  = api_key
        self._cache   = {}
        self._last_ts = 0.0

    def _wait(self):
        """Respect du rate-limit : 4 requêtes/minute (1 toutes les 15s)."""
        elapsed = time.time() - self._last_ts
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self._last_ts = time.time()

    def lookup(self, sha: str) -> dict:
        if not sha or not self.api_key or sha in ("N/A", ""):
            return {}
        sha = sha.strip().lower()
        if sha in self._cache:
            return self._cache[sha]
        self._wait()
        try:
            req = urllib.request.Request(
                f"{self.BASE}/{sha}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            attr  = data["data"]["attributes"]
            stats = attr.get("last_analysis_stats", {})
            result = {
                "found":     True,
                "malicious": stats.get("malicious", 0),
                "suspicious":stats.get("suspicious", 0),
                "harmless":  stats.get("harmless", 0),
                "undetected":stats.get("undetected", 0),
                "total":     sum(stats.values()),
                "name":      attr.get("meaningful_name", ""),
                "type":      attr.get("type_description", ""),
                "tags":      attr.get("tags", []),
                "first_seen":attr.get("first_submission_date", 0),
                "threat":    next(
                    (v.get("result", "") for v in
                     attr.get("last_analysis_results", {}).values()
                     if v.get("category") == "malicious" and v.get("result")),
                    ""
                ),
            }
        except urllib.error.HTTPError as e:
            result = {"found": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            result = {"found": False, "error": str(e)}
        self._cache[sha] = result
        return result

    def lookup_url(self, url: str) -> dict:
        """Lookup a URL on VirusTotal v3."""
        if not url or not self.api_key:
            return {}
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        cache_key = f"url:{url_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        self._wait()
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": self.api_key, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            attr = data["data"]["attributes"]
            stats = attr.get("last_analysis_stats", {})
            result = {
                "found":      True,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values()),
                "url":        attr.get("url", url),
                "threat":     next(
                    (v.get("result", "") for v in
                     attr.get("last_analysis_results", {}).values()
                     if v.get("category") == "malicious" and v.get("result")),
                    ""
                ),
            }
        except urllib.error.HTTPError as e:
            result = {"found": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            result = {"found": False, "error": str(e)}
        self._cache[cache_key] = result
        return result


# ---------------------------------------------------------------------------
# CLIENT MALWAREBAZAAR (abuse.ch — gratuit, aucune clé requise)
# ---------------------------------------------------------------------------
class MalwareBazaarClient:
    """Interroge l'API MalwareBazaar pour les hashes SHA1/SHA256."""
    API_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self):
        self._cache: dict = {}

    def lookup(self, sha: str) -> dict:
        if not sha or sha in ("N/A", ""):
            return {}
        sha = sha.strip().lower()
        if sha in self._cache:
            return self._cache[sha]
        try:
            payload = json.dumps({"query": "get_info", "hash": sha}).encode()
            req = urllib.request.Request(
                self.API_URL, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            if data.get("query_status") == "hash_not_found":
                result = {"found": False}
            else:
                info = data.get("data", [{}])[0]
                result = {
                    "found":       True,
                    "file_name":   info.get("file_name", ""),
                    "file_type":   info.get("file_type", ""),
                    "tags":        info.get("tags", []) or [],
                    "signature":   info.get("signature", ""),
                    "first_seen":  info.get("first_seen", ""),
                    "reporter":    info.get("reporter", ""),
                    "origin":      info.get("origin_country", ""),
                }
        except Exception as e:
            result = {"found": False, "error": str(e)}
        self._cache[sha] = result
        return result


# ---------------------------------------------------------------------------
# CLIENT ALIENTVAULT OTX (clé gratuite sur otx.alienvault.com)
# ---------------------------------------------------------------------------
class OTXClient:
    """Interroge AlienVault OTX pour la réputation des IPs, domaines et hashes."""
    BASE = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: dict = {}

    def _get(self, url: str) -> dict:
        try:
            req = urllib.request.Request(
                url, headers={"X-OTX-API-KEY": self.api_key}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"error": str(e)}

    def lookup_hash(self, sha1: str) -> dict:
        if not sha1 or not self.api_key:
            return {}
        key = f"hash:{sha1}"
        if key in self._cache:
            return self._cache[key]
        data = self._get(f"{self.BASE}/file/{sha1}/general")
        result = {
            "found":       bool(data.get("pulse_info", {}).get("count", 0)),
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "malware_families": [
                p.get("name", "") for p in
                data.get("pulse_info", {}).get("pulses", [])[:3]
            ],
        }
        self._cache[key] = result
        return result

    def lookup_ip(self, ip: str) -> dict:
        if not ip or not self.api_key:
            return {}
        key = f"ip:{ip}"
        if key in self._cache:
            return self._cache[key]
        data = self._get(f"{self.BASE}/IPv4/{ip}/general")
        result = {
            "found":       bool(data.get("pulse_info", {}).get("count", 0)),
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "reputation":  data.get("reputation", 0),
            "country":     data.get("country_name", ""),
        }
        self._cache[key] = result
        return result

    def lookup_domain(self, domain: str) -> dict:
        if not domain or not self.api_key:
            return {}
        key = f"domain:{domain}"
        if key in self._cache:
            return self._cache[key]
        data = self._get(f"{self.BASE}/domain/{domain}/general")
        result = {
            "found":       bool(data.get("pulse_info", {}).get("count", 0)),
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
        }
        self._cache[key] = result
        return result


# ---------------------------------------------------------------------------
# CLIENT SHODAN (clé API sur shodan.io)
# ---------------------------------------------------------------------------
class ShodanClient:
    """Interroge Shodan pour le profil des IPs externes inconnues."""
    BASE = "https://api.shodan.io/shodan/host"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: dict = {}

    def lookup(self, ip: str) -> dict:
        if not ip or not self.api_key:
            return {}
        if ip in self._cache:
            return self._cache[ip]
        try:
            url = f"{self.BASE}/{ip}?key={self.api_key}&minify=true"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            result = {
                "found":   True,
                "org":     data.get("org", ""),
                "country": data.get("country_name", ""),
                "ports":   data.get("ports", []),
                "tags":    data.get("tags", []),
                "vulns":   list(data.get("vulns", {}).keys())[:5],
                "hostnames": data.get("hostnames", [])[:3],
            }
        except urllib.error.HTTPError as e:
            result = {"found": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            result = {"found": False, "error": str(e)}
        self._cache[ip] = result
        return result


# ---------------------------------------------------------------------------
# ENRICHISSEUR D'ADRESSES IP (ip-api.com — gratuit, 45 req/min)
# ---------------------------------------------------------------------------
class IpEnricher:
    """Enrichit les IPs avec géolocalisation et ASN via ip-api.com."""
    BATCH_URL = "https://ip-api.com/batch?fields=query,country,city,org,as,hosting,status"

    def __init__(self):
        self._cache: dict = {}

    def enrich(self, ips: list) -> dict:
        to_fetch = [ip for ip in ips if ip and ip not in self._cache]
        if to_fetch:
            for i in range(0, len(to_fetch), 100):
                batch = to_fetch[i:i+100]
                try:
                    payload = json.dumps(
                        [{"query": ip, "fields": "query,country,city,org,as,hosting,status"}
                         for ip in batch]
                    ).encode()
                    req = urllib.request.Request(
                        self.BATCH_URL, data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        results = json.loads(resp.read())
                    for r in results:
                        self._cache[r.get("query", "")] = r
                except Exception:
                    for ip in batch:
                        self._cache[ip] = {}
        return {ip: self._cache.get(ip, {}) for ip in ips}

    @staticmethod
    def format(info: dict) -> str:
        if not info or info.get("status") == "fail":
            return ""
        parts = []
        if info.get("country"):
            parts.append(info["country"])
        if info.get("city"):
            parts.append(info["city"])
        org = info.get("org", "")
        asn = info.get("as", "")
        if org:
            parts.append(org)
        elif asn:
            parts.append(asn)
        hosting = " [HOSTING/VPS]" if info.get("hosting") else ""
        return ", ".join(parts) + hosting


# ===========================================================================
# GESTIONNAIRE DE RESSOURCES EXTERNES (--update)
# ===========================================================================

_ATTACK_URL   = ("https://raw.githubusercontent.com/mitre/cti/master/"
                 "enterprise-attack/enterprise-attack.json")
_SIGMA_ZIP    = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
_YARA_ZIP     = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"

# Toutes les catégories Windows pertinentes (SigmaHQ master)
_SIGMA_PATHS  = [
    "sigma-master/rules/windows/",  # capture TOUTES les sous-catégories Windows
]


def _dl(url: str, dest: Path, label: str) -> bool:
    """Download a file with inline progress. Returns True on success."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "s1-analyzer/2.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done  = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = int(done / total * 100)
                        print(f"\r  [\u2193] {label}: {pct}% ({done//1024}KB/{total//1024}KB)   ",
                              end="", file=sys.stderr)
        print(file=sys.stderr)
        print(C.ok(f"  [\u2713] {label} \u2192 {dest}"), file=sys.stderr)
        return True
    except Exception as e:
        print(C.high(f"  [\u2717] {label}: {e}"), file=sys.stderr)
        return False


def _update_attack() -> bool:
    return _dl(_ATTACK_URL, ATTACK_BUNDLE, "MITRE ATT&CK Enterprise bundle")


def _update_sigma() -> bool:
    tmp = DATA_DIR / "_sigma.zip"
    if not _dl(_SIGMA_ZIP, tmp, "SigmaHQ rules archive"):
        return False
    dest = SIGMA_DIR
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    try:
        with zipfile.ZipFile(tmp) as zf:
            for member in zf.namelist():
                if not member.endswith(".yml"):
                    continue
                if not any(member.startswith(p) for p in _SIGMA_PATHS):
                    continue
                parts = Path(member).parts
                if len(parts) < 2:
                    continue
                cat   = parts[-2]
                fname = parts[-1]
                cat_d = dest / cat
                cat_d.mkdir(exist_ok=True)
                (cat_d / fname).write_bytes(zf.read(member))
                count += 1
        tmp.unlink()
        print(C.ok(f"  [\u2713] {count} Sigma rules extracted to {dest}"), file=sys.stderr)
        return True
    except Exception as e:
        print(C.high(f"  [\u2717] Sigma extraction: {e}"), file=sys.stderr)
        return False


def _update_yara() -> bool:
    tmp = DATA_DIR / "_yara.zip"
    if not _dl(_YARA_ZIP, tmp, "signature-base YARA archive"):
        return False
    dest = YARA_DIR
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    try:
        with zipfile.ZipFile(tmp) as zf:
            for member in zf.namelist():
                if not (member.endswith(".yar") or member.endswith(".yara")):
                    continue
                if "/yara/" not in member:
                    continue
                fname = Path(member).name
                (dest / fname).write_bytes(zf.read(member))
                count += 1
        tmp.unlink()
        print(C.ok(f"  [\u2713] {count} YARA files extracted to {dest}"), file=sys.stderr)
        return True
    except Exception as e:
        print(C.high(f"  [\u2717] YARA extraction: {e}"), file=sys.stderr)
        return False


def _count_rules() -> tuple:
    """Compte les règles Sigma et YARA actuellement sur disque."""
    sigma_n = len(list(SIGMA_DIR.rglob("*.yml"))) if SIGMA_DIR.exists() else 0
    yara_n  = len(list(YARA_DIR.glob("*.yar")) + list(YARA_DIR.glob("*.yara"))) if YARA_DIR.exists() else 0
    attack  = ATTACK_BUNDLE.exists()
    return sigma_n, yara_n, attack


def update_all_resources() -> None:
    """Download/update ATT&CK bundle, Sigma rules, and YARA signature-base."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    s_before, y_before, a_before = _count_rules()
    print(C.bold(f"\n[{__tool__}] Updating external resources..."), file=sys.stderr)
    print(C.sep("=" * 60), file=sys.stderr)
    if s_before or y_before:
        print(f"  Current: Sigma={s_before} | YARA={y_before} | ATT&CK={'yes' if a_before else 'no'}", file=sys.stderr)
    ok1 = _update_attack()
    ok2 = _update_sigma()
    ok3 = _update_yara()
    s_after, y_after, a_after = _count_rules()
    print(C.sep("=" * 60), file=sys.stderr)
    status = C.ok("All OK") if all([ok1, ok2, ok3]) else C.high("Some downloads failed")
    print(C.bold(f"Update complete \u2014 {status}"), file=sys.stderr)
    print(f"  Data directory: {DATA_DIR}", file=sys.stderr)
    # Afficher les deltas
    s_delta = s_after - s_before
    y_delta = y_after - y_before
    s_sym = f" (+{s_delta})" if s_delta > 0 else (f" ({s_delta})" if s_delta < 0 else " (unchanged)")
    y_sym = f" (+{y_delta})" if y_delta > 0 else (f" ({y_delta})" if y_delta < 0 else " (unchanged)")
    print(f"  Sigma: {s_after} rules{s_sym}", file=sys.stderr)
    print(f"  YARA:  {y_after} files{y_sym}", file=sys.stderr)
    print(f"  ATT&CK: {'available' if a_after else 'missing'}", file=sys.stderr)


# ---------------------------------------------------------------------------
# UTILITAIRE — ENTROPIE DE SHANNON
# ---------------------------------------------------------------------------
import math as _math

def _shannon_entropy(s: str) -> float:
    """Calcule l'entropie de Shannon d'une chaîne (bits par caractère)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * _math.log2(f / n) for f in freq.values())


# ===========================================================================
# BASE DE CONNAISSANCE : 66 INDICATEURS
# ===========================================================================
# severity_base : niveau de severite intrinseque
# fp_contexts   : contextes techniques ou un FP est possible (a documenter, pas ignorer)
# tp_score      : contribution au score TP si context non-FP
# description   : analyse forensique complete de l'indicateur
INDICATOR_DB = {
    "AccountDiscovery": {
        "severity": "ELEVE", "category": "Discovery", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Local or domain account enumeration (T1087). Characteristic of the post-compromise "
            "reconnaissance phase. Attacker identifies privileged accounts to target privilege "
            "escalation or lateral movement."
        ),
        "mitre": ["T1087", "T1018", "T1069.002"],
    },
    "AddVehHandler": {
        "severity": "MOYEN", "category": "General", "tp_score": 1,
        "fp_contexts": ["chromium", "security_app"],
        "description": (
            "Vectored Exception Handler (VEH) registration. Chromium/Electron uses it for "
            "centralized exception handling in its multi-process architecture (FP in this context). "
            "Outside Chromium: may be used to intercept and redirect execution flow, or to detect debuggers."
        ),
        "mitre": [],
    },
    "AntiVm": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": ["security_app"],
        "description": (
            "Anti-virtualization technique detected (T1497). Process actively checks if it runs "
            "inside a sandbox or VM (CPUID, privileged instructions, VMware/VirtualBox artifacts). "
            "Goal: adapt behavior or self-terminate to avoid analysis. Strong indicator of evasive malware."
        ),
        "mitre": ["T1497"],
    },
    "BrowserMemoryInfoStealingAttempt": {
        "severity": "ELEVE", "category": "InfoStealer", "tp_score": 3,
        "fp_contexts": ["security_app"],
        "description": (
            "Attempted access to browser private memory (T1555.003). Infostealing technique: "
            "reading Chrome/Firefox memory regions to extract credentials, session cookies, or stored tokens. "
            "Outside a legitimate security tool context, constitutes evidence of malicious activity."
        ),
        "mitre": ["T1555.003", "T1555"],
    },
    "CoreDllRead": {
        "severity": "MOYEN", "category": "Malware", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Direct read of a core system DLL (ntdll.dll, kernel32.dll). Technique used to retrieve "
            "original unhooked syscall stubs, bypassing EDRs that instrument these DLLs. "
            "May also indicate a packer manually rebuilding its import table (T1562.001)."
        ),
        "mitre": ["T1562.001"],
    },
    "CredmanEnumerationInfoStealer": {
        "severity": "CRITIQUE", "category": "InfoStealer", "tp_score": 4,
        "fp_contexts": [],
        "description": (
            "Enumeration of credentials stored in the Windows Credential Manager (T1555). "
            "Direct credential theft: programmatic retrieval of all stored secrets (network passwords, "
            "certificates, tokens). No legitimate application requires enumerating the entire Credential Manager."
        ),
        "mitre": ["T1555", "T1552"],
    },
    "DLLHijackingD": {
        "severity": "ELEVE", "category": "Injection", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Confirmed DLL hijacking (T1574.001): a suspicious DLL (unusual path, unsigned, or "
            "impersonating a system DLL) was loaded in place of a legitimate one. Enables arbitrary "
            "code execution within an already-running process using its existing privileges."
        ),
        "mitre": ["T1574.001", "T1036.005", "T1055.001"],
    },
    "DirectSyscall": {
        "severity": "ELEVE", "category": "Direct Syscall", "tp_score": 3,
        "fp_contexts": ["installer"],
        "description": (
            "Direct syscall from userspace (T1562): process calls Windows syscalls directly "
            "(INT 2E / SYSCALL instruction) without going through ntdll.dll. Advanced EDR evasion "
            "technique — EDR hooks reside in ntdll and are bypassed. Indicator of an offensive tool "
            "or sophisticated malware. May occur in game DRM/anti-cheat during installation."
        ),
        "mitre": ["T1562", "T1055"],
    },
    "DisableOrModifySecurityTools": {
        "severity": "CRITIQUE", "category": "Evasion", "tp_score": 4,
        "fp_contexts": [],
        "description": (
            "Attempt to disable or modify security tools (T1562.001). Goal: neutralize the EDR, "
            "antivirus, AppLocker policies, or event logs before progressing in the attack. "
            "Strong indicator of active compromise and an attacker trying to suppress evidence."
        ),
        "mitre": ["T1562.001", "T1562.002", "T1552.002"],
    },
    "DllHijackExtended": {
        "severity": "ELEVE", "category": "Injection", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Extended DLL hijacking: process hijacked by a completely unknown DLL (absent from "
            "system and application lists). Risk of arbitrary code execution. The unknown DLL "
            "may be an implant, RAT, or injection module (T1574.001)."
        ),
        "mitre": ["T1574.001", "T1055.001"],
    },
    "DropAndExecuteFromChainedInterpreter": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Drop and execute via a chain of interpreters (e.g. cmd → powershell → python). "
            "Living-off-the-Land (LotL) technique: each layer obscures the origin and can bypass "
            "detection rules based on the direct parent process (T1059)."
        ),
        "mitre": ["T1059", "T1218"],
    },
    "EncodedPSCommand": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "PowerShell command encoded in Base64 via -EncodedCommand (T1027). Obfuscation technique "
            "hiding the actual command content from security solutions inspecting the command line. "
            "Legitimate use is rare (admin scripts); always verify by decoding the payload."
        ),
        "mitre": ["T1027", "T1059.001"],
    },
    "EventViewerTampering": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Windows event log tampering (T1070.001). Anti-forensic technique: attacker clears or "
            "modifies logs to hide their actions. Very rare in legitimate use (WPR profiling tools "
            "may interact with logs). Requires context verification."
        ),
        "mitre": ["T1070.001"],
    },
    "HeaderExtensionMismatch": {
        "severity": "MOYEN", "category": "Evasion", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Mismatch between file extension and magic header (T1036). "
            "E.g.: a PE (MZ) renamed to .pdf or .jpg to bypass extension-based filters. "
            "May also indicate a corrupted file or container format (self-extracting archives)."
        ),
        "mitre": ["T1036"],
    },
    "HeuristicallyRansomwareBehavior": {
        "severity": "CRITIQUE", "category": "Ransomware", "tp_score": 5,
        "fp_contexts": ["dev_build"],
        "description": (
            "Heuristic ransomware behavior detected (T1486): mass creation of encrypted files "
            "and rapid deletion of originals. False positive possible in build/compilation context "
            "(PyInstaller, webpack) generating and deleting many temporary files. "
            "Analyze created file names and extensions to confirm."
        ),
        "mitre": ["T1486"],
    },
    "HidingTracks": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Evidence erasure (T1070.004): deletion of log files, command history, execution "
            "artifacts. Classic post-compromise behavior to complicate forensic analysis "
            "and delay detection."
        ),
        "mitre": ["T1070.004"],
    },
    "HookingViaSetHookAPI": {
        "severity": "MOYEN", "category": "General", "tp_score": 2,
        "fp_contexts": ["security_app"],
        "description": (
            "Windows hook registered via SetWindowsHookEx (T1056). Intercepts global system events "
            "(keyboard, mouse, Windows messages). Legitimate use by accessibility apps or UI tools. "
            "Primary malicious use: keylogging. Evaluate based on the process involved."
        ),
        "mitre": ["T1056"],
    },
    "IndirectExecution": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Indirect command execution (T1059): passing through an intermediary "
            "(cmd /c, Invoke-Expression, exec()) to hide the real command. Common technique "
            "to bypass detections based on the direct command line."
        ),
        "mitre": ["T1059"],
    },
    "InterpreterChaining": {
        "severity": "MOYEN", "category": "Evasion", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Interpreter chain detected (T1059): cmd calls powershell which calls python, etc. "
            "Each level adds a layer of indirection. LotL technique to obscure the origin "
            "and bypass execution policies."
        ),
        "mitre": ["T1059"],
    },
    "KernelCallbackDirectSyscallNonNt": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": ["installer"],
        "description": (
            "Syscall dispatched from a non-ntdll module (T1562). Advanced technique: the syscall "
            "is invoked from an unexpected module (e.g. a loaded DLL), avoiding EDR hooks placed "
            "specifically on ntdll.dll. Characteristic of sophisticated offensive tools "
            "(Cobalt Strike, Sliver, etc.). May occur in game DRM/anti-cheat during installation."
        ),
        "mitre": ["T1562", "T1055"],
    },
    "KeyloggerRegistered": {
        "severity": "CRITIQUE", "category": "InfoStealer", "tp_score": 4,
        "fp_contexts": ["security_app"],
        "description": (
            "Keylogger registered via the Windows API (T1056.001). Real-time keystroke interception: "
            "passwords, PINs, messages, commands. Outside a certified security tool context, "
            "direct evidence of malicious activity. May operate alongside a network exfiltrator."
        ),
        "mitre": ["T1056.001"],
    },
    "MainBinaryInvokedDirectSyscall": {
        "severity": "ELEVE", "category": "Direct Syscall", "tp_score": 3,
        "fp_contexts": ["installer"],
        "description": (
            "Direct syscall invoked from the main binary itself (not via ntdll). "
            "Hell's Gate / SysWhispers technique: malware reads syscall numbers from ntdll in memory "
            "and calls them directly, rendering ntdll hooks useless. Indicator of highly sophisticated "
            "offensive tooling. May occur in game DRM/anti-cheat during installation."
        ),
        "mitre": ["T1562", "T1055"],
    },
    "MaliciousDiscoveryByAI": {
        "severity": "ELEVE", "category": "InfoStealer", "tp_score": 3,
        "fp_contexts": ["security_app"],
        "description": (
            "SentinelOne AI model: the combination of observed discovery operations statistically "
            "matches malicious activity. The model correlates multiple actions (process, file, "
            "network enumeration) whose sequence is characteristic of automated reconnaissance."
        ),
        "mitre": ["T1082", "T1087", "T1057"],
    },
    "MultipleInfostealersResearch": {
        "severity": "CRITIQUE", "category": "InfoStealer", "tp_score": 4,
        "fp_contexts": [],
        "description": (
            "Credential theft attempts from multiple sources simultaneously (T1555). "
            "Attacker targets in parallel: browsers, Credential Manager, password vaults, "
            "and other sources. Indicates a complete infostealer or an active operator "
            "systematically harvesting secrets."
        ),
        "mitre": ["T1555"],
    },
    "NetworkConfigurationDiscovery": {
        "severity": "MOYEN", "category": "Discovery", "tp_score": 1,
        "fp_contexts": ["installer"],
        "description": (
            "Network configuration discovery (T1016): interfaces, IP addresses, routing, DNS. "
            "Normal during installations or network applications. In an attack context: "
            "reconnaissance step to map the internal network before lateral movement."
        ),
        "mitre": ["T1016"],
    },
    "NetworkShareDiscovery": {
        "severity": "ELEVE", "category": "Discovery", "tp_score": 2,
        "fp_contexts": ["electron"],
        "description": (
            "Enumeration of accessible network shares (T1135). Typical target for lateral movement "
            "and ransomware propagation: shares allow access to data on other systems or "
            "spreading encryption. Correlate with other network discovery indicators."
        ),
        "mitre": ["T1135"],
    },
    "ObfuscatedPSCommand": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Obfuscated PowerShell command detected (T1027): string concatenation, backticks, "
            "variable substitution, Unicode characters, nested Invoke-Expression. "
            "Systematic obfuscation aims to bypass signature-based detections on command-line keywords."
        ),
        "mitre": ["T1027", "T1059.001"],
    },
    "OutputRedirection": {
        "severity": "MOYEN", "category": "Malware", "tp_score": 1,
        "fp_contexts": [],
        "description": (
            "Output redirection from a process (T1059). Benign in many contexts (admin scripts, CLI tools). "
            "Suspicious if the source process is hidden (hidden window), the target is a file in Temp, "
            "or if combined with other malicious execution indicators."
        ),
        "mitre": ["T1059"],
    },
    "PackedProcessSuspicion": {
        "severity": "ELEVE", "category": "Packer", "tp_score": 2,
        "fp_contexts": ["security_app", "installer"],
        "description": (
            "Process suspected of being packed (T1027.002): abnormal PE structure, high-entropy "
            "sections (compression/encryption), minimal imports, code that decompresses in memory "
            "at runtime. Common technique to hide malicious code from static analysis. "
            "FP common in game installers containing DRM/anti-cheat components."
        ),
        "mitre": ["T1027.002"],
    },
    "PasswordPolicyDiscovery": {
        "severity": "ELEVE", "category": "Discovery", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Query of local or domain password policy (T1201). Allows an attacker to tune dictionary "
            "attacks (min length, complexity) and understand AD domain constraints to prepare "
            "Kerberoasting or bruteforce attacks."
        ),
        "mitre": ["T1201"],
    },
    "PeripheralDeviceDiscovery": {
        "severity": "MOYEN", "category": "Discovery", "tp_score": 1,
        "fp_contexts": ["installer"],
        "description": (
            "Enumeration of connected peripherals (T1120): USB drives, printers, cameras. "
            "May target USB keys for data exfiltration, or serve to identify the workstation "
            "type (workstation/server) to adapt the attack strategy."
        ),
        "mitre": ["T1120", "T1082"],
    },
    "PermissionGroupsDiscovery": {
        "severity": "ELEVE", "category": "Discovery", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Permission group enumeration (T1069): Domain Admins, Enterprise Admins, "
            "privileged local groups. Key step before targeted privilege escalation or "
            "lateral movement toward high-privilege accounts."
        ),
        "mitre": ["T1069", "T1069.002", "T1087"],
    },
    "PersistenceFromLnk": {
        "severity": "ELEVE", "category": "Persistence", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Persistence established via a LNK file (T1547): a shortcut is placed in the "
            "Startup folder or referenced in the Run registry key. Executes malware at every "
            "user logon, invisibly if the LNK mimics a legitimate shortcut."
        ),
        "mitre": ["T1547", "T1547.001"],
    },
    "PossibleDllHijackingByKnownLibrary": {
        "severity": "MOYEN", "category": "Injection", "tp_score": 1,
        "fp_contexts": ["chromium"],
        "description": (
            "Potential DLL hijacking via a known library (T1574.001). Triggered when an unsigned "
            "process loads a system DLL. Very frequent FP for Electron apps (unsigned by nature, "
            "load ntdll, kernel32, etc.). Outside Electron: verify the exact DLL load path."
        ),
        "mitre": ["T1574.001", "T1036.005"],
    },
    "PossibleRegistryComLocalServerPersistence": {
        "severity": "ELEVE", "category": "Persistence", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Possible COM LocalServer32 object override (T1546.015). Subtle persistence technique: "
            "replaces the executable referenced by a COM object to execute code whenever that "
            "COM object is invoked by third-party applications."
        ),
        "mitre": ["T1546.015"],
    },
    "PowerSploit": {
        "severity": "CRITIQUE", "category": "Post Exploitation", "tp_score": 6,
        "fp_contexts": [],
        "description": (
            "Execution of PowerSploit, an open-source offensive post-exploitation framework (T1059.001). "
            "Documented modules: PowerView (AD recon), Invoke-Mimikatz (credentials), "
            "PowerUp (privilege escalation), Invoke-Shellcode (injection), Get-GPPPassword. "
            "This indicator alone constitutes sufficient evidence of active compromise."
        ),
        "mitre": ["T1059.001"],
    },
    "PowershellWithoutPowershellExeSigned": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": ["electron"],
        "description": (
            "System.Management.Automation.dll loaded by a non-powershell.exe signed process (T1059.001). "
            "'PowerShell without PowerShell' technique: bypasses powershell.exe restrictions "
            "(ExecutionPolicy, ScriptBlock logging, AMSI) by embedding the PS runtime directly."
        ),
        "mitre": ["T1059.001", "T1027"],
    },
    "PreloadInjection": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 2,
        "fp_contexts": ["chromium"],
        "description": (
            "Code injection during target process initialization (T1055.012). Code is injected "
            "before the main entry point executes. Confirmed FP for Chromium (sandbox setup). "
            "Outside Chromium: stealthy injection technique executing before the target process defenses."
        ),
        "mitre": ["T1055.012"],
    },
    "PrivilegedInstruction": {
        "severity": "ELEVE", "category": "Privilege Escalation", "tp_score": 3,
        "fp_contexts": ["security_app"],
        "description": (
            "Privileged instruction executed from usermode (T1068). May indicate an attempt "
            "to exploit a kernel vulnerability to escalate privileges from a standard user context."
        ),
        "mitre": ["T1068"],
    },
    "ProcessCreatedWithDifferentToken": {
        "severity": "ELEVE", "category": "Privilege Escalation", "tp_score": 2,
        "fp_contexts": ["chromium", "security_app"],
        "description": (
            "Process created with a different security token than its parent (T1134.002). "
            "Chromium uses this legitimately for its sandbox (Low Integrity token). "
            "Outside Chromium: potential privilege escalation or security context impersonation "
            "to execute under a different identity."
        ),
        "mitre": ["T1134.002", "T1078"],
    },
    "ProcessEnumeration": {
        "severity": "FAIBLE", "category": "Discovery", "tp_score": 1,
        "fp_contexts": ["chromium", "security_app"],
        "description": (
            "Running process enumeration (T1057). Very common: Electron, security tools, "
            "and malware all use it for different reasons. Low forensic value alone; relevant "
            "only when accompanied by other reconnaissance indicators."
        ),
        "mitre": ["T1057", "T1518"],
    },
    "ProcessExecutableFileNameMasquerade": {
        "severity": "CRITIQUE", "category": "Evasion", "tp_score": 4,
        "fp_contexts": [],
        "description": (
            "Executable masquerading as a legitimate binary (T1036.005): name mimicking a system "
            "process (svchost.exe, explorer.exe, lsass.exe) but from a non-standard path "
            "(AppData, Temp, etc.). Classic malware camouflage technique."
        ),
        "mitre": ["T1036.005", "T1036"],
    },
    "ProcessHollowingImagePatched": {
        "severity": "CRITIQUE", "category": "Evasion", "tp_score": 5,
        "fp_contexts": ["chromium"],
        "description": (
            "Process Hollowing: main process image patched in memory after creation in suspended "
            "state (T1055.012). Chromium uses this for its sandbox (FP). Outside Chromium: "
            "classic injection technique executing malicious code within a visible legitimate process. "
            "Strong indicator of active compromise or sophisticated offensive tooling."
        ),
        "mitre": ["T1055.012"],
    },
    "ProcessStartedFromLnk": {
        "severity": "MOYEN", "category": "General", "tp_score": 1,
        "fp_contexts": [],
        "description": (
            "Process started from a LNK shortcut file. Benign if the LNK is in an expected "
            "location (Desktop, Taskbar, Start Menu). Suspicious if the LNK originates from "
            "an email, removable media, or a temporary directory (phishing technique)."
        ),
        "mitre": ["T1204"],
    },
    "QuerySAM": {
        "severity": "CRITIQUE", "category": "InfoStealer", "tp_score": 4,
        "fp_contexts": ["electron"],
        "description": (
            "Direct access attempt to the SAM database (Security Account Manager) (T1003.002). "
            "SAM stores NTLM hashes of local Windows accounts. Direct access = credential dumping "
            "attempt. No legitimate non-system application justifies direct SAM access."
        ),
        "mitre": ["T1003.002", "T1552.002", "T1087"],
    },
    "RansomwareSuspiciousFileOperationsB": {
        "severity": "CRITIQUE", "category": "Ransomware", "tp_score": 5,
        "fp_contexts": ["dev_build"],
        "description": (
            "File operations characteristic of ransomware (T1486): mass creation of files with "
            "unusual extensions, rapid deletion of originals in sequence. FP in build/compilation "
            "context (PyInstaller, webpack). Analyze created file extensions to differentiate."
        ),
        "mitre": ["T1486"],
    },
    "RawVolumeAccess": {
        "severity": "ELEVE", "category": "Discovery", "tp_score": 3,
        "fp_contexts": ["security_app"],
        "description": (
            "Direct raw volume access (T1006): reading disk sectors bypassing the filesystem. "
            "Used by legitimate forensic and defragmentation tools, but also by malware to read "
            "locked files (e.g. NTDS.dit, SAM) or bypass access auditing."
        ),
        "mitre": ["T1006"],
    },
    "RegistryComLocalServerPersistence": {
        "severity": "ELEVE", "category": "Persistence", "tp_score": 4,
        "fp_contexts": [],
        "description": (
            "Confirmed COM LocalServer32 object override (T1546.015). Application replaced "
            "the reference of a legitimate COM object. Discreet persistence: automatically "
            "triggered whenever any process invokes that COM object, without direct user interaction."
        ),
        "mitre": ["T1546.015"],
    },
    "RemoteSystemsDiscovery": {
        "severity": "ELEVE", "category": "Discovery", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "Enumeration of remotely accessible systems on the network (T1018). Prerequisite "
            "for lateral movement: attacker identifies next targets (servers, DCs, hosts with "
            "privileged access). Typically follows initial compromise of a first endpoint."
        ),
        "mitre": ["T1018", "T1049", "T1087.002"],
    },
    "SecurityContextInitialization": {
        "severity": "FAIBLE", "category": "General", "tp_score": 0,
        "fp_contexts": [],
        "description": (
            "SSPI/Kerberos security context initialization. Standard operation during network "
            "authentication. Very low forensic value alone. Relevant only if followed by unusual "
            "authentication activity or combined with Pass-the-Ticket/Hash indicators."
        ),
        "mitre": ["T1558"],
    },
    "ShimmedApplication": {
        "severity": "FAIBLE", "category": "Persistence", "tp_score": 1,
        "fp_contexts": ["installer"],
        "description": (
            "Application shimmed by a known Windows compatibility shim (T1546.011). "
            "Normal compatibility mechanism. Monitor if the shim references a non-standard "
            "module or DLL that could be an implant."
        ),
        "mitre": ["T1546.011"],
    },
    "ShortcutModification": {
        "severity": "ELEVE", "category": "Persistence", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Modification of an existing LNK file (T1547). A legitimate shortcut (Desktop, "
            "Startup, Taskbar) is altered to point to a malicious executable. "
            "Icon and name remain unchanged, making user detection difficult."
        ),
        "mitre": ["T1547"],
    },
    "SignedAmsiDllHijack": {
        "severity": "ELEVE", "category": "Evasion", "tp_score": 3,
        "fp_contexts": ["chromium", "security_app"],
        "description": (
            "Signed amsi.dll loaded into a non-AMSI process (T1562.001). May indicate an AMSI "
            "bypass attempt: by loading an unpatched version of amsi.dll, some tools attempt "
            "to bypass script inspection. Analyze based on which process loads this DLL."
        ),
        "mitre": ["T1562.001", "T1574.001"],
    },
    "SuspiciousDiscoveryByAI": {
        "severity": "MOYEN", "category": "InfoStealer", "tp_score": 2,
        "fp_contexts": [],
        "description": (
            "SentinelOne AI model: suspicious discovery operations without definitive confirmation. "
            "Observed behavior deviates from baseline but may have a legitimate explanation. "
            "Monitor in correlation with other indicators."
        ),
        "mitre": ["T1082"],
    },
    "SuspiciousRedirectionHidden": {
        "severity": "ELEVE", "category": "Malware", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Data redirection from a hidden-window process (T1564.003). An invisible process "
            "(WindowStyle Hidden) redirects its output. Classic dropper/stager pattern: "
            "downloading or execution in the background without user visibility."
        ),
        "mitre": ["T1564.003"],
    },
    "SuspiciousRedirectionInterpreter": {
        "severity": "ELEVE", "category": "Malware", "tp_score": 3,
        "fp_contexts": ["electron"],
        "description": (
            "Redirection from a hidden-window interpreter (T1564.003 + T1059). "
            "PowerShell or cmd running in Hidden mode redirecting its output. "
            "Classic stager/downloader or silent C2 technique."
        ),
        "mitre": ["T1564.003", "T1059"],
    },
    "SuspiciousRedirectionPipe": {
        "severity": "ELEVE", "category": "Malware", "tp_score": 3,
        "fp_contexts": ["electron"],
        "description": (
            "Redirection to a pipe from a hidden interpreter (T1059). Inter-process communication "
            "via named pipe from a hidden-mode interpreter. Used for local C2 (commands transmitted "
            "via pipe) or to chain commands invisibly."
        ),
        "mitre": ["T1059", "T1564.003"],
    },
    "SuspiciousRedirectionUnsigned": {
        "severity": "ELEVE", "category": "Malware", "tp_score": 3,
        "fp_contexts": ["electron"],
        "description": (
            "Redirection from an unsigned process with hidden window (T1564.003). "
            "Double signal: unsigned process + hidden window + redirection = "
            "characteristic pattern of a dropper, stager, or unsigned malware."
        ),
        "mitre": ["T1564.003"],
    },
    "SuspiciousWMIQuery": {
        "severity": "ELEVE", "category": "Reconnaissance", "tp_score": 2,
        "fp_contexts": ["security_app"],
        "description": (
            "Suspicious WMI query identified (T1047). WMI enables complete system reconnaissance "
            "(processes, services, software, configuration) and remote command execution. "
            "Widely used by RATs, post-exploitation frameworks, and legitimate admin tools."
        ),
        "mitre": ["T1047", "T1518", "T1119"],
    },
    "SystemInformationDiscovery": {
        "severity": "FAIBLE", "category": "Discovery", "tp_score": 1,
        "fp_contexts": ["installer"],
        "description": (
            "System information discovery (T1082): OS version, CPU architecture, hostname, domain. "
            "Very common (installers, app telemetry). In attack context: initial reconnaissance "
            "to adapt the payload or identify the target."
        ),
        "mitre": ["T1082"],
    },
    "ThreadPoolObjectDuplication": {
        "severity": "ELEVE", "category": "Injection", "tp_score": 3,
        "fp_contexts": [],
        "description": (
            "Thread pool object duplication from a remote process (T1055). Advanced injection "
            "technique: by hijacking a target process's thread pool, code executes in its context "
            "without creating a suspicious thread, making detection more difficult."
        ),
        "mitre": ["T1055"],
    },
    "UIHooking": {
        "severity": "MOYEN", "category": "Discovery", "tp_score": 2,
        "fp_contexts": ["security_app"],
        "description": (
            "User interface hooking detected (T1056). Interception of global UI events "
            "(windows, messages, keyboard/mouse events). Legitimate use: accessibility tools, "
            "window managers. Malicious use: UI keylogging, form data theft."
        ),
        "mitre": ["T1056"],
    },
    "UnknownShimModuleLoaded": {
        "severity": "MOYEN", "category": "Persistence", "tp_score": 2,
        "fp_contexts": ["installer"],
        "description": (
            "Unknown shim module loaded (T1546.011). Unlike ShimmedApplication (known shim), "
            "this shim module is entirely unknown. May indicate a malicious shim installed "
            "to persist or intercept specific API calls. FP possible during game DRM installation."
        ),
        "mitre": ["T1546.011"],
    },
    "UnsignedProcessCreatedPseudoConsole": {
        "severity": "ELEVE", "category": "Execution", "tp_score": 3,
        "fp_contexts": ["electron"],
        "description": (
            "Pseudo-console creee par un processus non-signe (T1059). Les pseudo-consoles "
            "(ConPTY API) permettent de controler interactivement un processus depuis "
            "un programme. Un processus non-signe creant une pseudo-console suggere un "
            "C2 interactif ou un shell de commande masque."
        ),
        "mitre": ["T1059"],
    },
    "VaultDecryptAfterEnum": {
        "severity": "CRITIQUE", "category": "InfoStealer", "tp_score": 5,
        "fp_contexts": [],
        "description": (
            "Dechiffrement du coffre de credentials apres enumeration (T1555). Sequence "
            "confirmant un vol actif en deux etapes : 1) enumeration du vault (VaultEnum), "
            "2) dechiffrement des credentials (VaultGetItem). Preuve directe et irrefutable "
            "d'infostealing actif."
        ),
        "mitre": ["T1555", "T1552.001"],
    },
    "WinRMUsed": {
        "severity": "MOYEN", "category": "General", "tp_score": 1,
        "fp_contexts": [],
        "description": (
            "WinRM (Windows Remote Management) utilise (T1021.006). Protocole "
            "d'administration legitime (winrm, Enter-PSSession, Invoke-Command) "
            "frequemment detourne pour le mouvement lateral. Evaluer : qui utilise "
            "WinRM, vers quelle destination, et dans quel contexte."
        ),
        "mitre": ["T1021.006"],
    },
}

# ===========================================================================
# CHAINES D'ATTAQUE (correlation d'indicateurs)
# ===========================================================================
ATTACK_CHAINS = [
    {
        "name": "Infostealing actif confirme (vault)",
        "required_indicators": {"VaultDecryptAfterEnum", "CredmanEnumerationInfoStealer"},
        "required_categories": set(), "min_cat_indicators": 0,
        "score": 5,
        "description": "Complete confirmed sequence: credential enumeration THEN decryption. Irrefutable active theft.",
    },
    {
        "name": "Credential dumping SAM",
        "required_indicators": {"QuerySAM"},
        "required_categories": set(), "min_cat_indicators": 0,
        "score": 4,
        "description": "Direct SAM database access: attempt to retrieve local NTLM password hashes.",
    },
    {
        "name": "Offensive PowerShell post-exploitation",
        "required_indicators": {"PowerSploit"},
        "required_categories": {"Discovery"}, "min_cat_indicators": 1,
        "score": 3,
        "description": "Offensive framework combined with reconnaissance: active post-exploitation attack.",
    },
    {
        "name": "Defense neutralization + action",
        "required_indicators": {"DisableOrModifySecurityTools"},
        "required_categories": {"Discovery"}, "min_cat_indicators": 1,
        "score": 3,
        "description": "Security tool disabling followed by reconnaissance: two-phase attack in progress.",
    },
    {
        "name": "Pre-lateral-movement reconnaissance",
        "required_indicators": {"RemoteSystemsDiscovery", "NetworkShareDiscovery"},
        "required_categories": set(), "min_cat_indicators": 0,
        "score": 3,
        "description": "Remote systems + network shares: preparation for lateral movement or ransomware propagation.",
    },
    {
        "name": "Persistence + concealment",
        "required_indicators": set(),
        "required_categories": {"Persistence", "Evasion"}, "min_cat_indicators": 2,
        "score": 3,
        "description": "Persistence mechanism installed with concealment: durable compromise being prepared.",
    },
    {
        "name": "Injection + privilege escalation",
        "required_indicators": set(),
        "required_categories": {"Injection", "Privilege Escalation"}, "min_cat_indicators": 2,
        "score": 3,
        "description": "Code injection combined with privilege escalation: progression toward elevated access.",
    },
    {
        "name": "Multi-source credential theft",
        "required_indicators": set(),
        "required_categories": {"InfoStealer"}, "min_cat_indicators": 3,
        "score": 3,
        "description": "3+ InfoStealer indicators: attacker systematically targeting all credential sources.",
    },
    {
        "name": "Active evasion + execution",
        "required_indicators": set(),
        "required_categories": {"Evasion", "Execution"}, "min_cat_indicators": 2,
        "score": 2,
        "description": "Evasion techniques combined with execution: attacker concealing activity during execution.",
    },
    {
        "name": "Full domain reconnaissance",
        "required_indicators": {"AccountDiscovery", "PermissionGroupsDiscovery"},
        "required_categories": set(), "min_cat_indicators": 0,
        "score": 3,
        "description": "Account + group enumeration: AD domain mapping to target privileged accounts.",
    },
]

# ===========================================================================
# PATTERNS MALVEILLANTS DANS LES SCRIPTS (cmdScript.content)
# ===========================================================================
SCRIPT_PATTERNS = [
    (r"(?i)(IEX|Invoke-Expression)\s*[\(\$\(]", "CRITIQUE",
     "Invoke-Expression: dynamic code execution (T1059.001)", "T1059.001"),
    (r"(?i)FromBase64String", "ELEVE",
     "In-memory Base64 decoding: obfuscated payload (T1027)", "T1027"),
    (r"(?i)(Net\.WebClient|DownloadFile|DownloadString|Invoke-WebRequest|Start-BitsTransfer|wget\s+-\S|curl\s+-\S)[^\"']{0,300}\.(exe|dll|ps1|bat|vbs)\b",
     "CRITIQUE", "Download cradle: payload download and execution (T1105)", "T1105"),
    (r"(?i)bypass.*executionpolicy|executionpolicy.*bypass|ep\s+bypass", "ELEVE",
     "PowerShell execution policy bypass (T1059.001)", "T1059.001"),
    (r"(?i)(amsiInitFailed|AmsiScanBuffer|amsi\.dll.*patch)", "CRITIQUE",
     "AMSI bypass attempt (T1562.001)", "T1562.001"),
    (r"(?i)(Invoke-Mimikatz|sekurlsa|lsadump|kerberos::)", "CRITIQUE",
     "Mimikatz strings detected: credential dumping (T1003)", "T1003"),
    (r"(?i)(Get-ADUser|Get-ADGroup|Get-ADComputer|Get-ADDomain|Get-ADObject)", "ELEVE",
     "Active Directory reconnaissance (T1087.002)", "T1087.002"),
    (r"(?i)(New-Object\s+Net\.Sockets\.TCP|TCPClient\s*\(|socket\.connect)", "ELEVE",
     "TCP socket creation: potential reverse shell or C2 (T1059.001)", "T1059.001"),
    (r"(?i)(-w\s+hidden|-windowstyle\s+hidden|CreateNoWindow\s*=\s*true)", "MOYEN",
     "Hidden-window execution (T1564.003)", "T1564.003"),
    (r"(?i)(Stop-Service|sc\s+stop|net\s+stop)\s+\S*(defender|sense|mssec|symantec|mcafee|sentinel)",
     "CRITIQUE", "Security service stop attempt (T1562.001)", "T1562.001"),
    (r"(?i)(Set-MpPreference.*Disable|Add-MpPreference.*Exclusion)", "CRITIQUE",
     "Windows Defender modification (T1562.001)", "T1562.001"),
    (r"(?i)(schtasks.*\/create|Register-ScheduledTask)", "ELEVE",
     "Scheduled task creation: persistence mechanism (T1053.005)", "T1053.005"),
    (r"(?i)(reg\s+add.*\\Run|New-ItemProperty.*Run)", "ELEVE",
     "Autorun registry key: registry persistence (T1547.001)", "T1547.001"),
    (r"(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled)", "CRITIQUE",
     "Shadow Copy / recovery deletion: ransomware preparation (T1490)", "T1490"),
    (r"(?i)(netsh\s+(advfirewall|firewall).*allow)", "ELEVE",
     "Firewall rule modification (T1562.004)", "T1562.004"),
    (r"(?i)(compress-archive.*password|7z.*-p\S+)", "MOYEN",
     "Encrypted archive: exfiltration preparation (T1560)", "T1560"),
    (r"(?i)whoami\s*/priv|net\s+user.*\/domain|nltest\s*/domain", "MOYEN",
     "Privilege/domain reconnaissance commands (T1033)", "T1033"),
]

# ===========================================================================
# SUSPICIOUS DLLS IN MODULE LOADS
# ===========================================================================
SUSPICIOUS_MODULES = {
    "System.Management.Automation.dll": ("ELEVE",
        "PowerShell runtime loaded outside powershell.exe: hidden PowerShell execution (T1059.001)"),
    "System.Management.Automation.ni.dll": ("ELEVE",
        "PowerShell NGen runtime loaded outside powershell.exe: hidden PowerShell execution (T1059.001)"),
    "vbscript.dll": ("ELEVE",
        "VBScript engine directly loaded: possible VBScript execution (T1059.005)"),
    "scrrun.dll": ("MOYEN",
        "Windows Script Runtime: shell and filesystem access via VBScript/JScript"),
    "wshom.ocx": ("MOYEN",
        "WSH Object Model: shell access from script, often loaded by VBS malware"),
    "urlmon.dll": ("MOYEN",
        "URL Moniker: HTTP download possible from this process (T1105)"),
    "clrjit.dll": ("FAIBLE",
        ".NET JIT compiler: managed .NET code execution from this process"),
    "amsi.dll": ("MOYEN",
        "AMSI loaded: verify whether legitimate use or bypass attempt"),
}

# ===========================================================================
# RESEAUX CONNUS (prefixes precis, pas premier octet seulement)
# ===========================================================================
KNOWN_NETWORKS = {
    "Microsoft Azure / Microsoft": [
        "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "13.70.", "13.71.",
        "13.72.", "13.73.", "13.74.", "13.75.", "13.76.", "13.77.", "13.78.", "13.79.",
        "13.80.", "13.81.", "13.82.", "13.83.", "13.84.", "13.85.", "13.86.", "13.87.",
        "13.88.", "13.89.", "13.90.", "13.91.", "13.92.", "13.93.", "13.94.", "13.95.",
        "13.104.", "13.105.", "13.106.", "13.107.", "13.108.",
        "20.33.", "20.34.", "20.36.", "20.38.", "20.40.", "20.41.", "20.42.", "20.43.",
        "20.44.", "20.45.", "20.46.", "20.47.", "20.48.", "20.49.", "20.50.", "20.51.",
        "20.52.", "20.53.", "20.54.", "20.55.", "20.56.", "20.57.", "20.58.",
        "40.64.", "40.65.", "40.66.", "40.67.", "40.68.", "40.69.", "40.70.", "40.71.",
        "40.74.", "40.75.", "40.76.", "40.77.", "40.78.", "40.79.", "40.80.", "40.81.",
        "40.82.", "40.83.", "40.84.", "40.85.", "40.86.", "40.87.", "40.88.", "40.89.",
        "40.90.", "40.91.", "40.92.", "40.93.", "40.94.", "40.95.", "40.96.", "40.97.",
        "40.98.", "40.99.", "40.100.", "40.101.", "40.102.", "40.103.", "40.104.",
        "40.105.", "40.106.", "40.107.", "40.108.", "40.109.", "40.110.", "40.111.",
        "40.112.", "40.113.", "40.114.", "40.115.", "40.116.", "40.117.", "40.118.",
        "40.119.", "40.120.", "40.121.", "40.122.", "40.123.", "40.124.", "40.125.",
        "40.126.", "40.127.",
        "51.4.", "51.5.", "51.107.", "51.116.", "51.120.", "51.124.", "51.132.", "51.138.",
        "52.96.", "52.97.", "52.98.", "52.99.", "52.100.", "52.101.", "52.102.", "52.103.",
        "52.104.", "52.105.", "52.106.", "52.107.", "52.108.", "52.109.", "52.110.",
        "52.111.", "52.112.", "52.113.", "52.114.", "52.115.", "52.116.", "52.117.",
        "52.118.", "52.119.", "52.120.", "52.121.", "52.122.", "52.123.", "52.124.",
        "52.125.", "52.126.", "52.127.",
        "52.136.", "52.138.", "52.140.", "52.141.", "52.142.", "52.143.", "52.146.",
        "104.40.", "104.41.", "104.42.", "104.43.", "104.44.", "104.45.", "104.46.",
        "104.208.", "104.209.", "104.210.", "104.211.",
        "191.232.", "191.233.", "191.234.", "191.235.",
    ],
    "Google Cloud / Google": [
        "34.0.", "34.1.", "34.2.", "34.3.", "34.4.", "34.5.", "34.6.", "34.7.",
        "34.8.", "34.9.", "34.10.", "34.11.", "34.12.", "34.13.", "34.14.", "34.15.",
        "34.16.", "34.17.", "34.18.", "34.19.", "34.20.", "34.21.", "34.22.", "34.23.",
        "34.24.", "34.25.", "34.26.", "34.27.", "34.28.", "34.29.", "34.30.", "34.31.",
        "34.32.", "34.33.", "34.34.", "34.35.", "34.36.", "34.37.", "34.38.", "34.39.",
        "34.40.", "34.41.", "34.42.", "34.43.", "34.44.", "34.45.", "34.46.", "34.47.",
        "34.48.", "34.49.", "34.50.", "34.51.", "34.52.", "34.53.", "34.54.", "34.55.",
        "34.56.", "34.57.", "34.58.", "34.59.", "34.60.", "34.61.", "34.62.", "34.63.",
        "34.64.", "34.65.", "34.66.", "34.67.", "34.68.", "34.69.", "34.70.", "34.71.",
        "34.72.", "34.73.", "34.74.", "34.75.", "34.76.", "34.77.", "34.78.", "34.79.",
        "34.80.", "34.81.", "34.82.", "34.83.", "34.84.", "34.85.", "34.86.", "34.87.",
        "34.88.", "34.89.", "34.90.", "34.91.", "34.92.", "34.93.", "34.94.", "34.95.",
        "34.96.", "34.97.", "34.98.", "34.99.", "34.100.", "34.101.", "34.102.",
        "34.120.", "34.128.", "34.149.",
        "35.186.", "35.187.", "35.188.", "35.189.", "35.190.", "35.191.", "35.192.",
        "35.193.", "35.194.", "35.195.", "35.196.", "35.197.", "35.198.", "35.199.",
        "35.200.", "35.201.", "35.202.", "35.203.", "35.204.", "35.205.",
        "74.125.", "142.250.", "172.217.", "172.253.",
        "216.58.", "216.239.", "209.85.",
    ],
    "Amazon AWS": [
        "3.8.", "3.9.", "3.10.", "3.11.", "3.12.", "3.13.", "3.14.", "3.15.", "3.16.",
        "3.17.", "3.18.", "3.19.", "3.20.", "3.21.", "3.22.", "3.23.", "3.24.",
        "3.25.", "3.26.", "3.27.", "3.28.", "3.29.", "3.32.", "3.33.", "3.34.",
        "3.35.", "3.36.", "3.37.", "3.38.", "3.39.", "3.40.", "3.41.", "3.42.",
        "18.132.", "18.133.", "18.134.", "18.135.", "18.168.", "18.169.", "18.170.",
        "18.171.", "18.172.", "18.173.", "18.175.",
        "52.14.", "52.15.", "54.72.", "54.73.", "54.74.", "54.75.", "54.76.", "54.77.",
        "54.78.", "54.79.", "54.80.", "54.83.", "54.84.", "54.85.", "54.86.", "54.87.",
        "54.88.", "54.93.", "54.94.", "54.95.", "54.144.", "54.145.",
        "44.192.", "44.193.", "44.194.", "44.195.", "44.196.", "44.197.", "44.198.",
        "44.199.", "44.200.", "44.201.", "44.202.", "44.203.", "44.204.",
        "99.80.", "99.81.", "99.82.", "99.83.", "99.84.", "99.85.", "99.86.", "99.87.",
    ],
    "Cloudflare": [
        "1.1.1.", "1.0.0.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
        "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
        "104.28.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "172.70.", "172.71.", "198.41.", "190.93.",
    ],
    "Akamai": [
        "23.0.", "23.1.", "23.2.", "23.3.", "23.4.", "23.5.", "23.6.", "23.7.",
        "23.8.", "23.9.", "23.10.", "23.11.", "23.12.", "23.13.", "23.14.", "23.15.",
        "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.",
        "23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.", "23.46.", "23.47.",
        "23.48.", "23.49.", "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.",
        "23.56.", "23.57.", "23.58.", "23.59.", "23.60.", "23.61.", "23.62.", "23.63.",
        "23.64.", "23.65.", "23.66.", "23.67.", "23.68.", "23.69.", "23.70.", "23.71.",
        "23.72.", "23.79.", "23.192.", "23.193.", "23.194.", "23.195.", "23.196.",
        "23.197.", "23.198.", "23.199.", "23.200.", "23.201.", "23.202.", "23.203.",
        "23.208.", "23.209.", "23.210.", "23.211.", "23.212.", "23.213.", "23.214.",
        "23.215.", "23.216.", "23.217.", "23.218.", "23.219.", "23.220.", "23.221.",
        "23.222.", "23.223.", "95.100.", "95.101.", "95.102.",
        "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.", "104.70.",
        "104.71.", "104.72.", "104.73.", "104.74.", "104.75.", "104.76.", "104.77.",
        "104.78.", "104.79.", "104.80.", "104.81.", "104.82.", "104.83.", "104.84.",
        "104.85.", "104.86.", "104.87.", "104.88.", "104.89.", "104.90.", "104.91.",
        "104.92.", "104.93.", "104.94.", "104.95.", "104.96.", "104.97.", "104.98.",
        "104.99.", "104.100.", "104.101.", "104.102.", "104.103.", "104.104.",
        "104.105.", "104.106.", "104.107.", "104.108.", "104.109.", "104.110.",
        "104.111.", "104.112.", "104.113.", "104.114.", "104.115.", "104.116.",
        "104.117.", "104.118.", "104.119.", "104.120.", "104.121.", "104.122.",
        "104.123.", "104.124.", "104.125.",
    ],
    "GitHub": ["140.82.", "185.199.", "192.30."],
    "Anthropic": ["160.79."],
    "Fastly / CDN": ["151.101.", "199.232."],
    "Datadog": ["162.247."],
    "Amazon AWS (ap-northeast)": ["13.209.", "13.124.", "13.125.", "52.78.", "52.79."],
    "KT Corp / Korea Telecom": ["14.0.", "14.1.", "14.2.", "14.3.", "14.4.", "14.5.",
                                 "14.6.", "14.7.", "14.32.", "14.33.", "14.34.", "14.35.",
                                 "61.73.", "61.74.", "211.110.", "211.111.", "211.112.",
                                 "211.113.", "211.114.", "211.115.", "211.116.", "211.117.",
                                 "211.118.", "211.119.", "218.38.", "218.39.", "218.40.",
                                 "210.94.", "210.95.", "106.249.", "106.250.", "106.251.",
                                 "106.252.", "106.253.", "106.254.", "106.255."],
    "SK Broadband (Korea)": ["1.209.", "1.210.", "1.211.", "1.212.", "210.100.",
                              "210.101.", "210.102.", "210.103.", "210.104.", "210.217.",
                              "203.229.", "203.230.", "203.231."],
}

# Vecteurs d'attaque connus identifiables via le processus parent
ATTACK_VECTOR_PARENTS = {
    "w3wp.exe":     ("CRITIQUE", "Webshell ou RCE via IIS (T1190)"),
    "httpd":        ("CRITIQUE", "Webshell ou RCE via Apache (T1190)"),
    "nginx":        ("CRITIQUE", "Webshell ou RCE via Nginx (T1190)"),
    "tomcat":       ("CRITIQUE", "Webshell ou RCE via Tomcat (T1190)"),
    "iisexpress":   ("CRITIQUE", "Webshell ou RCE via IIS Express (T1190)"),
    "java.exe":     ("ELEVE",    "Execution depuis JVM : exploit Java possible (Log4Shell)"),
    "sqlservr.exe": ("CRITIQUE", "Execution depuis SQL Server : xp_cmdshell active (T1505)"),
    "msbuild.exe":  ("ELEVE",    "MSBuild utilise comme LOLBin (T1127.001)"),
    "wscript.exe":  ("ELEVE",    "Windows Script Host : execution VBScript/JScript (T1059.005)"),
    "cscript.exe":  ("ELEVE",    "Console Script Host : execution VBScript/JScript (T1059.005)"),
    "mshta.exe":    ("CRITIQUE", "HTA (HTML Application) : vecteur phishing classique (T1218.005)"),
    "regsvr32.exe": ("CRITIQUE", "Squiblydoo LOLBin : execution via regsvr32 (T1218.010)"),
    "rundll32.exe": ("ELEVE",    "Rundll32 LOLBin : execution de DLL arbitraire (T1218.011)"),
    "certutil.exe": ("CRITIQUE", "Certutil LOLBin : download ou decode de payload (T1105)"),
    "schtasks.exe": ("ELEVE",    "Tache planifiee comme vecteur d'execution (T1053.005)"),
    "wmiprvse.exe": ("ELEVE",    "Execution via WMI : mouvement lateral probable (T1047)"),
    "wmic.exe":     ("ELEVE",    "WMIC utilise comme vecteur d'execution LOLBin (T1047)"),
}

# Clés registre de persistance connues
PERSISTENCE_REG_PATTERNS = [
    (r"\\Run$",                   "Cle Run : execution automatique a chaque logon"),
    (r"\\RunOnce$",               "Cle RunOnce : execution unique au prochain logon"),
    (r"\\RunServices",            "Cle RunServices : service demarrant automatiquement"),
    (r"\\Winlogon\\Shell",        "Winlogon Shell : remplacement du shell utilisateur"),
    (r"\\Winlogon\\Userinit",     "Winlogon Userinit : execution au logon utilisateur"),
    (r"\\Image File Execution",   "IFEO : hijacking d'un debugger pour un exe cible"),
    (r"\\AppInit_DLLs",           "AppInit_DLLs : DLL injectee dans tous les processus GUI"),
    (r"\\Startup\\",              "Dossier Startup : execution au demarrage"),
    (r"\\Classes\\.*LocalServer", "COM LocalServer : persistence via objet COM"),
    (r"\\BootExecute",            "BootExecute : execution avant le chargement de Windows"),
    (r"\\SessionManager\\.*Known","Session Manager : execution au boot (drivers)"),
    (r"\\Services\\[^\\]+\\(Start|ImagePath|ServiceDll|FailureCommand)$",
     "Modification d'une cle de service Windows (demarrage/executable)"),
    (r"\\Policies.*Run",          "GPO Run : persistance via politiques de groupe"),
]

# Processus systeme standards (leur presence comme parent est normale)
LEGIT_PARENTS = {
    "explorer.exe", "userinit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "taskhostw.exe", "sihost.exe",
    "ctfmon.exe", "dwm.exe", "applicationframehost.exe", "shellexperiencehost.exe",
    "w3wp.exe", "iisexpress.exe",   # IIS worker processes
}

# Mapping displayName → exe pour quand cmdline est vide (SDL format)
_DISPLAY_TO_EXE = {
    "services and controller app": "services.exe",
    "host process for windows services": "svchost.exe",
    "windows explorer": "explorer.exe",
    "windows logon": "winlogon.exe",
    "windows logon application": "winlogon.exe",
    "application frame host": "applicationframehost.exe",
    "desktop window manager": "dwm.exe",
    "task host window": "taskhostw.exe",
    "ctf loader": "ctfmon.exe",
    "shell infrastructure host": "sihost.exe",
    "shell experience host": "shellexperiencehost.exe",
    "iis worker process": "w3wp.exe",
    "local security authority process": "lsass.exe",
}

# Caracteres Electron dans les lignes de commande
ELECTRON_CHILD_FLAGS = [
    "--type=crashpad-handler", "--type=gpu-process", "--type=renderer",
    "--type=utility", "--type=zygote", "--type=ppapi", "--type=broker",
    "--service-sandbox-type=",
]


# ===========================================================================
# PARSEURS CSV
# ===========================================================================

class EventParser:
    """Parse un champ event.details SentinelOne (paires cle=valeur + HTML MITRE)."""

    @staticmethod
    def parse(raw: str) -> dict:
        if not raw:
            return {}
        content = raw.strip()
        if content.startswith("[") and content.endswith("]"):
            content = content[1:-1]

        result = {}

        # 1. Extraire et parser le bloc HTML MITRE ATT&CK
        html_m = re.search(r'<div\s+style=.*?</div>', content, re.DOTALL)
        clean = content
        if html_m:
            html = html_m.group(0)
            result["_mitre_html"] = html
            clean = content[:html_m.start()] + content[html_m.end():]

            # Techniques
            seen = set()
            techs = []
            for tid, tname in re.findall(
                r'(T\d{4}(?:\.\d{3})?)\s*</a>\s*<strong>(.*?)</strong>', html
            ):
                if tid not in seen:
                    seen.add(tid)
                    techs.append({"id": tid, "name": tname.rstrip(": ")})
            if techs:
                result["_mitre_techniques"] = techs

            # Tactiques
            tactics = list(dict.fromkeys(
                re.findall(r'<h4[^>]*>(.*?)\s*\(TA\d+\)</h4>', html)
            ))
            if tactics:
                result["_mitre_tactics"] = tactics

        # 2. indicator.description (texte long avant le HTML ou metadata)
        desc_m = re.search(
            r'indicator\.description=(.*?)(?=\s*<div|\s*indicator\.metadata=|'
            r'\s*event\.repetitionCount=|$)',
            content, re.DOTALL
        )
        if desc_m:
            result["indicator.description"] = re.sub(
                r'\s+', ' ', re.sub(r'<[^>]+>', ' ', desc_m.group(1))
            ).strip()

        # 3. indicator.metadata
        meta_m = re.search(
            r'indicator\.metadata=(.*?)(?:\s*event\.repetitionCount=|$)',
            content, re.DOTALL
        )
        if meta_m:
            result["indicator.metadata"] = meta_m.group(1).strip()

        # 4. cmdScript.content (contenu complet du script)
        # Stop aussi sur osSrc.process. (champ SDL apres le contenu du script)
        script_m = re.search(
            r'cmdScript\.content=(.*?)(?:\s*cmdScript\.applicationName=|'
            r'\s*src\.process\.|\s*osSrc\.process\.|$)',
            content, re.DOTALL
        )
        if script_m:
            result["cmdScript.content"] = script_m.group(1).strip()

        # 4b. Champs multi-mots connus (publisher, displayName, cmdline) - valeur jusqu'au prochain champ
        for m in re.finditer(
            r'([\w.]*(?:publisher|displayName|\.cmdline))=(.*?)(?=\s+[\w][\w.]*\s*=|\s*[\]\[]|\s*$)',
            clean, re.IGNORECASE | re.DOTALL
        ):
            key = m.group(1)
            val = m.group(2).strip()
            # Remove surrounding quotes if the entire value is a single quoted string
            if val.startswith('"') and val.endswith('"') and val.count('"') == 2:
                val = val[1:-1]
            if key not in result and val:
                result[key] = val

        # 5. Toutes les paires cle=valeur restantes
        for m in re.finditer(
            r'([\w.]+)=(?:"((?:[^"]*(?:""[^"]*)*))"|((?:[^\s\[\]]+)))',
            clean
        ):
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
            if key not in result:
                result[key] = val.replace('""', '"')

        return result


class CsvParser:
    """Charge et normalise un CSV SentinelOne (format DV ou SDL)."""

    @staticmethod
    def parse_file(filepath: str) -> list:
        try:
            raw = Path(filepath).read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            raw = Path(filepath).read_text(encoding="latin-1")
        logical_lines = CsvParser._reconstruct_lines(raw)
        reader = csv.reader(StringIO("\n".join(logical_lines)))

        headers = None
        fmt = None
        events = []

        for row in reader:
            if headers is None:
                headers = row
                fmt = "SDL" if "dataSource.name" in headers else "DV"
                continue
            if len(row) < 2:
                continue
            rd = {headers[i]: row[i] for i in range(min(len(headers), len(row)))}
            if not rd.get("event.time"):
                continue
            ev = CsvParser._parse_sdl(rd) if fmt == "SDL" else CsvParser._parse_dv(rd)
            if ev:
                events.append(ev)

        return events

    @staticmethod
    def _parse_dv(r: dict) -> dict:
        details_raw = r.get("event.details", "")
        details = EventParser.parse(details_raw)
        return {
            "timestamp":      CsvParser._parse_ts(r.get("event.time", "")),
            "timestamp_raw":  r.get("event.time", ""),
            "agent_uuid":     r.get("agent.uuid", ""),
            "user":           r.get("src.process.user", ""),
            "event_type":     r.get("event.type", ""),
            "storyline_id":   r.get("src.process.storyline.id", ""),
            "details":        details,
            "details_raw":    details_raw,
            "_fmt":           "DV",
        }

    @staticmethod
    def _parse_sdl(r: dict) -> dict:
        src         = r.get("event.source", "")
        tgt         = r.get("event.target", "")
        details_raw = r.get("event.details", "")

        # Strip les crochets SDL de chaque champ avant concatenation pour eviter
        # que les "][" entre sections polluent le parsing (ex: cmdScript.content)
        def _sdl_strip(s: str) -> str:
            s = s.strip()
            return s[1:-1] if (s.startswith("[") and s.endswith("]")) else s

        combined = " ".join(filter(None, [
            _sdl_strip(src), _sdl_strip(tgt), _sdl_strip(details_raw)
        ]))
        details = EventParser.parse(combined)

        uuid_m  = re.search(r'agent\.uuid=(\S+)', src)
        # Stop avant le prochain champ SDL (lookahead sur mot.mot=)
        user_m  = re.search(
            r'src\.process\.user=(.*?)(?=\s+(?:src|tgt|osSrc|agent|event)\.\w|\]|$)',
            src, re.DOTALL
        )
        # DV: src.process.storyline.id  |  SDL: src.process.uid (même rôle)
        story_m = re.search(r'src\.process\.storyline\.id=(\S+)', src) or \
                  re.search(r'src\.process\.uid=(\S+)', src)

        return {
            "timestamp":      CsvParser._parse_ts(r.get("event.time", "")),
            "timestamp_raw":  r.get("event.time", ""),
            "agent_uuid":     uuid_m.group(1).strip()  if uuid_m  else "",
            "user":           user_m.group(1).strip()  if user_m  else "",
            "event_type":     r.get("event.type", ""),
            "storyline_id":   story_m.group(1).strip() if story_m else "",
            "details":        details,
            "details_raw":    combined,
            "_fmt":           "SDL",
        }

    @staticmethod
    def _reconstruct_lines(content: str) -> list:
        """Reconstitue les lignes logiques (champs CSV multi-lignes a cause du HTML)."""
        lines = content.split("\n")
        logical = []
        current = ""
        in_field = False

        for line in lines:
            if not in_field:
                current = line
                # Parité impaire = champ ouvert non fermé
                if current.replace('""', '').count('"') % 2 != 0:
                    in_field = True
                else:
                    logical.append(current)
            else:
                current += " " + line
                if current.replace('""', '').count('"') % 2 == 0:
                    in_field = False
                    logical.append(current)

        if current and in_field:
            logical.append(current)
        return logical

    @staticmethod
    def _parse_ts(s: str):
        for fmt in ("%b %d, %Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s.strip().strip('"'), fmt)
            except ValueError:
                continue
        return None


# ===========================================================================
# ANALYZERS
# ===========================================================================

class ProcessAnalyzer:
    """Reconstruit l'arbre de processus et identifie le contexte d'execution."""

    def __init__(self, events: list):
        self.events = events
        self.root = None
        self.children = {}   # key -> proc dict
        self._build()

    @staticmethod
    def _exe_from_details(d: dict, prefix: str) -> str:
        """Extrait le nom d'exe depuis cmdline ou displayName."""
        cmd = (d.get(f"{prefix}.process.cmdline", "") or "").replace('"', '').strip()
        if cmd:
            # Look for first .exe/.com/.cmd/.bat token (handles paths with spaces)
            m = re.search(r'([^\s"]*?\.(?:exe|com|cmd|bat|msi|dll|scr|ps1))\b', cmd, re.IGNORECASE)
            if m:
                return Path(m.group(1)).name.lower()
            # Fallback: if path-like, extract last component
            if '\\' in cmd or '/' in cmd:
                name = Path(cmd.split(' -')[0].split(' /')[0].strip()).name.lower()
                if name:
                    return name
        # Fallback: displayName → mapping connu
        dn = (d.get(f"{prefix}.process.displayName", "") or "").lower().strip()
        return _DISPLAY_TO_EXE.get(dn, "")

    @staticmethod
    def _proc_id(d: dict, prefix: str) -> str:
        """Identifiant de processus: cmdline ou displayName."""
        cmd = d.get(f"{prefix}.process.cmdline", "")
        if cmd:
            return cmd
        return d.get(f"{prefix}.process.displayName", "") or ""

    @staticmethod
    def _norm_cmd(s: str) -> str:
        """Normalise une cmdline pour comparaison (quotes, casse, espaces)."""
        return re.sub(r'\s+', ' ', (s or "").strip().strip('"').replace("\\\\", "\\")).lower()

    def _build(self):
        # Premiere passe : trouver le root (process dont le parent est dans LEGIT_PARENTS
        # Stratégie : le ROOT est le TGT d'un Process Creation dont le SRC est un
        # processus système légitime. C'est le processus "sujet" de la détection S1.
        # Fallback : le SRC le plus fréquent dans tous les événements.

        # Passe 1 : chercher le root via tgt.process (lancé depuis un parent légitime)
        for ev in self.events:
            if ev["event_type"] != "Process Creation":
                continue
            d = ev["details"]
            src_exe = self._exe_from_details(d, "src")
            if not src_exe or src_exe not in LEGIT_PARENTS:
                continue
            tgt_id = self._proc_id(d, "tgt")
            if not tgt_id:
                continue
            tgt_exe = self._exe_from_details(d, "tgt")
            # Le tgt ne doit pas lui-même être un processus système
            if tgt_exe in LEGIT_PARENTS:
                continue
            self.root = {
                "cmdline":        d.get("tgt.process.cmdline", "") or tgt_id,
                "display_name":   d.get("tgt.process.displayName", ""),
                "sha1":           d.get("tgt.process.image.sha1", ""),
                "signed":         d.get("tgt.process.signedStatus", ""),
                "publisher":      d.get("tgt.process.publisher", ""),
                "parent_cmdline": d.get("src.process.cmdline", "") or d.get("src.process.displayName", ""),
                "timestamp":      ev["timestamp_raw"],
            }
            break

        # Passe 2 : si pas trouvé, prendre le src.process le plus fréquent (hors système)
        if not self.root:
            src_counts = defaultdict(lambda: {"count": 0, "info": {}})
            for ev in self.events:
                d = ev["details"]
                src_id = self._proc_id(d, "src")
                if not src_id:
                    continue
                src_exe = self._exe_from_details(d, "src")
                if src_exe in LEGIT_PARENTS:
                    continue
                src_counts[src_id]["count"] += 1
                existing = src_counts[src_id]["info"]
                new_sha1 = d.get("src.process.image.sha1", "")
                # Toujours mettre à jour si on a de meilleures données
                if not existing or (new_sha1 and not existing.get("sha1")):
                    src_counts[src_id]["info"] = {
                        "cmdline":        d.get("src.process.cmdline", "") or src_id,
                        "display_name":   d.get("src.process.displayName", "") or (existing.get("display_name", "") if existing else ""),
                        "sha1":           new_sha1 or (existing.get("sha1", "") if existing else ""),
                        "signed":         d.get("src.process.signedStatus", "") or (existing.get("signed", "") if existing else ""),
                        "publisher":      d.get("src.process.publisher", "") or (existing.get("publisher", "") if existing else ""),
                        "parent_cmdline": d.get("src.process.parent.cmdline", "") or (existing.get("parent_cmdline", "") if existing else ""),
                        "timestamp":      ev["timestamp_raw"] or (existing.get("timestamp", "") if existing else ""),
                    }
            if src_counts:
                best = max(src_counts.values(), key=lambda x: x["count"])
                self.root = best["info"]

        # Passe 3 : enrichir root depuis les Process Creation (sha1/publisher/signed manquants)
        if self.root and not (self.root.get("sha1") and self.root.get("signed")):
            root_norm = self._norm_cmd(self.root.get("cmdline", ""))
            root_sha  = self.root.get("sha1", "")
            for ev in self.events:
                if ev["event_type"] != "Process Creation":
                    continue
                d = ev["details"]
                # Essayer tgt puis src — matching par cmdline normalisé OU par SHA1
                for pfx, pref_cmd, pref_sha in [
                    ("tgt", "tgt.process.cmdline", "tgt.process.image.sha1"),
                    ("src", "src.process.cmdline", "src.process.image.sha1"),
                ]:
                    cmd_norm = self._norm_cmd(d.get(pref_cmd, ""))
                    sha = d.get(pref_sha, "")
                    matched = (root_norm and cmd_norm and cmd_norm == root_norm) or \
                              (root_sha and sha and sha == root_sha)
                    if not matched:
                        continue
                    enriched = False
                    if d.get(f"{pfx}.process.image.sha1") and not self.root.get("sha1"):
                        self.root["sha1"] = d[f"{pfx}.process.image.sha1"]
                        enriched = True
                    if d.get(f"{pfx}.process.publisher") and not self.root.get("publisher"):
                        self.root["publisher"] = d[f"{pfx}.process.publisher"]
                        enriched = True
                    if d.get(f"{pfx}.process.signedStatus") and not self.root.get("signed"):
                        self.root["signed"] = d[f"{pfx}.process.signedStatus"]
                        enriched = True
                    if d.get(f"{pfx}.process.displayName") and not self.root.get("display_name"):
                        self.root["display_name"] = d[f"{pfx}.process.displayName"]
                    if enriched and self.root.get("sha1") and self.root.get("signed"):
                        break
                else:
                    continue
                break  # enrichissement complet

        # Passe 4 : enrichir root cmdline si trop court (script hosts sans arguments)
        # Cherche une cmdline plus complète dans d'autres types d'événements
        if self.root:
            root_cmd = (self.root.get("cmdline", "") or "").strip()
            _m = re.search(r'([^\s"\\/:]+\.exe)\b', root_cmd, re.IGNORECASE)
            root_exe = _m.group(1).lower() if _m else ""
            _script_hosts = ("wscript.exe", "cscript.exe", "mshta.exe",
                             "powershell.exe", "cmd.exe", "rundll32.exe")
            cmd_parts = root_cmd.replace('"', '').strip().split()
            if root_exe in _script_hosts or len(cmd_parts) <= 1:
                best_cmd = root_cmd
                for ev in self.events:
                    d = ev["details"]
                    for field in ("src.process.cmdline", "tgt.process.cmdline"):
                        cmd = (d.get(field, "") or "").strip()
                        if not cmd:
                            continue
                        _cm = re.search(r'([^\s"\\/:]+\.exe)\b', cmd, re.IGNORECASE)
                        if _cm and _cm.group(1).lower() == root_exe and len(cmd) > len(best_cmd):
                            best_cmd = cmd
                if len(best_cmd) > len(root_cmd):
                    self.root["cmdline"] = best_cmd

        # Enfants : tous les processus tgt.process.* des Process Creation
        seen = set()
        for ev in self.events:
            if ev["event_type"] != "Process Creation":
                continue
            d = ev["details"]
            tgt_cmd  = d.get("tgt.process.cmdline", "")
            tgt_name = d.get("tgt.process.displayName", "")
            key = (tgt_cmd or tgt_name)[:200]
            if not key or key in seen:
                continue
            seen.add(key)
            self.children[key] = {
                "cmdline":        tgt_cmd or tgt_name,
                "display_name":   tgt_name,
                "sha1":           d.get("tgt.process.image.sha1", ""),
                "signed":         d.get("tgt.process.signedStatus", ""),
                "publisher":      d.get("tgt.process.publisher", ""),
                "parent_cmdline": d.get("src.process.cmdline", "") or d.get("src.process.displayName", ""),
                "relation":       d.get("tgt.process.relation", ""),
                "timestamp":      ev["timestamp_raw"],
                "is_electron_child": any(f in (tgt_cmd or "") for f in ELECTRON_CHILD_FLAGS),
            }

    def get_root(self) -> dict:
        return self.root

    def get_children(self) -> list:
        return list(self.children.values())

    def get_full_parent_chain(self) -> list:
        """Retourne la chaine complete src.process.parent -> src.process -> processus analysé."""
        chain = []
        if not self.events:
            return chain
        # Prendre la chaine depuis le premier événement significatif
        for ev in self.events:
            d = ev["details"]
            os_src = d.get("osSrc.process.cmdline", "")
            os_src_parent = d.get("osSrc.process.parent.cmdline", "")
            src_parent = d.get("src.process.parent.cmdline", "")
            if os_src_parent:
                chain.append(("osSrc.parent", os_src_parent))
            if os_src:
                chain.append(("osSrc", os_src))
            if src_parent:
                chain.append(("src.parent", src_parent))
            if chain:
                break
        return chain

    def is_electron(self) -> bool:
        """Détecte l'architecture Chromium/Electron.
        Scan le details_raw directement car le parser coupe les valeurs aux '='.
        """
        # 1. Vérifier les enfants déjà parsés
        if any(c.get("is_electron_child") for c in self.children.values()):
            return True
        # 2. Scanner details_raw pour les flags Electron (plus fiable)
        electron_flags = ["--type=gpu-process", "--type=renderer",
                          "--type=crashpad-handler", "--type=utility",
                          "--type=broker", "--service-sandbox-type="]
        for ev in self.events:
            raw = ev.get("details_raw", "")
            if any(f in raw for f in electron_flags):
                return True
        return False

    def get_electron_meta(self) -> dict:
        """Extrait les métadonnées Electron depuis le crashpad-handler."""
        for c in self.children.values():
            cmd = c.get("cmdline", "") or ""
            if "--type=crashpad-handler" in cmd:
                meta = {}
                for field in ["_companyName", "_productName", "_version"]:
                    m = re.search(rf'--annotation={field}=(\S+)', cmd)
                    if m:
                        meta[field.strip("_")] = m.group(1)
                m = re.search(r'--annotation=ver=(\S+)', cmd)
                if m:
                    meta["electron_version"] = m.group(1)
                m = re.search(r'--annotation=prod=(\S+)', cmd)
                if m:
                    meta["framework"] = m.group(1)
                if meta:
                    return meta
        return {}

    def get_attack_vector(self) -> tuple:
        """Identifie si le processus parent est un vecteur d'attaque connu."""
        if not self.root:
            return None, None
        parent = (self.root.get("parent_cmdline", "") or "").lower()
        for exe, (severity, desc) in ATTACK_VECTOR_PARENTS.items():
            if exe in parent:
                return severity, desc
        return None, None

    def get_context_flags(self) -> dict:
        """Retourne les flags contextuels utilisés pour l'analyse des indicateurs."""
        return {
            "is_electron":   self.is_electron(),
            "is_signed":     self.root.get("signed") == "signed" if self.root else False,
            "publisher":     (self.root.get("publisher", "") or "").upper() if self.root else "",
            "parent_cmdline": (self.root.get("parent_cmdline", "") or "").lower() if self.root else "",
            "cmdline":       (self.root.get("cmdline", "") or "").lower() if self.root else "",
        }


class BehaviorAnalyzer:
    """Extrait et structure tous les indicateurs comportementaux."""

    def __init__(self, events: list):
        self.events = events
        self.all_indicators = []   # tous (avec doublons pour compter les occurrences)
        self.unique = []           # un par nom
        self._extract()

    def _extract(self):
        seen = set()
        for ev in self.events:
            if ev["event_type"] != "Behavioral Indicators":
                continue
            d = ev["details"]
            name     = d.get("indicator.name", "").strip()
            category = d.get("indicator.category", "Unknown").strip()
            desc     = d.get("indicator.description", "").strip()
            meta     = d.get("indicator.metadata", "").strip()
            src_cmd  = d.get("src.process.cmdline", "")

            if not name:
                continue

            ind = {
                "name":             name,
                "category":         category,
                "description":      desc,
                "metadata":         meta,
                "src_cmdline":      src_cmd,
                "timestamp":        ev["timestamp_raw"],
                "mitre_techniques": d.get("_mitre_techniques", []),
                "mitre_tactics":    d.get("_mitre_tactics", []),
            }
            self.all_indicators.append(ind)
            if name not in seen:
                seen.add(name)
                self.unique.append(ind)

    def get_unique(self) -> list:
        return self.unique

    def get_occurrence_count(self, name: str) -> int:
        return sum(1 for i in self.all_indicators if i["name"] == name)

    def get_categories(self) -> set:
        return {i["category"] for i in self.unique}

    def get_category_counts(self) -> dict:
        counts = defaultdict(int)
        for i in self.unique:
            counts[i["category"]] += 1
        return dict(counts)

    def get_all_techniques(self) -> list:
        seen = set()
        techs = []
        for ind in self.unique:
            for t in ind.get("mitre_techniques", []):
                if t["id"] not in seen:
                    seen.add(t["id"])
                    techs.append(t)
        return sorted(techs, key=lambda t: t["id"])

    def get_all_tactics(self) -> list:
        return sorted({t for i in self.unique for t in i.get("mitre_tactics", [])})

    def get_critical_indicators(self) -> list:
        """Retourne les indicateurs classifiés CRITIQUE dans INDICATOR_DB."""
        return [i for i in self.unique
                if INDICATOR_DB.get(i["name"], {}).get("severity") == "CRITIQUE"]


class NetworkAnalyzer:
    """Analyse les événements réseau avec corrélation DNS↔IP."""

    def __init__(self, events: list):
        self.events = events
        self.connections = []
        self.dns_queries = []
        self.listeners    = []
        self.http_requests = []
        self.dns_map      = {}   # domaine -> [ips]
        self.ip_to_domain = {}   # ip -> domaine
        self._extract()
        self._correlate_dns()

    def _extract(self):
        for ev in self.events:
            d  = ev["details"]
            et = ev["event_type"]

            if et == "IP Connect":
                self.connections.append({
                    "timestamp":  ev["timestamp_raw"],
                    "src_ip":     d.get("src.ip.address", ""),
                    "src_port":   d.get("src.port.number", ""),
                    "dst_ip":     d.get("dst.ip.address", ""),
                    "dst_port":   d.get("dst.port.number", ""),
                    "protocol":   d.get("event.network.protocolName", ""),
                    "direction":  d.get("event.network.direction", ""),
                    "status":     d.get("event.network.connectionStatus", ""),
                    "process":    d.get("src.process.cmdline", ""),
                })

            elif et in ("DNS Resolved", "DNS Unresolved"):
                self.dns_queries.append({
                    "timestamp": ev["timestamp_raw"],
                    "request":   d.get("event.dns.request", ""),
                    "response":  d.get("event.dns.response", ""),
                    "resolved":  et == "DNS Resolved",
                    "process":   d.get("src.process.cmdline", ""),
                })

            elif et == "IP Listen":
                self.listeners.append({
                    "timestamp": ev["timestamp_raw"],
                    "ip":        d.get("src.ip.address", ""),
                    "port":      d.get("src.port.number", ""),
                    "process":   d.get("src.process.cmdline", ""),
                })

            elif et in ("GET", "POST", "HTTP Request"):
                url = d.get("url.address", d.get("event.url.action", ""))
                ua  = d.get("event.network.http.requestHeaders.User-Agent",
                            d.get("http.request.headers.user-agent", ""))
                self.http_requests.append({
                    "timestamp":  ev["timestamp_raw"],
                    "method":     et,
                    "url":        url,
                    "user_agent": ua,
                    "process":    d.get("src.process.cmdline", ""),
                })

    def _correlate_dns(self):
        for q in self.dns_queries:
            if not q["resolved"] or not q["request"] or not q["response"]:
                continue
            domain = q["request"].rstrip(".")
            ips = [
                ip.strip().rstrip(";")
                for ip in q["response"].split(";")
                if ip.strip() and (
                    re.match(r'^\d+\.\d+\.\d+\.\d+$', ip.strip()) or  # IPv4
                    re.match(r'^[0-9a-fA-F:]{2,39}$', ip.strip())      # IPv6
                )
            ]
            if ips:
                self.dns_map[domain] = ips
                for ip in ips:
                    if ip not in self.ip_to_domain:
                        self.ip_to_domain[ip] = domain

    @staticmethod
    def is_private(ip: str) -> bool:
        if not ip:
            return False
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 169 and parts[1] == 254:
                return True
            if parts[0] == 127:
                return True
        except (ValueError, IndexError):
            pass
        return False

    def identify_ip(self, ip: str) -> str:
        """Identifie une IP : corrélation DNS > réseaux connus > privé > inconnu."""
        if not ip:
            return "N/A"
        if ip.startswith("127."):
            return "Localhost"
        if self.is_private(ip):
            return "Reseau interne (RFC1918)"

        # Corrélation DNS d'abord
        domain = self.ip_to_domain.get(ip)
        # Vérifier les réseaux connus
        for owner, prefixes in KNOWN_NETWORKS.items():
            if any(ip.startswith(p) for p in prefixes):
                if domain:
                    return f"{owner} [{domain}]"
                return owner
        # DNS seul sans réseau identifié
        if domain:
            return f"Domaine: {domain}"
        return "INCONNU - verification requise"

    def get_unique_external(self) -> list:
        seen = set()
        result = []
        for c in self.connections:
            dst = c["dst_ip"]
            if not dst or self.is_private(dst):
                continue
            key = f"{dst}:{c['dst_port']}"
            if key in seen:
                continue
            seen.add(key)
            result.append({
                **c,
                "owner": self.identify_ip(dst),
                "process_short": self._short(c["process"]),
            })
        return result

    def get_unique_internal(self) -> list:
        seen = set()
        result = []
        for c in self.connections:
            dst = c["dst_ip"]
            if not dst or not self.is_private(dst) or dst.startswith("127."):
                continue
            key = f"{dst}:{c['dst_port']}"
            if key in seen:
                continue
            seen.add(key)
            result.append({**c, "process_short": self._short(c["process"])})
        return result

    def get_localhost(self) -> list:
        return [c for c in self.connections if (c["dst_ip"] or "").startswith("127.")]

    def get_suspicious_external(self) -> list:
        """IPs externes non identifiées = nécessitent investigation."""
        return [d for d in self.get_unique_external()
                if "INCONNU" in d["owner"]]

    # Patterns User-Agent connus comme suspects
    _SUSPICIOUS_UA_PATTERNS = [
        (r"(?i)^python-requests/",     "MOYEN",   "python-requests UA: possible scripted/automated request (C2, dropper)"),
        (r"(?i)^go-http-client/",      "MOYEN",   "Go HTTP client UA: common in offensive Go tooling (Sliver, Mythic)"),
        (r"(?i)^curl/",                "MOYEN",   "curl UA: possible command-line download or C2 beacon"),
        (r"(?i)^powershell",           "ELEVE",   "PowerShell default UA: direct PS download (T1059.001)"),
        (r"(?i)^(microsoft|ms)-bitsow","MOYEN",   "BITS UA: possible BITS transfer abuse (T1197)"),
        (r"(?i)^mozilla/.*curl",       "ELEVE",   "Spoofed browser UA with curl characteristics: UA evasion"),
        (r"(?i)^-$|^\s*$",             "MOYEN",   "Empty or missing User-Agent: non-browser tool or custom C2"),
        (r"(?i)(metasploit|meterpreter|cobalt.strike|beacon)",
                                       "CRITIQUE","Known offensive framework string in User-Agent"),
    ]

    def get_suspicious_user_agents(self) -> list:
        """Retourne les User-Agents suspects détectés dans les requêtes HTTP."""
        results = []
        seen = set()
        for req in self.http_requests:
            ua = req.get("user_agent", "") or ""
            if not ua or ua in seen:
                continue
            for pattern, severity, desc in self._SUSPICIOUS_UA_PATTERNS:
                if re.search(pattern, ua):
                    seen.add(ua)
                    results.append({
                        "user_agent":  ua,
                        "severity":    severity,
                        "description": desc,
                        "url":         req["url"],
                        "timestamp":   req["timestamp"],
                    })
                    break
        return results

    def detect_c2_beacon(self, jitter_threshold: float = 0.15) -> list:
        """
        Détecte des patterns de beacon C2 par analyse des intervalles de connexion.
        Un beacon est caractérisé par des intervalles réguliers ± jitter.
        jitter_threshold : coefficient de variation max (0.15 = 15%)
        """
        from collections import defaultdict
        # Grouper les connexions par (dst_ip, dst_port)
        groups: dict = defaultdict(list)
        for c in self.connections:
            dst = c["dst_ip"]
            port = c["dst_port"]
            if not dst or self.is_private(dst):
                continue
            ts_raw = c["timestamp"]
            # Parser le timestamp
            ts = None
            for fmt in ("%b %d, %Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%d %H:%M:%S"):
                try:
                    ts = datetime.strptime(ts_raw.strip().strip('"'), fmt)
                    break
                except (ValueError, AttributeError):
                    continue
            if ts:
                groups[(dst, port)].append(ts)

        beacons = []
        for (dst, port), timestamps in groups.items():
            if len(timestamps) < 4:  # besoin d'au moins 4 connexions
                continue
            timestamps.sort()
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                         for i in range(len(timestamps) - 1)]
            if not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 5:  # ignorer les connexions très rapides (streaming)
                continue
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev  = variance ** 0.5
            cv = std_dev / mean_interval if mean_interval > 0 else 1.0  # coefficient de variation

            if cv <= jitter_threshold:
                beacons.append({
                    "dst_ip":          dst,
                    "dst_port":        port,
                    "owner":           self.identify_ip(dst),
                    "count":           len(timestamps),
                    "mean_interval_s": round(mean_interval, 1),
                    "std_dev_s":       round(std_dev, 1),
                    "cv":              round(cv, 3),
                    "first_seen":      timestamps[0].strftime("%H:%M:%S"),
                    "last_seen":       timestamps[-1].strftime("%H:%M:%S"),
                })
        return sorted(beacons, key=lambda x: x["cv"])

    @staticmethod
    def _short(cmd: str) -> str:
        if not cmd:
            return ""
        return Path(cmd.replace('"', '').split()[0]).name if cmd else ""


class FileAnalyzer:
    """Analyse l'activité fichier pour détecter des patterns suspects."""

    def __init__(self, events: list):
        self.events = events
        self.operations = defaultdict(list)
        self._extract()

    def _extract(self):
        for ev in self.events:
            if ev["event_type"] not in ("File Creation", "File Deletion",
                                         "File Rename", "File Modification"):
                continue
            d = ev["details"]
            self.operations[ev["event_type"]].append({
                "timestamp": ev["timestamp_raw"],
                "path":      d.get("tgt.file.path", ""),
                "old_path":  d.get("tgt.file.oldPath", ""),
                "sha1":      d.get("tgt.file.sha1", ""),
                "size":      d.get("tgt.file.size", ""),
                "desc":      d.get("tgt.file.description", ""),
                "internal":  d.get("tgt.file.internalName", ""),
            })

    def get_summary(self) -> dict:
        return {op: len(files) for op, files in self.operations.items()}

    def get_top_dirs(self, n: int = 10) -> dict:
        dirs = defaultdict(int)
        for files in self.operations.values():
            for f in files:
                p = f["path"]
                if p:
                    try:
                        dirs[str(Path(p).parent)] += 1
                    except Exception:
                        pass
        return dict(sorted(dirs.items(), key=lambda x: -x[1])[:n])

    def get_suspicious_files(self) -> list:
        SUSPECT_PATTERNS = [
            r"\\[Tt]emp\\[^\\]*\.(exe|dll|bat|vbs|ps1|lnk)$",
            r"\\[Tt]emp\\[^\\]+\.(exe|dll)$",
            r"\\[Ss]tartup\\.*\.(exe|dll|bat|vbs|ps1|lnk)$",
            r"\\[Dd]ownloads\\[^\\]*\.(exe|dll)$",
            r"\\[Pp]rogram[Dd]ata\\[^\\]*\.(exe|dll)$",
            r"\\[Ww]indows\\[Tt]emp\\.*\.ps1$",
            r"\\[Uu]sers\\[^\\]+\\[Aa]pp[Dd]ata\\[Rr]oaming\\[^\\]+\.(exe|dll)$",
        ]
        EXCLUDE_PATTERNS = [
            r"\\[Tt]emp\\[^\\]+\\.*\\.*\.",    # sous-dossiers dans temp (PyInstaller)
            r"\\deactivate\.ps1$",
            r"\\[Aa]ctivate\.ps1$",
            r"\\\.[a-z]+\\tasks\\",   # dev tool task dirs
            r"\\_MEI\d+\\",
            r"\\jedilsp\\",
            r"\\python_files\\",
            r"\\node_modules\\",
            r"\\__pycache__\\",
        ]
        seen = {}  # path -> sha1
        for files in self.operations.values():
            for f in files:
                p = f["path"]
                if not p:
                    continue
                if (any(re.search(pat, p, re.I) for pat in SUSPECT_PATTERNS) and
                        not any(re.search(exc, p, re.I) for exc in EXCLUDE_PATTERNS)):
                    sha1 = f.get("sha1", "") or ""
                    if p not in seen or (not seen[p] and sha1):
                        seen[p] = sha1
        return [{"path": p, "sha1": sha1} for p, sha1 in seen.items()]

    def is_build_activity(self) -> bool:
        """Détecte une activité de build/compilation basée sur les répertoires actifs."""
        dirs = self.get_top_dirs(20)
        markers = ["_MEI", "node_modules", "dist\\", "build\\",
                   "__pycache__", ".git\\", "target\\", ".rustup",
                   "site-packages", "\\Scripts\\", "jedilsp", "typeshed"]
        return sum(1 for d in dirs if any(m in d for m in markers)) >= 2

    def detect_mass_operation(self) -> tuple:
        """Détecte des opérations massives de fichiers (pattern ransomware)."""
        creations = len(self.operations.get("File Creation", []))
        deletions = len(self.operations.get("File Deletion", []))
        if creations > 200 and deletions > 200:
            ratio = min(creations, deletions) / max(creations, deletions)
            if ratio > 0.5:
                return True, creations, deletions
        return False, creations, deletions


class RegistryAnalyzer:
    """Analyse les modifications de registre pour détecter persistance et tampering."""

    def __init__(self, events: list):
        self.events = events
        self.mods = []
        self._extract()

    def _extract(self):
        for ev in self.events:
            if "Registry" not in ev["event_type"]:
                continue
            d = ev["details"]
            self.mods.append({
                "timestamp": ev["timestamp_raw"],
                "type":      ev["event_type"],
                "key":       d.get("registry.keyPath", ""),
                "value":     d.get("registry.value", ""),
                "old_value": d.get("registry.oldValue", ""),
            })

    def get_summary(self) -> dict:
        keys = defaultdict(int)
        for m in self.mods:
            parts = m["key"].split("\\")
            short_key = "\\".join(parts[:4]) if len(parts) > 4 else m["key"]
            keys[short_key] += 1
        return dict(sorted(keys.items(), key=lambda x: -x[1])[:10])

    def get_persistence_hits(self) -> list:
        """Retourne les clés de registre correspondant à des mécanismes de persistance."""
        hits = []
        for m in self.mods:
            for pattern, label in PERSISTENCE_REG_PATTERNS:
                if re.search(pattern, m["key"], re.I):
                    hits.append({
                        "type":  m["type"],
                        "key":   m["key"],
                        "value": m["value"],
                        "label": label,
                    })
                    break
        return hits


class ScriptAnalyzer:
    """Analyse le contenu des scripts exécutés (cmdScript.content)."""

    def __init__(self, events: list):
        self.events = events
        self.scripts = []
        self.findings = []
        self._extract()

    def _extract(self):
        seen_hashes = set()
        for ev in self.events:
            if ev["event_type"] not in ("Command Script", "Pre Execution Detection"):
                continue
            d    = ev["details"]
            content = d.get("cmdScript.content", "")
            app  = d.get("cmdScript.applicationName", "")
            if not content:
                continue
            h = hash(content[:2000])
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            self.scripts.append({
                "timestamp":  ev["timestamp_raw"],
                "app":        app,
                "content":    content,
                "content_short": content[:5000],
            })

    def analyze(self) -> list:
        """Analyse tous les scripts et retourne les findings suspects."""
        if self.findings:
            return self.findings

        # Patterns de contenu à exclure (FP connus : scripts IDE, activation venv, etc.)
        SCRIPT_FP_PATTERNS = [
            r"__VSCodeState",           # VS Code shell integration
            r"_VSCode",                 # VS Code shell scripts
            r"VSCODE_SHELL",            # VS Code shell variables
            r"\$activateScript",        # Python venv activation via IDE
            r"deactivate\.ps1",         # venv deactivation
            r"conda.*activate",         # conda activation
            r"RefreshEnv\.cmd",         # Chocolatey refresh
        ]

        for script in self.scripts:
            content = script["content"]
            # Exclure les scripts IDE connus (FP)
            is_ide_fp = any(re.search(p, content, re.I) for p in SCRIPT_FP_PATTERNS)
            for pattern, severity, description, mitre in SCRIPT_PATTERNS:
                m = re.search(pattern, content)
                if m and is_ide_fp and severity != "CRITIQUE":
                    continue  # Skip non-critical patterns in IDE scripts
                if m and is_ide_fp and description == (
                    "Invoke-Expression: dynamic code execution (T1059.001)"
                ):
                    continue  # IEX in VS Code shell integration = FP
                if m:
                    # Extraire le contexte (500 chars autour du match)
                    start = max(0, m.start() - 500)
                    end   = min(len(content), m.end() + 2000)
                    context = content[start:end].replace("\n", " ").replace("\r", "")
                    self.findings.append({
                        "severity":    severity,
                        "description": description,
                        "mitre":       mitre,
                        "context":     context,
                        "script_app":  script["app"],
                        "timestamp":   script["timestamp"],
                    })

        # Dédupliquer par description
        seen_desc = set()
        deduped = []
        for f in self.findings:
            if f["description"] not in seen_desc:
                seen_desc.add(f["description"])
                deduped.append(f)
        self.findings = deduped
        return self.findings

    def get_all_scripts_summary(self) -> list:
        """Résumé des scripts : application + extrait."""
        return [{
            "app":     s["app"],
            "preview": s["content_short"][:5000],
            "length":  len(s["content"]),
        } for s in self.scripts]


class ModuleAnalyzer:
    """Analyse les DLLs chargées pour détecter des comportements suspects."""

    def __init__(self, events: list):
        self.events = events
        self.modules = []
        self._extract()

    def _extract(self):
        seen = set()
        for ev in self.events:
            if ev["event_type"] != "Module Load":
                continue
            d    = ev["details"]
            path = d.get("module.path", d.get("tgt.file.path", ""))
            sha1 = d.get("module.sha1", "")
            if not path or path in seen:
                continue
            seen.add(path)
            self.modules.append({
                "timestamp": ev["timestamp_raw"],
                "path":      path,
                "sha1":      sha1,
                "name":      Path(path).name.lower() if path else "",
            })

    def get_suspicious(self) -> list:
        """Retourne les DLLs suspectes selon SUSPICIOUS_MODULES."""
        results = []
        for mod in self.modules:
            name = mod["name"]
            if name in SUSPICIOUS_MODULES:
                severity, desc = SUSPICIOUS_MODULES[name]
                results.append({
                    "path":      mod["path"],
                    "name":      name,
                    "severity":  severity,
                    "analysis":  desc,
                    "timestamp": mod["timestamp"],
                })
        return results

    def get_summary(self) -> dict:
        return {"total_modules": len(self.modules)}


class TaskAnalyzer:
    """Analyse les tâches planifiées (Task Trigger / Task Delete)."""

    def __init__(self, events: list):
        self.events = events
        self.tasks = []
        self._extract()

    def _extract(self):
        for ev in self.events:
            if ev["event_type"] not in ("Task Trigger", "Task Delete", "Task Create"):
                continue
            d = ev["details"]
            self.tasks.append({
                "timestamp":   ev["timestamp_raw"],
                "event_type":  ev["event_type"],
                "task_name":   d.get("task.name", d.get("task", "")),
                "task_path":   d.get("task.path", ""),
            })

    def get_all(self) -> list:
        return self.tasks

    def has_suspicious_tasks(self) -> list:
        """Retourne les tâches dont le nom ou chemin est suspect."""
        suspects = []
        SUSPECT_TASK_PATTERNS = [
            r"\\[Tt]emp\\", r"\\[Aa]pp[Dd]ata\\[Rr]oaming\\",
            r"\\[Pp]ublic\\", r"update.*task|task.*update",
            r"[A-Za-z0-9]{15,}",   # noms très longs et aléatoires
        ]
        for t in self.tasks:
            path = t["task_name"] + " " + t["task_path"]
            if any(re.search(p, path, re.I) for p in SUSPECT_TASK_PATTERNS):
                suspects.append(t)
        return suspects


class LsassAnalyzer:
    """Détecte les tentatives d'accès à LSASS (credential dumping)."""

    LSASS_NAMES = {"lsass.exe", "lsass"}

    def __init__(self, events: list):
        self.events = events
        self.hits: list = []
        self._extract()

    def _extract(self):
        for ev in self.events:
            et = ev["event_type"]
            d  = ev["details"]

            # Événements d'accès à des handles de processus distants
            if et in ("Open Remote Process Handle", "Duplicate Process Handle",
                      "Duplicate Thread Handle"):
                tgt_cmd = (d.get("tgt.process.cmdline", "") or
                           d.get("tgt.process.displayName", "") or "").lower()
                tgt_parts = tgt_cmd.replace('"', '').split()
                tgt_name = Path(tgt_parts[0]).name.lower() if tgt_parts else ""
                if tgt_name in self.LSASS_NAMES or "lsass" in tgt_cmd:
                    self.hits.append({
                        "timestamp":  ev["timestamp_raw"],
                        "event_type": et,
                        "src_cmd":    d.get("src.process.cmdline", ""),
                        "tgt_cmd":    tgt_cmd,
                        "access":     d.get("tgt.process.accessRights", ""),
                    })

            # Indicateur comportemental direct
            elif et == "Behavioral Indicators":
                name = d.get("indicator.name", "")
                if "lsass" in name.lower() or "credential" in name.lower():
                    self.hits.append({
                        "timestamp":  ev["timestamp_raw"],
                        "event_type": "BehavioralIndicator",
                        "src_cmd":    d.get("src.process.cmdline", ""),
                        "tgt_cmd":    "",
                        "access":     name,
                    })

    def get_hits(self) -> list:
        return self.hits

    def has_lsass_access(self) -> bool:
        return bool(self.hits)


class CmdlineAnalyzer:
    """Analyse heuristique des lignes de commande pour détecter des patterns suspects."""

    # Patterns suspects dans les command lines (regex, severity, description, mitre)
    CMDLINE_PATTERNS = [
        (r"(?i)[A-Za-z0-9+/]{60,}={0,2}",
         "ELEVE", "Long Base64-like string in command line (possible inline payload)", "T1027"),
        (r"(?i)\\(temp|tmp|appdata|programdata)\\[^\\]+\.(exe|dll|bat|ps1|vbs|lnk)\"?\s",
         "ELEVE", "Executable launched from suspicious path (Temp/AppData/ProgramData)", "T1059"),
        (r"(?i)\.[a-z]{2,4}\.[a-z]{2,4}($|\s)",
         "MOYEN", "Double extension detected (masquerading technique)", "T1036.007"),
        (r"(?i)(hidden|windowstyle\s+h|sw_hide)",
         "MOYEN", "Hidden window execution in command line", "T1564.003"),
        (r"(?i)(downloadstring|downloadfile|webclient|invoke-webrequest|wget|curl).*http",
         "CRITIQUE", "Download command in command line (possible dropper/stager)", "T1105"),
        (r"(?i)(-enc|-encodedcommand)\s+[A-Za-z0-9+/]{20,}",
         "ELEVE", "Encoded PowerShell command in command line", "T1027"),
        (r"(?i)(bypass|unrestricted)\s*(executionpolicy|ep)",
         "ELEVE", "PowerShell execution policy bypass in command line", "T1059.001"),
        (r"(?i)(net\s+user|net\s+group|net\s+localgroup)\s+.*\/add",
         "CRITIQUE", "User/group creation via net command (possible persistence/privilege)", "T1136"),
        (r"(?i)reg\s+(add|delete|export|import)\s+hk",
         "MOYEN", "Registry modification via reg.exe command line", "T1112"),
        (r"(?i)(sc\s+(create|config|start|stop)|sc\.exe)",
         "MOYEN", "Service manipulation via sc.exe command line", "T1543.003"),
    ]

    # Seuil d'entropie suspect pour les noms de fichiers exécutables
    ENTROPY_THRESHOLD = 4.2

    def __init__(self, events: list):
        self.events = events
        self.cmdline_findings: list = []
        self.high_entropy_procs: list = []
        self._analyze()

    def _analyze(self):
        seen_patterns: set = set()
        seen_entropy: set = set()

        for ev in self.events:
            d = ev["details"]
            for field in ("src.process.cmdline", "tgt.process.cmdline",
                          "src.process.parent.cmdline"):
                cmdline = d.get(field, "") or ""
                if not cmdline:
                    continue

                # Pattern matching
                for pattern, severity, description, mitre in self.CMDLINE_PATTERNS:
                    key = (pattern, cmdline[:80])
                    if key in seen_patterns:
                        continue
                    m = re.search(pattern, cmdline)
                    if m:
                        seen_patterns.add(key)
                        ctx_start = max(0, m.start() - 20)
                        ctx_end   = min(len(cmdline), m.end() + 40)
                        self.cmdline_findings.append({
                            "severity":    severity,
                            "description": description,
                            "mitre":       mitre,
                            "context":     cmdline[ctx_start:ctx_end],
                            "field":       field,
                            "timestamp":   ev["timestamp_raw"],
                        })

                # Entropie du nom d'exécutable
                parts = cmdline.replace('"', '').split()
                if parts:
                    exe_name = Path(parts[0]).stem
                    if len(exe_name) >= 6 and exe_name not in seen_entropy:
                        entropy = _shannon_entropy(exe_name)
                        if entropy >= self.ENTROPY_THRESHOLD:
                            seen_entropy.add(exe_name)
                            self.high_entropy_procs.append({
                                "name":      exe_name,
                                "entropy":   round(entropy, 2),
                                "cmdline":   cmdline[:500],
                                "timestamp": ev["timestamp_raw"],
                            })

    def get_findings(self) -> list:
        # Dédupliquer par description
        seen = set()
        result = []
        for f in self.cmdline_findings:
            if f["description"] not in seen:
                seen.add(f["description"])
                result.append(f)
        return result

    def get_high_entropy_procs(self) -> list:
        return sorted(self.high_entropy_procs, key=lambda x: -x["entropy"])


class TemporalCorrelationAnalyzer:
    """Détecte des séquences d'attaque temporelles (indicateurs ordonnés dans le temps)."""

    # Séquences suspectes : liste de (catégories ordonnées, fenêtre max en secondes, description)
    TEMPORAL_SEQUENCES = [
        (["Discovery", "Persistence"],       300,
         "Discovery followed by Persistence in <5min: rapid foothold establishment"),
        (["Discovery", "InfoStealer"],       600,
         "Discovery followed by credential theft in <10min: active post-compromise"),
        (["Evasion", "InfoStealer"],         120,
         "Defense evasion immediately before credential theft: deliberate bypass"),
        (["Evasion", "Persistence"],         300,
         "Defense evasion followed by Persistence: durable stealthy implant"),
        (["InfoStealer", "Discovery"],        60,
         "Credential theft then immediate reconnaissance: classic pivot preparation"),
        (["Persistence", "Evasion"],         180,
         "Persistence then cover tracks: attacker hiding installed implant"),
        (["Injection", "InfoStealer"],       300,
         "Code injection followed by credential theft: injected infostealer pattern"),
        (["Direct Syscall", "Injection"],    120,
         "EDR bypass (direct syscall) then injection: sophisticated offensive tooling"),
    ]

    def __init__(self, behav: "BehaviorAnalyzer"):
        self.behav = behav
        self._sequences: list = []
        self._analyze()

    def _analyze(self):
        # Construire la liste (timestamp, category, name) pour les indicateurs TP avec timestamp
        timed = []
        for ind in self.behav.get_unique():
            ts_raw = ind.get("timestamp", "")
            if not ts_raw:
                continue
            # Parser le timestamp
            ts = None
            for fmt in ("%b %d, %Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%d %H:%M:%S"):
                try:
                    ts = datetime.strptime(ts_raw.strip().strip('"'), fmt)
                    break
                except ValueError:
                    continue
            if ts:
                timed.append((ts, ind["category"], ind["name"]))

        if not timed:
            return

        timed.sort(key=lambda x: x[0])

        for seq_cats, window_sec, description in self.TEMPORAL_SEQUENCES:
            cat_a, cat_b = seq_cats[0], seq_cats[1]
            # Trouver les timestamps de chaque catégorie
            times_a = [t for t, c, _ in timed if c == cat_a]
            times_b = [t for t, c, _ in timed if c == cat_b]
            for ta in times_a:
                for tb in times_b:
                    delta = (tb - ta).total_seconds()
                    if 0 < delta <= window_sec:
                        self._sequences.append({
                            "description": description,
                            "cat_a":       cat_a,
                            "cat_b":       cat_b,
                            "delta_sec":   int(delta),
                            "window_sec":  window_sec,
                        })
                        break  # une seule correspondance par paire (cat_a, cat_b)
                else:
                    continue
                break

    def get_sequences(self) -> list:
        # Dédupliquer par description
        seen = set()
        result = []
        for s in self._sequences:
            if s["description"] not in seen:
                seen.add(s["description"])
                result.append(s)
        return result


# ===========================================================================
# PHASE 1 — MITRE ATT&CK ENRICHER (mitreattack-python)
# ===========================================================================

class MitreAttackEnricher:
    """
    Enrichit les techniques ATT&CK : guidance détection, mitigations, groupes APT.
    Nécessite : pip install mitreattack-python  +  --update (bundle ATT&CK)
    """

    def __init__(self):
        self._data    = None
        self._ok      = False
        self._load()

    def _load(self):
        if not HAS_MITRE_LIB:
            return
        if not ATTACK_BUNDLE.exists():
            return
        try:
            self._data = _MitreData(str(ATTACK_BUNDLE))
            self._ok   = True
        except Exception:
            pass

    @property
    def available(self) -> bool:
        return self._ok

    def get_technique_info(self, tid: str) -> dict:
        """Guidance détection, mitigations et groupes pour un TID (ex: T1055)."""
        if not self._ok:
            return {}
        try:
            results = [t for t in self._data.get_techniques(remove_revoked_deprecated=True)
                       if any(r.get("external_id") == tid
                              for r in t.get("external_references", []))]
            if not results:
                return {}
            tech = results[0]
            detection   = tech.get("x_mitre_detection", "")
            data_srcs   = tech.get("x_mitre_data_sources", [])
            # kill_chain_phases are KillChainPhase objects, use .phase_name
            _phases = tech.get("kill_chain_phases", [])
            tactics = []
            for p in _phases:
                pn = getattr(p, "phase_name", None) or (p.get("phase_name") if isinstance(p, dict) else "")
                if pn:
                    tactics.append(pn)
            tactic = ", ".join(tactics) if tactics else ""
            # Mitigations — library returns {"object": CoA, "relationships": [...]}
            mits = []
            try:
                for m in self._data.get_mitigations_mitigating_technique(tech["id"])[:5]:
                    mobj = m["object"] if isinstance(m, dict) and "object" in m else m
                    mid = next((r["external_id"] for r in mobj.get("external_references", [])
                                if r.get("source_name") == "mitre-attack"), "")
                    mname = mobj.get("name", "")
                    if mid or mname:
                        mits.append({"id": mid, "name": mname})
            except Exception:
                pass
            # Groups — library returns {"object": IntrusionSet, "relationships": [...]}
            groups = []
            try:
                for g in self._data.get_groups_using_technique(tech["id"])[:5]:
                    gobj = g["object"] if isinstance(g, dict) and "object" in g else g
                    gid = next((r["external_id"] for r in gobj.get("external_references", [])
                                if r.get("source_name") == "mitre-attack"), "")
                    gname = gobj.get("name", "")
                    if gid or gname:
                        groups.append({"id": gid, "name": gname})
            except Exception:
                pass
            return {
                "name":         tech.get("name", ""),
                "tactic":       tactic,
                "tactics":      tactics,
                "detection":    detection[:500] if detection else "",
                "mitigations":  mits,
                "groups":       groups,
                "data_sources": data_srcs[:5],
            }
        except Exception:
            return {}

    def get_groups_for_techniques(self, tids: list) -> list:
        seen, result = set(), []
        for tid in tids:
            for g in self.get_technique_info(tid).get("groups", []):
                if g["id"] not in seen:
                    seen.add(g["id"])
                    result.append(g)
        return result

    def generate_navigator_layer(self, technique_ids: list, score_map: dict = None) -> dict:
        """Génère un layer ATT&CK Navigator JSON."""
        techniques = []
        for tid in set(technique_ids):
            techniques.append({
                "techniqueID": tid,
                "score":       (score_map or {}).get(tid, 1),
                "color":       "",
                "comment":     "Detected by s1_analyzer",
                "enabled":     True,
            })
        return {
            "name": "S1 Analyzer Detection",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Auto-generated by s1_analyzer",
            "filters": {"platforms": ["Windows"]},
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 10},
            "legendItems": [],
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
        }


# ===========================================================================
# PHASE 2 — SIGMA RULE EVALUATOR (custom YAML, no pySigma required)
# ===========================================================================

class SigmaEvaluator:
    """
    Évalue les règles Sigma communautaires contre les events S1 parsés.
    Nécessite : pip install pyyaml  +  --update (télécharge les règles SigmaHQ)
    """

    # Catégories Sigma → types d'events S1
    CATEGORY_MAP: dict = {
        "process_creation":    {"Process Creation"},
        "registry":            {"Registry Value Modified", "Registry Key Created",
                                "Registry Key Deleted", "Registry Value Deleted"},
        "registry_add":        {"Registry Key Created"},
        "registry_delete":     {"Registry Key Deleted", "Registry Value Deleted"},
        "registry_set":        {"Registry Value Modified"},
        "registry_event":      {"Registry Value Modified", "Registry Key Created",
                                "Registry Key Deleted", "Registry Value Deleted"},
        "network_connection":  {"IP Connect", "DNS Resolved", "DNS Unresolved"},
        "dns_query":           {"DNS Resolved", "DNS Unresolved"},
        "file":                {"File Creation", "File Deletion",
                                "File Modification", "File Rename"},
        "file_event":          {"File Creation", "File Deletion",
                                "File Modification", "File Rename"},
        "image_load":          {"Module Load"},
        "driver_load":         {"Module Load"},
        "powershell":          {"Command Script", "Pre Execution Detection"},
        "powershell_classic":  {"Command Script"},
        "powershell_module":   {"Module Load"},
        "powershell_script":   {"Command Script"},
        "ps_script":           {"Command Script"},
        "ps_module":           {"Module Load"},
        "create_remote_thread": {"Duplicate Process Handle", "Open Remote Process Handle"},
        "process_access":      {"Open Remote Process Handle", "Duplicate Process Handle"},
        "create_stream_hash":  {"File Creation"},
        "pipe_created":        {"File Creation"},
        "sysmon":              set(),  # pas d'événement S1 direct
        "wmi_event":           set(),
        "builtin":             set(),  # règles Windows Event Log — non applicable
        "process_tampering":   {"Open Remote Process Handle"},
        "raw_access_thread":   {"Open Remote Process Handle"},
    }

    # Champs S1 → nom Sigma standard
    FIELD_MAP: dict = {
        "src.process.cmdline":        "CommandLine",
        "tgt.process.cmdline":        "CommandLine",
        "src.process.image.path":     "Image",
        "tgt.process.image.path":     "Image",
        "src.process.displayName":    "Description",
        "tgt.process.displayName":    "Description",
        "src.process.parent.cmdline": "ParentCommandLine",
        "src.process.publisher":      "Company",
        "tgt.process.publisher":      "Company",
        "tgt.file.path":              "TargetFilename",
        "registry.keyPath":           "TargetObject",
        "registry.value":             "Details",
        "event.dns.request":          "QueryName",
        "dst.ip.address":             "DestinationIp",
        "dst.port.number":            "DestinationPort",
        "module.path":                "ImageLoaded",
        "src.process.image.sha256":   "Hashes",
        "tgt.process.image.sha256":   "Hashes",
    }

    def __init__(self):
        self._rules: list = []
        self._load()

    def _load(self):
        if not HAS_YAML or not SIGMA_DIR.exists():
            return
        for yf in SIGMA_DIR.rglob("*.yml"):
            try:
                with open(yf, encoding="utf-8", errors="replace") as f:
                    rule = _yaml.safe_load(f)
                if not isinstance(rule, dict):
                    continue
                if rule.get("status") in ("deprecated", "unsupported"):
                    continue
                if not rule.get("detection"):
                    continue
                rule["_cat"]  = yf.parent.name
                rule["_path"] = str(yf)
                self._rules.append(rule)
            except Exception:
                continue

    @property
    def available(self) -> bool:
        return bool(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    # ---- internal evaluation helpers ----

    def _norm(self, ev: dict) -> dict:
        d    = ev["details"]
        norm = {"_etype": ev["event_type"]}
        for s1f, sf in self.FIELD_MAP.items():
            v = d.get(s1f, "")
            if v:
                norm[sf]          = v
                norm[sf.lower()]  = v
        return norm

    def _fval(self, norm: dict, field: str) -> str:
        return str(norm.get(field) or norm.get(field.lower()) or "")

    def _match_val(self, actual: str, expected: str, mods: list) -> bool:
        al = actual.lower()
        el = str(expected).lower()
        if "re" in mods:
            try:
                return bool(re.search(str(expected), actual, re.I))
            except re.error:
                return False
        if "contains" in mods:
            return el in al
        if "startswith" in mods:
            return al.startswith(el)
        if "endswith" in mods:
            return al.endswith(el)
        if "*" in el or "?" in el:
            pat = re.escape(el).replace(r"\*", ".*").replace(r"\?", ".")
            return bool(re.fullmatch(pat, al))
        return al == el

    def _eval_item(self, field: str, raw_val, norm: dict) -> bool:
        parts     = field.split("|")
        fname     = parts[0]
        mods      = [m.lower() for m in parts[1:]]
        # Special: keywords = full-text search
        if fname == "keywords":
            vals = raw_val if isinstance(raw_val, list) else [raw_val]
            alltext = " ".join(str(v) for v in norm.values()).lower()
            return any(str(v).lower() in alltext for v in vals)
        actual = self._fval(norm, fname)
        vals   = raw_val if isinstance(raw_val, list) else [raw_val]
        if "all" in mods:
            return all(self._match_val(actual, v, mods) for v in vals)
        return any(self._match_val(actual, v, mods) for v in vals)

    def _eval_block(self, block, norm: dict) -> bool:
        if isinstance(block, list):
            return any(self._eval_block(b, norm) for b in block)
        if not isinstance(block, dict):
            return False
        return all(self._eval_item(f, v, norm) for f, v in block.items())

    def _eval_cond(self, cond: str, named: dict) -> bool:
        cond = cond.strip()
        # "N of selection*"
        m = re.match(r'^(\d+)\s+of\s+(\S+)$', cond)
        if m:
            n   = int(m.group(1))
            pfx = m.group(2).rstrip("*")
            return sum(1 for k, v in named.items() if k.startswith(pfx) and v) >= n
        if re.match(r'^all\s+of\s+them$', cond, re.I):
            return all(named.values())
        if re.match(r'^1\s+of\s+them$', cond, re.I):
            return any(named.values())
        m2 = re.match(r'^all\s+of\s+(\S+)$', cond, re.I)
        if m2:
            pfx     = m2.group(1).rstrip("*")
            matches = [v for k, v in named.items() if k.startswith(pfx)]
            return all(matches) if matches else False
        # Tokenize for and/or/not
        tokens = re.split(r'(\s+|\(|\))', cond)
        expr   = []
        for tok in tokens:
            tok = tok.strip()
            if not tok:
                continue
            tl = tok.lower()
            if tl in ("and", "or", "not", "(", ")"):
                expr.append(tl)
            else:
                ref = tok.rstrip("*")
                if "*" in tok:
                    val = any(v for k, v in named.items() if k.startswith(ref))
                else:
                    val = named.get(tok, False)
                expr.append("True" if val else "False")
        try:
            return bool(eval(" ".join(expr)))
        except Exception:
            return False

    def evaluate_event(self, ev: dict) -> list:
        if not self._rules:
            return []
        etype = ev["event_type"]
        norm  = self._norm(ev)
        hits  = []
        for rule in self._rules:
            cat          = rule.get("_cat", "")
            relevant_ets = self.CATEGORY_MAP.get(cat, set())
            if relevant_ets and etype not in relevant_ets:
                continue
            detection = rule.get("detection", {})
            condition  = detection.get("condition", "selection")
            named      = {}
            for name, block in detection.items():
                if name in ("condition", "timeframe"):
                    continue
                named[name] = self._eval_block(block, norm)
            if not named:
                continue
            try:
                matched = self._eval_cond(condition, named)
            except Exception:
                continue
            if matched:
                lvl  = rule.get("level", "medium").upper()
                tags = rule.get("tags", []) or []
                mitre = [t.replace("attack.", "").upper()
                         for t in tags if t.lower().startswith("attack.t")]
                hits.append({
                    "title":       rule.get("title", "Unknown"),
                    "description": rule.get("description", ""),
                    "level":       lvl,
                    "mitre":       mitre,
                    "category":    cat,
                    "tags":        tags,
                })
        return hits

    def evaluate_all(self, events: list) -> list:
        """Évalue toutes les règles contre tous les events. Retourne les hits dédupliqués."""
        seen, all_hits = set(), []
        for ev in events:
            for hit in self.evaluate_event(ev):
                key = hit["title"]
                if key not in seen:
                    seen.add(key)
                    hit["timestamp"] = ev["timestamp_raw"]
                    all_hits.append(hit)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        all_hits.sort(key=lambda h: order.get(h["level"], 5))
        return all_hits


# ===========================================================================
# PHASE 3 — PROCESS GRAPH ANALYZER (NetworkX)
# ===========================================================================

class ProcessGraphAnalyzer:
    """
    Analyse l'arbre de processus comme graphe dirigé.
    Détecte cycles (injection), profondeur excessive, spawning anormal, centralité.
    Nécessite : pip install networkx
    """

    DEGREE_THRESHOLD = 8
    DEPTH_THRESHOLD  = 6

    def __init__(self, events: list):
        self.events     = events
        self._G         = None
        self._anomalies: list = []
        self._build()

    def _build(self):
        if not HAS_NX:
            return
        G = _nx.DiGraph()
        for ev in self.events:
            if ev["event_type"] != "Process Creation":
                continue
            d    = ev["details"]
            src  = (d.get("src.process.cmdline","") or
                    d.get("src.process.displayName","") or "").replace('"','')
            tgt  = (d.get("tgt.process.cmdline","") or
                    d.get("tgt.process.displayName","") or "").replace('"','')
            src_n = Path(src.split()[0]).name.lower() if src.split() else src[:30]
            tgt_n = Path(tgt.split()[0]).name.lower() if tgt.split() else tgt[:30]
            if not src_n or not tgt_n or src_n == tgt_n:
                continue
            G.add_edge(src_n, tgt_n, ts=ev["timestamp"])
        self._G = G
        self._detect()

    def _detect(self):
        G = self._G
        if not G or not G.nodes():
            return

        # 1. High out-degree
        for node, deg in G.out_degree():
            if deg >= self.DEGREE_THRESHOLD:
                self._anomalies.append({
                    "type": "HIGH_SPAWN", "severity": "ELEVE",
                    "description": (
                        f"'{node}' spawned {deg} child processes "
                        f"(\u2265{self.DEGREE_THRESHOLD}): possible loader/dropper/worm"
                    ),
                    "node": node, "value": deg,
                })

        # 2. Cycles (injection indicator)
        try:
            for cycle in _nx.simple_cycles(G):
                self._anomalies.append({
                    "type": "CYCLE", "severity": "CRITIQUE",
                    "description": (
                        "Cycle in process tree: " + " \u2192 ".join(cycle[:5])
                        + ("\u2192..." if len(cycle) > 5 else "") + " \u2014 impossible in normal "
                        "execution, indicates injection or tree manipulation"
                    ),
                    "node": cycle[0], "value": len(cycle),
                })
        except Exception:
            pass

        # 3. Deep chain
        try:
            if _nx.is_directed_acyclic_graph(G):
                path = _nx.dag_longest_path(G)
                if len(path) >= self.DEPTH_THRESHOLD:
                    self._anomalies.append({
                        "type": "DEEP_CHAIN", "severity": "MOYEN",
                        "description": (
                            f"Deep execution chain (depth={len(path)}): "
                            f"{' \u2192 '.join(path[:7])}{'…' if len(path)>7 else ''}"
                        ),
                        "node": path[0] if path else "", "value": len(path),
                    })
        except Exception:
            pass

        # 4. Centrality hub
        try:
            if len(G.nodes()) > 4:
                cent     = _nx.degree_centrality(G)
                top, val = max(cent.items(), key=lambda x: x[1])
                if val > 0.6:
                    self._anomalies.append({
                        "type": "HUB", "severity": "MOYEN",
                        "description": (
                            f"'{top}' is a central hub (centrality={val:.2f} >0.6): "
                            f"possible C2 orchestrator or pivoting process"
                        ),
                        "node": top, "value": round(val, 3),
                    })
        except Exception:
            pass

    @property
    def available(self) -> bool:
        return self._G is not None

    def get_anomalies(self) -> list:
        return self._anomalies

    def node_count(self) -> int:
        return len(self._G.nodes()) if self._G else 0

    def edge_count(self) -> int:
        return len(self._G.edges()) if self._G else 0


# ===========================================================================
# PHASE 4 — STATISTICAL ANOMALY ANALYZER (pandas feature engineering + pyod)
# ===========================================================================

class StatisticalAnalyzer:
    """
    Baselining comportemental statistique + IsolationForest (pyod) sur les events.
    Nécessite : pip install pyod  (pandas est optionnel, utilise stdlib sinon)
    """

    def __init__(self, events: list):
        self.events    = events
        self._outliers: list = []
        self._stats:    dict = {}
        self._after_h:  list = []
        self._build()

    def _build(self):
        if not self.events:
            return

        rows = []
        pair_freq: dict = defaultdict(int)

        for ev in self.events:
            d   = ev["details"]
            cmd = d.get("src.process.cmdline","") or ""
            rows.append({
                "cmd_len":    len(cmd),
                "cmd_entr":   _shannon_entropy(cmd),
                "is_net":     1 if ev["event_type"] in
                              ("IP Connect","DNS Resolved","DNS Unresolved") else 0,
                "is_behav":   1 if ev["event_type"] == "Behavioral Indicators" else 0,
                "is_script":  1 if ev["event_type"] in
                              ("Command Script","Pre Execution Detection") else 0,
                "hour":       ev["timestamp"].hour if ev["timestamp"] else 12,
                "_ev":        ev,
            })
            if ev["event_type"] == "Process Creation":
                sc = d.get("src.process.cmdline","") or ""
                tc = d.get("tgt.process.cmdline","") or ""
                sn = Path(sc.replace('"','').split()[0]).name.lower() if sc.split() else ""
                tn = Path(tc.replace('"','').split()[0]).name.lower() if tc.split() else ""
                if sn and tn:
                    pair_freq[(sn, tn)] += 1

        # Basic stats
        cl = [r["cmd_len"]  for r in rows if r["cmd_len"]  > 0]
        ce = [r["cmd_entr"] for r in rows if r["cmd_entr"] > 0]
        if cl:
            mu  = sum(cl)/len(cl)
            sd  = (sum((x-mu)**2 for x in cl)/len(cl))**.5
            self._stats["cmd_len"]  = {"mean": round(mu,1), "std": round(sd,1)}
        if ce:
            mu  = sum(ce)/len(ce)
            sd  = (sum((x-mu)**2 for x in ce)/len(ce))**.5
            self._stats["cmd_entropy"] = {"mean": round(mu,2), "std": round(sd,2)}

        self._stats["rare_pairs"] = [
            f"{s}\u2192{t}" for (s,t), c in pair_freq.items() if c == 1
        ][:10]

        # After-hours events
        self._after_h = [
            r["_ev"] for r in rows
            if r["_ev"]["timestamp"] and
            (r["_ev"]["timestamp"].hour < 7 or r["_ev"]["timestamp"].hour > 20)
        ]

        # IsolationForest (pyod)
        if HAS_PYOD and len(rows) >= 10:
            try:
                X = [[r["cmd_len"], r["cmd_entr"], r["is_net"],
                      r["is_behav"], r["is_script"], r["hour"]]
                     for r in rows]
                clf    = _IForest(contamination=0.1, random_state=42)
                clf.fit(X)
                scores = clf.decision_function(X)
                labels = clf.predict(X)
                for i, (lbl, sc) in enumerate(zip(labels, scores)):
                    if lbl == 1:
                        ev  = rows[i]["_ev"]
                        cmd = ev["details"].get("src.process.cmdline","") or ""
                        self._outliers.append({
                            "event_type": ev["event_type"],
                            "timestamp":  ev["timestamp_raw"],
                            "score":      round(float(sc), 4),
                            "cmd":        cmd[:80],
                            "entropy":    round(rows[i]["cmd_entr"], 2),
                        })
                self._outliers.sort(key=lambda x: x["score"])
                self._outliers = self._outliers[:10]
            except Exception:
                pass

    def get_outliers(self)     -> list: return self._outliers
    def get_stats(self)        -> dict: return self._stats
    def get_after_hours(self)  -> list: return self._after_h
    @property
    def has_pyod(self) -> bool: return HAS_PYOD


# ===========================================================================
# PHASE 5 — YARA ANALYZER (yara-python + signature-base rules)
# ===========================================================================

class YaraAnalyzer:
    """
    Évalue des règles YARA sur les cmdlines, scripts et chemins.
    Nécessite : pip install yara-python  +  --update (télécharge signature-base)
    """

    def __init__(self, events: list):
        self.events        = events
        self._rule_sets:   dict = {}   # filename → compiled rules
        self._hits:        list = []
        self._file_count   = 0
        self._load()
        if self._rule_sets:
            self._scan()

    def _load(self):
        if not HAS_YARA or not YARA_DIR.exists():
            return
        for rf in list(YARA_DIR.glob("*.yar")) + list(YARA_DIR.glob("*.yara")):
            try:
                src = rf.read_text(encoding="utf-8", errors="replace")
                # Skip rules requiring external variables we cannot provide
                if re.search(r'^\s*externals\s*:', src, re.M):
                    continue
                compiled = _yara.compile(source=src)
                self._rule_sets[rf.name] = compiled
                self._file_count += 1
            except Exception:
                continue

    def _scan_text(self, text: str, ctx: str, ts: str):
        if not text:
            return
        data = text.encode("utf-8", errors="replace")
        for fname, rules in self._rule_sets.items():
            try:
                for m in rules.match(data=data):
                    self._hits.append({
                        "rule":      m.rule,
                        "tags":      list(m.tags),
                        "context":   ctx,
                        "timestamp": ts,
                        "preview":   text[:80],
                        "severity":  "CRITIQUE" if any(
                            t.upper() in ("HIGHTRUST","HIGHCONFIDENCE","CRITICAL")
                            for t in (m.tags or [])
                        ) else "ELEVE",
                    })
            except Exception:
                continue

    def _scan(self):
        seen = set()
        for ev in self.events:
            d  = ev["details"]
            ts = ev["timestamp_raw"]
            for field in ("src.process.cmdline","tgt.process.cmdline"):
                txt = d.get(field,"") or ""
                key = txt[:200]
                if txt and key not in seen:
                    seen.add(key)
                    self._scan_text(txt, f"cmdline:{field}", ts)
            script = d.get("cmdScript.content","") or ""
            if script and script[:40] not in seen:
                seen.add(script[:40])
                self._scan_text(script[:8192], "script", ts)
            fp = d.get("tgt.file.path","") or ""
            if fp and fp[:40] not in seen:
                seen.add(fp[:40])
                self._scan_text(fp, "file_path", ts)
        # Deduplicate by rule name
        seen_rules, deduped = set(), []
        for h in self._hits:
            if h["rule"] not in seen_rules:
                seen_rules.add(h["rule"])
                deduped.append(h)
        self._hits = deduped

    @property
    def available(self) -> bool: return bool(self._rule_sets)
    def get_hits(self)   -> list: return self._hits
    def loaded_count(self) -> int: return self._file_count


# ===========================================================================
# PHASE 6 — IOC EXTRACT ANALYZER (iocextract)
# ===========================================================================

class IocExtractAnalyzer:
    """
    Extrait et déobfusque les IOCs cachés dans les scripts et cmdlines.
    Nécessite : pip install iocextract
    """

    def __init__(self, events: list):
        self.events = events
        self._iocs: dict = {"urls": [], "ips": [], "hashes": [], "emails": []}
        self._extract()

    def _extract(self):
        if not HAS_IOC:
            return
        seen, texts = set(), []
        for ev in self.events:
            d = ev["details"]
            for field in ("cmdScript.content","src.process.cmdline",
                          "tgt.process.cmdline","event.dns.request"):
                val = d.get(field,"") or ""
                if val and val not in seen:
                    seen.add(val)
                    texts.append(val)
        combined = "\n".join(texts)
        if not combined.strip():
            return
        try:
            raw_urls = list(set(_iocextract.extract_urls(combined, refang=True)))[:20]
            # Clean URLs: iocextract can capture trailing garbage after the URL
            cleaned = []
            for u in raw_urls:
                # Trim at first single-quote, comma, space, or closing bracket
                u = re.split(r"[',\s\]\)\}>]", u)[0]
                if u and len(u) > 8:
                    cleaned.append(u)
            self._iocs["urls"] = list(set(cleaned))
        except Exception:
            pass
        try:
            self._iocs["ips"]    = list(set(_iocextract.extract_ips(combined, refang=True)))[:20]
        except Exception:
            pass
        try:
            self._iocs["hashes"] = list(set(_iocextract.extract_hashes(combined)))[:20]
        except Exception:
            pass
        try:
            self._iocs["emails"] = list(set(_iocextract.extract_emails(combined)))[:10]
        except Exception:
            pass

    @property
    def available(self) -> bool: return HAS_IOC
    def get_iocs(self)   -> dict: return self._iocs
    def has_findings(self) -> bool: return any(self._iocs.values())


# ===========================================================================
# MOTEUR DE CORRÉLATION ET DE VERDICT
# ===========================================================================

class CorrelationEngine:
    """Détecte les chaînes d'attaque et corrèle les indicateurs entre eux."""

    def __init__(self, behav: BehaviorAnalyzer):
        self.behav = behav

    def get_matched_chains(self, ctx: "IndicatorContextualizer" = None) -> list:

        all_indicators = self.behav.get_unique()

        # Séparer les indicateurs TP (non-FP) des FP pour la corrélation
        # La corrélation ne doit se baser que sur des indicateurs réellement suspects
        tp_indicators = []
        if ctx:
            for ind in all_indicators:
                analysis = ctx.analyze(ind)
                if not analysis["is_fp"]:
                    tp_indicators.append(ind)
        else:
            tp_indicators = all_indicators

        tp_names = {i["name"] for i in tp_indicators}
        tp_cats  = {i["category"] for i in tp_indicators}
        tp_cat_counts = defaultdict(int)
        for i in tp_indicators:
            tp_cat_counts[i["category"]] += 1

        matched = []
        for chain in ATTACK_CHAINS:
            req_ind = chain["required_indicators"]
            req_cat = chain["required_categories"]
            min_cat = chain.get("min_cat_indicators", 0)

            # Les indicateurs requis doivent être dans les indicateurs TP
            ind_ok = req_ind.issubset(tp_names) if req_ind else True
            # Les catégories requises ne doivent venir que d'indicateurs TP
            cat_ok = req_cat.issubset(tp_cats) if req_cat else True
            cnt_ok = (not req_cat or
                      all(tp_cat_counts.get(c, 0) >= max(1, min_cat // max(1, len(req_cat)))
                          for c in req_cat)) if min_cat > 0 else True

            if ind_ok and cat_ok and cnt_ok:
                matched.append(chain)

        return matched


class IndicatorContextualizer:
    """Produit une analyse contextuelle forensique pour chaque indicateur."""

    _INSTALLER_EXES = {
        "msiexec.exe", "setup.exe", "install.exe", "installer.exe",
        "setup64.exe", "install64.exe", "dotnet-install.exe",
        "unins000.exe", "unins001.exe", "uninst.exe",
    }

    def __init__(self, proc: ProcessAnalyzer, behav: BehaviorAnalyzer,
                 files: FileAnalyzer):
        self.proc  = proc
        self.behav = behav
        self.files = files
        self._ctx  = proc.get_context_flags()
        self._is_electron  = self._ctx["is_electron"]
        self._is_build     = files.is_build_activity()
        _cmd = self._ctx["cmdline"]
        _exe = Path(_cmd.replace('"', '').split()[0]).name.lower() if _cmd else ""
        self._is_installer = _exe in self._INSTALLER_EXES

    def analyze(self, ind: dict) -> dict:
        """Retourne l'analyse contextuelle complète d'un indicateur."""
        name = ind["name"]
        db   = INDICATOR_DB.get(name, {})

        base_severity  = db.get("severity", "ELEVE")
        fp_contexts    = db.get("fp_contexts", [])
        db_description = db.get("description", "")

        severity   = base_severity
        assessment = "SUSPICIOUS"
        reasoning  = db_description or ind.get("description", f"Indicator {name}")
        is_fp      = False
        fp_reason  = ""

        # ----- Rule 1: Known offensive tool (ALWAYS CRITICAL, no FP possible) -----
        if db.get("severity") == "CRITIQUE" and "Post Exploitation" in ind.get("category", ""):
            severity   = "CRITIQUE"
            assessment = "CONFIRMED TRUE POSITIVE"

        # ----- Rule 2: Chromium/Electron FP -----
        elif self._is_electron and ("chromium" in fp_contexts or "electron" in fp_contexts):
            meta = ind.get("metadata", "")
            is_same_exe = "IsSameExe:true" in meta or "IsSameName:true" in meta
            severity   = "INFO"
            assessment = "FALSE POSITIVE (Chromium architecture)"
            is_fp      = True
            fp_reason  = (
                f"Application uses the Chromium/Electron architecture. "
                f"Indicator '{name}' is normal behavior of its multi-process sandbox mechanism."
            )
            if is_same_exe and name in ("ProcessHollowingImagePatched", "PreloadInjection"):
                fp_reason += (
                    " Confirmed by IsSameExe=true: injection is from parent process "
                    "to its own child process (same binary)."
                )

        # ----- Rule 3: Installer context (msiexec, setup.exe, etc.) -----
        elif self._is_installer and "installer" in fp_contexts:
            severity   = "INFO"
            assessment = "FALSE POSITIVE (Installer / DRM context)"
            is_fp      = True
            fp_reason  = (
                f"Process is a known installer binary (msiexec.exe, setup.exe, etc.). "
                f"Indicator '{name}' is commonly triggered by game DRM, anti-cheat components, "
                f"or compatibility shims during software installation. "
                f"Verify the MSI package source and publisher to confirm legitimacy."
            )

        # ----- Rule 3b: Build/dev context for Ransomware indicators -----
        elif self._is_build and "dev_build" in fp_contexts:
            severity   = "MOYEN"
            assessment = "LIKELY FALSE POSITIVE (build context)"
            is_fp      = True
            fp_reason  = (
                f"Build/compilation activity detected in active directories. "
                f"Indicator '{name}' may be triggered by packaging tools "
                f"(PyInstaller, webpack) that bulk-create and delete temporary files. "
                f"Verify the extensions of created files to confirm."
            )

        # ----- Rule 4: Security application for specific indicators -----
        elif "security_app" in fp_contexts:
            pub = self._ctx["publisher"].lower()
            known_sec_pubs = ["inca", "wellbia", "xigncode", "gameguard",
                              "battleye", "vanguard", "kaspersky", "malwarebytes",
                              "bitdefender", "norton", "avast", "avg", "sophos",
                              "sentinel", "crowdstrike", "cylance", "carbon black",
                              "nprotect", "eset", "trend micro", "mcafee", "symantec",
                              "f-secure", "panda", "webroot", "comodo"]
            if any(p in pub for p in known_sec_pubs):
                severity   = "INFO"
                assessment = "FALSE POSITIVE (Security tool)"
                is_fp      = True
                fp_reason  = (
                    f"Publisher '{self._ctx['publisher']}' is a recognized security vendor. "
                    f"Indicator '{name}' matches expected technical behavior for this type of tool "
                    f"(memory scanning, low-level access, kernel hooks, enumeration, anti-VM). "
                    f"VERIFY that this version is legitimate and authorized by security policy."
                )

        # ----- Rule 5: Low forensic value indicators alone -----
        elif base_severity == "FAIBLE":
            severity   = "FAIBLE"
            assessment = "INFORMATIONAL"

        return {
            "name":        name,
            "category":    ind["category"],
            "description": ind.get("description", ""),
            "severity":    severity,
            "assessment":  assessment,
            "reasoning":   reasoning if not is_fp else fp_reason,
            "is_fp":       is_fp,
            "mitre":       ind.get("mitre_techniques", db.get("mitre", [])),
            "occurrences": 0,  # sera rempli par BehaviorAnalyzer
        }

    def get_confidence_bonus(self, ind: dict) -> int:
        """
        Calcule un bonus de confiance TP basé sur des facteurs bayésiens :
        - Occurrences multiples du même indicateur (+1 par 3 occurrences)
        - Co-occurrence avec d'autres indicateurs de la même catégorie
        - Combinaison avec un indicateur CRITIQUE dans la même session
        Retourne un entier ajouté au score global dans VerdictEngine.
        """
        name     = ind["name"]
        category = ind.get("category", "")
        db       = INDICATOR_DB.get(name, {})
        if db.get("severity") in ("FAIBLE",) or not category:
            return 0

        bonus = 0
        occurrences = self.behav.get_occurrence_count(name)
        # +1 par tranche de 3 occurrences (max +3)
        bonus += min(3, occurrences // 3)

        # Co-occurrence dans la même catégorie (hors FP)
        same_cat = [i for i in self.behav.get_unique()
                    if i["category"] == category and i["name"] != name
                    and not self.analyze(i)["is_fp"]]
        if len(same_cat) >= 2:
            bonus += 1

        # Co-occurrence avec un indicateur CRITIQUE (force multiplicatrice)
        has_critique = any(
            INDICATOR_DB.get(i["name"], {}).get("severity") == "CRITIQUE"
            for i in self.behav.get_unique()
            if not self.analyze(i)["is_fp"] and i["name"] != name
        )
        if has_critique and db.get("severity") == "ELEVE":
            bonus += 1

        return bonus


class VerdictEngine:
    """
    Moteur de verdict basé exclusivement sur le comportement observé.
    L'identité de l'application est une OBSERVATION dans le rapport,
    jamais un facteur réduisant automatiquement le score.
    """

    def __init__(self, proc: ProcessAnalyzer, behav: BehaviorAnalyzer,
                 net: NetworkAnalyzer, files: FileAnalyzer,
                 reg: RegistryAnalyzer, scripts: ScriptAnalyzer,
                 modules: ModuleAnalyzer, tasks: TaskAnalyzer,
                 correlation: CorrelationEngine,
                 contextualizer: IndicatorContextualizer,
                 lsass: "LsassAnalyzer" = None,
                 cmdline_analyzer: "CmdlineAnalyzer" = None,
                 temporal: "TemporalCorrelationAnalyzer" = None,
                 sigma: "SigmaEvaluator" = None,
                 process_graph: "ProcessGraphAnalyzer" = None,
                 stats: "StatisticalAnalyzer" = None,
                 yara_an: "YaraAnalyzer" = None,
                 mitre_enricher: "MitreAttackEnricher" = None):
        self.proc   = proc
        self.behav  = behav
        self.net    = net
        self.files  = files
        self.reg    = reg
        self.scripts = scripts
        self.modules = modules
        self.tasks  = tasks
        self.corr   = correlation
        self.ctx    = contextualizer
        self.lsass        = lsass
        self.cmdline_an   = cmdline_analyzer
        self.temporal     = temporal
        self.sigma        = sigma
        self.process_graph = process_graph
        self.stats        = stats
        self.yara_an      = yara_an
        self.mitre_enricher = mitre_enricher
        self.events = []  # populated by evaluate() caller

        self.score = 0
        self.evidence_tp = []   # arguments en faveur d'un TP
        self.evidence_fp = []   # arguments en faveur d'un FP (contexte explicatif)
        self.observations = []  # observations neutres

    def evaluate(self) -> dict:
        self._check_execution_context()
        self._check_indicators()
        self._check_attack_chains()
        self._check_script_content()
        self._check_suspicious_modules()
        self._check_network()
        self._check_files()
        self._check_registry()
        self._check_tasks()
        self._check_process_signature()
        if self.lsass:
            self._check_lsass(self.lsass)
        if self.cmdline_an:
            self._check_cmdline(self.cmdline_an)
        if self.temporal:
            self._check_temporal(self.temporal)
        self._check_user_agents(self.net)
        self._check_beacon(self.net)
        if self.sigma:
            self._check_sigma(self.sigma)
        if self.process_graph:
            self._check_process_graph(self.process_graph)
        if self.stats:
            self._check_stats(self.stats)
        if self.yara_an:
            self._check_yara(self.yara_an)

        # ── Normalize raw score to 0-20 scale ──
        # Raw score is unbounded; use a logarithmic scaling to map to 0-20
        # This gives meaningful spread: raw 1→1, 4→4, 8→8, 15→13, 30→16, 60→18, 100→19
        raw = self.score
        if raw <= 0:
            norm_score = 0  # score floor is 0 (0-20 scale)
        elif raw <= 20:
            norm_score = raw           # 0-20: linear (1:1)
        else:
            # 20+: logarithmic compression → 20 maps to 20, 100+ approaches 20
            import math
            norm_score = 20 * (1 - math.exp(-(raw / 20)))
        norm_score = round(min(20, norm_score))

        # ── Verdict thresholds (based on normalized 0-20 scale) ──
        # Qualitative context: presence of CRITICAL indicators or attack chains
        has_critical = any("[CRITICAL]" in e or "[CHAIN]" in e for e in self.evidence_tp)
        has_multiple_high = sum(1 for e in self.evidence_tp
                                if e.startswith("[CRITICAL]") or e.startswith("[HIGH]")
                                or e.startswith("[CHAIN]")) >= 3

        # Score thresholds:
        #   0-3  / 20 : FALSE POSITIVE / BENIGN
        #   4-7  / 20 : LIKELY FALSE POSITIVE / LOW RISK
        #   8-11 / 20 : UNDETERMINED - needs investigation
        #  12-15 / 20 : SUSPICIOUS - likely malicious, investigate
        #  16-20 / 20 : MALICIOUS - confirmed threat
        if norm_score >= 16 and has_critical:
            verdict    = "TRUE POSITIVE - Confirmed threat"
            confidence = "High"
        elif norm_score >= 14 and has_multiple_high:
            verdict    = "TRUE POSITIVE - Confirmed threat"
            confidence = "High"
        elif norm_score >= 12:
            verdict    = "SUSPICIOUS - Investigation required"
            confidence = "Medium-High"
        elif norm_score >= 8:
            verdict    = "UNDETERMINED - Additional context needed"
            confidence = "Medium"
        elif norm_score >= 4:
            verdict    = "LIKELY FALSE POSITIVE - Low risk"
            confidence = "Medium-Low"
        elif norm_score >= 1:
            verdict    = "LIKELY BENIGN - Minimal indicators"
            confidence = "Medium"
        else:
            verdict    = "FALSE POSITIVE - Benign activity"
            confidence = "High"

        return {
            "verdict":      verdict,
            "confidence":   confidence,
            "score":        norm_score,
            "raw_score":    raw,
            "evidence_tp":  self.evidence_tp,
            "evidence_fp":  self.evidence_fp,
            "observations": self.observations,
        }

    def _check_execution_context(self):
        """Analyse le vecteur d'exécution (qui a lancé le processus)."""
        sev, desc = self.proc.get_attack_vector()
        if sev:
            pts = 5 if sev == "CRITIQUE" else 3
            self.score += pts
            self.evidence_tp.append(
                f"[{sev}] Attack vector identified: {desc} "
                f"(process launched from a high-risk program)"
            )
        else:
            root = self.proc.get_root()
            if root:
                parent = (root.get("parent_cmdline", "") or "").lower().strip()
                parent_parts = parent.replace('"', '').split()
                parent_exe = Path(parent_parts[0]).name.lower() if parent_parts else ""
                if parent_exe in LEGIT_PARENTS:
                    self.observations.append(
                        f"Process started from a legitimate system parent: {parent_exe}"
                    )

        # Full parent chain
        chain = self.proc.get_full_parent_chain()
        for level, cmd in chain:
            for exe, (sev2, desc2) in ATTACK_VECTOR_PARENTS.items():
                if exe in cmd.lower():
                    self.score += 2
                    self.evidence_tp.append(
                        f"[HIGH] Suspicious ancestor in execution chain ({level}): "
                        f"{exe} - {desc2}"
                    )

    def _check_indicators(self):
        """Score basé sur les indicateurs comportementaux."""
        is_electron = self.proc.is_electron()

        for ind in self.behav.get_unique():
            name     = ind["name"]
            db       = INDICATOR_DB.get(name, {})
            analysis = self.ctx.analyze(ind)
            fp_ctxs  = db.get("fp_contexts", [])
            tp_score = db.get("tp_score", 1)

            # FP: log and skip TP scoring; security tool FPs actively reduce score
            if analysis["is_fp"]:
                self.evidence_fp.append(
                    f"Indicator '{name}': {analysis['assessment']}"
                )
                if "Security tool" in analysis.get("assessment", ""):
                    self.score -= 1  # Known security vendor: counteract false positives
                continue

            sev = db.get("severity", "ELEVE")

            if sev == "CRITIQUE":
                self.score += tp_score
                self.evidence_tp.append(
                    f"[CRITICAL] {name}: {db.get('description', ind.get('description',''))}"
                )
            elif sev == "ELEVE":
                self.score += max(1, tp_score - 1)
                self.evidence_tp.append(
                    f"[HIGH] {name}: {db.get('description', ind.get('description',''))}"
                )
            elif sev == "MOYEN":
                self.score += max(1, tp_score - 2)
                self.observations.append(f"[MEDIUM] {name} detected")
            else:
                self.observations.append(f"[{sev}] {name} detected (low forensic value alone)")

            # Bayesian confidence bonus
            bonus = self.ctx.get_confidence_bonus(ind)
            if bonus > 0:
                self.score += bonus
                self.observations.append(
                    f"[CONFIDENCE +{bonus}] '{name}': elevated confidence "
                    f"(occurrences/co-indicators/critical context)"
                )

    def _check_attack_chains(self):
        """Score based on correlated attack chains."""
        for chain in self.corr.get_matched_chains(ctx=self.ctx):
            self.score += chain["score"]
            self.evidence_tp.append(
                f"[CHAIN] {chain['name']}: {chain['description']}"
            )

    def _check_script_content(self):
        """Score based on script content analysis."""
        for finding in self.scripts.analyze():
            sev = finding["severity"]
            pts = {"CRITIQUE": 4, "ELEVE": 2, "MOYEN": 1}.get(sev, 1)
            self.score += pts
            self.evidence_tp.append(
                f"[SCRIPT {sev}] {finding['description']} "
                f"(extract: ...{finding['context'][:80]}...)"
            )

    def _check_suspicious_modules(self):
        """Score based on suspicious loaded DLLs."""
        for mod in self.modules.get_suspicious():
            sev = mod["severity"]
            pts = {"ELEVE": 2, "MOYEN": 1}.get(sev, 0)
            if pts > 0:
                self.score += pts
                self.evidence_tp.append(
                    f"[MODULE {sev}] {mod['name']}: {mod['analysis']}"
                )

    def _check_network(self):
        """Analyse réseau basée sur le comportement, pas sur la réputation seule."""
        ext = self.net.get_unique_external()
        suspicious_ips = self.net.get_suspicious_external()

        # IPs non identifiées
        for d in suspicious_ips:
            self.score += 1
            self.evidence_tp.append(
                f"[NETWORK] Connection to unidentified IP: "
                f"{d['dst_ip']}:{d['dst_port']} - verification required"
            )

        # Non-standard ports (outside 80/443/8080/8443/53)
        std_ports = {"80", "443", "8080", "8443", "53", "22", "21"}
        non_std = [d for d in ext if d["dst_port"] not in std_ports]
        if non_std:
            ports_str = ", ".join(set(f"{d['dst_ip']}:{d['dst_port']}" for d in non_std[:3]))
            self.score += 1
            self.evidence_tp.append(
                f"[NETWORK] Connections on non-standard ports: {ports_str}"
            )

        # All connections to identified providers
        if ext and not suspicious_ips:
            owners = sorted(set(d["owner"].split("[")[0].strip() for d in ext))
            self.observations.append(
                f"All external connections to identified providers: "
                f"{', '.join(owners)}"
            )

        # Internal connections on high ports (potential internal C2)
        internal = self.net.get_unique_internal()
        c2_internal = [d for d in internal
                       if d["dst_port"].isdigit() and int(d["dst_port"]) > 40000
                       and d["dst_port"] not in {"65535"}]
        if c2_internal:
            self.score += 1
            pts = ", ".join(f"{d['dst_ip']}:{d['dst_port']}" for d in c2_internal[:3])
            self.evidence_tp.append(
                f"[NETWORK] Internal connections on high ports (potential C2): {pts}"
            )

    def _check_files(self):
        suspects = self.files.get_suspicious_files()
        if suspects:
            self.score += 2
            for s in suspects[:3]:
                self.evidence_tp.append(f"[FILE] Suspicious file: {s['path']}")

        mass, creations, deletions = self.files.detect_mass_operation()
        if mass:
            if self.files.is_build_activity():
                self.evidence_fp.append(
                    f"Bulk file operations ({creations} creations, {deletions} deletions) "
                    f"consistent with a build/packaging context"
                )
            else:
                self.score += 2
                self.evidence_tp.append(
                    f"[FILE] Mass operations: {creations} creations + "
                    f"{deletions} deletions (possible ransomware pattern)"
                )

    def _check_registry(self):
        hits = self.reg.get_persistence_hits()
        for h in hits:
            self.score += 3
            self.evidence_tp.append(
                f"[PERSISTENCE] {h['label']}: {h['key']}"
                + (f" = {h['value'][:60]}" if h["value"] else "")
            )
        if not hits:
            self.observations.append("No registry persistence key identified")

    def _check_tasks(self):
        suspicious_tasks = self.tasks.has_suspicious_tasks()
        for t in suspicious_tasks:
            self.score += 2
            self.evidence_tp.append(
                f"[TASK] Suspicious scheduled task: {t['task_name']} "
                f"({t['event_type']})"
            )

    def _check_sigma(self, sigma: "SigmaEvaluator"):
        """Score based on Sigma community rule matches."""
        level_pts = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFORMATIONAL": 0}
        sigma_total = 0
        sigma_cap   = 6  # plafond pour éviter les FP massifs en volume
        for hit in sigma.evaluate_all(self.behav.events):
            pts = level_pts.get(hit["level"], 1)
            if pts > 0 and sigma_total < sigma_cap:
                self.score += pts
                sigma_total += pts
                mitre_str = f" [{', '.join(hit['mitre'][:3])}]" if hit["mitre"] else ""
                self.evidence_tp.append(
                    f"[SIGMA {hit['level']}] {hit['title']}{mitre_str}: "
                    f"{hit['description'][:120]}"
                )

    def _check_process_graph(self, pg: "ProcessGraphAnalyzer"):
        """Score based on process graph anomalies."""
        sev_pts = {"CRITIQUE": 4, "ELEVE": 2, "MOYEN": 1}
        for a in pg.get_anomalies():
            pts = sev_pts.get(a["severity"], 1)
            self.score += pts
            self.evidence_tp.append(
                f"[GRAPH {a['severity']}] {a['description']}"
            )

    def _check_stats(self, stats: "StatisticalAnalyzer"):
        """Score based on statistical anomalies."""
        if stats.get_outliers():
            n = len(stats.get_outliers())
            self.score += min(n, 3)
            self.evidence_tp.append(
                f"[STATS] {n} statistically anomalous event(s) detected "
                f"by IsolationForest (unusual cmd length/entropy/type distribution)"
            )
        ah = stats.get_after_hours()
        if ah:
            self.score += 1
            self.observations.append(
                f"[STATS] {len(ah)} event(s) occurred outside business hours "
                f"(before 07:00 or after 20:00)"
            )
        rare = stats.get_stats().get("rare_pairs", [])
        if rare:
            self.observations.append(
                f"[STATS] {len(rare)} rare parent-child process pair(s) seen only once: "
                + ", ".join(rare[:3])
            )

    def _check_yara(self, yara_an: "YaraAnalyzer"):
        """Score based on YARA rule matches."""
        for hit in yara_an.get_hits():
            sev = hit["severity"]
            pts = {"CRITIQUE": 4, "ELEVE": 2}.get(sev, 1)
            self.score += pts
            self.evidence_tp.append(
                f"[YARA {sev}] Rule '{hit['rule']}' matched in {hit['context']}: "
                f"{hit['preview'][:60]}\u2026"
            )

    def _check_process_signature(self):
        """Score la signature : bonus de confiance pour éditeurs connus, malus si non signé."""
        root = self.proc.get_root()
        if not root:
            return
        signed = root.get("signed", "")
        pub    = root.get("publisher", "") or ""

        if signed == "unsigned":
            self.score += 1
            self.evidence_tp.append(
                "Process is not digitally signed: cannot verify executable integrity "
                "via the PKI trust chain"
            )
        elif signed == "signed":
            pub_lower = pub.lower()
            # Known trusted publishers — mitigating factor
            trusted = any(t in pub_lower for t in (
                "microsoft", "google", "apple", "mozilla", "adobe",
                "oracle", "vmware", "citrix", "cisco",
            ))
            if trusted:
                self.score -= 2
                self.evidence_fp.append(
                    f"Process signed by trusted publisher: {pub} "
                    f"(reduces likelihood of malicious binary, does not exclude exploitation)"
                )
            else:
                self.observations.append(
                    f"Process signed by: {pub or 'N/A'} "
                    f"(valid signature does not guarantee absence of exploitation)"
                )

        # Electron architecture
        if self.proc.is_electron():
            meta = self.proc.get_electron_meta()
            meta_str = ""
            if meta:
                meta_str = f" ({meta.get('productName','?')} v{meta.get('version','?')})"
            self.evidence_fp.append(
                f"Chromium/Electron architecture detected{meta_str}. "
                f"Some indicators are inherent false positives of this architecture "
                f"(multi-process sandbox, GPU process, etc.)"
            )

    def _check_lsass(self, lsass: "LsassAnalyzer"):
        """Score basé sur les accès à LSASS détectés."""
        for hit in lsass.get_hits():
            et = hit["event_type"]
            if et == "BehavioralIndicator":
                # Already scored via _check_indicators, skip
                continue
            self.score += 4
            self.evidence_tp.append(
                f"[LSASS] Direct LSASS access via {et}: "
                f"credential dumping attempt — {hit['access'] or 'unknown access rights'}"
            )

    def _check_cmdline(self, cmdline: "CmdlineAnalyzer"):
        """Score basé sur l'analyse heuristique des lignes de commande."""
        for f in cmdline.get_findings():
            sev = f["severity"]
            pts = {"CRITIQUE": 4, "ELEVE": 2, "MOYEN": 1}.get(sev, 1)
            self.score += pts
            self.evidence_tp.append(
                f"[CMDLINE {sev}] {f['description']} "
                f"(extract: ...{f['context'][:70]}...)"
            )
        for ep in cmdline.get_high_entropy_procs()[:3]:
            self.score += 1
            self.evidence_tp.append(
                f"[ENTROPY] High-entropy executable name '{ep['name']}' "
                f"(H={ep['entropy']} bits): possible randomly-generated malware name"
            )

    def _check_temporal(self, temporal: "TemporalCorrelationAnalyzer"):
        """Score basé sur les séquences d'attaque temporelles."""
        for seq in temporal.get_sequences():
            self.score += 2
            self.evidence_tp.append(
                f"[TEMPORAL] {seq['description']} "
                f"(delta: {seq['delta_sec']}s / window: {seq['window_sec']}s)"
            )

    def _check_user_agents(self, net: "NetworkAnalyzer"):
        """Score basé sur les User-Agents HTTP suspects."""
        for ua in net.get_suspicious_user_agents():
            sev = ua["severity"]
            pts = {"CRITIQUE": 4, "ELEVE": 2, "MOYEN": 1}.get(sev, 0)
            if pts:
                self.score += pts
                self.evidence_tp.append(
                    f"[UA {sev}] {ua['description']} "
                    f"(UA: {ua['user_agent'][:60]})"
                )

    def _check_beacon(self, net: "NetworkAnalyzer"):
        """Score basé sur la détection de beacon C2."""
        for b in net.detect_c2_beacon():
            self.score += 3
            self.evidence_tp.append(
                f"[BEACON] Possible C2 beacon to {b['dst_ip']}:{b['dst_port']} "
                f"({b['owner']}) — {b['count']} connections, "
                f"interval={b['mean_interval_s']}s ±{b['std_dev_s']}s (CV={b['cv']})"
            )


# ===========================================================================
# TIMELINE BUILDER
# ===========================================================================

class TimelineBuilder:
    PHASES = [
        ("Initial access vector",
         lambda ev: ev["event_type"] == "Process Creation" and any(
             exe in (ev["details"].get("src.process.parent.cmdline", "") or "").lower()
             for exe in ATTACK_VECTOR_PARENTS
         )),
        ("Initial launch (user action)",
         lambda ev: ev["event_type"] == "Process Creation" and
         "explorer.exe" in (ev["details"].get("src.process.parent.cmdline", "") or "").lower()),
        ("Process initialization & injection",
         lambda ev: ev["event_type"] in ("Process Creation", "Duplicate Process Handle",
                                          "Open Remote Process Handle", "Duplicate Thread Handle")),
        ("Behavioral indicators",
         lambda ev: ev["event_type"] == "Behavioral Indicators"),
        ("Network activity & C2",
         lambda ev: ev["event_type"] in ("IP Connect", "IP Listen", "DNS Resolved",
                                          "DNS Unresolved", "GET", "POST", "HTTP Request")),
        ("Script & command execution",
         lambda ev: ev["event_type"] in ("Command Script", "Pre Execution Detection")),
        ("Module loading",
         lambda ev: ev["event_type"] == "Module Load"),
        ("File activity",
         lambda ev: ev["event_type"] in ("File Creation", "File Deletion",
                                          "File Rename", "File Modification")),
        ("Registry activity",
         lambda ev: "Registry" in ev["event_type"]),
        ("Scheduled tasks",
         lambda ev: ev["event_type"] in ("Task Trigger", "Task Delete", "Task Create")),
    ]

    def __init__(self, events: list):
        self.events = events

    def get_phases(self) -> dict:
        phases = defaultdict(list)
        for ev in self.events:
            for name, rule in self.PHASES:
                if rule(ev):
                    phases[name].append(ev)
                    break
            else:
                phases["Autre"].append(ev)
        return dict(phases)

    def get_time_range(self) -> tuple:
        ts = [ev["timestamp"] for ev in self.events if ev["timestamp"]]
        if not ts:
            return None, None, None
        return min(ts), max(ts), (max(ts) - min(ts)).total_seconds()


# ===========================================================================
# GÉNÉRATEUR DE RAPPORT
# ===========================================================================

class ReportGenerator:

    def __init__(self, events, proc, behav, net, files, reg,
                 scripts, modules, tasks, timeline, ctx, verdict,
                 vt_client=None, ip_info=None,
                 mb_client=None, otx_client=None, shodan_client=None,
                 lsass=None, cmdline_an=None, temporal=None,
                 sigma=None, process_graph=None, stats=None,
                 yara_an=None, mitre_enricher=None, ioc_an=None,
                 correlation=None):
        self.events    = events
        self.proc      = proc
        self.behav     = behav
        self.net       = net
        self.files     = files
        self.reg       = reg
        self.scripts   = scripts
        self.modules   = modules
        self.tasks     = tasks
        self.timeline  = timeline
        self.ctx       = ctx
        self.verdict   = verdict
        self.vt        = vt_client   # VirusTotalClient or None
        self.ip_info   = ip_info or {}  # {ip: geo_dict}
        self.mb           = mb_client
        self.otx          = otx_client
        self.shodan       = shodan_client
        self.lsass        = lsass
        self.cmdline_an   = cmdline_an
        self.temporal     = temporal
        self.sigma        = sigma
        self.process_graph = process_graph
        self.stats        = stats
        self.yara_an      = yara_an
        self.mitre_enricher = mitre_enricher
        self.ioc_an       = ioc_an
        self.corr         = correlation

    # ------------------------------------------------------------------ #
    @staticmethod
    def _S():  return C.sep("=" * 80)
    @staticmethod
    def _S2(): return C.sep2("-" * 80)

    def _H(self, text: str) -> str:
        return C.header(text)

    @staticmethod
    def _extract_exe_name(cmdline: str) -> str:
        """Extract executable name from a command line, handling paths with spaces.

        Handles: 'C:\\Program Files\\Git\\bin\\bash.exe -arg', 'cmd.exe /c dir',
                 'C:\\path with spaces\\app.exe', plain names like 'python.exe'.
        Returns '' for non-executable strings (e.g. displayName without extension).
        """
        if not cmdline:
            return ""
        # Strategy 1: look for the first .exe/.com/.cmd/.bat/.msi/.dll/.scr/.ps1 in the string
        m = re.search(r'([^\s"]*?\.(?:exe|com|cmd|bat|msi|dll|scr|ps1))\b', cmdline, re.IGNORECASE)
        if m:
            return Path(m.group(1)).name
        # Strategy 2: if the whole string looks like a path, use Path.name
        if '\\' in cmdline or '/' in cmdline:
            return Path(cmdline.split(' -')[0].split(' /')[0].strip()).name or ""
        # No executable extension found and not a path — likely a displayName, return empty
        # so caller falls back to displayName
        return ""

    def generate(self) -> str:
        L = []

        L += [self._S(),
              C.bold("  \u26a1 SOC ANALYSIS REPORT - SentinelOne Detection"),
              self._S(), ""]

        L.append(self._H("EXECUTIVE SUMMARY"))
        L.append(self._S2())
        L += self._executive_summary()
        L.append("")

        L.append(self._H("1. PROCESS IDENTIFICATION & EXECUTION CONTEXT"))
        L.append(self._S2())
        L += self._section_identification()

        L.append("")
        L.append(self._H("2. EVENT TIMELINE"))
        L.append(self._S2())
        L += self._section_timeline()

        L.append("")
        L.append(self._H("3. BEHAVIORAL INDICATORS"))
        L.append(self._S2())
        L += self._section_indicators()

        techniques = self.behav.get_all_techniques()
        if techniques:
            L.append("")
            L.append(self._H("4. MITRE ATT&CK MAPPING"))
            L.append(self._S2())
            L += self._section_mitre(techniques)

        L.append("")
        L.append(self._H("5. SCRIPT CONTENT ANALYSIS"))
        L.append(self._S2())
        L += self._section_scripts()

        L.append("")
        L.append(self._H("6. LOADED MODULES (DLLs)"))
        L.append(self._S2())
        L += self._section_modules()

        L.append("")
        L.append(self._H("7. NETWORK ANALYSIS"))
        L.append(self._S2())
        L += self._section_network()

        L.append("")
        L.append(self._H("8. PROCESS TREE"))
        L.append(self._S2())
        L += self._section_process_tree()

        L.append("")
        L.append(self._H("9. FILE ACTIVITY"))
        L.append(self._S2())
        L += self._section_files()

        L.append("")
        L.append(self._H("10. REGISTRY ACTIVITY"))
        L.append(self._S2())
        L += self._section_registry()

        # VirusTotal section (only if VT client configured)
        vt_lines = self._section_virustotal()
        if vt_lines:
            L.append("")
            L.append(self._H("11. VIRUSTOTAL ANALYSIS"))
            L.append(self._S2())
            L += vt_lines

        # LSASS section
        if self.lsass and self.lsass.has_lsass_access():
            L.append("")
            L.append(self._H("12. LSASS ACCESS ATTEMPTS"))
            L.append(self._S2())
            L += self._section_lsass()

        # Command line heuristics section
        if self.cmdline_an and (self.cmdline_an.get_findings() or
                                 self.cmdline_an.get_high_entropy_procs()):
            L.append("")
            L.append(self._H("13. COMMAND LINE ANALYSIS"))
            L.append(self._S2())
            L += self._section_cmdline()

        # Temporal sequences section
        if self.temporal and self.temporal.get_sequences():
            L.append("")
            L.append(self._H("14. TEMPORAL ATTACK SEQUENCES"))
            L.append(self._S2())
            L += self._section_temporal()

        # Multi-source IOC section
        ioc_lines = self._section_multi_ioc()
        if ioc_lines:
            L.append("")
            L.append(self._H("15. MULTI-SOURCE IOC ANALYSIS"))
            L.append(self._S2())
            L += ioc_lines

        # C2 Beacon section
        beacons = self.net.detect_c2_beacon()
        if beacons:
            L.append("")
            L.append(self._H("16. C2 BEACON DETECTION"))
            L.append(self._S2())
            L += self._section_beacons(beacons)

        # Suspicious User-Agent section
        sus_uas = self.net.get_suspicious_user_agents()
        if sus_uas:
            L.append("")
            L.append(self._H("17. SUSPICIOUS HTTP USER-AGENTS"))
            L.append(self._S2())
            L += self._section_user_agents(sus_uas)

        # Sigma rule matches
        if self.sigma and self.sigma.available:
            sigma_hits = self.sigma.evaluate_all(self.events)
            if sigma_hits:
                L.append("")
                L.append(self._H(f"18. SIGMA RULE MATCHES ({len(sigma_hits)} hits / {self.sigma.rule_count} rules)"))
                L.append(self._S2())
                L += self._section_sigma(sigma_hits)

        # Process graph anomalies
        if self.process_graph and self.process_graph.available:
            pg_anomalies = self.process_graph.get_anomalies()
            if pg_anomalies:
                L.append("")
                L.append(self._H("19. PROCESS GRAPH ANOMALIES (NetworkX)"))
                L.append(self._S2())
                L += self._section_process_graph(pg_anomalies)

        # Statistical analysis
        if self.stats:
            if self.stats.get_outliers() or self.stats.get_after_hours() or self.stats.get_stats().get("rare_pairs"):
                L.append("")
                L.append(self._H("20. STATISTICAL ANOMALY ANALYSIS"))
                L.append(self._S2())
                L += self._section_stats()

        # YARA matches
        if self.yara_an and self.yara_an.available:
            yara_hits = self.yara_an.get_hits()
            if yara_hits:
                L.append("")
                L.append(self._H(f"21. YARA RULE MATCHES ({len(yara_hits)} hits / {self.yara_an.loaded_count()} rule files)"))
                L.append(self._S2())
                L += self._section_yara(yara_hits)

        # ATT&CK enrichment
        if self.mitre_enricher and self.mitre_enricher.available:
            L.append("")
            L.append(self._H("22. ATT&CK ENRICHMENT (mitre-attack-python)"))
            L.append(self._S2())
            L += self._section_attack_enrichment()

        # IOC extraction
        if self.ioc_an and self.ioc_an.available and self.ioc_an.has_findings():
            L.append("")
            L.append(self._H("23. IOC EXTRACTION (iocextract)"))
            L.append(self._S2())
            L += self._section_ioc_extract()

        L += ["", self._S(), C.bold("  \U0001f50d DIAGNOSIS & VERDICT"), self._S()]
        L += self._section_verdict()

        L += ["", self._S(), C.dim("  End of report"), self._S()]
        return "\n".join(L)

    # ------------------------------------------------------------------ #
    def _executive_summary(self) -> list:
        root = self.proc.get_root()
        v    = self.verdict
        ts_min, ts_max, dur = self.timeline.get_time_range()
        dur_str = f"{int(dur)}s (~{int(dur)//60}min)" if dur and dur >= 60 else f"{int(dur or 0)}s"

        n_ind  = len(self.behav.get_unique())
        n_crit = len(self.behav.get_critical_indicators())
        n_ext  = len(self.net.get_unique_external())
        n_unk  = len(self.net.get_suspicious_external())
        n_scr  = len(self.scripts.analyze())

        lines = []
        if root:
            name   = (root.get("display_name", "") or "").replace("\x00", "").strip() or "unknown"
            cmd    = self._trunc(root.get("cmdline", ""), 90)
            is_signed = root.get("signed") == "signed"
            signed = (C.ok("\u2713 SIGNED") if is_signed else C.high("\u2717 UNSIGNED"))
            pub    = root.get("publisher", "") or "no publisher"
            parent = self._trunc(root.get("parent_cmdline", ""), 70)
            user   = self.events[0].get("user", "?") if self.events else "?"
            lines.append(
                f"  \u2699  Process analyzed  : {C.bold(name)}  ({cmd})"
            )
            lines.append(
                f"  \U0001f512 Context           : {signed}, publisher [{C.info(pub)}], "
                f"launched by [{parent}], user [{C.bold(user)}]"
            )
        if ts_min:
            lines.append(
                f"  \U0001f550 Activity          : {ts_min.strftime('%Y-%m-%d %H:%M:%S')} to "
                f"{ts_max.strftime('%H:%M:%S')} ({dur_str}), "
                f"{len(self.events)} events"
            )
        ind_str = (C.crit(f"{n_crit} CRITICAL") if n_crit
                   else C.ok("0 CRITICAL"))
        unk_str = (C.high(f"{n_unk} unidentified") if n_unk
                   else C.ok(f"{n_unk} unidentified"))
        lines.append(
            f"  \U0001f4cb Indicators        : {n_ind} unique ({ind_str}), "
            f"{n_ext} external connections ({unk_str}), "
            f"{n_scr} script finding(s)"
        )
        lines.append("")

        # Verdict coloré avec icône
        verdict_styles = {
            "TRUE POSITIVE":        (C.crit,  "\U0001f480 [!!!] CONFIRMED COMPROMISE"),
            "LIKELY TRUE POSITIVE": (C.high,  "\u26a0  [ ! ] SUSPICIOUS"),
            "UNDETERMINED":         (C.med,   "\u2753 [ ? ] UNDETERMINED"),
            "LIKELY FALSE POSITIVE":(C.ok,    "\u2705 [   ] LIKELY BENIGN"),
            "FALSE POSITIVE":       (C.ok,    "\u2705 [   ] FALSE POSITIVE"),
        }
        fn, prefix = next(
            ((fn, p) for k, (fn, p) in verdict_styles.items() if k in v["verdict"]),
            (C.bold, ">>> ???")
        )
        lines.append(f"  {fn(prefix + ' : ' + v['verdict'])}")
        score_color = C.crit if v["score"] >= 8 else (C.high if v["score"] >= 4
                      else (C.med if v["score"] >= 1 else C.ok))
        lines.append(f"  Behavioral score  : {score_color(str(v['score']))} | "
                     f"Confidence : {C.bold(v['confidence'])}")
        return lines

    # ------------------------------------------------------------------ #
    def _section_identification(self) -> list:
        L    = []
        root = self.proc.get_root()
        if root:
            L.append(f"  Process            : {root.get('display_name', 'N/A')}")
            L.append(f"  Command line       : {self._trunc(root.get('cmdline',''), 120)}")
            L.append(f"  SHA1               : {root.get('sha1','N/A')}")
            signed = root.get("signed", "N/A")
            pub    = root.get("publisher", "") or "Unsigned / no known publisher"
            L.append(f"  Signature          : {signed} | Publisher: {pub}")
            L.append(f"  Parent             : {root.get('parent_cmdline','N/A')}")

        if self.events:
            _u = self.events[0].get('user', 'N/A')
            _u = _u.split("osSrc")[0].strip() or "N/A"
            _sl = self.events[0].get('storyline_id', '') or 'N/A'
            L.append(f"  User               : {_u}")
            L.append(f"  Agent UUID         : {self.events[0].get('agent_uuid','N/A')}")
            L.append(f"  Storyline ID       : {_sl}")

        # Vecteur d'attaque
        sev, desc = self.proc.get_attack_vector()
        if sev:
            L.append(f"\n  *** ATTACK VECTOR [{sev}] ***")
            L.append(f"  {desc}")

        # Parent chain
        chain = self.proc.get_full_parent_chain()
        if chain:
            L.append("\n  Execution chain:")
            for level, cmd in chain:
                L.append(f"    [{level}] {self._trunc(cmd, 100)}")

        # Electron
        if self.proc.is_electron():
            meta = self.proc.get_electron_meta()
            L.append("\n  [INFO] Chromium/Electron architecture detected")
            if meta:
                for k, v in meta.items():
                    L.append(f"    {k}: {v}")
        return L

    # ------------------------------------------------------------------ #
    def _section_timeline(self) -> list:
        L = []
        ts_min, ts_max, dur = self.timeline.get_time_range()
        if ts_min:
            L.append(f"  Start    : {ts_min}")
            L.append(f"  End      : {ts_max}")
            L.append(f"  Duration : {int(dur)} seconds")
        L.append(f"  Total events: {len(self.events)}")

        # Distribution by type
        types = defaultdict(int)
        for ev in self.events:
            types[ev["event_type"]] += 1
        L.append("\n  Distribution by type:")
        for t, c in sorted(types.items(), key=lambda x: -x[1]):
            L.append(f"    {t:45s} {c:>5d}")

        # Activity phases
        phases = self.timeline.get_phases()
        L.append("\n  Activity phases:")
        for phase, evts in phases.items():
            if not evts:
                continue
            ts = [e["timestamp"] for e in evts if e["timestamp"]]
            if ts:
                L.append(
                    f"    {min(ts).strftime('%H:%M:%S')} - {max(ts).strftime('%H:%M:%S')}  "
                    f"{phase} ({len(evts)} evt)"
                )
        return L

    # ------------------------------------------------------------------ #
    def _section_indicators(self) -> list:
        L = []
        indicators = self.behav.get_unique()
        if not indicators:
            L.append("  No behavioral indicators.")
            return L

        for ind in indicators:
            analysis = self.ctx.analyze(ind)
            db       = INDICATOR_DB.get(ind["name"], {})
            count    = self.behav.get_occurrence_count(ind["name"])
            sev      = analysis["severity"]
            is_fp    = analysis["is_fp"]

            # Icon + severity badge
            icons = {"CRITIQUE": "\U0001f480", "ELEVE": "\u26a0 ", "MOYEN": "\u25b3 ",
                     "FAIBLE": "\u25cb ", "INFO": "  "}
            icon = icons.get(sev, "  ")
            sev_badge = _sev_color(sev, f"[{sev}]")
            if is_fp:
                sev_badge = C.ok(f"[{sev}]")
            name_str = C.bold(ind["name"]) if not is_fp else C.dim(ind["name"])
            cnt_str  = C.dim(f" (x{count})") if count > 1 else ""

            L.append(f"\n  {icon} {sev_badge} {name_str}{cnt_str}")
            L.append(f"       Category   : {C.info(ind['category'])}")

            # Color-coded assessment
            assessment = analysis["assessment"]
            if "FALSE POSITIVE" in assessment or "LIKELY FALSE" in assessment:
                diag_str = C.ok(assessment)
            elif "TRUE POSITIVE" in assessment or "CONFIRMED" in assessment:
                diag_str = C.crit(assessment)
            elif "SUSPICIOUS" in assessment or "SUSPECT" in assessment:
                diag_str = C.high(assessment)
            else:
                diag_str = C.med(assessment)
            L.append(f"       Assessment : {diag_str}")

            # Forensic analysis
            reasoning = analysis["reasoning"]
            L += self._wrap("       Analysis   : ", reasoning, 80)

            # MITRE techniques
            mitre = analysis["mitre"] or db.get("mitre", [])
            if mitre:
                if isinstance(mitre[0], dict):
                    tech_str = ", ".join(
                        C.info(f"{t['id']}") + f" ({t['name']})" for t in mitre[:4])
                else:
                    tech_str = ", ".join(C.info(t) for t in mitre[:4])
                L.append(f"       MITRE      : {tech_str}")

        return L

    # ------------------------------------------------------------------ #
    def _section_mitre(self, techniques: list) -> list:
        L = []
        tactics = self.behav.get_all_tactics()
        if tactics:
            L.append(f"  Tactics    : {', '.join(tactics)}")
        L.append("\n  Techniques :")
        for t in techniques:
            L.append(f"    {t['id']:15s} {t['name']}")
        return L

    # ------------------------------------------------------------------ #
    def _section_scripts(self) -> list:
        L = []
        findings = self.scripts.analyze()
        summaries = self.scripts.get_all_scripts_summary()

        if not summaries:
            L.append("  No executed script detected.")
            return L

        L.append(f"  {len(summaries)} script(s) detected:")
        for s in summaries[:5]:
            raw_app = s['app'] or 'N/A'
            exe_name = raw_app.replace("\\", "/").split("/")[-1].split("_")[0]
            chars_str = f" ({s['length']} chars)" if s['length'] > 0 else ""
            L.append(f"  \u2022 {C.dim(exe_name)}{chars_str}")
            L += self._wrap("    ", s['preview'], 120)

        if not findings:
            L.append("\n  No malicious pattern detected in scripts.")
        else:
            L.append(f"\n  {len(findings)} suspicious pattern(s) detected:")
            for f in findings:
                L.append(f"\n    [{f['severity']}] {f['description']}")
                L.append(f"    MITRE  : {f['mitre']}")
                L += self._wrap("    Extract: ...", f['context'], 120)
                L[-1] += "..."
        return L

    # ------------------------------------------------------------------ #
    def _section_modules(self) -> list:
        L = []
        suspicious = self.modules.get_suspicious()
        total = self.modules.get_summary()["total_modules"]

        L.append(f"  Total loaded modules: {total}")
        if not suspicious:
            L.append("  No suspicious module identified.")
        else:
            L.append(f"\n  {len(suspicious)} suspicious module(s):")
            for m in suspicious:
                L.append(f"    [{m['severity']}] {m['name']}")
                L += self._wrap("           ", m["analysis"], 75)
                L.append(f"           Path   : {m['path']}")
        return L

    # ------------------------------------------------------------------ #
    def _section_network(self) -> list:
        L = []
        ext  = self.net.get_unique_external()
        intl = self.net.get_unique_internal()
        lh   = self.net.get_localhost()
        dns  = self.net.dns_queries
        http = self.net.http_requests

        if ext:
            L.append(f"  \U0001f310 Connexions externes ({len(ext)}) :")
            for d in ext:
                is_unknown = "INCONNU" in d["owner"]
                ip   = d["dst_ip"]
                port = d["dst_port"]
                owner= d["owner"]

                # Enrichissement géo si disponible
                geo = self.ip_info.get(ip, {})
                geo_str = IpEnricher.format(geo)
                if geo_str:
                    owner_line = f"{owner}  |  {C.dim(geo_str)}"
                else:
                    owner_line = owner

                # Reverse DNS si non résolu par S1
                domain = self.net.ip_to_domain.get(ip, "")

                if is_unknown:
                    ip_col   = C.high(f"{ip:>20s}")
                    flag_col = C.crit(" [!!!] UNKNOWN")
                else:
                    ip_col   = C.ok(f"{ip:>20s}")
                    flag_col = ""

                L.append(
                    f"    {ip_col}:{port:<5s} "
                    f"{d.get('protocol',''):>5s} {d.get('direction',''):>8s} "
                    f"{d.get('status',''):>7s}  {flag_col}"
                )
                L.append(f"          \u2192 {owner_line}")
                if domain:
                    L.append(f"          \u2192 DNS : {C.info(domain)}")
                if geo_str and is_unknown:
                    L.append(f"          \u2192 Geo : {C.med(geo_str)}")
                L.append(f"          \u2192 Processus : [{d['process_short']}]")
        else:
            L.append("  No external connection.")

        if intl:
            L.append(f"\n  Internal network connections ({len(intl)}):")
            for d in intl:
                L.append(
                    f"    {d['dst_ip']:>15s}:{d['dst_port']:<5s} "
                    f"{d.get('protocol',''):>5s} -> [{d['process_short']}]"
                )

        if lh:
            ports = defaultdict(int)
            for c in lh:
                ports[f"127.0.0.1:{c['dst_port']}"] += 1
            L.append(f"\n  Localhost connections (IPC): {len(lh)} total")
            for p, n in sorted(ports.items()):
                L.append(f"    {p} (x{n})")

        if dns:
            L.append(f"\n  \U0001f4e1 Requetes DNS ({len(dns)}) :")
            seen_d = set()
            for q in dns:
                k = q["request"]
                if k in seen_d:
                    continue
                seen_d.add(k)
                status_str = C.ok("[OK   ]") if q["resolved"] else C.high("[FAIL ]")
                ips    = self.net.dns_map.get(k.rstrip("."), [])
                ip_str = ", ".join(ips[:2]) if ips else q.get("response", "")[:40]
                L.append(f"    {status_str} {k:>50s} -> {C.info(ip_str) if ip_str else ''}")

        if http:
            L.append(f"\n  \U0001f4bb Requetes HTTP ({len(http)}) :")
            for r in http[:10]:
                url_str = r['url'][:100]
                method  = C.info(f"[{r['method']}]")
                L.append(f"    {method} {url_str}")

        return L

    # ------------------------------------------------------------------ #
    def _section_process_tree(self) -> list:
        L = []
        root = self.proc.get_root()

        # Collecte des indicateurs TP par processus (pour annotation)
        tp_inds = set()
        for ind in self.behav.get_unique():
            analysis = self.ctx.analyze(ind)
            if not analysis["is_fp"]:
                tp_inds.add(ind["name"])

        def _sign_tag(proc: dict) -> str:
            signed = proc.get("signed", "")
            if signed == "signed":
                return C.ok("[\u2713 SIGNED]")
            elif signed == "unsigned":
                return C.high("[\u2717 UNSIGNED]")
            return C.dim("[? UNKNOWN]")

        def _hash_line(sha1: str) -> str:
            sha1 = (sha1 or "").strip()
            if not sha1 or sha1 == "N/A":
                return ""
            return C.dim(f"  SHA1 : {sha1}")

        def _pub_str(proc: dict) -> str:
            pub = (proc.get("publisher", "") or "").strip()
            return C.info(pub) if pub else C.dim("no publisher")

        if root:
            name = (root.get("display_name", "") or "").replace("\x00","").strip() or "unknown"
            pub  = _pub_str(root)
            stag = _sign_tag(root)
            sha1 = root.get("sha1", "")
            cmd  = self._trunc(root.get("cmdline", ""), 100)
            L.append(f"  \u2699  {C.bold(name)} {stag}  ({pub})")
            L.append(f"     CMD: {cmd}")
            hl = _hash_line(sha1)
            if hl:
                L.append(f"    {hl}")
            # Parent
            parent = root.get("parent_cmdline", "")
            if parent:
                L.append(f"     Parent : {C.dim(self._trunc(parent, 90))}")

            # Attack vector annotation
            av = self.proc.get_attack_vector()
            if av and av[0]:
                L.append(f"     {C.crit('[!] Attack vector: ' + av[1])}")

        children = self.proc.get_children()
        n = len(children)
        for idx, child in enumerate(children[:30]):
            is_last = (idx == min(n, 30) - 1)
            branch  = "\u2514\u2500\u2500" if is_last else "\u251c\u2500\u2500"
            cont    = "   " if is_last else "\u2502  "

            name = (child.get("display_name", "") or "").replace("\x00","").strip() or "unknown"
            stag = _sign_tag(child)
            etag = C.dim(" [Electron]") if child.get("is_electron_child") else ""
            pub  = _pub_str(child)
            cmd  = self._trunc(child.get("cmdline", ""), 80)
            sha1 = child.get("sha1", "")

            L.append(f"  {branch} \u2699  {C.bold(name)} {stag}{etag}  ({pub})")
            L.append(f"  {cont}    {C.dim(cmd)}")
            hl = _hash_line(sha1)
            if hl:
                L.append(f"  {cont}   {hl}")

        if n > 30:
            L.append(C.dim(f"  ... and {n - 30} more child processes"))
        return L

    # ------------------------------------------------------------------ #
    def _section_files(self) -> list:
        L = []
        summary = self.files.get_summary()
        if not summary:
            L.append("  No file activity.")
            return L

        for op, count in summary.items():
            L.append(f"  {op:30s}: {count}")

        dirs = self.files.get_top_dirs()
        if dirs:
            L.append("\n  Top directories:")
            for d, n in dirs.items():
                L.append(f"    [{n:>4d}] {d}")

        suspects = self.files.get_suspicious_files()
        if suspects:
            L.append(f"\n  *** Suspicious files ({len(suspects)}) ***")
            for s in suspects:
                sha_str = f"\n      SHA1 : {C.dim(s['sha1'])}" if s.get("sha1") else ""
                L.append(f"    ! {C.high(s['path'])}{sha_str}")

        mass, crea, dlt = self.files.detect_mass_operation()
        if mass:
            L.append(f"\n  *** Bulk operations: {crea} creations + {dlt} deletions ***")
            if self.files.is_build_activity():
                L.append("      Build context identified (likely FP).")
            else:
                L.append("      No build context detected. Potential ransomware pattern.")
        return L

    # ------------------------------------------------------------------ #
    def _section_registry(self) -> list:
        L = []
        summary = self.reg.get_summary()
        if summary:
            for key, count in summary.items():
                L.append(f"  [{count:>3d}] {key}")

        hits = self.reg.get_persistence_hits()
        if hits:
            L.append(f"\n  *** REGISTRY PERSISTENCE ({len(hits)} entry(ies)) ***")
            for h in hits:
                L.append(f"    ! {h['label']}")
                L.append(f"      Key   : {h['key']}")
                if h["value"]:
                    L.append(f"      Value : {h['value'][:80]}")
        else:
            L.append("\n  No persistence key detected.")
        return L

    # ------------------------------------------------------------------ #
    def _section_virustotal(self) -> list:
        """Requêtes VirusTotal pour les hashes du processus root + enfants suspects."""
        if not self.vt:
            return []
        L = []
        # Collecter les hashes à vérifier
        to_check = []
        root = self.proc.get_root()
        if root and root.get("sha1"):
            to_check.append(("Root", root.get("display_name","?"), root["sha1"]))
        for child in self.proc.get_children():
            sha = child.get("sha1", "")
            if sha and child.get("signed") == "unsigned":
                name = (child.get("display_name","") or "").replace("\x00","").strip() or "?"
                to_check.append(("Child", name, sha))
        for s in self.files.get_suspicious_files():
            sha = s.get("sha1", "")
            if sha:
                fname = s["path"].replace("\\", "/").split("/")[-1]
                to_check.append(("Fichier suspect", fname, sha))

        if not to_check:
            L.append("  No hash available for VirusTotal analysis.")
            return L

        seen = set()
        for role, name, sha in to_check[:10]:  # max 10 lookups
            if sha in seen:
                continue
            seen.add(sha)
            L.append(f"\n  \U0001f50e [{role}] {C.bold(name)}")
            L.append(f"     SHA1   : {C.dim(sha)}")
            res = self.vt.lookup(sha)
            if not res:
                L.append(f"     VT     : {C.dim('No result (VT key not configured?)')}")
                continue
            if res.get("error"):
                L.append(f"     VT     : {C.med('Error: ' + res['error'])}")
            elif not res.get("found"):
                L.append(f"     VT     : {C.ok('Not found (unknown to VT)')}")
            else:
                mal = res["malicious"]
                sus = res["suspicious"]
                tot = res["total"]
                ratio = f"{mal}/{tot}"
                if mal > 0:
                    ratio_col = C.crit(ratio)
                elif sus > 0:
                    ratio_col = C.high(ratio)
                else:
                    ratio_col = C.ok(ratio)
                L.append(f"     VT     : {ratio_col} engines detect as malicious")
                if res.get("threat"):
                    L.append(f"     Threat : {C.crit(res['threat'])}")
                if res.get("name"):
                    L.append(f"     Name   : {res['name']}")
                if res.get("type"):
                    L.append(f"     Type   : {res['type']}")
                if res.get("tags"):
                    L.append(f"     Tags   : {', '.join(res['tags'][:5])}")
        return L

    # ------------------------------------------------------------------ #
    def _section_verdict(self) -> list:
        v = self.verdict
        L = []
        # Colorer le verdict
        verdict_txt = v["verdict"]
        if "TRUE POSITIVE" in verdict_txt and "LIKELY" not in verdict_txt:
            v_col = C.crit(verdict_txt)
        elif "LIKELY TRUE" in verdict_txt:
            v_col = C.high(verdict_txt)
        elif "UNDETERMINED" in verdict_txt:
            v_col = C.med(verdict_txt)
        else:
            v_col = C.ok(verdict_txt)

        score = v["score"]
        score_col = (C.crit if score >= 8 else C.high if score >= 4
                     else C.med if score >= 1 else C.ok)(str(score))
        L.append(f"\n  VERDICT    : {v_col}")
        L.append(f"  CONFIDENCE : {C.bold(v['confidence'])}")
        L.append(f"  SCORE      : {score_col}  (negative = likely FP, positive = likely TP)")

        if v["evidence_tp"]:
            L.append(C.high(f"\n  Evidence supporting TRUE POSITIVE ({len(v['evidence_tp'])}) :"))
            for r in v["evidence_tp"]:
                L += self._wrap(C.high("    [+] "), r, 80)

        if v["evidence_fp"]:
            L.append(C.ok(f"\n  Mitigating factors (possible FP context):"))
            for r in v["evidence_fp"]:
                L += self._wrap(C.ok("    [-] "), r, 80)

        if v["observations"]:
            L.append(C.info(f"\n  Neutral observations:"))
            for o in v["observations"]:
                L += self._wrap("    [i] ", o, 80)

        # Correlated attack chains
        chains = []
        for ev in v["evidence_tp"]:
            if ev.startswith("[CHAIN]"):
                chains.append(ev[7:].strip())
        if chains:
            L.append(f"\n  Correlated attack chains:")
            for c in chains:
                L += self._wrap("    [>>] ", c, 80)

        L.append("")
        L.append("  RECOMMENDATIONS")
        L.append("-" * 80)
        for rec in self._recommendations():
            L.append(f"  {rec}")
        return L

    # ------------------------------------------------------------------ #
    def _recommendations(self) -> list:
        score = self.verdict["score"]
        root  = self.proc.get_root()
        recs  = []

        if score >= 8:
            recs += [
                "1. IMMEDIATE INCIDENT RESPONSE - Activate the crisis management plan.",
                "2. ISOLATE the endpoint from the network IMMEDIATELY (SentinelOne containment or VLAN).",
                "3. PRESERVE evidence: disk image, memory dump, logs (before remediation).",
                "4. ANALYZE the initial access vector and identify patient zero.",
                "5. HUNT for similar IOCs across the entire fleet (threat hunting).",
                "6. NOTIFY CISO, management, and if required, relevant authorities.",
                "7. Activate the business continuity plan if necessary.",
            ]
        elif score >= 4:
            recs += [
                "1. ESCALATE to SOC L3 / incident response team within 2 hours.",
                "2. ISOLATE the endpoint (network containment) as a precautionary measure.",
                "3. COLLECT forensic artifacts: Windows Event logs, prefetch, amcache.",
                "4. CHECK other endpoints for the same user and network segment.",
                "5. CONTACT the user to validate or refute the activity.",
                "6. SEARCH for similar connections to the same IPs across the fleet.",
            ]
        elif score >= 1:
            recs += [
                "1. Further investigation by a SOC L2 analyst required.",
                "2. Verify context: was this activity planned or expected?",
                "3. Analyze Windows Event Viewer logs and application logs.",
                "4. Contact the user or IT team for additional context.",
            ]
            if root and root.get("sha1"):
                recs.append(
                    f"5. Check SHA1 ({root['sha1']}) on VirusTotal and MalwareBazaar."
                )
        elif score >= -2:
            recs += [
                "1. Verify that the application is listed in the authorized software inventory.",
                "2. Validate user context: was the installation voluntary?",
            ]
            if root and root.get("sha1"):
                recs.append(
                    f"3. Validate SHA1 ({root['sha1']}) on VirusTotal as a precaution."
                )
            recs.append("4. Create a SentinelOne exclusion if confirmed legitimate.")
        else:
            recs += [
                "1. Classify this alert as FALSE POSITIVE in SentinelOne.",
            ]
            if root and root.get("sha1"):
                recs.append(
                    f"2. Create an exclusion based on SHA1 ({root['sha1']}) "
                    f"to prevent recurrence."
                )
            recs.append("3. No remediation action required.")
        return recs

    # ------------------------------------------------------------------ #
    def _section_lsass(self) -> list:
        L = []
        if not self.lsass:
            return L
        for hit in self.lsass.get_hits():
            L.append(f"  {C.crit('[!!!]')} {hit['event_type']} at {hit['timestamp']}")
            if hit.get("src_cmd"):
                L.append(f"       Source  : {self._trunc(hit['src_cmd'], 100)}")
            if hit.get("tgt_cmd"):
                L.append(f"       Target  : {self._trunc(hit['tgt_cmd'], 100)}")
            if hit.get("access"):
                L.append(f"       Access  : {hit['access']}")
        return L

    # ------------------------------------------------------------------ #
    def _section_cmdline(self) -> list:
        L = []
        if not self.cmdline_an:
            return L
        findings = self.cmdline_an.get_findings()
        ep = self.cmdline_an.get_high_entropy_procs()
        if findings:
            L.append(f"  {len(findings)} suspicious pattern(s) in command lines:")
            for f in findings:
                L.append(f"\n    [{f['severity']}] {f['description']}")
                L.append(f"    MITRE  : {f['mitre']}")
                L += self._wrap("    Extract: ...", f["context"], 120)
                L[-1] += "..."
        if ep:
            L.append(f"\n  {len(ep)} high-entropy executable name(s):")
            for e in ep:
                L.append(f"    H={e['entropy']}  {C.high(e['name'])}  —  {self._trunc(e['cmdline'], 80)}")
        return L

    # ------------------------------------------------------------------ #
    def _section_temporal(self) -> list:
        L = []
        if not self.temporal:
            return L
        for seq in self.temporal.get_sequences():
            L.append(
                f"  {C.high('[SEQUENCE]')} {seq['description']}"
            )
            L.append(
                f"             {seq['cat_a']} → {seq['cat_b']} "
                f"in {seq['delta_sec']}s (window: {seq['window_sec']}s)"
            )
        return L

    # ------------------------------------------------------------------ #
    def _section_multi_ioc(self) -> list:
        L = []
        has_any = False

        # --- MalwareBazaar ---
        if self.mb:
            hashes = []
            root = self.proc.get_root()
            if root and root.get("sha1"):
                hashes.append(("Root", root.get("display_name", "?"), root["sha1"]))
            for child in self.proc.get_children():
                sha = child.get("sha1", "")
                if sha and child.get("signed") == "unsigned":
                    name = (child.get("display_name", "") or "").replace("\x00", "").strip() or "?"
                    hashes.append(("Child", name, sha))
            seen_mb = set()
            for role, name, sha in hashes[:8]:
                if sha in seen_mb:
                    continue
                seen_mb.add(sha)
                res = self.mb.lookup(sha)
                if res.get("found"):
                    has_any = True
                    L.append(f"\n  {C.crit('[MalwareBazaar]')} {role}: {C.bold(name)}")
                    L.append(f"     SHA1       : {C.dim(sha)}")
                    L.append(f"     File type  : {res.get('file_type','?')}")
                    L.append(f"     Signature  : {C.crit(res['signature']) if res.get('signature') else C.dim('N/A')}")
                    L.append(f"     First seen : {res.get('first_seen','?')}")
                    if res.get("tags"):
                        L.append(f"     Tags       : {', '.join(res['tags'][:5])}")

        # --- AlienVault OTX ---
        if self.otx:
            # Hashes
            root = self.proc.get_root()
            if root and root.get("sha1"):
                res = self.otx.lookup_hash(root["sha1"])
                if res.get("found"):
                    has_any = True
                    L.append(f"\n  {C.high('[OTX]')} Root hash found in {res['pulse_count']} pulse(s)")
                    if res.get("malware_families"):
                        L.append(f"     Families : {', '.join(res['malware_families'])}")
            # IPs externes inconnues
            for ext in self.net.get_suspicious_external()[:5]:
                ip = ext["dst_ip"]
                res = self.otx.lookup_ip(ip)
                if res.get("found"):
                    has_any = True
                    L.append(f"\n  {C.high('[OTX]')} IP {ip} in {res['pulse_count']} pulse(s)")
                    if res.get("country"):
                        L.append(f"     Country  : {res['country']}")
            # Domaines inconnus
            for q in self.net.dns_queries[:10]:
                domain = q.get("request", "").rstrip(".")
                if not domain:
                    continue
                res = self.otx.lookup_domain(domain)
                if res.get("found"):
                    has_any = True
                    L.append(f"\n  {C.high('[OTX]')} Domain {domain} in {res['pulse_count']} pulse(s)")

        # --- Shodan ---
        if self.shodan:
            for ext in self.net.get_suspicious_external()[:5]:
                ip = ext["dst_ip"]
                res = self.shodan.lookup(ip)
                if res.get("found"):
                    has_any = True
                    L.append(f"\n  {C.info('[Shodan]')} {ip}")
                    L.append(f"     Org       : {res.get('org','?')}")
                    L.append(f"     Country   : {res.get('country','?')}")
                    if res.get("ports"):
                        L.append(f"     Open ports: {', '.join(str(p) for p in res['ports'][:10])}")
                    if res.get("vulns"):
                        L.append(f"     {C.crit('Vulns')}     : {', '.join(res['vulns'])}")
                    if res.get("tags"):
                        L.append(f"     Tags      : {', '.join(res['tags'])}")
                    if res.get("hostnames"):
                        L.append(f"     Hostnames : {', '.join(res['hostnames'])}")

        if not has_any and (self.mb or self.otx or self.shodan):
            L.append("  No additional IOC hits from configured sources.")
        return L

    # ------------------------------------------------------------------ #
    def _section_beacons(self, beacons: list) -> list:
        L = []
        for b in beacons:
            is_unknown = "INCONNU" in b["owner"]
            ip_col = C.high(b["dst_ip"]) if is_unknown else C.ok(b["dst_ip"])
            L.append(
                f"  {C.crit('[BEACON]')} {ip_col}:{b['dst_port']}  —  {b['owner']}"
            )
            L.append(
                f"     Connections    : {b['count']}"
            )
            L.append(
                f"     Mean interval  : {b['mean_interval_s']}s  (±{b['std_dev_s']}s, CV={b['cv']})"
            )
            L.append(
                f"     Time range     : {b['first_seen']} → {b['last_seen']}"
            )
        return L

    # ------------------------------------------------------------------ #
    def _section_user_agents(self, uas: list) -> list:
        L = []
        for ua in uas:
            sev = ua["severity"]
            L.append(f"\n  [{sev}] {ua['description']}")
            L.append(f"     UA  : {C.high(ua['user_agent'][:100])}")
            L.append(f"     URL : {self._trunc(ua['url'], 100)}")
        return L

    # ------------------------------------------------------------------ #
    def _section_sigma(self, hits: list) -> list:
        L = []
        sev_order = {"CRITICAL": C.crit, "HIGH": C.high, "MEDIUM": C.med,
                     "LOW": C.dim, "INFORMATIONAL": C.dim}
        for h in hits[:30]:
            fn    = sev_order.get(h["level"], C.dim)
            m_str = f"  [{', '.join(h['mitre'][:3])}]" if h["mitre"] else ""
            lvl_badge = fn("[" + h["level"] + "]")
            L.append(f"\n  {lvl_badge} {C.bold(h['title'])}{C.dim(m_str)}")
            L.append(f"       Category : {h['category']}")
            if h.get("description"):
                L += self._wrap("       Detail   : ", h["description"][:200], 90)
        if len(hits) > 30:
            L.append(C.dim(f"\n  ... and {len(hits)-30} more Sigma hits"))
        return L

    # ------------------------------------------------------------------ #
    def _section_process_graph(self, anomalies: list) -> list:
        L = []
        sev_fn = {"CRITIQUE": C.crit, "ELEVE": C.high, "MOYEN": C.med}
        for a in anomalies:
            fn = sev_fn.get(a["severity"], C.dim)
            type_badge = fn("[" + a["type"] + "]")
            L.append(f"  {type_badge} {a['description']}")
        return L

    # ------------------------------------------------------------------ #
    def _section_stats(self) -> list:
        L = []
        stats = self.stats.get_stats()
        if stats.get("cmd_len"):
            s = stats["cmd_len"]
            L.append(f"  Cmdline length      : mean={s['mean']}  std={s['std']}")
        if stats.get("cmd_entropy"):
            s = stats["cmd_entropy"]
            L.append(f"  Cmdline entropy     : mean={s['mean']}  std={s['std']} bits")
        if stats.get("rare_pairs"):
            L.append(f"  Rare parent\u2192child   : {', '.join(stats['rare_pairs'][:5])}")

        ah = self.stats.get_after_hours()
        if ah:
            L.append(f"\n  After-hours events  : {len(ah)}")
            for ev in ah[:3]:
                ts = ev["timestamp_raw"] if ev.get("timestamp_raw") else "?"
                L.append(f"    [{ts}] {ev['event_type']}")

        outliers = self.stats.get_outliers()
        if outliers:
            L.append(f"\n  IsolationForest outliers ({len(outliers)}):")
            for o in outliers[:5]:
                L.append(f"    score={o['score']:+.3f}  H={o['entropy']}  "
                         f"{o['event_type']}  {o['cmd'][:60]}")
        elif self.stats.has_pyod:
            L.append("\n  IsolationForest: no outliers detected.")
        else:
            L.append("\n  (pyod not installed \u2014 install with: pip install pyod)")
        return L

    # ------------------------------------------------------------------ #
    def _section_yara(self, hits: list) -> list:
        L = []
        for h in hits[:20]:
            sev_fn    = C.crit if h["severity"] == "CRITIQUE" else C.high
            sev_badge = sev_fn("[" + h["severity"] + "]")
            L.append(f"\n  {sev_badge} Rule: {C.bold(h['rule'])}")
            L.append(f"       Context   : {h['context']}")
            L.append(f"       Preview   : {C.dim(h['preview'][:80])}")
            if h.get("tags"):
                L.append(f"       Tags      : {', '.join(h['tags'][:5])}")
        return L

    # ------------------------------------------------------------------ #
    def _section_attack_enrichment(self) -> list:
        L = []
        techniques = self.behav.get_all_techniques()
        all_tids   = [t["id"] for t in techniques]

        # Threat groups across all techniques
        groups = self.mitre_enricher.get_groups_for_techniques(all_tids)
        if groups:
            L.append(f"  Threat groups using detected techniques ({len(groups)}):")
            for g in groups[:8]:
                L.append(f"    {C.high(g['id'])}  {g['name']}")

        # Per-technique enrichment
        L.append("")
        for t in techniques[:10]:
            tid  = t["id"]
            info = self.mitre_enricher.get_technique_info(tid)
            if not info:
                continue
            L.append(f"\n  {C.info(tid)} \u2014 {C.bold(info.get('name',''))}"
                     f"  [{info.get('tactic','')}]")
            if info.get("detection"):
                L += self._wrap("    Detection : ", info["detection"][:300], 90)
            if info.get("mitigations"):
                mits = "  |  ".join(f"{m['id']} {m['name']}" for m in info["mitigations"][:3])
                L.append(f"    Mitigations: {C.ok(mits)}")
            if info.get("groups"):
                grps = ", ".join(f"{g['id']} ({g['name']})" for g in info["groups"][:3])
                L.append(f"    Groups     : {C.high(grps)}")

        # Navigator layer hint
        if all_tids:
            L.append(f"\n  {C.dim('[TIP] Use --json to get the ATT&CK Navigator layer JSON.')}")
        return L

    # ------------------------------------------------------------------ #
    def _section_ioc_extract(self) -> list:
        L = []
        iocs = self.ioc_an.get_iocs()
        for kind, items in iocs.items():
            if items:
                L.append(f"  {kind.upper()} ({len(items)}):")
                for item in items[:10]:
                    L.append(f"    {C.high(item)}")
        return L

    # ------------------------------------------------------------------ #
    def generate_json(self) -> dict:
        from datetime import datetime as _dt

        root = self.proc.get_root()
        ts_min, ts_max, dur = self.timeline.get_time_range()

        # ── Identification ──
        proc_name = None
        if root:
            _dn = (root.get("display_name", "") or "").replace("\x00", "").strip()
            _cmd_raw = (root.get("cmdline", "") or "").replace('"', '').strip()
            _cmd_exe = self._extract_exe_name(_cmd_raw)
            # Prefer exe name for "Process" field; display_name only as last resort
            proc_name = _cmd_exe or _dn or "Unknown"

        av_sev, av_desc = self.proc.get_attack_vector()
        electron_meta = self.proc.get_electron_meta() if self.proc.is_electron() else {}

        # Build execution chain
        exec_chain = []
        parent_chain = self.proc.get_full_parent_chain()
        for level, cmdline in parent_chain:
            exec_chain.append({"level": level, "cmdline": cmdline})
        if root:
            exec_chain.append({"level": "src.process", "cmdline": root.get("cmdline", "")})

        # Extract target file for script hosts (wscript, cscript, mshta, etc.)
        target_file = ""
        if root:
            _cmd = root.get("cmdline", "") or ""
            _pn = proc_name.lower()
            _script_exts = r'\.(?:vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)'
            if any(h in _pn for h in ("wscript", "cscript", "mshta", "powershell", "cmd.exe")):
                # Try quoted path first (handles filenames with spaces)
                _tf_match = re.search(r'"([^"]+' + _script_exts + r')"', _cmd, re.IGNORECASE)
                if not _tf_match:
                    # Try unquoted path
                    _tf_match = re.search(r'(?:^|\s)([^\s"<>|&]+' + _script_exts + r')\b', _cmd, re.IGNORECASE)
                if _tf_match:
                    target_file = _tf_match.group(1)
                    # Show just the filename, not the full path
                    target_file = Path(target_file).name if target_file else ""

        identification = {
            "process":      proc_name,
            "cmdline":      root.get("cmdline") if root else None,
            "target_file":  target_file,
            "sha1":         root.get("sha1") if root else None,
            "signed":       root.get("signed") if root else None,
            "publisher":    root.get("publisher") if root else None,
            "parent":       root.get("parent_cmdline") if root else None,
            "user":         self.events[0].get("user") if self.events else None,
            "agent_uuid":   self.events[0].get("agent_uuid", "") if self.events else "",
            "storyline_id": self.events[0].get("storyline_id", "") if self.events else "",
            "is_electron":  self.proc.is_electron(),
            "electron_meta": electron_meta,
            "attack_vector": {"severity": av_sev, "description": av_desc} if av_sev else {},
            "execution_chain": exec_chain,
        }

        # ── Behavioral indicators (enriched via contextualizer) ──
        indicators_enriched = []
        sev_dist = {"CRITIQUE": 0, "ELEVE": 0, "MOYEN": 0, "FAIBLE": 0, "INFO": 0}
        for ind in self.behav.get_unique():
            analyzed = self.ctx.analyze(ind)
            occ = self.behav.get_occurrence_count(ind["name"])
            entry = {
                "name":        analyzed["name"],
                "category":    analyzed["category"],
                "description": analyzed.get("description", ""),
                "severity":    analyzed["severity"],
                "assessment":  analyzed.get("assessment", ""),
                "explanation": analyzed.get("reasoning", ""),
                "false_positive": analyzed.get("is_fp", False),
                "occurrences": occ,
                "context":     ind.get("description", ""),
                "timestamp":   ind.get("timestamp", ""),
                "mitre_techniques": [
                    {"id": t["id"], "name": t.get("name", "")}
                    for t in ind.get("mitre_techniques", [])
                ],
            }
            sev_dist[analyzed["severity"]] = sev_dist.get(analyzed["severity"], 0) + 1
            indicators_enriched.append(entry)

        # ── Metrics ──
        n_indicators = len(indicators_enriched)
        n_critical = len(self.behav.get_critical_indicators())
        n_ext = len(self.net.get_unique_external())
        n_unk = len(self.net.get_suspicious_external())
        script_findings = self.scripts.analyze()
        persistence_hits = self.reg.get_persistence_hits()
        suspicious_files = self.files.get_suspicious_files()
        sigma_hits = self.sigma.evaluate_all(self.events) if self.sigma and self.sigma.available else []
        yara_hits = self.yara_an.get_hits() if self.yara_an and self.yara_an.available else []
        pg_anomalies = self.process_graph.get_anomalies() if self.process_graph and self.process_graph.available else []
        stat_outliers = self.stats.get_outliers() if self.stats else []

        metrics = {
            "total_events":        len(self.events),
            "indicators":          n_indicators,
            "critical":            n_critical,
            "ext_connections":     n_ext,
            "unknown_connections": n_unk,
            "script_findings":     len(script_findings),
            "persistence_keys":    len(persistence_hits),
            "suspicious_files":    len(suspicious_files),
            "sigma_matches":       len(sigma_hits),
            "yara_matches":        len(yara_hits),
            "graph_anomalies":     len(pg_anomalies),
            "stat_outliers":       len(stat_outliers),
        }

        # ── Timeline ──
        # Event type distribution
        evt_dist = defaultdict(int)
        for ev in self.events:
            evt_dist[ev["event_type"]] += 1

        # Phases
        phases_raw = self.timeline.get_phases()
        phases = []
        for pname, pevents in phases_raw.items():
            if not pevents:
                continue
            p_ts = [e["timestamp"] for e in pevents if e["timestamp"]]
            phases.append({
                "name":        pname,
                "event_count": len(pevents),
                "start":       min(p_ts).strftime("%H:%M:%S") if p_ts else "",
                "end":         max(p_ts).strftime("%H:%M:%S") if p_ts else "",
            })

        timeline = {
            "start":                   ts_min.strftime("%Y-%m-%d %H:%M:%S") if ts_min else None,
            "end":                     ts_max.strftime("%Y-%m-%d %H:%M:%S") if ts_max else None,
            "duration_seconds":        dur or 0,
            "event_type_distribution": dict(evt_dist),
            "phases":                  phases,
        }

        # ── Attack chains ──
        corr = self.corr or CorrelationEngine(self.behav)
        attack_chains = [c["name"] for c in
                         corr.get_matched_chains(ctx=self.ctx)]

        # ── MITRE ATT&CK ──
        techniques = self.behav.get_all_techniques()
        # Build heatmap: tactic → list of technique ids (from indicators)
        heatmap = {}
        for ind in self.behav.get_unique():
            tactics = ind.get("mitre_tactics", [])
            techs   = ind.get("mitre_techniques", [])
            for tac in tactics:
                for tech in techs:
                    tid = tech["id"]
                    heatmap.setdefault(tac, [])
                    if tid not in heatmap[tac]:
                        heatmap[tac].append(tid)
        mitre_attack = {
            "tactics":    self.behav.get_all_tactics(),
            "techniques": [{"id": t["id"], "name": t.get("name", "")} for t in techniques],
            "heatmap":    heatmap,
        }

        # ── Scripts ──
        scripts_data = {
            "summaries": self.scripts.get_all_scripts_summary(),
            "findings":  script_findings,
        }

        # ── Modules ──
        mod_summary = self.modules.get_summary()
        # Add 'description' alias for 'analysis' (HTML renderer uses m.description||m.reason)
        suspicious_mods_raw = self.modules.get_suspicious()
        suspicious_mods_normalized = []
        for m in suspicious_mods_raw:
            entry = dict(m)
            if "analysis" in entry and "description" not in entry:
                entry["description"] = entry["analysis"]
            suspicious_mods_normalized.append(entry)
        modules_data = {
            "total":      mod_summary.get("total_modules", 0),
            "suspicious": suspicious_mods_normalized,
        }

        # ── Network ──
        ext_connections = []
        for conn in self.net.get_unique_external():
            ip_addr = conn.get("dst_ip", conn.get("ip", ""))
            entry = {
                "dst_ip":    ip_addr,
                "dst_port":  conn.get("dst_port", conn.get("port", "")),
                "direction": conn.get("direction", conn.get("event_type", "")),
                "domain":    conn.get("domain", "") or self.net.ip_to_domain.get(ip_addr, ""),
            }
            # Add geo info from ip_info
            ip = entry["dst_ip"]
            if ip and ip in self.ip_info:
                entry["geo"] = self.ip_info[ip]
            ext_connections.append(entry)

        network = {
            "external_connections": ext_connections,
            "internal":            self.net.get_unique_internal(),
            "suspicious":          self.net.get_suspicious_external(),
            "dns_queries":         [{"request": q["request"], "resolved": q["resolved"]}
                                    for q in self.net.dns_queries],
            "c2_beacons":              self.net.detect_c2_beacon(),
            "suspicious_user_agents":  self.net.get_suspicious_user_agents(),
            "listeners":               getattr(self.net, 'listeners', []),
            "http_requests":           self.net.http_requests[:50],
        }

        # ── Process tree ──
        children_list = []
        for child in self.proc.get_children():
            children_list.append({
                "display_name": child.get("display_name", ""),
                "cmdline":      child.get("cmdline", ""),
                "sha1":         child.get("sha1", ""),
                "signed":       child.get("signed", ""),
                "publisher":    child.get("publisher", ""),
            })
        process_tree = {
            "root":     {
                "display_name": root.get("display_name", "") if root else "",
                "cmdline":      root.get("cmdline", "") if root else "",
                "sha1":         root.get("sha1", "") if root else "",
                "signed":       root.get("signed", "") if root else "",
                "publisher":    root.get("publisher", "") if root else "",
            },
            "children": children_list,
        }

        # ── Files ──
        top_dirs = self.files.get_top_dirs(10)
        files_data = {
            "summary":    self.files.get_summary(),
            "top_dirs":   [[d, c] for d, c in top_dirs.items()],
            "suspicious": [{"path": f.get("path", ""), "sha1": f.get("sha1", "")}
                           for f in suspicious_files],
        }

        # ── Registry ──
        registry_data = {
            "summary":          self.reg.get_summary(),
            "persistence_hits": persistence_hits,
        }

        # ── Tasks ──
        tasks_data = self.tasks.tasks if self.tasks else []

        # ── LSASS ──
        lsass_data = []
        if self.lsass and self.lsass.has_lsass_access():
            for h in self.lsass.get_hits():
                lsass_data.append({
                    "source":    h.get("src_cmd", h.get("process", "")),
                    "access":    h.get("access", h.get("access_mask", "")),
                    "timestamp": h.get("timestamp", ""),
                })

        # ── Command line analysis ──
        cmdline_data = {}
        if self.cmdline_an:
            raw_findings = self.cmdline_an.get_findings()
            # Add 'cmdline' field as alias for 'context' (used by HTML renderer)
            findings_normalized = []
            for f in raw_findings:
                entry = dict(f)
                if "context" in entry and "cmdline" not in entry:
                    entry["cmdline"] = entry["context"]
                findings_normalized.append(entry)
            cmdline_data = {
                "findings":     findings_normalized,
                "high_entropy": self.cmdline_an.get_high_entropy_procs(),
            }

        # ── Temporal sequences ──
        temporal_data = []
        if self.temporal:
            temporal_data = self.temporal.get_sequences()

        # ── Sigma matches ──
        sigma_data = []
        for hit in sigma_hits:
            sigma_data.append({
                "title":       hit.get("title", hit.get("name", "")),
                "level":       hit.get("level", hit.get("severity", "info")),
                "description": hit.get("description", ""),
                "category":    hit.get("category", ""),
                "tags":        hit.get("tags", []),
            })

        # ── Process graph ──
        process_graph_data = {"available": False}
        if self.process_graph and self.process_graph.available:
            process_graph_data = {
                "available":  True,
                "anomalies":  pg_anomalies,
            }

        # ── Statistical analysis ──
        stat_data = {}
        if self.stats:
            raw_stats = self.stats.get_stats()
            after_h_clean = []
            for ev in self.stats.get_after_hours():
                after_h_clean.append({
                    "timestamp_raw": ev.get("timestamp_raw", str(ev.get("timestamp", ""))),
                    "event_type":    ev.get("event_type", ""),
                    "process":       (ev.get("details") or {}).get("src.process.cmdline", "")[:120],
                })
            stat_data = {
                "stats":       raw_stats,
                "outliers":    stat_outliers,
                "after_hours": after_h_clean,
                "has_pyod":    self.stats.has_pyod if hasattr(self.stats, 'has_pyod') else False,
            }

        # ── YARA matches ──
        yara_data = []
        for h in yara_hits:
            yara_data.append({
                "rule":     h.get("rule", h.get("name", "")),
                "severity": h.get("severity", "MOYEN"),
                "context":  h.get("context", ""),
                "preview":  h.get("preview", ""),
                "tags":     h.get("tags", []),
            })

        # ── MITRE enrichment ──
        mitre_enrichment = {}
        if self.mitre_enricher and self.mitre_enricher.available:
            all_tids = [t["id"] for t in techniques]
            groups = self.mitre_enricher.get_groups_for_techniques(all_tids)
            enriched_techs = []
            for t in techniques[:10]:
                tid = t["id"]
                info = self.mitre_enricher.get_technique_info(tid)
                if not info:
                    continue
                enriched_techs.append({
                    "id":          tid,
                    "name":        info.get("name", ""),
                    "tactic":      info.get("tactic", ""),
                    "detection":   info.get("detection", ""),
                    "mitigations": info.get("mitigations", []),
                    "groups":      info.get("groups", []),
                })
            mitre_enrichment = {
                "groups":     groups,
                "techniques": enriched_techs,
            }

        # ── IOC extraction ──
        ioc_data = {}
        if self.ioc_an and self.ioc_an.available and self.ioc_an.has_findings():
            ioc_data = dict(self.ioc_an.get_iocs())

        # Enrich with SHA1/SHA256 hashes from structured event fields
        seen_hashes = set(ioc_data.get("hashes", []))
        sha1_map = {}  # sha1 → {role, name}
        for ev in self.events:
            d = ev["details"]
            for field in ("src.process.image.sha1", "tgt.process.image.sha1",
                          "tgt.file.sha1", "src.process.parent.image.sha1"):
                h = (d.get(field, "") or "").strip().lower()
                if h and len(h) == 40 and h not in seen_hashes:
                    seen_hashes.add(h)
                    # Determine context: prefer exe name from cmdline over displayName
                    role = field.split(".")[0]  # src or tgt
                    if "file" in field:
                        # tgt.file.sha1 → show file path
                        name = d.get("tgt.file.path", "") or ""
                    else:
                        # Process hash → show exe name from cmdline
                        cmdline = d.get(f"{role}.process.cmdline", "") or ""
                        exe_name = self._extract_exe_name(cmdline)
                        display = d.get(f"{role}.process.displayName", "") or ""
                        if "parent" in field:
                            cmdline = d.get("src.process.parent.cmdline", "") or ""
                            exe_name = self._extract_exe_name(cmdline)
                            display = d.get("src.process.parent.displayName", "") or ""
                        name = exe_name or cmdline or display or ""
                    sha1_map[h] = {"sha1": h, "source": field, "name": Path(name.replace('"', '').strip()).name if name else ""}
        if sha1_map:
            ioc_data.setdefault("hashes", [])
            ioc_data["hashes"].extend(list(sha1_map.keys()))
            ioc_data["file_hashes"] = list(sha1_map.values())

        # ── VirusTotal ──
        vt_data = []
        if self.vt:
            vt_section = self._section_virustotal_json()
            if vt_section:
                vt_data = vt_section

        # ── Threat Intelligence (MB / OTX / Shodan) ──
        ti_data = {"malwarebazaar": [], "otx_hashes": [], "otx_ips": [],
                   "otx_domains": [], "shodan": [], "_enabled": []}
        if self.mb:
            ti_data["_enabled"].append("mb")
        if self.otx:
            ti_data["_enabled"].append("otx")
        if self.shodan:
            ti_data["_enabled"].append("shodan")

        if self.mb:
            root = self.proc.get_root()
            hashes_mb = []
            if root and root.get("sha1"):
                hashes_mb.append(("Root", (root.get("display_name","") or "").strip(), root["sha1"]))
            for child in self.proc.get_children():
                sha = child.get("sha1","")
                if sha and child.get("signed") == "unsigned":
                    n = (child.get("display_name","") or "").replace("\x00","").strip() or "?"
                    hashes_mb.append(("Child", n, sha))
            seen_mb = set()
            for role, name, sha in hashes_mb[:8]:
                if sha in seen_mb:
                    continue
                seen_mb.add(sha)
                res = self.mb.lookup(sha)
                if res.get("found"):
                    ti_data["malwarebazaar"].append({
                        "role": role, "name": name, "sha1": sha,
                        "file_type": res.get("file_type",""),
                        "signature": res.get("signature",""),
                        "first_seen": res.get("first_seen",""),
                        "tags": res.get("tags",[]),
                    })

        if self.otx:
            root = self.proc.get_root()
            if root and root.get("sha1"):
                res = self.otx.lookup_hash(root["sha1"])
                if res.get("found"):
                    ti_data["otx_hashes"].append({
                        "sha1": root["sha1"],
                        "pulse_count": res.get("pulse_count",0),
                        "malware_families": res.get("malware_families",[]),
                    })
            for ext in self.net.get_suspicious_external()[:5]:
                ip = ext.get("dst_ip","")
                res = self.otx.lookup_ip(ip)
                if res.get("found"):
                    ti_data["otx_ips"].append({
                        "ip": ip, "pulse_count": res.get("pulse_count",0),
                        "country": res.get("country",""),
                    })
            for q in self.net.dns_queries[:10]:
                domain = q.get("request","").rstrip(".")
                if not domain:
                    continue
                res = self.otx.lookup_domain(domain)
                if res.get("found"):
                    ti_data["otx_domains"].append({
                        "domain": domain, "pulse_count": res.get("pulse_count",0),
                    })

        if self.shodan:
            for ext in self.net.get_suspicious_external()[:5]:
                ip = ext.get("dst_ip","")
                res = self.shodan.lookup(ip)
                if res.get("found"):
                    ti_data["shodan"].append({
                        "ip": ip,
                        "org": res.get("org",""),
                        "country": res.get("country",""),
                        "ports": res.get("ports",[]),
                        "vulns": res.get("vulns",[]),
                        "tags": res.get("tags",[]),
                        "hostnames": res.get("hostnames",[]),
                    })

        # ── Verdict (with recommendations) ──
        verdict = dict(self.verdict)
        verdict["recommendations"] = self._generate_recommendations()

        # Detect CSV format from events
        _fmt = self.events[0].get("_fmt", "DV") if self.events else "DV"

        return {
            "meta": {
                "analyzer_version": f"{__tool__} v{__version__}",
                "generated_at":     _dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                "csv_file":         "",
                "csv_format":       _fmt,
                "frameworks": {
                    "pyod":      HAS_PYOD,
                    "yara":      HAS_YARA,
                    "networkx":  HAS_NX,
                    "yaml/sigma": HAS_YAML,
                    "ioc_finder": HAS_IOC,
                    "mitre_lib": HAS_MITRE_LIB,
                },
            },
            "identification":        identification,
            "verdict":               verdict,
            "metrics":               metrics,
            "timeline":              timeline,
            "behavioral_indicators": indicators_enriched,
            "severity_distribution": sev_dist,
            "attack_chains":         attack_chains,
            "mitre_attack":          mitre_attack,
            "scripts":               scripts_data,
            "modules":               modules_data,
            "network":               network,
            "process_tree":          process_tree,
            "files":                 files_data,
            "registry":              registry_data,
            "tasks":                 tasks_data,
            "lsass":                 lsass_data,
            "cmdline_analysis":      cmdline_data,
            "temporal_sequences":    temporal_data,
            "sigma_matches":         sigma_data,
            "process_graph":         process_graph_data,
            "statistical_analysis":  stat_data,
            "yara_matches":          yara_data,
            "mitre_enrichment":      mitre_enrichment,
            "ioc_extraction":        ioc_data,
            "virustotal":            vt_data,
            "_vt_enabled":           self.vt is not None,
            "threat_intelligence":   ti_data,
        }

    def _section_virustotal_json(self) -> list:
        """Build VT data for JSON export (matches _section_virustotal logic)."""
        if not self.vt:
            return []
        to_check = []
        root = self.proc.get_root()
        if root and root.get("sha1"):
            name = (root.get("display_name", "") or "").replace("\x00", "").strip()
            to_check.append(("Root process", name, root["sha1"]))
        for child in self.proc.get_children():
            sha = child.get("sha1", "")
            if sha and child.get("signed") == "unsigned":
                name = (child.get("display_name", "") or "").replace("\x00", "").strip() or "?"
                to_check.append(("Child process", name, sha))
        for s in self.files.get_suspicious_files():
            sha = s.get("sha1", "")
            if sha:
                fname = s["path"].replace("\\", "/").split("/")[-1]
                to_check.append(("Suspicious file", fname, sha))

        results = []
        seen = set()
        for role, name, sha in to_check[:10]:
            if sha in seen:
                continue
            seen.add(sha)
            res = self.vt.lookup(sha)
            # Normalize result: add threat_type alias for threat field
            if res and res.get("threat"):
                res = dict(res)
                res["threat_type"] = res.get("threat", "")
            results.append({
                "role":   role,
                "name":   name,
                "sha1":   sha,
                "result": res or {},
            })

        # Check extracted URLs against VT (skip known-safe domains)
        _safe_domains = {"microsoft.com", "windows.com", "windowsupdate.com",
                         "office.com", "live.com", "bing.com", "google.com",
                         "googleapis.com", "gstatic.com", "github.com",
                         "digicert.com", "verisign.com", "symantec.com"}
        if self.ioc_an and hasattr(self.ioc_an, 'get_iocs'):
            ioc_urls = self.ioc_an.get_iocs().get("urls", [])
            for url in ioc_urls[:10]:
                u = url if isinstance(url, str) else str(url)
                # Extract domain
                dm = re.search(r'https?://([^/:]+)', u)
                if not dm:
                    continue
                domain = dm.group(1).lower()
                # Skip safe domains
                if any(domain.endswith(sd) for sd in _safe_domains):
                    continue
                res = self.vt.lookup_url(u)
                if res and res.get("threat"):
                    res = dict(res)
                    res["threat_type"] = res.get("threat", "")
                results.append({
                    "role":   "Extracted URL",
                    "name":   u,
                    "sha1":   "",
                    "result": res or {},
                })

        return results

    def _generate_recommendations(self) -> list:
        """Generate actionable recommendations based on verdict score."""
        recs = []
        v = self.verdict
        score = v["score"]
        if score >= 8:
            recs.append("IMMEDIATE: Isolate the endpoint from the network to prevent lateral movement.")
            recs.append("Collect a full forensic image before remediation.")
            recs.append("Check other endpoints for IOCs found in this analysis.")
        elif score >= 4:
            recs.append("Investigate the process execution chain and validate the binary's legitimacy.")
            recs.append("Check for similar detections on other endpoints in the environment.")
        elif score >= 1:
            recs.append("Review the behavioral indicators in context and validate with the end user.")
            recs.append("Monitor the endpoint for recurring suspicious activity.")
        if len(self.net.get_suspicious_external()) > 0:
            recs.append("Investigate unidentified external connections — verify destination IPs against threat intelligence.")
        if self.lsass and self.lsass.has_lsass_access():
            recs.append("CRITICAL: LSASS access detected — reset credentials for affected accounts immediately.")
        if len(self.reg.get_persistence_hits()) > 0:
            recs.append("Review and remove identified persistence mechanisms from the registry.")
        return recs

    # ------------------------------------------------------------------ #
    def generate_html(self) -> str:
        """Generate a professional, self-contained HTML SOC analysis report."""
        import html as _html

        def esc(s):
            return _html.escape(str(s or ""))

        root    = self.proc.get_root()
        v       = self.verdict
        score   = v["score"]
        ts_min, ts_max, dur = self.timeline.get_time_range()

        # Verdict classification
        verdict_txt = v["verdict"]
        if "TRUE POSITIVE" in verdict_txt and "LIKELY" not in verdict_txt:
            verdict_class, verdict_icon = "critical", "&#9888;"
        elif "LIKELY TRUE" in verdict_txt:
            verdict_class, verdict_icon = "high", "&#9888;"
        elif "UNDETERMINED" in verdict_txt:
            verdict_class, verdict_icon = "medium", "&#9679;"
        else:
            verdict_class, verdict_icon = "low", "&#10003;"

        score_class = ("critical" if score >= 8 else "high" if score >= 4
                       else "medium" if score >= 1 else "low")

        if root:
            _dn = (root.get("display_name", "") or "").replace("\x00","").strip()
            _cmd_raw = (root.get("cmdline", "") or "").replace('"','').strip()
            _cmd_exe = Path(_cmd_raw.split()[0]).name if _cmd_raw.split() else ""
            proc_name = _cmd_exe or _dn or "Unknown"
            sha1      = root.get("sha1", "") or "N/A"
            pub       = (root.get("publisher", "") or "").strip() or "No publisher"
            signed    = root.get("signed", "") or "N/A"
            cmdline   = root.get("cmdline", "") or ""
        else:
            proc_name, sha1, pub, signed, cmdline = "N/A", "N/A", "N/A", "N/A", ""
        _raw_user = self.events[0].get("user", "N/A") if self.events else "N/A"
        user      = _raw_user.split("osSrc")[0].strip() or "N/A"

        n_ind     = len(self.behav.get_unique())
        n_crit    = len(self.behav.get_critical_indicators())
        n_ext     = len(self.net.get_unique_external())
        n_unk     = len(self.net.get_suspicious_external())
        n_scr     = len(self.scripts.analyze())
        dur_str   = (f"{int(dur//60)}m {int(dur%60)}s" if dur and dur >= 60
                     else f"{int(dur or 0)}s")
        ts_range  = (f"{ts_min.strftime('%Y-%m-%d %H:%M:%S')} → {ts_max.strftime('%H:%M:%S')} ({dur_str})"
                     if ts_min else "N/A")

        # ---- CSS ----
        css = """
/* ── DESIGN SYSTEM ── */
[data-theme="dark"]{
  --bg-body:#0a0e1a;--bg-primary:#0f1923;--bg-card:#151d2b;--bg-card-hover:#1a2535;
  --bg-input:#1a2332;--border:#1e2d3d;--border-light:#253545;
  --text:#e2e8f0;--text-secondary:#8899aa;--text-muted:#556677;
  --accent:#3b82f6;--accent-glow:rgba(59,130,246,0.15);
  --surface:#151d2b;--surface2:#1a2535;--surface3:#0f1923;
  --primary:#3b82f6;--primary-d:#2563eb;--primary-l:rgba(59,130,246,0.12);
  --red:#ef4444;--red-l:rgba(239,68,68,0.12);--red-d:#f87171;
  --orange:#f97316;--orange-l:rgba(249,115,22,0.12);
  --yellow:#eab308;--yellow-l:rgba(234,179,8,0.12);
  --green:#22c55e;--green-l:rgba(34,197,94,0.12);--green-d:#4ade80;
  --blue:#3b82f6;--blue-l:rgba(59,130,246,0.12);--blue-d:#60a5fa;
  --purple:#a78bfa;--purple-l:rgba(139,92,246,0.15);
  --cyan:#22d3ee;--cyan-l:rgba(6,182,212,0.12);
  --shadow:0 2px 8px rgba(0,0,0,.35),0 1px 3px rgba(0,0,0,.25);
  --shadow-md:0 8px 24px rgba(0,0,0,.4),0 2px 8px rgba(0,0,0,.3);
  --shadow-lg:0 16px 48px rgba(0,0,0,.5),0 4px 16px rgba(0,0,0,.3);
  --dim:#8899aa;--dim2:#556677;
}
[data-theme="light"]{
  --bg-body:#f0f2f7;--bg-primary:#f8f9fc;--bg-card:#ffffff;--bg-card-hover:#f8faff;
  --bg-input:#f0f2f7;--border:#e2e6ef;--border-light:#eef1f8;
  --text:#1a1d2e;--text-secondary:#5a6178;--text-muted:#8a91a8;
  --accent:#4f46e5;--accent-glow:rgba(79,70,229,0.10);
  --surface:#ffffff;--surface2:#f8f9fc;--surface3:#f0f2f7;
  --primary:#4f46e5;--primary-d:#4338ca;--primary-l:rgba(79,70,229,0.08);
  --red:#dc2626;--red-l:#fef2f2;--red-d:#b91c1c;
  --orange:#ea580c;--orange-l:#fff7ed;
  --yellow:#d97706;--yellow-l:#fffbeb;
  --green:#16a34a;--green-l:#f0fdf4;--green-d:#15803d;
  --blue:#2563eb;--blue-l:#eff6ff;--blue-d:#1d4ed8;
  --purple:#7c3aed;--purple-l:#f5f3ff;
  --cyan:#0891b2;--cyan-l:#ecfeff;
  --shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
  --shadow-md:0 4px 16px rgba(0,0,0,.08),0 2px 6px rgba(0,0,0,.04);
  --shadow-lg:0 10px 40px rgba(0,0,0,.1),0 4px 12px rgba(0,0,0,.05);
  --dim:#64748b;--dim2:#94a3b8;
}
:root{
  --critical:#ef4444;--critical-bg:rgba(239,68,68,0.12);
  --high:#f97316;--high-bg:rgba(249,115,22,0.12);
  --medium:#eab308;--medium-bg:rgba(234,179,8,0.12);
  --low:#22c55e;--low-bg:rgba(34,197,94,0.12);
  --info:#3b82f6;--info-bg:rgba(59,130,246,0.12);
  --radius:12px;--radius-sm:8px;--radius-xs:6px;
  --font-sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
  --font-mono:'Cascadia Code','Fira Code','JetBrains Mono','Courier New',monospace;
  --transition:all .2s cubic-bezier(.4,0,.2,1);
}

*{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{background:var(--bg-body);color:var(--text);font-family:var(--font-sans);
  font-size:14px;line-height:1.65;min-height:100vh;transition:background .3s,color .3s;
  padding-top:60px;}
a{color:var(--blue);text-decoration:none;transition:color .15s;}
a:hover{text-decoration:underline;color:var(--blue-d);}
code{font-family:var(--font-mono);font-size:12px;
  background:var(--surface3);border-radius:4px;padding:2px 6px;transition:background .2s;}

/* ── STICKY HEADER ── */
.top-bar{position:fixed;top:0;left:0;right:0;z-index:100;
  background:rgba(15,25,35,0.75);backdrop-filter:blur(16px) saturate(180%);
  -webkit-backdrop-filter:blur(16px) saturate(180%);
  border-bottom:1px solid var(--border);transition:background .3s;}
[data-theme="light"] .top-bar{background:rgba(248,249,252,0.8);}
.top-bar-inner{max-width:1440px;margin:0 auto;padding:0 32px;height:56px;
  display:flex;align-items:center;justify-content:space-between;}
.brand{display:flex;align-items:center;gap:12px;}
.brand-icon{width:34px;height:34px;
  background:linear-gradient(135deg,var(--accent),#7c3aed);
  border-radius:9px;display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:800;font-size:14px;flex-shrink:0;
  box-shadow:0 2px 8px rgba(59,130,246,.3);}
.brand-title{font-size:14px;font-weight:800;color:var(--text);letter-spacing:-.3px;}
.brand-sub{font-size:10px;color:var(--dim);font-weight:500;letter-spacing:.3px;}
.top-actions{display:flex;align-items:center;gap:8px;}
.theme-toggle{display:flex;align-items:center;justify-content:center;
  width:36px;height:36px;border-radius:var(--radius-sm);cursor:pointer;
  font-size:18px;color:var(--dim);background:var(--surface3);
  border:1px solid var(--border);transition:var(--transition);}
.theme-toggle:hover{background:var(--primary-l);color:var(--accent);border-color:var(--accent);}
.theme-icon{line-height:1;}
.btn-print{padding:6px 14px;border-radius:var(--radius-sm);cursor:pointer;
  font-size:12px;font-weight:600;color:var(--dim);background:var(--surface3);
  border:1px solid var(--border);transition:var(--transition);font-family:var(--font-sans);}
.btn-print:hover{background:var(--primary-l);color:var(--accent);border-color:var(--accent);}

/* ── VERDICT HERO ── */
.verdict-hero{max-width:1440px;margin:20px auto 0;padding:28px 32px;
  border-radius:var(--radius);display:flex;align-items:center;gap:28px;flex-wrap:wrap;
  transition:var(--transition);border:1px solid var(--border);}
.verdict-hero.critical{background:linear-gradient(135deg,rgba(239,68,68,.12),rgba(239,68,68,.04));
  border-color:rgba(239,68,68,.25);}
.verdict-hero.high{background:linear-gradient(135deg,rgba(249,115,22,.12),rgba(249,115,22,.04));
  border-color:rgba(249,115,22,.25);}
.verdict-hero.medium{background:linear-gradient(135deg,rgba(234,179,8,.1),rgba(234,179,8,.03));
  border-color:rgba(234,179,8,.2);}
.verdict-hero.low{background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.03));
  border-color:rgba(34,197,94,.2);}
[data-theme="light"] .verdict-hero.critical{background:linear-gradient(135deg,#fef2f2,#fff1f2);border-color:#fecaca;}
[data-theme="light"] .verdict-hero.high{background:linear-gradient(135deg,#fff7ed,#fffcfa);border-color:#fed7aa;}
[data-theme="light"] .verdict-hero.medium{background:linear-gradient(135deg,#fffbeb,#fffefc);border-color:#fde68a;}
[data-theme="light"] .verdict-hero.low{background:linear-gradient(135deg,#f0fdf4,#fafffe);border-color:#bbf7d0;}
.vh-gauge{text-align:center;min-width:120px;flex-shrink:0;}
.vh-gauge svg{overflow:visible;}
.vh-center{flex:1;min-width:200px;}
.vh-verdict{font-size:22px;font-weight:800;letter-spacing:-.4px;margin-bottom:4px;}
.verdict-hero.critical .vh-verdict{color:var(--critical);}
.verdict-hero.high .vh-verdict{color:var(--high);}
.verdict-hero.medium .vh-verdict{color:var(--medium);}
.verdict-hero.low .vh-verdict{color:var(--low);}
.vh-confidence{font-size:13px;color:var(--dim);font-weight:500;}
.vh-stats{display:flex;gap:20px;flex-wrap:wrap;align-items:center;}
.vh-stat{text-align:center;min-width:70px;}
.vh-stat-num{font-size:24px;font-weight:800;line-height:1.1;}
.vh-stat-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:700;margin-top:2px;}

/* ── BENTO METRICS GRID ── */
.bento-grid{max-width:1440px;margin:16px auto 0;padding:0 32px;
  display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:14px;}
.mc{background:var(--bg-card);border-radius:var(--radius);padding:18px 18px 14px;
  box-shadow:var(--shadow);border:1px solid var(--border);
  transition:all .25s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden;}
.mc::after{content:'';position:absolute;inset:0;border-radius:var(--radius);
  background:linear-gradient(135deg,transparent 60%,var(--accent-glow));pointer-events:none;opacity:0;transition:opacity .3s;}
.mc:hover{box-shadow:var(--shadow-md);transform:translateY(-2px);border-color:var(--border-light);}
.mc:hover::after{opacity:1;}
.mc.alert{border-top:3px solid var(--critical);}
.mc.warn{border-top:3px solid var(--high);}
.mc.ok{border-top:3px solid var(--low);}
.mc.info{border-top:3px solid var(--accent);}
.mc .mv{font-size:30px;font-weight:800;line-height:1.1;font-family:var(--font-sans);}
.mc .ml{font-size:11px;color:var(--dim);margin-top:5px;line-height:1.3;}
.mc.alert .mv{color:var(--critical);}
.mc.warn .mv{color:var(--high);}
.mc.ok .mv{color:var(--low);}
.mc.info .mv{color:var(--accent);}

/* ── CHARTS ROW ── */
.charts-row{max-width:1440px;margin:16px auto 0;padding:0 32px;
  display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.chart-card{background:var(--bg-card);border-radius:var(--radius);padding:22px;
  box-shadow:var(--shadow);border:1px solid var(--border);transition:var(--transition);}
.chart-card:hover{box-shadow:var(--shadow-md);}
.chart-card.full-width{grid-column:1/-1;}
.chart-title{font-size:11px;text-transform:uppercase;letter-spacing:1px;
  font-weight:700;color:var(--dim);margin-bottom:14px;}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;}
.bar-label{font-size:12px;color:var(--text);min-width:90px;font-weight:500;}
.bar-track{flex:1;background:var(--surface3);border-radius:6px;height:10px;overflow:hidden;}
.bar-fill{height:100%;border-radius:6px;transition:width 1.2s cubic-bezier(.4,0,.2,1);}
.bar-count{font-size:12px;color:var(--dim);min-width:28px;text-align:right;font-weight:600;}
.bar-critical{background:linear-gradient(90deg,#dc2626,#ef4444);}
.bar-high{background:linear-gradient(90deg,#ea580c,#f97316);}
.bar-medium{background:linear-gradient(90deg,#d97706,#f59e0b);}
.bar-low{background:linear-gradient(90deg,#16a34a,#22c55e);}
.bar-info{background:linear-gradient(90deg,#64748b,#94a3b8);}
.bar-blue{background:linear-gradient(90deg,var(--accent),#818cf8);}

/* ── CONTAINER ── */
.wrap{max-width:1440px;margin:0 auto;padding:20px 32px 40px;}
.sections-wrap{display:flex;flex-direction:column;gap:14px;}

/* ── SECTIONS ── */
.sec{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;box-shadow:var(--shadow);transition:all .25s cubic-bezier(.4,0,.2,1);}
.sec:hover{box-shadow:var(--shadow-md);}
.sh{padding:15px 20px;background:var(--bg-card);border-bottom:1px solid transparent;
  cursor:pointer;display:flex;align-items:center;justify-content:space-between;
  user-select:none;transition:var(--transition);}
.sh:hover{background:var(--bg-card-hover);}
.sec:not(.collapsed) .sh{border-bottom-color:var(--border);}
.st{font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.6px;
  color:var(--accent);display:flex;align-items:center;gap:8px;}
.sb{font-size:11px;background:var(--surface3);color:var(--dim);padding:4px 12px;
  border-radius:20px;border:1px solid var(--border);white-space:nowrap;font-weight:600;
  transition:var(--transition);}
.chevron{font-size:11px;color:var(--dim2);transition:transform .3s cubic-bezier(.4,0,.2,1);margin-left:8px;}
.sec.collapsed .chevron{transform:rotate(-90deg);}
.sec.collapsed .sbody{display:none;}
.sbody{padding:20px;animation:fadeIn .3s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}

/* ── BADGES ── */
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:var(--radius-xs);
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;
  transition:var(--transition);}
.b-critical{background:var(--critical-bg);color:var(--critical);border:1px solid rgba(239,68,68,.25);}
.b-high{background:var(--high-bg);color:var(--high);border:1px solid rgba(249,115,22,.25);}
.b-medium{background:var(--medium-bg);color:var(--medium);border:1px solid rgba(234,179,8,.25);}
.b-low{background:var(--low-bg);color:var(--low);border:1px solid rgba(34,197,94,.25);}
.b-info{background:var(--surface3);color:var(--dim);border:1px solid var(--border);}
.b-fp{background:var(--low-bg);color:var(--low);border:1px solid rgba(34,197,94,.25);}
.b-signed{color:var(--green);font-weight:700;}
.b-unsigned{color:var(--critical);font-weight:700;}

/* ── TABLES ── */
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:10px 14px;background:var(--surface2);color:var(--dim);
  font-size:10px;text-transform:uppercase;letter-spacing:.8px;font-weight:700;
  border-bottom:2px solid var(--border);}
td{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top;
  transition:background .15s;}
tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:var(--surface3);}
tbody tr:nth-child(even) td{background:var(--surface2);}
tbody tr:nth-child(even):hover td{background:var(--surface3);}

/* ── CODE BLOCKS ── */
.code{background:#0d1117;border:1px solid #21262d;border-radius:var(--radius-xs);
  padding:12px 16px;font-family:var(--font-mono);font-size:12px;
  color:#c9d1d9;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
  line-height:1.7;transition:var(--transition);}
[data-theme="light"] .code{background:#f6f8fa;border-color:#d0d7de;color:#24292f;}

/* ── EVIDENCE LIST ── */
.ev-list{list-style:none;}
.ev-item{display:flex;gap:10px;padding:10px 14px;margin-bottom:6px;border-radius:var(--radius-sm);
  font-size:13px;line-height:1.5;transition:var(--transition);}
.ev-item:hover{transform:translateX(3px);}
.ev-tp{background:var(--critical-bg);border-left:3px solid var(--critical);}
.ev-fp{background:var(--low-bg);border-left:3px solid var(--low);}
.ev-obs{background:var(--info-bg);border-left:3px solid var(--info);}
.ev-icon{font-weight:800;flex-shrink:0;margin-top:1px;font-size:13px;}
.ev-tp .ev-icon{color:var(--critical);}
.ev-fp .ev-icon{color:var(--low);}
.ev-obs .ev-icon{color:var(--info);}

/* ── PROCESS TREE ── */
.ptree{font-family:var(--font-mono);font-size:13px;line-height:1.9;}
.pnode{padding:3px 0;transition:background .15s;border-radius:4px;padding-left:4px;}
.pnode:hover{background:var(--surface3);}
.pname{font-weight:700;color:var(--text);}
.pcmd{color:var(--dim);font-size:12px;}
.psha{color:var(--dim2);font-size:11px;}
.ppub{color:var(--accent);font-size:12px;}

/* ── NETWORK ── */
.ip-unk{color:var(--high);font-weight:700;}
.ip-ok{color:var(--low);}
.unk-badge{font-size:10px;background:var(--high-bg);color:var(--high);
  border:1px solid rgba(249,115,22,.25);padding:2px 8px;border-radius:4px;margin-left:5px;font-weight:600;}

/* ── MITRE ── */
.mitre-grid{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px;}
.mitre-badge{background:var(--purple-l);color:var(--purple);
  border:1px solid rgba(139,92,246,.25);padding:5px 12px;border-radius:var(--radius-xs);
  font-size:12px;font-family:var(--font-mono);font-weight:600;transition:var(--transition);}
.mitre-badge:hover{transform:translateY(-1px);box-shadow:var(--shadow);}
.tactic-badge{background:var(--cyan-l);color:var(--cyan);border:1px solid rgba(6,182,212,.25);
  padding:5px 12px;border-radius:var(--radius-xs);font-size:12px;font-weight:600;
  transition:var(--transition);}
.tactic-badge:hover{transform:translateY(-1px);box-shadow:var(--shadow);}

/* ── MITRE HEATMAP ── */
.mitre-heatmap{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;}
.mitre-hm-col{background:var(--surface2);border-radius:var(--radius-sm);padding:12px;border:1px solid var(--border);}
.mitre-hm-tactic{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
  color:var(--cyan);margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);}
.mitre-hm-tech{display:inline-block;font-size:11px;padding:3px 8px;border-radius:4px;
  background:var(--purple-l);color:var(--purple);font-family:var(--font-mono);
  font-weight:600;margin:2px 3px 2px 0;border:1px solid rgba(139,92,246,.2);}

/* ── INDICATOR CARDS ── */
.ind-card{border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:12px;
  overflow:hidden;transition:all .25s cubic-bezier(.4,0,.2,1);}
.ind-card:hover{box-shadow:var(--shadow-md);transform:translateY(-1px);}
.ind-card.fp{border-color:rgba(34,197,94,.25);background:rgba(34,197,94,.04);}
[data-theme="light"] .ind-card.fp{background:#fafffe;border-color:#bbf7d0;}
.ind-hdr{display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--surface2);}
.ind-card.fp .ind-hdr{background:var(--low-bg);}
.ind-body{padding:12px 16px;font-size:13px;background:var(--bg-card);}
.ind-row{display:flex;gap:10px;margin-bottom:6px;align-items:flex-start;}
.ind-lbl{color:var(--dim);min-width:90px;font-size:12px;font-weight:600;padding-top:1px;}
.ind-val{flex:1;line-height:1.5;}

/* ── TOOLTIP ── */
[data-tip]{position:relative;cursor:help;}
[data-tip]:hover::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 8px);
  left:50%;transform:translateX(-50%);background:var(--text);color:var(--bg-body);
  padding:6px 12px;border-radius:var(--radius-xs);font-size:11px;white-space:nowrap;
  z-index:100;box-shadow:var(--shadow-lg);pointer-events:none;
  animation:tooltipIn .15s ease;}
[data-tip]:hover::before{content:'';position:absolute;bottom:calc(100% + 2px);
  left:50%;transform:translateX(-50%);border:5px solid transparent;
  border-top-color:var(--text);z-index:100;pointer-events:none;}
@keyframes tooltipIn{from{opacity:0;transform:translateX(-50%) translateY(4px)}to{opacity:1;transform:translateX(-50%)}}

/* ── RECOMMENDATIONS ── */
.rec-list{list-style:none;}
.rec-item{display:flex;gap:14px;padding:12px 0;border-bottom:1px solid var(--border);
  transition:var(--transition);}
.rec-item:last-child{border-bottom:none;}
.rec-item:hover{padding-left:6px;}
.rec-num{background:linear-gradient(135deg,var(--accent),#7c3aed);color:#fff;
  width:26px;height:26px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;font-size:11px;
  font-weight:800;flex-shrink:0;margin-top:1px;box-shadow:0 2px 6px rgba(59,130,246,.25);}
.rec-num.urgent{background:linear-gradient(135deg,var(--critical),#dc2626);
  box-shadow:0 2px 6px rgba(239,68,68,.3);}

/* ── TIMELINE PHASES ── */
.tl-phases{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px;}
.tl-phase{background:var(--cyan-l);border:1px solid rgba(6,182,212,.25);border-radius:var(--radius-sm);
  padding:10px 16px;font-size:12px;transition:var(--transition);}
.tl-phase:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.tl-phase-name{font-weight:700;color:var(--cyan);}
.tl-phase-time{color:var(--dim);font-size:11px;margin-top:3px;}

/* ── KEY-VALUE GRID ── */
.kv-grid{display:grid;grid-template-columns:160px 1fr;gap:8px 20px;font-size:13px;}
.kv-k{color:var(--dim);font-weight:600;padding-top:2px;}
.kv-v{font-family:var(--font-mono);font-size:12px;word-break:break-all;color:var(--text);}

/* ── ALERT BOX ── */
.alert-box{padding:12px 16px;border-radius:var(--radius-sm);display:flex;gap:10px;
  align-items:flex-start;transition:var(--transition);}
.alert-box.danger{background:var(--critical-bg);border-left:3px solid var(--critical);}
.alert-box.info{background:var(--info-bg);border-left:3px solid var(--info);}
.alert-box.success{background:var(--low-bg);border-left:3px solid var(--low);}

/* ── COPYABLE ── */
.copyable{cursor:pointer;position:relative;transition:var(--transition);
  border-radius:4px;padding:1px 4px;margin:-1px -4px;}
.copyable:hover{background:var(--primary-l);color:var(--accent);}
.copyable:active{transform:scale(.97);}

/* ── TOAST ── */
#toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;}
.toast{padding:12px 20px;border-radius:var(--radius-sm);color:#fff;font-size:13px;font-weight:600;
  box-shadow:var(--shadow-lg);animation:slideIn .35s cubic-bezier(.4,0,.2,1) forwards;
  display:flex;align-items:center;gap:8px;}
.toast.fade-out{opacity:0;transform:translateX(40px);transition:all .4s ease;}
.toast.success{background:#16a34a;}
.toast.info{background:var(--accent);}
@keyframes slideIn{from{opacity:0;transform:translateX(60px)}to{opacity:1;transform:translateX(0)}}

/* ── DONUT CHART ── */
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.donut-legend{display:flex;flex-direction:column;gap:6px;}
.donut-legend-item{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500;color:var(--text);}
.donut-legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.donut-legend-count{font-weight:700;margin-left:auto;padding-left:12px;font-family:var(--font-mono);font-size:11px;color:var(--dim);}

/* ── FOOTER ── */
.report-footer{text-align:center;padding:24px 32px;color:var(--dim2);font-size:12px;
  border-top:1px solid var(--border);margin-top:12px;max-width:1440px;margin-left:auto;margin-right:auto;
  transition:var(--transition);}

/* ── RESPONSIVE ── */
@media(max-width:768px){
  .bento-grid{grid-template-columns:repeat(2,1fr);}
  .charts-row{grid-template-columns:1fr;}
  .kv-grid{grid-template-columns:1fr;}
  .verdict-hero{flex-direction:column;text-align:center;}
  .vh-stats{justify-content:center;}
  .top-bar-inner,.bento-grid,.charts-row,.wrap,.verdict-hero{padding-left:16px;padding-right:16px;}
  .mitre-heatmap{grid-template-columns:1fr 1fr;}
}
@media(max-width:480px){
  .bento-grid{grid-template-columns:1fr 1fr;}
  .mitre-heatmap{grid-template-columns:1fr;}
}

/* ── PRINT ── */
@media print{
  .top-bar,.btn-print,.theme-toggle,#toast-container{display:none !important;}
  body{background:#fff;color:#000;font-size:12px;padding-top:0;}
  .sec{break-inside:avoid;box-shadow:none;border:1px solid #ddd;}
  .sec.collapsed .sbody{display:block !important;}
  .mc,.chart-card,.verdict-hero{box-shadow:none;border:1px solid #ddd;}
  .mc:hover,.ind-card:hover,.chart-card:hover{transform:none;}
  .verdict-hero,.bento-grid,.charts-row,.wrap{padding-left:16px;padding-right:16px;max-width:100%;}
  .code{background:#f6f8fa;color:#24292f;border-color:#d0d7de;}
}"""

        # ---- JS ----
        js = r"""
// ── THEME ──
function toggleTheme(){
  var html=document.documentElement;
  var cur=html.getAttribute('data-theme');
  var next=cur==='dark'?'light':'dark';
  html.setAttribute('data-theme',next);
  localStorage.setItem('s1-theme',next);
  var icon=document.querySelector('.theme-icon');
  if(icon)icon.textContent=next==='dark'?'\u2600':'\u263E';
}
(function(){
  var saved=localStorage.getItem('s1-theme');
  var prefer=window.matchMedia('(prefers-color-scheme:light)').matches?'light':'dark';
  var theme=saved||prefer;
  document.documentElement.setAttribute('data-theme',theme);
  document.addEventListener('DOMContentLoaded',function(){
    var icon=document.querySelector('.theme-icon');
    if(icon)icon.textContent=theme==='dark'?'\u2600':'\u263E';
  });
})();

// ── COLLAPSIBLE SECTIONS ──
// Handled via inline onclick on .sh elements

// ── ANIMATED COUNTERS ──
function animateCounters(){
  document.querySelectorAll('[data-count]').forEach(function(el){
    var target=parseInt(el.dataset.count,10)||0;
    if(target===0){el.textContent='0';return;}
    var duration=1200;var start=performance.now();
    function update(now){
      var elapsed=now-start;
      var progress=Math.min(elapsed/duration,1);
      var eased=1-Math.pow(1-progress,3);
      el.textContent=Math.round(target*eased);
      if(progress<1)requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
  });
}

// ── TOAST ──
function showToast(msg,type){
  var c=document.getElementById('toast-container');
  if(!c)return;
  var t=document.createElement('div');
  t.className='toast '+(type||'info');
  t.textContent=msg;
  c.appendChild(t);
  setTimeout(function(){t.classList.add('fade-out');setTimeout(function(){t.remove();},400);},2500);
}

// ── COPY TO CLIPBOARD ──
document.addEventListener('click',function(e){
  var el=e.target.closest('.copyable');
  if(!el)return;
  var text=el.getAttribute('data-copy')||el.textContent.trim();
  if(navigator.clipboard){
    navigator.clipboard.writeText(text).then(function(){showToast('Copied: '+text.substring(0,40),'success');});
  }else{
    var ta=document.createElement('textarea');
    ta.value=text;document.body.appendChild(ta);ta.select();
    document.execCommand('copy');document.body.removeChild(ta);
    showToast('Copied: '+text.substring(0,40),'success');
  }
});

// ── KEYBOARD SHORTCUTS ──
document.addEventListener('keydown',function(e){
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
  if(e.key==='t'||e.key==='T')toggleTheme();
});

// ── ANIMATE BARS + GAUGE ──
function animateBars(){
  document.querySelectorAll('.bar-fill[data-w]').forEach(function(b){
    b.style.width='0';
    requestAnimationFrame(function(){requestAnimationFrame(function(){b.style.width=b.dataset.w+'%';});});
  });
}
function drawGauge(){
  var g=document.getElementById('gauge-arc');
  if(!g)return;
  var score=parseFloat(g.dataset.score)||0;
  var maxScore=parseFloat(g.dataset.max)||20;
  var pct=Math.min(Math.max(score/maxScore,0),1);
  var R=42,cx=50,cy=52;
  var startAngle=-220,sweepAngle=260;
  var toRad=function(a){return a*Math.PI/180;};
  var arc=function(a){return[cx+R*Math.cos(toRad(a)),cy+R*Math.sin(toRad(a))];};
  var s=arc(startAngle),e=arc(startAngle+sweepAngle*pct);
  var large=sweepAngle*pct>180?1:0;
  if(pct===0){g.setAttribute('d','');return;}
  g.setAttribute('d','M'+s[0]+','+s[1]+' A'+R+','+R+' 0 '+large+',1 '+e[0]+','+e[1]);
  var len=g.getTotalLength?g.getTotalLength():200;
  g.style.strokeDasharray=len;
  g.style.strokeDashoffset=len;
  requestAnimationFrame(function(){requestAnimationFrame(function(){
    g.style.transition='stroke-dashoffset 1.5s cubic-bezier(.4,0,.2,1)';
    g.style.strokeDashoffset=0;
  });});
}

window.addEventListener('load',function(){
  animateCounters();
  animateBars();
  drawGauge();
});
"""

        def sev_badge(sev: str) -> str:
            cls = {"CRITIQUE":"critical","ELEVE":"high","MOYEN":"medium",
                   "FAIBLE":"low","INFO":"info"}.get(sev, "info")
            label = {"CRITIQUE":"CRITICAL","ELEVE":"HIGH","MOYEN":"MEDIUM",
                     "FAIBLE":"LOW","INFO":"INFO"}.get(sev, sev)
            return f'<span class="badge b-{cls}">{label}</span>'

        def section(num_title: str, badge: str, body: str, collapsed: bool = False) -> str:
            cls = " collapsed" if collapsed else ""
            sid = "".join(c if c.isalnum() else "-" for c in num_title.lower()).strip("-")
            return (f'<div class="sec{cls}" id="sec-{sid}"><div class="sh"'
                    f' onclick="this.parentElement.classList.toggle(\'collapsed\')">'
                    f'<span class="st">{esc(num_title)}</span>'
                    f'<div style="display:flex;gap:8px;align-items:center">'
                    f'<span class="sb">{badge}</span>'
                    f'<span class="chevron">&#9660;</span></div></div>'
                    f'<div class="sbody">{body}</div></div>')

        def kv(label: str, val: str, code: bool = False) -> str:
            v_html = f'<code>{esc(val)}</code>' if code else esc(val)
            return f'<div class="kv-k">{esc(label)}</div><div class="kv-v">{v_html}</div>'

        # ---- Section: Identification ----
        id_rows = ""
        if root:
            av_sev, av_desc = self.proc.get_attack_vector()
            chain = self.proc.get_full_parent_chain()
            sign_cls = "b-signed" if signed == "signed" else "b-unsigned"
            sign_lbl = ("&#10003; SIGNED" if signed == "signed" else
                        "&#10007; UNSIGNED" if signed == "unsigned" else "? UNKNOWN")
            _story = (self.events[0].get("storyline_id","") if self.events else "") or "N/A"
            id_rows = (f'<div class="kv-grid">'
                       f'{kv("Process", proc_name)}'
                       f'{kv("Command line", cmdline, True)}'
                       f'{kv("SHA1", sha1, True)}'
                       f'<div class="kv-k">Signature</div>'
                       f'<div class="kv-v"><span class="{sign_cls}">{sign_lbl}</span>'
                       f' &nbsp;|&nbsp; {esc(pub)}</div>'
                       f'{kv("Parent", root.get("parent_cmdline","") or "N/A", True)}'
                       f'{kv("User", user)}'
                       f'{kv("Agent UUID", self.events[0].get("agent_uuid","N/A") if self.events else "N/A")}'
                       f'{kv("Storyline ID", _story)}'
                       f'</div>')
            if av_sev:
                id_rows += (f'<div class="alert-box danger" style="margin-top:12px">'
                            f'<div><strong style="color:var(--red-d)">&#9888; ATTACK VECTOR [{esc(av_sev)}]</strong>'
                            f'<div style="color:var(--text);margin-top:3px">{esc(av_desc)}</div></div></div>')
            if chain:
                chain_html = '<div style="margin-top:12px"><div style="color:var(--dim);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">Execution Chain</div><div class="code">'
                for lvl, cmd in chain:
                    chain_html += f'[{esc(lvl)}] {esc(cmd)}\n'
                chain_html += '</div></div>'
                id_rows += chain_html
            if self.proc.is_electron():
                id_rows += '<div class="alert-box info" style="margin-top:10px;font-size:12px">&#8505; Chromium/Electron architecture detected</div>'
        s_identification = section("1. Process Identification & Execution Context",
                                    "identification", id_rows)

        # ---- Section: Timeline ----
        types = {}
        for ev in self.events:
            types[ev["event_type"]] = types.get(ev["event_type"], 0) + 1
        sorted_types = sorted(types.items(), key=lambda x: -x[1])
        max_type_count = sorted_types[0][1] if sorted_types else 1
        type_chart = ""
        for t, c in sorted_types[:10]:
            pct = round(c / max_type_count * 100)
            type_chart += (f'<div class="bar-row">'
                           f'<div class="bar-label" data-tip="{esc(t)}">{esc(t[:20]+("…" if len(t)>20 else ""))}</div>'
                           f'<div class="bar-track"><div class="bar-fill bar-blue" data-w="{pct}" style="width:0"></div></div>'
                           f'<div class="bar-count">{c}</div></div>')
        phases = self.timeline.get_phases()
        phase_cards = ""
        for ph, evts in phases.items():
            if not evts:
                continue
            ts_list = [e["timestamp"] for e in evts if e["timestamp"]]
            if ts_list:
                phase_cards += (f'<div class="tl-phase">'
                                f'<div class="tl-phase-name">{esc(ph)}</div>'
                                f'<div class="tl-phase-time">{min(ts_list).strftime("%H:%M:%S")} – {max(ts_list).strftime("%H:%M:%S")} ({len(evts)} events)</div>'
                                f'</div>')
        tl_body = (f'<div style="color:var(--dim);font-size:13px;margin-bottom:14px">'
                   f'Period: <strong style="color:var(--text)">{esc(ts_range)}</strong>'
                   f' &nbsp;&#183;&nbsp; Events: <strong style="color:var(--text)">{len(self.events)}</strong></div>'
                   f'{type_chart}')
        if phase_cards:
            tl_body += f'<div style="margin-top:14px"><div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin-bottom:8px">Activity Phases</div><div class="tl-phases">{phase_cards}</div></div>'
        s_timeline = section("2. Event Timeline", f"{len(self.events)} events", tl_body)

        # ---- Section: Behavioral Indicators ----
        indicators = self.behav.get_unique()
        sev_counts = {"CRITIQUE":0,"ELEVE":0,"MOYEN":0,"FAIBLE":0,"INFO":0}
        for _ind in indicators:
            _a = self.ctx.analyze(_ind)
            _k = "INFO" if _a["is_fp"] else _a["severity"]
            if _k in sev_counts:
                sev_counts[_k] += 1
        sev_max = max(sev_counts.values()) or 1
        sev_chart = ""
        for _key, _lbl, _bar in [("CRITIQUE","Critical","bar-critical"),("ELEVE","High","bar-high"),
                                   ("MOYEN","Medium","bar-medium"),("FAIBLE","Low","bar-low"),("INFO","Info/FP","bar-info")]:
            _cnt = sev_counts[_key]
            _pct = round(_cnt / sev_max * 100)
            sev_chart += (f'<div class="bar-row"><div class="bar-label">{_lbl}</div>'
                          f'<div class="bar-track"><div class="bar-fill {_bar}" data-w="{_pct}" style="width:0"></div></div>'
                          f'<div class="bar-count">{_cnt}</div></div>')
        ind_html = ""
        if not indicators:
            ind_html = '<p style="color:var(--dim)">No behavioral indicators.</p>'
        for ind in indicators:
            analysis = self.ctx.analyze(ind)
            db       = INDICATOR_DB.get(ind["name"], {})
            count    = self.behav.get_occurrence_count(ind["name"])
            sev      = analysis["severity"]
            is_fp    = analysis["is_fp"]
            mitre    = analysis["mitre"] or db.get("mitre", [])
            fp_cls   = " fp" if is_fp else ""
            badge    = sev_badge("INFO" if is_fp else sev)
            cnt_str  = (f'<span style="background:#eef0f7;border-radius:10px;padding:1px 7px;'
                        f'font-size:11px;color:var(--dim);font-weight:600"> &#215;{count}</span>'
                        if count > 1 else "")
            name_style = ('color:var(--dim);font-style:italic' if is_fp
                          else 'color:var(--text);font-weight:700')
            asmnt_color = ("var(--green-d)" if "FALSE" in analysis["assessment"]
                           else ("var(--red-d)" if ("TRUE" in analysis["assessment"]
                                 or "CONFIRMED" in analysis["assessment"])
                           else ("var(--orange)" if "SUSPICIOUS" in analysis["assessment"]
                           else "var(--yellow)")))
            mitre_html = ""
            if mitre:
                tags = []
                if isinstance(mitre[0], dict):
                    for t in mitre[:5]:
                        tags.append(f'<span class="mitre-badge">{esc(t["id"])} — {esc(t["name"])}</span>')
                else:
                    tags = [f'<span class="mitre-badge">{esc(t)}</span>' for t in mitre[:5]]
                mitre_html = (f'<div class="ind-row"><div class="ind-lbl">MITRE</div>'
                              f'<div class="ind-val"><div class="mitre-grid">{"".join(tags)}</div></div></div>')
            ind_html += (
                f'<div class="ind-card{fp_cls}">'
                f'<div class="ind-hdr">{badge}&nbsp;'
                f'<span style="{name_style}">{esc(ind["name"])}</span>{cnt_str}'
                f'<span style="margin-left:auto;font-size:11px;color:var(--dim);font-weight:500">{esc(ind["category"])}</span></div>'
                f'<div class="ind-body">'
                f'<div class="ind-row"><div class="ind-lbl">Assessment</div>'
                f'<div class="ind-val"><strong style="color:{asmnt_color}">{esc(analysis["assessment"])}</strong></div></div>'
                f'<div class="ind-row"><div class="ind-lbl">Analysis</div>'
                f'<div class="ind-val" style="color:var(--dim)">{esc(analysis["reasoning"])}</div></div>'
                f'{mitre_html}'
                f'</div></div>'
            )
        s_indicators = section("3. Behavioral Indicators",
                               f'{n_ind} indicators · {n_crit} critical',
                               sev_chart + ('<hr style="border:none;border-top:1px solid var(--border);margin:14px 0">' if ind_html else "") + ind_html)

        # ---- Section: MITRE ATT&CK ----
        techniques = self.behav.get_all_techniques()
        tactics    = self.behav.get_all_tactics()
        mitre_body = ""
        if tactics:
            tactic_tags = "".join(f'<span class="tactic-badge">{esc(t)}</span>' for t in tactics)
            mitre_body += (f'<div style="margin-bottom:16px">'
                           f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin-bottom:8px">Tactics Covered</div>'
                           f'<div class="mitre-grid">{tactic_tags}</div></div>')
        if techniques:
            rows = "".join(
                f'<tr><td><code style="color:var(--purple)">{esc(t["id"])}</code></td>'
                f'<td style="font-weight:500">{esc(t["name"])}</td></tr>'
                for t in techniques
            )
            mitre_body += f'<table><thead><tr><th>Technique ID</th><th>Name</th></tr></thead><tbody>{rows}</tbody></table>'
        else:
            mitre_body = '<p style="color:var(--dim)">No MITRE techniques mapped.</p>'
        s_mitre = section("4. MITRE ATT&CK Mapping",
                          f'{len(techniques)} technique(s)', mitre_body)

        # ---- Section: Scripts ----
        findings  = self.scripts.analyze()
        summaries = self.scripts.get_all_scripts_summary()
        scr_body  = ""
        if summaries:
            scr_body += f'<p style="color:var(--dim);font-size:12px;margin-bottom:12px">{len(summaries)} script(s) captured</p>'
            for s in summaries[:8]:
                raw_app  = s["app"] or "N/A"
                exe_name = raw_app.replace("\\", "/").split("/")[-1].split("_")[0]
                scr_body += (f'<div style="margin-bottom:10px">'
                             f'<div style="font-size:12px;color:var(--dim);font-weight:600;margin-bottom:4px">'
                             f'&#9658; {esc(exe_name)} <span style="font-weight:400">({s["length"]} chars)</span></div>'
                             f'<div class="code" style="font-size:11px;max-height:200px;overflow-y:auto">{esc(s["preview"])}</div></div>')
        if findings:
            scr_body += (f'<div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border)">'
                         f'<div style="font-weight:700;color:var(--red-d);margin-bottom:10px">&#9888; {len(findings)} malicious pattern(s) detected</div>')
            for f in findings:
                scr_body += (
                    f'<div style="margin-bottom:10px;border:1px solid #fecaca;border-radius:7px;overflow:hidden">'
                    f'<div style="background:#fef2f2;padding:8px 12px;display:flex;gap:10px;align-items:center">'
                    f'{sev_badge(f["severity"])} <strong style="color:var(--red-d)">{esc(f["description"])}</strong>'
                    f'<span style="margin-left:auto;color:var(--dim);font-size:11px">MITRE: {esc(str(f["mitre"]))}</span></div>'
                    f'<div class="code" style="border:none;border-radius:0;border-top:1px solid rgba(239,68,68,.2);font-size:11px;max-height:300px;overflow-y:auto">{esc(f["context"])}</div></div>'
                )
            scr_body += '</div>'
        elif not summaries:
            scr_body = '<p style="color:var(--dim)">No executed script detected.</p>'
        s_scripts = section("5. Script Content Analysis",
                            f'{len(findings)} finding(s)', scr_body)

        # ---- Section: Modules ----
        suspicious_mods = self.modules.get_suspicious()
        total_mods = self.modules.get_summary()["total_modules"]
        if suspicious_mods:
            mod_rows = "".join(
                f'<tr><td>{sev_badge(m["severity"])}</td>'
                f'<td><strong>{esc(m["name"])}</strong></td>'
                f'<td style="font-size:12px;color:var(--dim)">{esc(m["analysis"])}</td>'
                f'<td style="font-size:11px;font-family:monospace;color:var(--dim2)">{esc(m["path"])}</td></tr>'
                for m in suspicious_mods
            )
            mod_body = (f'<p style="color:var(--dim);font-size:12px;margin-bottom:10px">'
                        f'Total loaded: {total_mods} &nbsp;&#183;&nbsp; Suspicious: <strong style="color:var(--orange)">{len(suspicious_mods)}</strong></p>'
                        f'<table><thead><tr><th>Severity</th><th>Name</th><th>Analysis</th><th>Path</th></tr></thead><tbody>{mod_rows}</tbody></table>')
        else:
            mod_body = f'<p style="color:var(--dim)">Total loaded modules: {total_mods}. No suspicious module identified.</p>'
        s_modules = section("6. Loaded Modules (DLLs)",
                            f'{len(suspicious_mods)} suspicious', mod_body, collapsed=True)

        # ---- Section: Network ----
        ext_conns = self.net.get_unique_external()
        net_body  = ""
        if ext_conns:
            net_rows = ""
            for d in ext_conns:
                ip      = d["dst_ip"]
                is_unk  = "INCONNU" in d["owner"] or "UNKNOWN" in d["owner"]
                geo     = self.ip_info.get(ip, {})
                geo_str = IpEnricher.format(geo)
                domain  = self.net.ip_to_domain.get(ip, "")
                ip_cls  = "ip-unk" if is_unk else "ip-ok"
                unk_tag = '<span class="unk-badge">UNKNOWN</span>' if is_unk else ""
                owner_geo = (esc(d["owner"])
                             + (f' <span style="color:var(--dim2);font-size:11px">| {esc(geo_str)}</span>'
                                if geo_str else ""))
                dns_row = (f'<br><span style="color:var(--cyan);font-size:11px">&#8618; DNS: {esc(domain)}</span>'
                           if domain else "")
                net_rows += (f'<tr>'
                             f'<td><span class="{ip_cls}">{esc(ip)}</span>{unk_tag}</td>'
                             f'<td style="font-family:monospace">{esc(d["dst_port"])}</td>'
                             f'<td style="font-size:12px;color:var(--dim)">{esc(d.get("protocol",""))} {esc(d.get("direction",""))}</td>'
                             f'<td style="font-size:12px">{owner_geo}{dns_row}</td>'
                             f'<td style="font-size:12px;color:var(--dim)">{esc(d["process_short"])}</td></tr>')
            net_body += f'<table><thead><tr><th>IP Address</th><th>Port</th><th>Protocol</th><th>Owner / Geo</th><th>Process</th></tr></thead><tbody>{net_rows}</tbody></table>'
        else:
            net_body = '<p style="color:var(--dim)">No external connection.</p>'
        dns_q = self.net.dns_queries
        if dns_q:
            seen_d = set()
            dns_rows = ""
            for q in dns_q:
                if q["request"] in seen_d:
                    continue
                seen_d.add(q["request"])
                st_color = "var(--green-d)" if q["resolved"] else "var(--orange)"
                st_lbl   = "OK" if q["resolved"] else "FAIL"
                ips_res  = ", ".join(self.net.dns_map.get(q["request"].rstrip("."), [])[:2])
                dns_rows += (f'<tr>'
                             f'<td><span style="font-size:11px;font-weight:700;color:{st_color}">[{st_lbl}]</span></td>'
                             f'<td style="font-family:monospace;font-size:12px">{esc(q["request"])}</td>'
                             f'<td style="font-size:12px;color:var(--cyan)">{esc(ips_res)}</td></tr>')
            net_body += (f'<div style="margin-top:16px">'
                         f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin-bottom:8px">DNS Queries ({len(dns_q)})</div>'
                         f'<table><thead><tr><th>Status</th><th>Request</th><th>Response IPs</th></tr></thead><tbody>{dns_rows}</tbody></table></div>')
        s_network = section("7. Network Analysis",
                            f'{n_ext} external · {n_unk} unknown', net_body)

        # ---- Section: Process Tree ----
        def ptree_node(p: dict, prefix: str = "", is_root: bool = False) -> str:
            name  = (p.get("display_name","") or "").replace("\x00","").strip() or "unknown"
            pname = prefix + ("&#9881; " if is_root else "")
            pub   = (p.get("publisher","") or "").strip()
            sig   = p.get("signed","")
            sig_c = "b-signed" if sig == "signed" else ("b-unsigned" if sig == "unsigned" else "")
            sig_l = ("&#10003; SIGNED" if sig == "signed" else
                     "&#10007; UNSIGNED" if sig == "unsigned" else "? UNKNOWN")
            sha   = (p.get("sha1","") or "").strip()
            cmd   = (p.get("cmdline","") or "").strip()
            pub_html  = f'<span class="ppub">({esc(pub)})</span> ' if pub else ""
            sha_html  = f'<div class="psha">  SHA1: {esc(sha)}</div>' if sha else ""
            cmd_disp  = cmd[:120] + ("..." if len(cmd) > 120 else "")
            cmd_html  = f'<div class="pcmd">  CMD: {esc(cmd_disp)}</div>' if cmd else ""
            return (f'<div class="pnode">'
                    f'<span class="pname">{pname}{esc(name)}</span> '
                    f'<span class="{sig_c}" style="font-size:11px">[{sig_l}]</span> '
                    f'{pub_html}{sha_html}{cmd_html}'
                    f'</div>')

        tree_html = ""
        if root:
            tree_html += ptree_node(root, is_root=True)
            children = self.proc.get_children()
            for i, child in enumerate(children[:30]):
                is_last = (i == min(len(children), 30) - 1)
                br = "&#9492;&#9472;&#9472; " if is_last else "&#9500;&#9472;&#9472; "
                tree_html += ptree_node(child, prefix=br)
            if len(children) > 30:
                tree_html += f'<div style="color:var(--dim);font-size:12px">... and {len(children)-30} more child processes</div>'
        else:
            tree_html = '<p style="color:var(--dim)">No process tree available.</p>'
        s_proctree = section("8. Process Tree",
                             f'{1 + len(self.proc.get_children())} processes',
                             f'<div class="ptree">{tree_html}</div>')

        # ---- Section: File Activity ----
        file_summary = self.files.get_summary()
        file_body    = ""
        if file_summary:
            op_rows = "".join(
                f'<tr><td style="font-weight:500">{esc(op)}</td>'
                f'<td style="text-align:right;color:var(--dim)">{count}</td></tr>'
                for op, count in file_summary.items()
            )
            file_body += f'<table><thead><tr><th>Operation</th><th style="text-align:right">Count</th></tr></thead><tbody>{op_rows}</tbody></table>'
            dirs = self.files.get_top_dirs()
            if dirs:
                dir_rows = "".join(
                    f'<tr><td style="font-family:monospace;font-size:12px">{esc(d)}</td>'
                    f'<td style="text-align:right;color:var(--dim)">{n}</td></tr>'
                    for d, n in list(dirs.items())[:10]
                )
                file_body += (f'<div style="margin-top:14px">'
                              f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin-bottom:8px">Top Directories</div>'
                              f'<table><thead><tr><th>Path</th><th style="text-align:right">Files</th></tr></thead><tbody>{dir_rows}</tbody></table></div>')
            suspects = self.files.get_suspicious_files()
            if suspects:
                def _sus_item(s):
                    sha_div = (f'<div style="color:var(--dim2);margin-top:2px;font-size:11px">SHA1: {esc(s["sha1"])}</div>'
                               if s.get("sha1") else "")
                    return (f'<div style="padding:8px 12px;background:#fef2f2;border-left:3px solid var(--red);'
                            f'border-radius:4px;margin-bottom:6px;font-family:monospace;font-size:12px">'
                            f'<span style="color:var(--red-d)">&#9888; {esc(s["path"])}</span>{sha_div}</div>')
                sus_html = "".join(_sus_item(s) for s in suspects)
                file_body += (f'<div style="margin-top:14px">'
                              f'<div style="font-weight:700;color:var(--red-d);margin-bottom:8px">Suspicious Files ({len(suspects)})</div>'
                              f'{sus_html}</div>')
        else:
            file_body = '<p style="color:var(--dim)">No file activity.</p>'
        s_files = section("9. File Activity",
                          f'{sum(file_summary.values()) if file_summary else 0} operations',
                          file_body, collapsed=True)

        # ---- Section: Registry ----
        reg_summary = self.reg.get_summary()
        reg_hits    = self.reg.get_persistence_hits()
        reg_body    = ""
        if reg_summary:
            reg_rows = "".join(
                f'<tr><td style="font-family:monospace;font-size:12px">{esc(k)}</td>'
                f'<td style="text-align:right;color:var(--dim)">{c}</td></tr>'
                for k, c in reg_summary.items()
            )
            reg_body += f'<table><thead><tr><th>Registry Hive</th><th style="text-align:right">Count</th></tr></thead><tbody>{reg_rows}</tbody></table>'
        if reg_hits:
            def _reg_item(h):
                val_div = (f'<div style="font-size:12px;color:var(--dim);margin-top:2px">Value: {esc(h["value"][:80])}</div>'
                           if h.get("value") else "")
                return (f'<div style="padding:8px 12px;background:#fef2f2;border-left:3px solid var(--red);'
                        f'border-radius:4px;margin-bottom:6px">'
                        f'<div style="color:var(--red-d);font-weight:700">&#9888; {esc(h["label"])}</div>'
                        f'<div style="font-family:monospace;font-size:12px;color:var(--dim);margin-top:2px">{esc(h["key"])}</div>'
                        f'{val_div}</div>')
            pers_html = "".join(_reg_item(h) for h in reg_hits)
            reg_body += (f'<div style="margin-top:12px">'
                         f'<div style="font-weight:700;color:var(--red-d);margin-bottom:8px">Persistence Keys Detected ({len(reg_hits)})</div>'
                         f'{pers_html}</div>')
        else:
            reg_body += '<p style="color:var(--dim);margin-top:8px">No persistence key detected.</p>'
        s_registry = section("10. Registry Activity",
                             f'{len(reg_hits)} persistence key(s)', reg_body, collapsed=True)

        # ---- Section: VirusTotal ----
        s_vt = ""
        if self.vt:
            vt_rows = []
            to_check = []
            if root and root.get("sha1"):
                to_check.append(("Root process", proc_name, root["sha1"]))
            for child in self.proc.get_children():
                sha_c = child.get("sha1","")
                if sha_c and child.get("signed") == "unsigned":
                    cname = (child.get("display_name","") or "").replace("\x00","").strip() or "?"
                    to_check.append(("Child process", cname, sha_c))
            for sf in self.files.get_suspicious_files():
                sha_f = sf.get("sha1","")
                if sha_f:
                    to_check.append(("Suspicious file", sf["path"].split("\\")[-1], sha_f))
            seen_vt = set()
            for role, name_vt, sha_vt in to_check[:10]:
                if sha_vt in seen_vt:
                    continue
                seen_vt.add(sha_vt)
                res = self.vt.lookup(sha_vt)
                if not res:
                    vt_rows.append(f'<tr><td>{esc(role)}</td><td><strong>{esc(name_vt)}</strong></td><td style="font-family:monospace;font-size:11px;color:var(--dim)">{esc(sha_vt)}</td><td style="color:var(--dim)">No result</td></tr>')
                    continue
                if res.get("error"):
                    vt_rows.append(f'<tr><td>{esc(role)}</td><td><strong>{esc(name_vt)}</strong></td><td style="font-family:monospace;font-size:11px;color:var(--dim)">{esc(sha_vt)}</td><td style="color:var(--orange)">Error: {esc(res["error"])}</td></tr>')
                elif not res.get("found"):
                    vt_rows.append(f'<tr><td>{esc(role)}</td><td><strong>{esc(name_vt)}</strong></td><td style="font-family:monospace;font-size:11px;color:var(--dim)">{esc(sha_vt)}</td><td style="color:var(--green-d)">&#10003; Not found (unknown to VT)</td></tr>')
                else:
                    mal = res["malicious"]
                    tot = res["total"]
                    rat_color = "var(--red)" if mal > 0 else ("var(--orange)" if res["suspicious"] > 0 else "var(--green-d)")
                    threat_html = (f'<br><span style="color:var(--red);font-size:11px;font-weight:600">{esc(res["threat"])}</span>'
                                   if res.get("threat") else "")
                    vt_rows.append(f'<tr><td>{esc(role)}</td><td><strong>{esc(name_vt)}</strong></td><td style="font-family:monospace;font-size:11px;color:var(--dim)">{esc(sha_vt)}</td><td><span style="color:{rat_color};font-weight:700">{mal}/{tot} engines</span>{threat_html}</td></tr>')
            if vt_rows:
                vt_body = f'<table><thead><tr><th>Role</th><th>Name</th><th>SHA1</th><th>VT Result</th></tr></thead><tbody>{"".join(vt_rows)}</tbody></table>'
            else:
                vt_body = '<p style="color:var(--dim)">No hash available.</p>'
            s_vt = section("11. VirusTotal Analysis", f'{len(seen_vt)} lookup(s)', vt_body)

        # ---- Section: Verdict ----
        ev_tp = v["evidence_tp"]
        ev_fp = v["evidence_fp"]
        ev_ob = v["observations"]
        recs  = self._recommendations()

        def ev_items(items, cls):
            icon = {"ev-tp":"&#8853;","ev-fp":"&#8854;","ev-obs":"&#8505;"}[cls]
            return "".join(
                f'<li class="ev-item {cls}"><span class="ev-icon">{icon}</span><span>{esc(it)}</span></li>'
                for it in items
            )

        rec_items = ""
        for i, r in enumerate(recs, 1):
            urgent = i <= 2 and score >= 4
            num_cls = " urgent" if urgent else ""
            rec_items += (f'<li class="rec-item"><div class="rec-num{num_cls}">{i}</div>'
                          f'<div>{esc(r.lstrip("0123456789. "))}</div></li>')

        gauge_color = {"critical":"#dc2626","high":"#ea580c","medium":"#d97706","low":"#16a34a"}[score_class]
        gauge_svg = (f'<svg viewBox="0 0 100 80" width="120" height="96">'
                     f'<path d="M13.4,71.6 A38,38 0 1,1 86.6,71.6" fill="none" stroke="#eef0f7" stroke-width="9" stroke-linecap="round"/>'
                     f'<path id="gauge-arc" data-score="{score}" data-max="20" fill="none"'
                     f' stroke="{gauge_color}" stroke-width="9" stroke-linecap="round"/>'
                     f'<text x="50" y="58" text-anchor="middle" font-family="Segoe UI,system-ui,sans-serif"'
                     f' font-size="22" font-weight="800" fill="{gauge_color}">{score}</text>'
                     f'<text x="50" y="72" text-anchor="middle" font-family="Segoe UI,system-ui,sans-serif"'
                     f' font-size="9" fill="#9aa3be" letter-spacing="1">SCORE</text>'
                     f'</svg>')

        vrd_summary = (f'<div style="display:flex;gap:32px;flex-wrap:wrap;align-items:center;'
                       f'background:var(--surface2);border-radius:var(--radius);padding:16px 20px;margin-bottom:20px">'
                       f'{gauge_svg}'
                       f'<div style="flex:1"><div style="display:flex;gap:24px;flex-wrap:wrap">'
                       f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:700">Verdict</div>'
                       f'<div style="font-size:16px;font-weight:800;margin-top:4px;color:var(--text)">{esc(verdict_txt)}</div></div>'
                       f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:700">Confidence</div>'
                       f'<div style="font-size:16px;font-weight:800;margin-top:4px;color:var(--text)">{esc(v["confidence"])}</div></div>'
                       f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:700">TP Evidence</div>'
                       f'<div style="font-size:16px;font-weight:800;margin-top:4px;color:var(--red)">{len(ev_tp)}</div></div>'
                       f'<div><div style="font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:700">Mitigating</div>'
                       f'<div style="font-size:16px;font-weight:800;margin-top:4px;color:var(--green-d)">{len(ev_fp)}</div></div>'
                       f'</div></div></div>')

        vrd_body = (
            vrd_summary
            + (f'<div style="margin-bottom:14px"><div style="font-weight:700;color:var(--red-d);margin-bottom:8px">Evidence &#8212; True Positive ({len(ev_tp)})</div><ul class="ev-list">{ev_items(ev_tp,"ev-tp")}</ul></div>' if ev_tp else "")
            + (f'<div style="margin-bottom:14px"><div style="font-weight:700;color:var(--green-d);margin-bottom:8px">Mitigating Factors ({len(ev_fp)})</div><ul class="ev-list">{ev_items(ev_fp,"ev-fp")}</ul></div>' if ev_fp else "")
            + (f'<div style="margin-bottom:14px"><div style="font-weight:700;color:var(--blue);margin-bottom:8px">Neutral Observations ({len(ev_ob)})</div><ul class="ev-list">{ev_items(ev_ob,"ev-obs")}</ul></div>' if ev_ob else "")
            + f'<div style="border-top:1px solid var(--border);padding-top:16px"><div style="font-weight:700;color:var(--text);margin-bottom:10px">&#128203; Recommendations</div><ul class="rec-list">{rec_items}</ul></div>'
        )
        s_verdict = section("Diagnosis & Verdict", f'Score {score}', vrd_body)

        # ---- Section: Sigma Rule Matches ----
        s_sigma = ""
        if self.sigma:
            sigma_hits = self.sigma.evaluate_all(self.behav.events)
            if sigma_hits:
                level_cls = {"CRITICAL": "b-critical", "HIGH": "b-high",
                             "MEDIUM": "b-medium", "LOW": "b-low", "INFORMATIONAL": "b-info"}
                sigma_rows = ""
                for h in sigma_hits[:30]:
                    mitre_tags = "".join(
                        f'<span class="mitre-badge">{esc(m)}</span>' for m in h["mitre"][:3])
                    mitre_div = (f'<div class="mitre-grid" style="margin-top:5px">{mitre_tags}</div>'
                                 if h["mitre"] else "")
                    lcls = level_cls.get(h["level"], "b-info")
                    sigma_rows += (
                        f'<div style="border:1px solid var(--border);border-radius:7px;'
                        f'margin-bottom:8px;overflow:hidden">'
                        f'<div style="background:var(--surface2);padding:8px 12px;'
                        f'display:flex;align-items:center;gap:10px">'
                        f'<span class="badge {lcls}">{esc(h["level"])}</span>'
                        f'<strong>{esc(h["title"])}</strong>'
                        f'<span style="margin-left:auto;color:var(--dim);font-size:11px">'
                        f'{esc(h["category"])}</span></div>'
                        f'<div style="padding:8px 12px;font-size:12px;color:var(--dim)">'
                        f'{esc(h.get("description","")[:200])}{mitre_div}</div></div>'
                    )
                if len(sigma_hits) > 30:
                    sigma_rows += (f'<p style="color:var(--dim);font-size:12px">'
                                   f'... and {len(sigma_hits)-30} more matches</p>')
                s_sigma = section("12. Sigma Rule Matches",
                                  f'{len(sigma_hits)} match(es)', sigma_rows, collapsed=True)

        # ---- Section: Process Graph (NetworkX) ----
        s_process_graph = ""
        if self.process_graph:
            pg_anomalies = self.process_graph.get_anomalies()
            sev_cls_pg = {"CRITIQUE": "b-critical", "ELEVE": "b-high", "MOYEN": "b-medium"}
            if pg_anomalies:
                pg_items = ""
                for a in pg_anomalies:
                    acls = sev_cls_pg.get(a["severity"], "b-info")
                    pg_items += (
                        f'<div style="display:flex;gap:10px;align-items:flex-start;'
                        f'padding:9px 12px;border-bottom:1px solid var(--border)">'
                        f'<span class="badge {acls}">{esc(a["type"])}</span>'
                        f'<div style="font-size:13px">{esc(a["description"])}</div></div>'
                    )
                pg_body = (f'<div style="border:1px solid var(--border);border-radius:7px;'
                           f'overflow:hidden">{pg_items}</div>')
                s_process_graph = section("13. Process Graph Analysis (NetworkX)",
                                          f'{len(pg_anomalies)} anomaly/anomalies',
                                          pg_body, collapsed=True)
            else:
                s_process_graph = section("13. Process Graph Analysis (NetworkX)",
                                          "No anomaly",
                                          '<p style="color:var(--dim)">No graph anomaly detected.</p>',
                                          collapsed=True)

        # ---- Section: Statistical Anomaly Detection ----
        s_stats_sec = ""
        if self.stats:
            stats_data  = self.stats.get_stats()
            after_hours = self.stats.get_after_hours()
            outliers    = self.stats.get_outliers()
            rare_pairs  = stats_data.get("rare_pairs", [])
            stats_body  = ""
            kv_rows = ""
            if stats_data.get("cmd_len"):
                s2 = stats_data["cmd_len"]
                kv_rows += kv("Cmdline length", f'mean={s2["mean"]}  std={s2["std"]}')
            if stats_data.get("cmd_entropy"):
                s2 = stats_data["cmd_entropy"]
                kv_rows += kv("Cmdline entropy", f'mean={s2["mean"]}  std={s2["std"]} bits')
            if kv_rows:
                stats_body += f'<div class="kv-grid" style="margin-bottom:14px">{kv_rows}</div>'
            if after_hours:
                ah_rows = "".join(
                    f'<tr><td style="font-family:monospace;font-size:11px;color:var(--dim)">'
                    f'{esc(ev.get("timestamp_raw","?"))}</td>'
                    f'<td style="font-size:12px">{esc(ev.get("event_type",""))}</td></tr>'
                    for ev in after_hours[:5]
                )
                stats_body += (
                    f'<div style="margin-bottom:14px">'
                    f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
                    f'letter-spacing:.6px;color:var(--dim);margin-bottom:8px">'
                    f'After-hours Events ({len(after_hours)})</div>'
                    f'<table><thead><tr><th>Timestamp</th><th>Event Type</th></tr></thead>'
                    f'<tbody>{ah_rows}</tbody></table></div>'
                )
            if outliers:
                out_rows = "".join(
                    f'<tr>'
                    f'<td style="font-family:monospace;font-size:11px;color:var(--red)">'
                    f'{esc(str(o.get("score","?")))}</td>'
                    f'<td style="font-size:12px">{esc(o.get("event_type",""))}</td>'
                    f'<td style="font-family:monospace;font-size:11px;color:var(--dim)">'
                    f'{esc(o.get("cmd","")[:80])}</td>'
                    f'<td style="font-size:11px;color:var(--dim)">'
                    f'{esc(str(o.get("entropy","?")))}</td></tr>'
                    for o in outliers[:10]
                )
                stats_body += (
                    f'<div style="margin-bottom:14px">'
                    f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
                    f'letter-spacing:.6px;color:var(--dim);margin-bottom:8px">'
                    f'IsolationForest Outliers ({len(outliers)})</div>'
                    f'<table><thead><tr><th>Score</th><th>Event</th>'
                    f'<th>Command</th><th>Entropy</th></tr></thead>'
                    f'<tbody>{out_rows}</tbody></table></div>'
                )
            elif getattr(self.stats, "has_pyod", False):
                stats_body += '<div class="alert-box success">IsolationForest: No outlier detected.</div>'
            else:
                stats_body += ('<div class="alert-box info">pyod not installed — '
                               'install with: pip install pyod</div>')
            if rare_pairs:
                stats_body += (f'<div style="font-size:12px;color:var(--dim);margin-top:8px">'
                               f'<strong>Rare parent→child pairs:</strong> '
                               f'{esc(", ".join(rare_pairs[:8]))}</div>')
            if not stats_body:
                stats_body = '<p style="color:var(--dim)">No statistical anomaly detected.</p>'
            s_stats_sec = section(
                "14. Statistical Anomaly Detection",
                f'{len(outliers)} outlier(s) · {len(after_hours)} after-hours',
                stats_body, collapsed=True
            )

        # ---- Section: YARA Matches ----
        s_yara_sec = ""
        if self.yara_an:
            yara_hits = self.yara_an.get_hits()
            if yara_hits:
                sev_cls_y = {"CRITIQUE": "b-critical", "ELEVE": "b-high"}
                yara_rows = ""
                for h in yara_hits[:20]:
                    ycls = sev_cls_y.get(h["severity"], "b-medium")
                    tag_html = (f'<span style="font-size:11px;color:var(--dim)">'
                                f'Tags: {esc(", ".join(h["tags"][:5]))}</span>'
                                if h.get("tags") else "")
                    yara_rows += (
                        f'<div style="border:1px solid var(--border);border-radius:7px;'
                        f'margin-bottom:8px;overflow:hidden">'
                        f'<div style="background:var(--surface2);padding:8px 12px;'
                        f'display:flex;align-items:center;gap:10px">'
                        f'<span class="badge {ycls}">{esc(h["severity"])}</span>'
                        f'<strong>{esc(h["rule"])}</strong>'
                        f'<span style="margin-left:auto;color:var(--dim);font-size:11px">'
                        f'{esc(h["context"])}</span></div>'
                        f'<div style="padding:8px 12px">'
                        f'<div class="code" style="font-size:11px">'
                        f'{esc(h["preview"][:120])}</div>{tag_html}</div></div>'
                    )
                s_yara_sec = section("15. YARA Rule Matches",
                                     f'{len(yara_hits)} match(es)', yara_rows, collapsed=True)
            else:
                s_yara_sec = section("15. YARA Rule Matches", "No match",
                                     '<p style="color:var(--dim)">No YARA rule matched.</p>',
                                     collapsed=True)

        # ---- Section: ATT&CK Enrichment ----
        s_attack_enrich = ""
        if self.mitre_enricher:
            techniques_e = self.behav.get_all_techniques()
            all_tids_e   = [t["id"] for t in techniques_e]
            atk_body     = ""
            groups_e     = self.mitre_enricher.get_groups_for_techniques(all_tids_e)
            if groups_e:
                grp_tags = "".join(
                    f'<span style="background:var(--orange-l);color:var(--orange);'
                    f'border:1px solid #fed7aa;padding:3px 10px;border-radius:6px;'
                    f'font-size:12px;font-weight:600">'
                    f'{esc(g["id"])} — {esc(g["name"])}</span>'
                    for g in groups_e[:8]
                )
                atk_body += (
                    f'<div style="margin-bottom:16px">'
                    f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
                    f'letter-spacing:.6px;color:var(--dim);margin-bottom:8px">'
                    f'Threat Groups Using These Techniques ({len(groups_e)})</div>'
                    f'<div style="display:flex;flex-wrap:wrap;gap:7px">{grp_tags}</div></div>'
                )
            for t in techniques_e[:10]:
                tid  = t["id"]
                info = self.mitre_enricher.get_technique_info(tid)
                if not info:
                    continue
                mit_html = ""
                if info.get("mitigations"):
                    mits = "".join(
                        f'<span style="background:var(--green-l);color:var(--green-d);'
                        f'border:1px solid #bbf7d0;padding:2px 8px;border-radius:4px;'
                        f'font-size:11px;font-weight:600;margin-right:5px">'
                        f'{esc(m["id"])} {esc(m["name"])}</span>'
                        for m in info["mitigations"][:3]
                    )
                    mit_html = f'<div style="margin-top:6px">{mits}</div>'
                grp_html = ""
                if info.get("groups"):
                    grps = ", ".join(f'{g["id"]} ({g["name"]})' for g in info["groups"][:3])
                    grp_html = (f'<div style="font-size:11px;color:var(--orange);margin-top:4px">'
                                f'Groups: {esc(grps)}</div>')
                det_html = ""
                if info.get("detection"):
                    det_html = (f'<div style="margin-top:6px;padding:8px;background:#f8f9fc;'
                                f'border-radius:4px;font-size:11px;color:var(--text)">'
                                f'{esc(info["detection"][:300])}</div>')
                atk_body += (
                    f'<div style="border:1px solid var(--border);border-radius:7px;'
                    f'margin-bottom:8px;overflow:hidden">'
                    f'<div style="background:var(--surface2);padding:8px 12px;'
                    f'display:flex;align-items:center;gap:10px">'
                    f'<code style="color:var(--purple)">{esc(tid)}</code>'
                    f'<strong>{esc(info.get("name",""))}</strong>'
                    f'<span class="tactic-badge" style="margin-left:auto">'
                    f'{esc(info.get("tactic",""))}</span></div>'
                    f'<div style="padding:8px 12px">{det_html}{mit_html}{grp_html}</div></div>'
                )
            if not atk_body:
                atk_body = ('<p style="color:var(--dim)">ATT&amp;CK bundle not loaded '
                            '— run --update first.</p>')
            s_attack_enrich = section(
                "16. ATT&CK Enrichment (MITRE)",
                f'{len(all_tids_e)} technique(s) · {len(groups_e) if groups_e else 0} group(s)',
                atk_body, collapsed=True
            )

        # ---- Section: IOC Extraction ----
        s_ioc_sec = ""
        if self.ioc_an:
            iocs = self.ioc_an.get_iocs()
            total_iocs = sum(len(v) for v in iocs.values())
            if total_iocs:
                kind_labels = {"urls": "URLs", "ips": "IP Addresses",
                               "hashes": "Hashes", "emails": "Emails"}
                ioc_body = ""
                for kind, items in iocs.items():
                    if not items:
                        continue
                    tags = "".join(
                        f'<div style="font-family:monospace;font-size:12px;padding:4px 8px;'
                        f'background:#fef2f2;border-radius:4px;margin-bottom:3px;'
                        f'word-break:break-all;color:var(--red-d)">{esc(item)}</div>'
                        for item in items[:15]
                    )
                    more = (f'<div style="color:var(--dim);font-size:11px">... and '
                            f'{len(items)-15} more</div>' if len(items) > 15 else "")
                    ioc_body += (
                        f'<div style="margin-bottom:14px">'
                        f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
                        f'letter-spacing:.6px;color:var(--dim);margin-bottom:8px">'
                        f'{kind_labels.get(kind, kind)} ({len(items)})</div>'
                        f'{tags}{more}</div>'
                    )
                s_ioc_sec = section("17. IOC Extraction (iocextract)",
                                    f'{total_iocs} IOC(s)', ioc_body, collapsed=True)

        # ---- Assemble ----
        report_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sections_html = (s_identification + s_timeline + s_indicators + s_mitre
                         + s_scripts + s_modules + s_network + s_proctree
                         + s_files + s_registry + s_vt
                         + s_sigma + s_process_graph + s_stats_sec
                         + s_yara_sec + s_attack_enrich + s_ioc_sec
                         + s_verdict)
        n_pers      = len(self.reg.get_persistence_hits())
        n_sus_files = len(self.files.get_suspicious_files())
        n_sigma_h   = len(self.sigma.evaluate_all(self.behav.events)) if self.sigma else 0
        n_yara_h    = len(self.yara_an.get_hits()) if self.yara_an else 0
        n_graph_a   = len(self.process_graph.get_anomalies()) if self.process_graph else 0
        n_outliers  = len(self.stats.get_outliers()) if self.stats else 0

        # ---- SVG Donut Chart: severity distribution ----
        import math as _math
        _donut_colors = {"CRITIQUE":"#ef4444","ELEVE":"#f97316","MOYEN":"#eab308",
                         "FAIBLE":"#22c55e","INFO":"#3b82f6"}
        _donut_labels = {"CRITIQUE":"Critical","ELEVE":"High","MOYEN":"Medium",
                         "FAIBLE":"Low","INFO":"Info/FP"}
        _donut_total = sum(sev_counts.values())
        donut_svg = ""
        if _donut_total > 0:
            _R = 70
            _inner = 45
            _sw = _R - _inner
            _cr = (_R + _inner) / 2
            _circ = 2 * _math.pi * _cr
            _offset = 0
            _arcs = ""
            for _dk in ["CRITIQUE","ELEVE","MOYEN","FAIBLE","INFO"]:
                _dv = sev_counts[_dk]
                if _dv == 0:
                    continue
                _pct = _dv / _donut_total
                _dash = _circ * _pct
                _gap = _circ - _dash
                _arcs += (f'<circle cx="90" cy="90" r="{_cr}" fill="none" '
                          f'stroke="{_donut_colors[_dk]}" stroke-width="{_sw}" '
                          f'stroke-dasharray="{_dash:.2f} {_gap:.2f}" '
                          f'stroke-dashoffset="{-_offset:.2f}" '
                          f'transform="rotate(-90 90 90)"/>')
                _offset += _dash
            _legend = ""
            for _dk in ["CRITIQUE","ELEVE","MOYEN","FAIBLE","INFO"]:
                _dv = sev_counts[_dk]
                _legend += (f'<div class="donut-legend-item">'
                            f'<span class="donut-legend-dot" style="background:{_donut_colors[_dk]}"></span>'
                            f'{_donut_labels[_dk]}'
                            f'<span class="donut-legend-count">{_dv}</span></div>')
            donut_svg = (f'<div class="donut-wrap">'
                         f'<svg viewBox="0 0 180 180" width="170" height="170">'
                         f'{_arcs}'
                         f'<text x="90" y="85" text-anchor="middle" fill="var(--text)" '
                         f'font-family="Inter,Segoe UI,system-ui,sans-serif" '
                         f'font-size="28" font-weight="800">{_donut_total}</text>'
                         f'<text x="90" y="105" text-anchor="middle" fill="var(--dim)" '
                         f'font-family="Inter,Segoe UI,system-ui,sans-serif" '
                         f'font-size="10" letter-spacing="1" text-transform="uppercase">INDICATORS</text>'
                         f'</svg>'
                         f'<div class="donut-legend">{_legend}</div></div>')
        else:
            donut_svg = '<p style="color:var(--dim)">No indicators</p>'

        # ---- MITRE ATT&CK mini-heatmap ----
        mitre_heatmap_html = ""
        if techniques or tactics:
            # Build tactic→techniques mapping from indicators
            _tactic_tech_map = {}
            for _ind in self.behav.get_unique():
                _ind_tactics = _ind.get("mitre_tactics", [])
                _ind_techs   = _ind.get("mitre_techniques", [])
                if _ind_tactics and _ind_techs:
                    for _tac in _ind_tactics:
                        _tactic_tech_map.setdefault(_tac, [])
                        for _tt in _ind_techs:
                            if _tt not in _tactic_tech_map[_tac]:
                                _tactic_tech_map[_tac].append(_tt)
                elif _ind_techs:
                    _tactic_tech_map.setdefault("Other", [])
                    for _tt in _ind_techs:
                        if _tt not in _tactic_tech_map["Other"]:
                            _tactic_tech_map["Other"].append(_tt)
            # If mitre_enricher is available, use it for better tactic mapping
            if self.mitre_enricher and self.mitre_enricher.available:
                _enriched_map = {}
                for _t in techniques:
                    _tid = _t.get("id", "") if isinstance(_t, dict) else str(_t)
                    _tname = _t.get("name", "") if isinstance(_t, dict) else ""
                    _info = self.mitre_enricher.get_technique_info(_tid)
                    _etac = _info.get("tactic", "Other") if _info else "Other"
                    _enriched_map.setdefault(_etac, []).append(_t)
                if _enriched_map:
                    _tactic_tech_map = _enriched_map
            if _tactic_tech_map:
                _hm_cols = ""
                for _tac in sorted(_tactic_tech_map.keys()):
                    _techs = _tactic_tech_map[_tac]
                    _badges = ""
                    for _tt in _techs:
                        _tid = _tt.get("id", "?") if isinstance(_tt, dict) else str(_tt)
                        _tname = _tt.get("name", "") if isinstance(_tt, dict) else ""
                        _tip = f' title="{esc(_tname)}"' if _tname else ""
                        _badges += f'<span class="mitre-hm-tech"{_tip}>{esc(_tid)}</span>'
                    _hm_cols += (f'<div class="mitre-hm-col">'
                                 f'<div class="mitre-hm-tactic">{esc(_tac)}</div>'
                                 f'{_badges}</div>')
                mitre_heatmap_html = (f'<div class="charts-row" style="margin-top:16px">'
                                      f'<div class="chart-card full-width">'
                                      f'<div class="chart-title">MITRE ATT&amp;CK Coverage Heatmap</div>'
                                      f'<div class="mitre-heatmap">{_hm_cols}</div>'
                                      f'</div></div>')

        # ---- Charts row ----
        charts_html = (f'<div class="charts-row">'
                       f'<div class="chart-card">'
                       f'<div class="chart-title">Indicator Severity Distribution</div>'
                       f'{donut_svg}'
                       f'</div>'
                       f'<div class="chart-card">'
                       f'<div class="chart-title">Event Type Distribution</div>'
                       f'{type_chart}'
                       f'</div>'
                       f'</div>'
                       f'{mitre_heatmap_html}')

        # ---- Gauge SVG for verdict hero ----
        _gauge_colors = {"critical":"#ef4444","high":"#f97316","medium":"#eab308","low":"#22c55e"}
        gauge_color = _gauge_colors.get(score_class, "#3b82f6")
        gauge_svg = (f'<svg viewBox="0 0 100 80" width="130" height="104">'
                     f'<path d="M10.4,69.6 A42,42 0 1,1 89.6,69.6" fill="none" '
                     f'stroke="var(--border)" stroke-width="8" stroke-linecap="round" opacity="0.5"/>'
                     f'<path id="gauge-arc" data-score="{score}" data-max="20" fill="none"'
                     f' stroke="{gauge_color}" stroke-width="8" stroke-linecap="round"/>'
                     f'<text x="50" y="55" text-anchor="middle" font-family="Inter,Segoe UI,system-ui,sans-serif"'
                     f' font-size="24" font-weight="800" fill="{gauge_color}">{score}</text>'
                     f'<text x="50" y="70" text-anchor="middle" font-family="Inter,Segoe UI,system-ui,sans-serif"'
                     f' font-size="8" fill="var(--dim)" letter-spacing="1.5">SCORE / 20</text>'
                     f'</svg>')

        return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Report &#8212; {esc(proc_name)}</title>
<style>{css}</style>
</head>
<body>

<header class="top-bar">
  <div class="top-bar-inner">
    <div class="brand">
      <div class="brand-icon">S1</div>
      <div>
        <div class="brand-title">SentinelOne Deep Visibility Analyzer</div>
        <div class="brand-sub">SOC Analysis Report &mdash; {esc(report_ts)}</div>
      </div>
    </div>
    <div class="top-actions">
      <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme (T)">
        <span class="theme-icon">&#9728;</span>
      </button>
      <button class="btn-print" onclick="window.print()" title="Print report">&#9112; Print</button>
    </div>
  </div>
</header>

<section class="verdict-hero {verdict_class}">
  <div class="vh-gauge">{gauge_svg}</div>
  <div class="vh-center">
    <div class="vh-verdict">{verdict_icon} {esc(verdict_txt)}</div>
    <div class="vh-confidence">Confidence: <strong style="color:var(--text)">{esc(v["confidence"])}</strong>
    &nbsp;&#183;&nbsp; Process: <strong style="color:var(--text)" class="copyable" data-copy="{esc(proc_name)}">{esc(proc_name)}</strong>
    &nbsp;&#183;&nbsp; User: <strong style="color:var(--text)">{esc(user)}</strong>
    &nbsp;&#183;&nbsp; Period: <strong style="color:var(--text)">{esc(ts_range)}</strong></div>
  </div>
  <div class="vh-stats">
    <div class="vh-stat"><div class="vh-stat-num" style="color:var(--critical)">{len(ev_tp)}</div><div class="vh-stat-lbl">TP Evidence</div></div>
    <div class="vh-stat"><div class="vh-stat-num" style="color:var(--low)">{len(ev_fp)}</div><div class="vh-stat-lbl">Mitigating</div></div>
    <div class="vh-stat"><div class="vh-stat-num" style="color:var(--info)">{len(ev_ob)}</div><div class="vh-stat-lbl">Observations</div></div>
  </div>
</section>

<div class="bento-grid">
  <div class="mc {'alert' if n_crit else 'ok'}" data-tip="Behavioral indicators triggered">
    <div class="mv" data-count="{n_ind}">{n_ind}</div><div class="ml">Indicators<br>{n_crit} critical</div></div>
  <div class="mc {'warn' if n_unk else 'ok'}" data-tip="External network connections">
    <div class="mv" data-count="{n_ext}">{n_ext}</div><div class="ml">Ext. Connections<br>{n_unk} unknown</div></div>
  <div class="mc {'alert' if n_scr else 'ok'}" data-tip="Malicious script patterns">
    <div class="mv" data-count="{n_scr}">{n_scr}</div><div class="ml">Script Findings</div></div>
  <div class="mc {'alert' if n_pers else 'ok'}" data-tip="Persistence registry keys">
    <div class="mv" data-count="{n_pers}">{n_pers}</div><div class="ml">Persistence Keys</div></div>
  <div class="mc {'alert' if n_sus_files else 'ok'}" data-tip="Suspicious file operations">
    <div class="mv" data-count="{n_sus_files}">{n_sus_files}</div><div class="ml">Suspicious Files</div></div>
  <div class="mc {'alert' if n_sigma_h else 'ok'}" data-tip="Sigma community rule matches">
    <div class="mv" data-count="{n_sigma_h}">{n_sigma_h}</div><div class="ml">Sigma Matches</div></div>
  <div class="mc {'alert' if n_yara_h else 'ok'}" data-tip="YARA pattern matches">
    <div class="mv" data-count="{n_yara_h}">{n_yara_h}</div><div class="ml">YARA Matches</div></div>
  <div class="mc {'alert' if n_graph_a else 'ok'}" data-tip="Process graph anomalies (NetworkX)">
    <div class="mv" data-count="{n_graph_a}">{n_graph_a}</div><div class="ml">Graph Anomalies</div></div>
  <div class="mc {'warn' if n_outliers else 'ok'}" data-tip="Statistical outliers (IsolationForest)">
    <div class="mv" data-count="{n_outliers}">{n_outliers}</div><div class="ml">Stat. Outliers</div></div>
  <div class="mc info" data-tip="Total Deep Visibility events analyzed">
    <div class="mv" data-count="{len(self.events)}">{len(self.events)}</div><div class="ml">Total Events</div></div>
</div>

{charts_html}

<div class="wrap">
<div class="sections-wrap">
{sections_html}
</div>
</div>

<footer class="report-footer">
  SentinelOne DV Analyzer &nbsp;&#183;&nbsp; Behavioral analysis &nbsp;&#183;&nbsp; {esc(report_ts)}
  <br><span style="opacity:.5">Keyboard: T = toggle theme &nbsp;&#183;&nbsp; &#9112; = print</span>
</footer>

<div id="toast-container"></div>

<script>{js}</script>
</body>
</html>"""

    # ------------------------------------------------------------------ #
    @staticmethod
    def _trunc(s: str, n: int) -> str:
        s = s or "N/A"
        return s[:n] + "..." if len(s) > n else s

    @staticmethod
    def _wrap(prefix: str, text: str, width: int) -> list:
        words       = text.split()
        lines       = []
        line        = prefix
        # Longueur visible (sans codes ANSI) pour le calcul du retour à la ligne
        prefix_vis  = len(_strip_ansi(prefix))
        indent      = " " * prefix_vis
        for w in words:
            line_vis = len(_strip_ansi(line))
            if line_vis + len(w) + 1 > width and line_vis > prefix_vis:
                lines.append(line)
                line = indent + w
            else:
                line += ("" if line == prefix else " ") + w
        if _strip_ansi(line).strip():
            lines.append(line)
        return lines


# ===========================================================================
# POINT D'ENTREE
# ===========================================================================

class _Spinner:
    """Animated spinner for long-running operations (stderr)."""
    _FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, message: str):
        self._msg = message
        self._running = False
        self._thread = None
        self._idx = 0

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self):
        while self._running:
            frame = self._FRAMES[self._idx % len(self._FRAMES)]
            print(f"\r  {C.wrap(C.LCYAN, f'[{frame}]')} {C.dim(self._msg)}   ",
                  end="", file=sys.stderr, flush=True)
            self._idx += 1
            time.sleep(0.12)

    def stop(self, final_msg: str = "", ok: bool = True):
        self._running = False
        if self._thread:
            self._thread.join()
        if final_msg:
            tag = C.ok("[OK]") if ok else C.high("[!!]")
            print(f"\r  {tag} {final_msg}                                          ",
                  file=sys.stderr)
        else:
            print(f"\r{'':70}", end="\r", file=sys.stderr)


def _progress_bar(current: int, total: int, width: int = 20) -> str:
    """Return a text progress bar."""
    if total <= 0:
        return ""
    ratio = min(current / total, 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    pct = int(ratio * 100)
    return f"{C.dim('[')}{bar}{C.dim(']')} {pct:3d}%"


def _fmt_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"


def _separator(title: str = "") -> str:
    """Return a visual separator line for stderr."""
    if title:
        return f"  {'=' * 3} {C.bold(title)} {'=' * (50 - len(title))}"
    return f"  {'=' * 56}"


def _progress(msg: str):
    """Affiche une ligne de progression coloree."""
    print(C.wrap(C.DIM + C.CYAN, f"  [*] {msg}"), file=sys.stderr)


def _step(step_num: int, total_steps: int, msg: str):
    """Affiche une etape numerotee avec barre de progression globale."""
    bar = _progress_bar(step_num, total_steps, width=15)
    print(f"  {bar} {C.info(msg)}", file=sys.stderr)


def analyze(filepath: str, output_json: bool = False, output_html: bool = False,
            output_report: bool = False,
            vt_client=None, ip_enrich: bool = False,
            mb_client=None, otx_client=None, shodan_client=None,
            enable_sigma: bool = True, enable_yara: bool = True,
            enable_graph: bool = True, enable_stats: bool = True,
            enable_attack: bool = True):

    t_total = time.time()

    # Count total steps for progress tracking
    total_steps = 16  # base analyzers
    if enable_sigma:  total_steps += 1
    if enable_graph:  total_steps += 1
    if enable_stats:  total_steps += 1
    if enable_yara:   total_steps += 1
    if enable_attack: total_steps += 1
    total_steps += 3  # IOC + verdict + report
    if ip_enrich:     total_steps += 1
    step = 0

    # ── Phase 1: Loading ──
    print(file=sys.stderr)
    print(_separator("Analysis"), file=sys.stderr)
    print(file=sys.stderr)

    sp = _Spinner(f"Loading {Path(filepath).name}...").start()
    t0 = time.time()
    events = CsvParser.parse_file(filepath)
    elapsed = time.time() - t0
    sp.stop(f"{C.bold(str(len(events)))} events loaded from {C.dim(Path(filepath).name)} {C.dim(f'({_fmt_duration(elapsed)})')}")
    print(file=sys.stderr)

    # ── Phase 2: Core analyzers ──
    print(f"  {C.bold('Phase 1/4')} {C.dim('- Core analysis')}", file=sys.stderr)
    print(file=sys.stderr)

    core_analyzers = [
        ("Processes",              lambda: ProcessAnalyzer(events)),
        ("Behavioral indicators",  lambda: BehaviorAnalyzer(events)),
        ("Network activity",       lambda: NetworkAnalyzer(events)),
        ("File activity",          lambda: FileAnalyzer(events)),
        ("Registry activity",      lambda: RegistryAnalyzer(events)),
        ("Scripts",                lambda: ScriptAnalyzer(events)),
        ("Modules",                lambda: ModuleAnalyzer(events)),
        ("Scheduled tasks",        lambda: TaskAnalyzer(events)),
        ("Timeline",               lambda: TimelineBuilder(events)),
        ("LSASS access",           lambda: LsassAnalyzer(events)),
        ("Command lines",          lambda: CmdlineAnalyzer(events)),
    ]
    results = {}
    for name, factory in core_analyzers:
        step += 1
        t0 = time.time()
        results[name] = factory()
        elapsed = time.time() - t0
        _step(step, total_steps, f"{name} {C.dim(f'({_fmt_duration(elapsed)})')}")

    proc     = results["Processes"]
    behav    = results["Behavioral indicators"]
    net      = results["Network activity"]
    files    = results["File activity"]
    reg      = results["Registry activity"]
    scripts  = results["Scripts"]
    modules  = results["Modules"]
    tasks    = results["Scheduled tasks"]
    timeline = results["Timeline"]
    lsass    = results["LSASS access"]
    cmdline_an = results["Command lines"]

    # Correlation + contextualization
    step += 1
    t0 = time.time()
    correlation = CorrelationEngine(behav)
    _step(step, total_steps, f"Correlation engine {C.dim(f'({_fmt_duration(time.time() - t0)})')}")

    step += 1
    t0 = time.time()
    ctx = IndicatorContextualizer(proc, behav, files)
    _step(step, total_steps, f"Forensic contextualization {C.dim(f'({_fmt_duration(time.time() - t0)})')}")

    step += 1
    t0 = time.time()
    temporal = TemporalCorrelationAnalyzer(behav)
    _step(step, total_steps, f"Temporal sequences {C.dim(f'({_fmt_duration(time.time() - t0)})')}")

    step += 1
    t0 = time.time()
    ioc_an = IocExtractAnalyzer(events)
    _step(step, total_steps, f"IOC extraction {C.dim(f'({_fmt_duration(time.time() - t0)})')}")

    print(file=sys.stderr)

    # ── Phase 3: Detection engines ──
    print(f"  {C.bold('Phase 2/4')} {C.dim('- Detection engines')}", file=sys.stderr)
    print(file=sys.stderr)

    sigma = None
    if enable_sigma:
        step += 1
        sp = _Spinner("Loading Sigma rules...").start()
        t0 = time.time()
        sigma = SigmaEvaluator()
        elapsed = time.time() - t0
        if sigma.available:
            sp.stop(f"{C.bold(str(sigma.rule_count))} Sigma rules loaded {C.dim(f'({_fmt_duration(elapsed)})')}")
        else:
            sp.stop("Sigma rules not available (run --update or pip install pyyaml)", ok=False)

    process_graph = None
    if enable_graph:
        step += 1
        sp = _Spinner("Building process graph (NetworkX)...").start()
        t0 = time.time()
        process_graph = ProcessGraphAnalyzer(events)
        elapsed = time.time() - t0
        if process_graph.available:
            sp.stop(f"Process graph built {C.dim(f'({_fmt_duration(elapsed)})')}")
        else:
            sp.stop("NetworkX not available (pip install networkx)", ok=False)

    stats = None
    if enable_stats:
        step += 1
        sp = _Spinner("Statistical anomaly analysis...").start()
        t0 = time.time()
        stats = StatisticalAnalyzer(events)
        elapsed = time.time() - t0
        sp.stop(f"Statistical analysis done {C.dim(f'({_fmt_duration(elapsed)})')}")

    yara_an = None
    if enable_yara:
        step += 1
        sp = _Spinner("Loading YARA rules...").start()
        t0 = time.time()
        yara_an = YaraAnalyzer(events)
        elapsed = time.time() - t0
        if yara_an.available:
            sp.stop(f"{C.bold(str(yara_an.loaded_count()))} YARA rule files loaded {C.dim(f'({_fmt_duration(elapsed)})')}")
        else:
            sp.stop("YARA rules not available (run --update or pip install yara-python)", ok=False)

    mitre_enricher = None
    if enable_attack:
        step += 1
        sp = _Spinner("Loading ATT&CK enrichment...").start()
        t0 = time.time()
        mitre_enricher = MitreAttackEnricher()
        elapsed = time.time() - t0
        if mitre_enricher.available:
            sp.stop(f"ATT&CK enrichment loaded {C.dim(f'({_fmt_duration(elapsed)})')}")
        else:
            sp.stop("ATT&CK bundle not available (run --update or pip install mitreattack-python)", ok=False)

    print(file=sys.stderr)

    # ── Phase 4: Verdict ──
    print(f"  {C.bold('Phase 3/4')} {C.dim('- Verdict computation')}", file=sys.stderr)
    print(file=sys.stderr)

    step += 1
    sp = _Spinner("Computing verdict...").start()
    t0 = time.time()
    engine = VerdictEngine(proc, behav, net, files, reg, scripts,
                           modules, tasks, correlation, ctx,
                           lsass=lsass, cmdline_analyzer=cmdline_an,
                           temporal=temporal, sigma=sigma,
                           process_graph=process_graph, stats=stats,
                           yara_an=yara_an, mitre_enricher=mitre_enricher)
    verdict = engine.evaluate()
    elapsed = time.time() - t0
    sp.stop(f"Verdict computed {C.dim(f'({_fmt_duration(elapsed)})')}")

    # Optional IP geolocation enrichment
    ip_info = {}
    if ip_enrich:
        step += 1
        ext_ips = [d["dst_ip"] for d in net.get_unique_external()]
        if ext_ips:
            sp = _Spinner(f"Enriching {len(ext_ips)} IPs (geolocation)...").start()
            t0 = time.time()
            enricher = IpEnricher()
            ip_info = enricher.enrich(ext_ips)
            elapsed = time.time() - t0
            sp.stop(f"{C.bold(str(len(ip_info)))} IPs enriched {C.dim(f'({_fmt_duration(elapsed)})')}")

    print(file=sys.stderr)

    # ── Phase 5: Report generation ──
    print(f"  {C.bold('Phase 4/4')} {C.dim('- Report generation')}", file=sys.stderr)
    print(file=sys.stderr)

    step += 1
    sp = _Spinner("Generating report...").start()
    t0 = time.time()
    report = ReportGenerator(events, proc, behav, net, files, reg,
                             scripts, modules, tasks, timeline, ctx, verdict,
                             vt_client=vt_client, ip_info=ip_info,
                             mb_client=mb_client, otx_client=otx_client,
                             shodan_client=shodan_client,
                             lsass=lsass, cmdline_an=cmdline_an,
                             temporal=temporal, sigma=sigma,
                             process_graph=process_graph, stats=stats,
                             yara_an=yara_an, mitre_enricher=mitre_enricher,
                             ioc_an=ioc_an, correlation=correlation)

    if output_report:
        result = report.generate_json()
    elif output_json:
        result = report.generate_json()
    elif output_html:
        result = report.generate_html()
    else:
        result = report.generate()

    elapsed = time.time() - t0
    sp.stop(f"Report generated {C.dim(f'({_fmt_duration(elapsed)})')}")

    # ── Summary ──
    total_elapsed = time.time() - t_total
    print(file=sys.stderr)
    print(_separator("Analysis Complete"), file=sys.stderr)
    print(file=sys.stderr)
    print(f"  {C.ok('[OK]')} {C.bold(str(len(events)))} events analyzed in "
          f"{C.bold(_fmt_duration(total_elapsed))}", file=sys.stderr)

    # Quick stats summary
    n_behav = len(behav.unique) if hasattr(behav, 'unique') else 0
    n_net   = len(net.get_unique_external()) if hasattr(net, 'get_unique_external') else 0
    n_sigma = sigma.rule_count if sigma and sigma.available else 0
    n_yara  = yara_an.loaded_count() if yara_an and yara_an.available else 0

    summary_parts = []
    if n_behav:
        summary_parts.append(f"{n_behav} behavioral indicators")
    if n_net:
        summary_parts.append(f"{n_net} ext. connections")
    if n_sigma:
        summary_parts.append(f"{n_sigma} Sigma rules evaluated")
    if n_yara:
        summary_parts.append(f"{n_yara} YARA rules scanned")
    if summary_parts:
        print(f"      {C.dim(' | '.join(summary_parts))}", file=sys.stderr)

    print(file=sys.stderr)

    return result


def _banner():
    """Affiche la bannière de l'outil."""
    banner = f"""
\033[96m  ___  _     _                _
 / __|| |   /_\\  _ _   __ _ | | _  _  ___ ___  _ _
 \\__ \\| |  / _ \\| ' \\ / _` || || || ||_ // -_)| '_|
 |___/|_| /_/ \\_\\|_||_|\\__,_||_| \\_, |/__|\\___|_|
                                  |__/              \033[0m
\033[97m  {__tool__} v{__version__}\033[0m — SentinelOne Deep Visibility Forensic Analyzer
\033[90m  Author: {__author__}\033[0m
"""
    print(banner, file=sys.stderr)


def main():
    global _USE_COLOR
    parser = argparse.ArgumentParser(
        description=f"{__tool__} v{__version__} — SentinelOne Deep Visibility Forensic Analyzer | {__author__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python s1_analyzer.py --update                          # Download ATT&CK, Sigma, YARA rules\n"
            "  python s1_analyzer.py alert.csv                         # Full analysis (JSON + HTML auto-generated)\n"
            "  python s1_analyzer.py alert.csv -o report.txt           # Save text report to file\n"
            "  python s1_analyzer.py alert.csv --json                  # Print raw JSON to stdout\n"
            "  python s1_analyzer.py alert.csv --vt-key KEY --mb --enrich-ips  # Full TI enrichment\n"
            "  python s1_analyzer.py alert.csv --no-sigma --no-yara    # Skip heavy analysis\n"
            "  python s1_analyzer.py alert.csv --no-color -o report.txt\n"
            "\nOutput:\n"
            "  By default, a folder is created with both report.json and report.html.\n"
            "  The HTML dashboard is self-contained and can be opened in any browser.\n"
            "\nThreat Score (0-20):\n"
            "   0 -  3 : FALSE POSITIVE / Benign      - No malicious indicators\n"
            "   4 -  7 : LIKELY FALSE POSITIVE         - Low risk, mostly benign context\n"
            "   8 - 11 : UNDETERMINED                  - Needs analyst investigation\n"
            "  12 - 15 : SUSPICIOUS                    - Likely malicious, investigate urgently\n"
            "  16 - 20 : TRUE POSITIVE / Malicious     - Confirmed threat, requires action\n"
            "\nRequired pip packages for full analysis:\n"
            "  pip install pyyaml networkx pyod yara-python iocextract mitreattack-python"
        )
    )
    parser.add_argument("csv_file",     nargs="?", default=None,
                        help="Path to SentinelOne CSV file (optional when using --update)")
    parser.add_argument("--report",     action="store_true",
                        help="Generate full report (JSON + HTML are always auto-generated)")
    parser.add_argument("--html",       action="store_true", help="Print HTML to stdout (or use with -o)")
    parser.add_argument("--json",       action="store_true", help="Raw JSON output")
    parser.add_argument("-o", "--output", help="Output file (text, HTML, or JSON)")
    parser.add_argument("--no-color",   action="store_true",
                        help="Disable ANSI colors (for logs/files)")
    parser.add_argument("--vt-key",     metavar="API_KEY",
                        help="VirusTotal v3 API key (free at virustotal.com)")
    parser.add_argument("--enrich-ips", action="store_true",
                        help="Enrich external IPs via ip-api.com (geo/ASN)")
    parser.add_argument("--update",      action="store_true",
                        help="Download/update ATT&CK bundle, Sigma rules, YARA signature-base")
    parser.add_argument("--no-sigma",    action="store_true",
                        help="Disable Sigma rule evaluation")
    parser.add_argument("--no-yara",     action="store_true",
                        help="Disable YARA scanning")
    parser.add_argument("--no-graph",    action="store_true",
                        help="Disable NetworkX process graph analysis")
    parser.add_argument("--no-stats",    action="store_true",
                        help="Disable statistical anomaly analysis")
    parser.add_argument("--no-attack",   action="store_true",
                        help="Disable ATT&CK enrichment")
    parser.add_argument("--mb",          action="store_true",
                        help="Enable MalwareBazaar hash lookups (no API key required)")
    parser.add_argument("--otx-key",     metavar="API_KEY",
                        help="AlienVault OTX API key (free at otx.alienvault.com)")
    parser.add_argument("--shodan-key",  metavar="API_KEY",
                        help="Shodan API key (shodan.io)")
    args = parser.parse_args()

    if args.no_color or (args.output and not args.html):
        _USE_COLOR = False

    _banner()

    # Handle --update independently of csv_file
    if args.update:
        update_all_resources()
        if not args.csv_file:
            sys.exit(0)

    if not args.csv_file:
        print(f"  {C.high('[!]')} Please provide a CSV file or use --update", file=sys.stderr)
        sys.exit(1)

    if not Path(args.csv_file).exists():
        print(f"  {C.high('[!]')} File not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    # ── Configuration summary ──
    csv_path = Path(args.csv_file)
    csv_size = csv_path.stat().st_size
    print(f"  {C.info('Input')}  : {C.bold(csv_path.name)} {C.dim(f'({csv_size / 1024:.1f} KB)')}", file=sys.stderr)

    enabled_modules = []
    disabled_modules = []
    for name, flag in [("Sigma", args.no_sigma), ("YARA", args.no_yara),
                       ("Graph", args.no_graph), ("Stats", args.no_stats),
                       ("ATT&CK", args.no_attack)]:
        if flag:
            disabled_modules.append(name)
        else:
            enabled_modules.append(name)

    ti_sources = []
    if args.vt_key:     ti_sources.append("VirusTotal")
    if args.mb:         ti_sources.append("MalwareBazaar")
    if args.otx_key:    ti_sources.append("OTX")
    if args.shodan_key: ti_sources.append("Shodan")
    if args.enrich_ips: ti_sources.append("IP geo")

    print(f"  {C.info('Modules')}: {C.dim(', '.join(enabled_modules))}"
          f"{C.dim(f'  (disabled: {', '.join(disabled_modules)})') if disabled_modules else ''}",
          file=sys.stderr)
    if ti_sources:
        print(f"  {C.info('TI')}     : {C.dim(', '.join(ti_sources))}", file=sys.stderr)
    print(file=sys.stderr)

    vt     = VirusTotalClient(args.vt_key)  if args.vt_key     else None
    mb     = MalwareBazaarClient()          if args.mb         else None
    otx    = OTXClient(args.otx_key)        if args.otx_key    else None
    shodan = ShodanClient(args.shodan_key)  if args.shodan_key else None

    # Single analysis run
    t_main = time.time()
    data = analyze(args.csv_file, output_report=True,
                   vt_client=vt, ip_enrich=args.enrich_ips,
                   mb_client=mb, otx_client=otx, shodan_client=shodan,
                   enable_sigma=not args.no_sigma,
                   enable_yara=not args.no_yara,
                   enable_graph=not args.no_graph,
                   enable_stats=not args.no_stats,
                   enable_attack=not args.no_attack)

    # ── Output files ──
    print(_separator("Output"), file=sys.stderr)
    print(file=sys.stderr)

    from datetime import datetime as _dt
    timestamp = _dt.now().strftime("%Y%m%d_%H%M%S")
    out_dir = csv_path.parent / f"{csv_path.stem}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Inject CSV filename into meta
    if "meta" in data:
        data["meta"]["csv_file"] = csv_path.name

    # Write report.json (always)
    sp = _Spinner("Writing report.json...").start()
    json_path = out_dir / "report.json"
    json_str = json.dumps(data, ensure_ascii=False, default=str, indent=2)
    json_path.write_text(json_str, encoding="utf-8")
    json_size = json_path.stat().st_size
    sp.stop(f"report.json {C.dim(f'({json_size / 1024:.1f} KB)')}")

    # Write report.html (always, via s1_report if available)
    html_content = None
    try:
        sp = _Spinner("Generating report.html...").start()
        import s1_report
        html_content = s1_report.generate_html(data)
        html_path = out_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        html_size = html_path.stat().st_size
        sp.stop(f"report.html {C.dim(f'({html_size / 1024:.1f} KB)')}")
    except ImportError:
        sp.stop("s1_report.py not found - only JSON generated", ok=False)
    except Exception as e:
        sp.stop(f"HTML generation failed: {e}", ok=False)

    total_elapsed = time.time() - t_main
    print(file=sys.stderr)
    print(f"  {C.ok('[+]')} Report folder: {C.bold(str(out_dir))}", file=sys.stderr)
    print(f"  {C.ok('[+]')} Total time: {C.bold(_fmt_duration(total_elapsed))}", file=sys.stderr)
    print(file=sys.stderr)

    # Stdout output based on flags (no re-analysis needed)
    if args.json:
        print(json_str)
    elif args.html and args.output and html_content:
        Path(args.output).write_text(html_content, encoding="utf-8")
        print(f"  {C.ok('[+]')} HTML also written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()

