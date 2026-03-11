#!/usr/bin/env python3
"""
S1 Analyzer - Sync / Update Tool

Unified updater: synchronizes application files AND detection rules.

  - Application files are compared (SHA1) against the GitHub repository
    and only changed files are downloaded.
  - Detection rules (MITRE ATT&CK, Sigma, YARA) are downloaded from
    their respective upstream sources.

Usage:
    python s1_update.py              # Update everything (app + rules)
    python s1_update.py --app        # Update application files only
    python s1_update.py --rules      # Update detection rules only
    python s1_update.py --check      # Dry run (show what would change)
    python s1_update.py --force      # Force re-download everything

No dependencies required (uses Python stdlib only).
"""

__version__ = "2.0.0"
__author__  = "Florian Bertaux"
__tool__    = "S1 Update"

import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

# -- Repository Configuration --
REPO_OWNER = "Flor1an-B"
REPO_NAME  = "s1-analyzer"
BRANCH     = "main"
API_BASE   = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"

# -- Local Paths --
BASE_DIR    = Path(__file__).resolve().parent
DATA_DIR    = BASE_DIR / "data"
ATTACK_BUNDLE = DATA_DIR / "attack" / "enterprise-attack.json"
SIGMA_DIR     = DATA_DIR / "sigma" / "rules"
YARA_DIR      = DATA_DIR / "yara" / "rules"

# -- Paths excluded from app sync (managed by rules update) --
EXCLUDE_PREFIXES = (
    "data/attack/",
    "data/sigma/rules/",
    "data/yara/rules/",
)

# -- Directories to ensure exist locally --
PROJECT_DIRS = [
    "data/attack",
    "data/sigma/rules",
    "data/yara/rules",
]

# -- Rules sources --
_ATTACK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
               "enterprise-attack/enterprise-attack.json")
_SIGMA_ZIP  = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
_YARA_ZIP   = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"

_SIGMA_PATHS = [
    "sigma-master/rules/windows/",
]


# ===========================================================================
# COLORS
# ===========================================================================

class Colors:
    """ANSI color codes (disabled on non-TTY or Windows without VT)."""
    _enabled = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    try:
        os.system("")  # Enable VT100 on Windows
    except Exception:
        pass

    @staticmethod
    def _c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if Colors._enabled else text

    @staticmethod
    def green(t):  return Colors._c("92", t)
    @staticmethod
    def red(t):    return Colors._c("91", t)
    @staticmethod
    def yellow(t): return Colors._c("93", t)
    @staticmethod
    def cyan(t):   return Colors._c("96", t)
    @staticmethod
    def dim(t):    return Colors._c("2", t)
    @staticmethod
    def bold(t):   return Colors._c("1", t)
    @staticmethod
    def white(t):  return Colors._c("97", t)


C = Colors


# ===========================================================================
# SPINNER / PROGRESS INDICATORS
# ===========================================================================

class Spinner:
    """Animated spinner for long-running operations."""
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
            print(f"\r  {C.cyan(f'[{frame}]')} {self._msg}   ", end="", flush=True)
            self._idx += 1
            time.sleep(0.12)

    def stop(self, final_msg: str = "", ok: bool = True):
        self._running = False
        if self._thread:
            self._thread.join()
        if final_msg:
            tag = C.green("[OK]") if ok else C.red("[!!]")
            print(f"\r  {tag} {final_msg}                              ")
        else:
            print(f"\r{'':60}", end="\r")


def _progress_bar(current: int, total: int, width: int = 25) -> str:
    """Return a text progress bar string."""
    if total <= 0:
        return ""
    ratio = min(current / total, 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    pct = int(ratio * 100)
    return f"{C.dim('[')}{bar}{C.dim(']')} {pct:3d}%"


# ===========================================================================
# UTILITIES
# ===========================================================================

def _fmt_size(n: int) -> str:
    """Format byte count as human-readable string."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / (1024 * 1024):.1f} MB"


def _fmt_duration(seconds: float) -> str:
    """Format duration as human-readable string."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"


def _separator(title: str = "") -> str:
    """Return a visual separator line."""
    if title:
        return f"  {'=' * 3} {C.bold(title)} {'=' * (50 - len(title))}"
    return f"  {'=' * 56}"


def sha1_file(filepath: Path) -> str:
    """Compute SHA1 hash of a local file (same algorithm as git blob)."""
    try:
        content = filepath.read_bytes()
        content = content.replace(b"\r\n", b"\n")
        header = f"blob {len(content)}\0".encode()
        return hashlib.sha1(header + content).hexdigest()
    except (OSError, IOError):
        return ""


# ===========================================================================
# GITHUB API
# ===========================================================================

def api_get(endpoint: str) -> dict:
    """GET request to GitHub API."""
    url = f"{API_BASE}/{endpoint}" if not endpoint.startswith("http") else endpoint
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "s1-analyzer-updater/2.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"\n  {C.red('[!]')} GitHub API rate limit exceeded. Try again later.")
            print(f"      {C.dim('(Unauthenticated: 60 requests/hour)')}")
            sys.exit(1)
        raise


def get_remote_tree() -> dict:
    """Fetch the full file tree from GitHub (recursive), excluding data/rules."""
    data = api_get(f"git/trees/{BRANCH}?recursive=1")
    tree = {}
    for item in data.get("tree", []):
        if item["type"] != "blob":
            continue
        path = item["path"]
        if any(path.startswith(p) for p in EXCLUDE_PREFIXES):
            continue
        tree[path] = item["sha"]
    return tree


def get_remote_version() -> str:
    """Fetch __version__ from the remote s1_analyzer.py (first 100 lines)."""
    try:
        url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/s1_analyzer.py"
        req = urllib.request.Request(url, headers={"User-Agent": "s1-analyzer-updater/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            for line in resp.read().decode("utf-8", errors="replace").splitlines()[:100]:
                if line.strip().startswith("__version__"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "?"


def get_local_version() -> str:
    """Read __version__ from local s1_analyzer.py."""
    analyzer = BASE_DIR / "s1_analyzer.py"
    if not analyzer.exists():
        return "not installed"
    try:
        for line in analyzer.read_text(encoding="utf-8").splitlines()[:100]:
            if line.strip().startswith("__version__"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "?"


# ===========================================================================
# APPLICATION UPDATE
# ===========================================================================

def download_file(path: str, dest: Path) -> int:
    """Download a single file from the repository. Returns bytes written."""
    url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "s1-analyzer-updater/2.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    return len(content)


def compare_files(remote_tree: dict, force: bool = False) -> tuple:
    """
    Compare local files with remote tree.
    Returns (to_update, to_create, up_to_date) lists.
    """
    to_update  = []
    to_create  = []
    up_to_date = []

    for path, remote_sha in remote_tree.items():
        local_path = BASE_DIR / path
        if not local_path.exists():
            to_create.append((path, remote_sha))
        elif force:
            to_update.append((path, "forced", remote_sha))
        else:
            local_sha = sha1_file(local_path)
            if local_sha != remote_sha:
                to_update.append((path, local_sha, remote_sha))
            else:
                up_to_date.append((path,))

    return to_update, to_create, up_to_date


def update_app(check: bool = False, force: bool = False) -> bool:
    """
    Update application files from the GitHub repository.
    Returns True if everything succeeded.
    """
    print()
    print(_separator("Application Update"))
    print()

    # -- Versions --
    sp = Spinner("Checking versions...").start()
    local_ver  = get_local_version()
    remote_ver = get_remote_version()
    sp.stop("Version check complete")
    print(f"      Local version  : {C.bold(local_ver)}")
    print(f"      Remote version : {C.bold(remote_ver)}")
    if local_ver == remote_ver and not force:
        print(f"      Status         : {C.green('Up to date')}")
    elif local_ver != remote_ver:
        print(f"      Status         : {C.yellow('Update available!')}")
    print()

    # -- Fetch & compare --
    sp = Spinner("Fetching remote file tree...").start()
    t0 = time.time()
    remote_tree = get_remote_tree()
    elapsed = time.time() - t0
    if not remote_tree:
        sp.stop("Could not fetch remote tree. Check your internet connection.", ok=False)
        return False

    sp.stop(f"Found {C.bold(str(len(remote_tree)))} tracked file(s) {C.dim(f'({_fmt_duration(elapsed)})')}")
    print()

    sp = Spinner("Comparing local files with remote...").start()
    to_update, to_create, up_to_date = compare_files(remote_tree, force)
    total_compared = len(to_update) + len(to_create) + len(up_to_date)
    sp.stop(f"Compared {C.bold(str(total_compared))} file(s)")

    # -- Details --
    if up_to_date and not force:
        print(f"  {C.green('[OK]')} {len(up_to_date)} file(s) already up to date")

    if to_create:
        print(f"  {C.yellow('[NEW]')} {len(to_create)} new file(s) to download:")
        for path, _ in to_create:
            print(f"           + {C.green(path)}")

    if to_update:
        label = "to re-download (forced)" if force else "modified, to update"
        print(f"  {C.yellow('[UPD]')} {len(to_update)} file(s) {label}:")
        for path, *_ in to_update:
            print(f"           ~ {C.yellow(path)}")

    if not to_create and not to_update:
        print(f"\n  {C.green('All application files are up to date.')} Nothing to do.")
        return True

    # -- Dry run --
    if check:
        total = len(to_create) + len(to_update)
        print(f"\n  {C.dim(f'[Dry run] {total} file(s) would be downloaded. Run without --check to apply.')}")
        return True

    # -- Download --
    print()
    total = len(to_create) + len(to_update)
    downloaded = 0
    errors = 0
    total_bytes = 0
    t0 = time.time()

    all_files = [(path, "+", _) for path, _ in to_create] + \
                 [(path, "~", *rest) for path, *rest in to_update]

    for i, (path, symbol, *_rest) in enumerate(all_files, 1):
        progress = _progress_bar(i, total, width=15)
        try:
            nbytes = download_file(path, BASE_DIR / path)
            downloaded += 1
            total_bytes += nbytes
            tag = C.green(f'[{symbol}]')
            print(f"  {tag} {progress} {path} {C.dim(f'({_fmt_size(nbytes)})')}")
        except Exception as e:
            errors += 1
            print(f"  {C.red('[!]')} {progress} {path} - {e}")

    elapsed = time.time() - t0

    # -- Ensure data directories exist --
    for d in PROJECT_DIRS:
        dp = BASE_DIR / d
        dp.mkdir(parents=True, exist_ok=True)
        gitkeep = dp / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.touch()

    # -- Summary --
    print()
    if errors:
        print(f"  {C.yellow('[!]')} {downloaded}/{total} file(s) downloaded, {C.red(f'{errors} error(s)')}")
    else:
        print(f"  {C.green('[OK]')} {downloaded}/{total} file(s) synchronized "
              f"{C.dim(f'({_fmt_size(total_bytes)} in {_fmt_duration(elapsed)})')}")

    new_ver = get_local_version()
    if new_ver != local_ver:
        print(f"  {C.green('[OK]')} Version updated: {local_ver} {C.bold('->')} {C.bold(new_ver)}")

    return errors == 0


# ===========================================================================
# RULES UPDATE (ATT&CK, Sigma, YARA)
# ===========================================================================

def _dl(url: str, dest: Path, label: str) -> tuple:
    """Download a file with progress. Returns (success, bytes_downloaded)."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "s1-analyzer-updater/2.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = int(done / total * 100)
                        bar_w = 20
                        filled = int(bar_w * done / total)
                        bar = "#" * filled + "-" * (bar_w - filled)
                        print(f"\r      {C.dim('[')}{bar}{C.dim(']')} {pct:3d}% "
                              f"{C.dim(f'{_fmt_size(done)}/{_fmt_size(total)}')}   ",
                              end="", flush=True)
        print(f"\r      {C.green('OK')} {label}: {C.bold(_fmt_size(done))}"
              f"                                        ")
        return True, done
    except Exception as e:
        print(f"\r      {C.red('FAIL')} {label}: {e}"
              f"                                        ")
        return False, 0


def _update_attack() -> tuple:
    """Download ATT&CK bundle. Returns (success, bytes)."""
    return _dl(_ATTACK_URL, ATTACK_BUNDLE, "MITRE ATT&CK Enterprise bundle")


def _update_sigma() -> tuple:
    """Download & extract Sigma rules. Returns (success, rule_count)."""
    tmp = DATA_DIR / "_sigma.zip"
    ok, dl_bytes = _dl(_SIGMA_ZIP, tmp, "SigmaHQ rules archive")
    if not ok:
        return False, 0
    dest = SIGMA_DIR
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    try:
        with zipfile.ZipFile(tmp) as zf:
            # Pre-count eligible members for progress
            eligible = [m for m in zf.namelist()
                        if m.endswith(".yml")
                        and any(m.startswith(p) for p in _SIGMA_PATHS)
                        and len(Path(m).parts) >= 2]
            total_e = len(eligible)
            for i, member in enumerate(eligible, 1):
                parts = Path(member).parts
                cat   = parts[-2]
                fname = parts[-1]
                cat_d = dest / cat
                cat_d.mkdir(exist_ok=True)
                (cat_d / fname).write_bytes(zf.read(member))
                count += 1
                if count % 200 == 0 or count == total_e:
                    print(f"\r      {C.dim('Extracting Sigma:')} "
                          f"{_progress_bar(count, total_e, 15)} "
                          f"{C.dim(f'{count}/{total_e} rules')}   ", end="", flush=True)
        tmp.unlink()
        print(f"\r      {C.green('OK')} Extracted {C.bold(str(count))} Sigma rules "
              f"to {C.dim(str(dest))}                            ")
        return True, count
    except Exception as e:
        print(f"\r      {C.red('FAIL')} Sigma extraction failed: {e}"
              f"                            ")
        return False, 0


def _update_yara() -> tuple:
    """Download & extract YARA rules. Returns (success, rule_count)."""
    tmp = DATA_DIR / "_yara.zip"
    ok, dl_bytes = _dl(_YARA_ZIP, tmp, "signature-base YARA archive")
    if not ok:
        return False, 0
    dest = YARA_DIR
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    try:
        with zipfile.ZipFile(tmp) as zf:
            eligible = [m for m in zf.namelist()
                        if (m.endswith(".yar") or m.endswith(".yara"))
                        and "/yara/" in m]
            total_e = len(eligible)
            for i, member in enumerate(eligible, 1):
                fname = Path(member).name
                (dest / fname).write_bytes(zf.read(member))
                count += 1
                if count % 100 == 0 or count == total_e:
                    print(f"\r      {C.dim('Extracting YARA :')} "
                          f"{_progress_bar(count, total_e, 15)} "
                          f"{C.dim(f'{count}/{total_e} rules')}   ", end="", flush=True)
        tmp.unlink()
        print(f"\r      {C.green('OK')} Extracted {C.bold(str(count))} YARA rules "
              f"to {C.dim(str(dest))}                            ")
        return True, count
    except Exception as e:
        print(f"\r      {C.red('FAIL')} YARA extraction failed: {e}"
              f"                            ")
        return False, 0


def _count_rules() -> tuple:
    """Count current Sigma/YARA rules on disk."""
    sigma_n = len(list(SIGMA_DIR.rglob("*.yml"))) if SIGMA_DIR.exists() else 0
    yara_n  = len(list(YARA_DIR.glob("*.yar")) + list(YARA_DIR.glob("*.yara"))) if YARA_DIR.exists() else 0
    attack  = ATTACK_BUNDLE.exists()
    attack_size = ATTACK_BUNDLE.stat().st_size if attack else 0
    return sigma_n, yara_n, attack, attack_size


def update_rules(check: bool = False, force: bool = False) -> bool:
    """
    Download/update ATT&CK bundle, Sigma rules, and YARA signature-base.
    Returns True if everything succeeded.
    """
    print()
    print(_separator("Detection Rules Update"))
    print()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # -- Current state --
    s_before, y_before, a_before, a_size = _count_rules()
    print(f"  {C.cyan('[*]')} Current detection rules:")
    print(f"      ATT&CK  : {'Installed' if a_before else C.dim('Not installed')}"
          f"{C.dim(f' ({_fmt_size(a_size)})') if a_before else ''}")
    print(f"      Sigma   : {C.bold(str(s_before))} rule(s)"
          f"{'' if s_before else C.dim(' (not installed)')}")
    print(f"      YARA    : {C.bold(str(y_before))} rule(s)"
          f"{'' if y_before else C.dim(' (not installed)')}")
    print()

    # -- Dry run --
    if check:
        print(f"  {C.dim('[Dry run] Rules would be downloaded from:')}")
        print(f"      {C.dim('- MITRE ATT&CK   :')} {C.dim(_ATTACK_URL[:70])}...")
        print(f"      {C.dim('- SigmaHQ        :')} {C.dim(_SIGMA_ZIP[:70])}...")
        print(f"      {C.dim('- signature-base :')} {C.dim(_YARA_ZIP[:70])}...")
        print(f"\n  {C.dim('Run without --check to download.')}")
        return True

    # -- Download --
    print(f"  {C.cyan('[*]')} Downloading detection rules...")
    print()
    t0 = time.time()

    ok1, _ = _update_attack()
    ok2, sigma_count = _update_sigma()
    ok3, yara_count = _update_yara()

    elapsed = time.time() - t0
    print()

    # -- Summary --
    s_after, y_after, a_after, a_size_after = _count_rules()
    all_ok = all([ok1, ok2, ok3])

    if all_ok:
        print(f"  {C.green('[OK]')} All rules updated successfully "
              f"{C.dim(f'({_fmt_duration(elapsed)})')}")
    else:
        failed = sum(1 for x in [ok1, ok2, ok3] if not x)
        print(f"  {C.red('[!]')} {failed} download(s) failed "
              f"{C.dim(f'({_fmt_duration(elapsed)})')}")

    # -- Deltas --
    print()
    s_delta = s_after - s_before
    y_delta = y_after - y_before
    s_sym = f" ({'+' if s_delta > 0 else ''}{s_delta})" if s_delta != 0 else " (unchanged)"
    y_sym = f" ({'+' if y_delta > 0 else ''}{y_delta})" if y_delta != 0 else " (unchanged)"
    a_label = "installed" if a_after and not a_before else ("updated" if a_after else "missing")

    print(f"      ATT&CK  : {C.green(a_label) if a_after else C.red(a_label)}"
          f"{C.dim(f' ({_fmt_size(a_size_after)})') if a_after else ''}")
    print(f"      Sigma   : {C.bold(str(s_after))} rules{C.dim(s_sym)}")
    print(f"      YARA    : {C.bold(str(y_after))} rules{C.dim(y_sym)}")
    print(f"      Location: {C.dim(str(DATA_DIR))}")

    return all_ok


# ===========================================================================
# MAIN
# ===========================================================================

def print_banner():
    print(f"""
 {C.bold(f'{__tool__} v{__version__}')} - S1 Analyzer Sync & Update Tool
 {C.dim(f'Author    : {__author__}')}
 {C.dim(f'Repository: github.com/{REPO_OWNER}/{REPO_NAME}')}
 {C.dim(f'Directory : {BASE_DIR}')}
""")


def main():
    parser = argparse.ArgumentParser(
        description=f"{__tool__} v{__version__} - Unified updater for S1 Analyzer | {__author__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python s1_update.py              # Update everything (app + rules)\n"
            "  python s1_update.py --app        # Update application files only\n"
            "  python s1_update.py --rules      # Update detection rules only\n"
            "  python s1_update.py --check      # Dry run (show what would change)\n"
            "  python s1_update.py --force      # Force re-download everything\n"
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--app", action="store_true",
                        help="Update application files only")
    parser.add_argument("--rules", action="store_true",
                        help="Update detection rules only (ATT&CK, Sigma, YARA)")
    parser.add_argument("--check", action="store_true",
                        help="Check for updates without downloading (dry run)")
    parser.add_argument("--force", action="store_true",
                        help="Force re-download regardless of current state")
    args = parser.parse_args()

    print_banner()

    # If neither --app nor --rules specified, do both
    do_app   = args.app or (not args.app and not args.rules)
    do_rules = args.rules or (not args.app and not args.rules)

    t_start = time.time()
    app_ok   = True
    rules_ok = True

    if do_app:
        app_ok = update_app(check=args.check, force=args.force)

    if do_rules:
        rules_ok = update_rules(check=args.check, force=args.force)

    # -- Final report --
    total_elapsed = time.time() - t_start
    print()
    print(_separator("Done"))
    print()

    if do_app and do_rules:
        if app_ok and rules_ok:
            print(f"  {C.green('[OK]')} Everything updated successfully "
                  f"{C.dim(f'(total: {_fmt_duration(total_elapsed)})')}")
        else:
            parts = []
            if not app_ok:
                parts.append("application")
            if not rules_ok:
                parts.append("rules")
            print(f"  {C.yellow('[!]')} Some errors occurred: {', '.join(parts)} "
                  f"{C.dim(f'(total: {_fmt_duration(total_elapsed)})')}")
    elif do_app:
        status = C.green("OK") if app_ok else C.red("errors occurred")
        print(f"  Application update: {status} "
              f"{C.dim(f'({_fmt_duration(total_elapsed)})')}")
    else:
        status = C.green("OK") if rules_ok else C.red("errors occurred")
        print(f"  Rules update: {status} "
              f"{C.dim(f'({_fmt_duration(total_elapsed)})')}")

    print()


if __name__ == "__main__":
    main()
