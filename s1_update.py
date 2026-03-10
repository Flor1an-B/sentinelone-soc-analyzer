#!/usr/bin/env python3
"""
S1 Analyzer — Sync / Update Tool

Synchronizes local project files with the latest version on GitHub.
Compares local files against the remote repository using the GitHub API
and downloads only what has changed.

Usage:
    python s1_update.py              # Check & update
    python s1_update.py --check      # Check only (dry run)
    python s1_update.py --force      # Re-download all project files

No dependencies required (uses Python stdlib only).
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ── Configuration ──
REPO_OWNER = "Flor1an-B"
REPO_NAME  = "s1-analyzer"
BRANCH     = "main"
API_BASE   = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}"

# Files that are part of the project (exclude data/, outputs, caches)
PROJECT_FILES = {
    "s1_analyzer.py",
    "s1_report.py",
    "s1_update.py",
    "requirements.txt",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    ".gitignore",
}

# Directories to ensure exist
PROJECT_DIRS = [
    "data/attack",
    "data/sigma/rules",
    "data/yara/rules",
]


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


C = Colors


def get_local_dir() -> Path:
    """Return the directory where this script lives."""
    return Path(__file__).resolve().parent


def sha1_file(filepath: Path) -> str:
    """Compute SHA1 hash of a local file (same algorithm as git blob)."""
    try:
        content = filepath.read_bytes()
        # Git blob SHA1: "blob <size>\0<content>"
        header = f"blob {len(content)}\0".encode()
        return hashlib.sha1(header + content).hexdigest()
    except (OSError, IOError):
        return ""


def api_get(endpoint: str) -> dict:
    """GET request to GitHub API."""
    url = f"{API_BASE}/{endpoint}" if not endpoint.startswith("http") else endpoint
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "s1-analyzer-updater/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"\n{C.red('[!]')} GitHub API rate limit exceeded. Try again later.")
            print(f"    {C.dim('(Unauthenticated: 60 requests/hour)')}")
            sys.exit(1)
        raise


def get_remote_tree() -> dict:
    """Fetch the full file tree from GitHub (recursive)."""
    data = api_get(f"git/trees/{BRANCH}?recursive=1")
    tree = {}
    for item in data.get("tree", []):
        if item["type"] == "blob" and item["path"] in PROJECT_FILES:
            tree[item["path"]] = item["sha"]
    return tree


def get_remote_version() -> str:
    """Fetch __version__ from the remote s1_analyzer.py (first 100 lines)."""
    try:
        url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/s1_analyzer.py"
        req = urllib.request.Request(url, headers={"User-Agent": "s1-analyzer-updater/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            for line in resp.read().decode("utf-8", errors="replace").splitlines()[:100]:
                if line.strip().startswith("__version__"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "?"


def get_local_version(base: Path) -> str:
    """Read __version__ from local s1_analyzer.py."""
    analyzer = base / "s1_analyzer.py"
    if not analyzer.exists():
        return "not installed"
    try:
        for line in analyzer.read_text(encoding="utf-8").splitlines()[:100]:
            if line.strip().startswith("__version__"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "?"


def download_file(path: str, dest: Path):
    """Download a single file from the repository."""
    url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "s1-analyzer-updater/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)


def compare_files(base: Path, remote_tree: dict, force: bool = False) -> tuple:
    """
    Compare local files with remote tree.
    Returns (to_update, to_create, up_to_date) lists.
    """
    to_update  = []  # (path, local_sha, remote_sha)
    to_create  = []  # (path, remote_sha)
    up_to_date = []  # (path,)

    for path, remote_sha in remote_tree.items():
        local_path = base / path
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


def print_banner():
    print(f"""
 {C.bold('S1 Analyzer — Update Tool')}
 {C.dim(f'Repository: github.com/{REPO_OWNER}/{REPO_NAME}')}
""")


def main():
    parser = argparse.ArgumentParser(
        description="Sync local S1 Analyzer files with the latest GitHub version."
    )
    parser.add_argument("--check", action="store_true",
                        help="Check for updates without downloading (dry run)")
    parser.add_argument("--force", action="store_true",
                        help="Re-download all project files regardless of changes")
    args = parser.parse_args()

    print_banner()
    base = get_local_dir()

    # ── Versions ──
    print(f"  {C.cyan('[*]')} Checking versions...")
    local_ver  = get_local_version(base)
    remote_ver = get_remote_version()
    print(f"      Local  : {C.bold(local_ver)}")
    print(f"      Remote : {C.bold(remote_ver)}")
    if local_ver == remote_ver and not args.force:
        print(f"\n      {C.dim('Same version.')}")
    elif local_ver != remote_ver:
        print(f"\n      {C.yellow('Update available!')}")
    print()

    # ── Compare files ──
    print(f"  {C.cyan('[*]')} Fetching remote file tree...")
    remote_tree = get_remote_tree()
    if not remote_tree:
        print(f"  {C.red('[!]')} Could not fetch remote tree. Check your internet connection.")
        sys.exit(1)

    print(f"  {C.cyan('[*]')} Comparing {len(remote_tree)} project file(s)...")
    to_update, to_create, up_to_date = compare_files(base, remote_tree, args.force)

    # ── Summary ──
    print()
    if up_to_date and not args.force:
        print(f"  {C.green('[OK]')} {len(up_to_date)} file(s) up to date")

    if to_create:
        print(f"  {C.yellow('[NEW]')} {len(to_create)} file(s) to download:")
        for path, _ in to_create:
            print(f"         + {C.green(path)}")

    if to_update:
        label = "to re-download" if args.force else "to update"
        print(f"  {C.yellow('[UPD]')} {len(to_update)} file(s) {label}:")
        for path, *_ in to_update:
            print(f"         ~ {C.yellow(path)}")

    if not to_create and not to_update:
        print(f"\n  {C.green('Everything is up to date.')} Nothing to do.")
        return

    # ── Dry run? ──
    if args.check:
        total = len(to_create) + len(to_update)
        print(f"\n  {C.dim(f'Dry run: {total} file(s) would be downloaded. Run without --check to apply.')}")
        return

    # ── Download ──
    print()
    total = len(to_create) + len(to_update)
    downloaded = 0
    errors = 0

    for path, _ in to_create:
        try:
            download_file(path, base / path)
            downloaded += 1
            print(f"  {C.green('[+]')} {path}")
        except Exception as e:
            errors += 1
            print(f"  {C.red('[!]')} {path} — {e}")

    for path, *_ in to_update:
        try:
            download_file(path, base / path)
            downloaded += 1
            print(f"  {C.green('[~]')} {path}")
        except Exception as e:
            errors += 1
            print(f"  {C.red('[!]')} {path} — {e}")

    # ── Ensure data directories exist ──
    for d in PROJECT_DIRS:
        dp = base / d
        dp.mkdir(parents=True, exist_ok=True)
        gitkeep = dp / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.touch()

    # ── Report ──
    print()
    if errors:
        print(f"  {C.yellow('[!]')} {downloaded}/{total} file(s) downloaded, {errors} error(s)")
    else:
        print(f"  {C.green('[OK]')} {downloaded}/{total} file(s) synchronized successfully")

    new_ver = get_local_version(base)
    if new_ver != local_ver:
        print(f"  {C.green('[OK]')} Updated: {local_ver} -> {C.bold(new_ver)}")

    # Remind about rule updates
    print(f"\n  {C.dim('Tip: Run')} python s1_analyzer.py --update {C.dim('to download the latest detection rules.')}")
    print()


if __name__ == "__main__":
    main()
