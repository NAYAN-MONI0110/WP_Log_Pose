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

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from .config       import load_config
from .core_http    import is_valid_http_url, normalise_url
from .reporting    import (
    SUPPORTED_FORMATS,
    print_banner,
    print_config_summary,
    print_findings_summary,
    print_section,
    save_results,
    c, C
)
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
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


# ── auth gate ─────────────────────────────────────────────────────────────────
def _confirm(target: str) -> None:
    print(c("\n  ⚠   AUTHORISED TESTING ONLY", C.BOLD, C.YELLOW))
    print(c("  " + "-" * 55, C.DIM))
    print(f"  Target : {c(target, C.CYAN)}\n")
    print(c("  This tool may only be used against systems you own or", C.DIM))
    print(c("  have explicit written permission to test.", C.DIM))
    print(c("  Unauthorised use may violate laws.\n", C.DIM))

    try:
        ans = input(c("  Do you have permission? (yes/no): ", C.WHITE)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.")
        sys.exit(0)

    if ans not in {"yes", "y"}:
        print(c("\n  Not confirmed — exiting.\n", C.RED))
        sys.exit(0)

    print()


# ── argument parser ───────────────────────────────────────────────────────────
def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python3 -m WP_Log_Pose.main",
        description="WP_Log_Pose — WordPress Testing Toolkit",
    )

    p.add_argument("command", choices=["enumerate","bruteforce","vuln","auto"])
    p.add_argument("-u","--url", required=True)
    p.add_argument("-w","--wordlist")
    p.add_argument("-U","--usernames")
    p.add_argument("--output")
    p.add_argument("--format", choices=list(SUPPORTED_FORMATS), default="txt")
    p.add_argument("-m","--mode", choices=["xmlrpc","wplogin","restapi","all"], default="all")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--batch", type=int, default=1)
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--proxy")
    p.add_argument("--safe", action="store_true")
    p.add_argument("--config")
    p.add_argument("--no-confirm", action="store_true")
    p.add_argument("-v","--verbose", action="count", default=0)

    return p


# ── helpers ───────────────────────────────────────────────────────────────────
def _merge(base: dict, args: argparse.Namespace) -> dict:
    cfg = dict(base)
    for k, v in vars(args).items():
        if v is not None:
            cfg[k] = v
    return cfg


def _load_users(path: str | None) -> list[str]:
    if not path:
        return []

    p = Path(path)
    if not p.exists():
        logging.warning("User file not found: %s", path)
        return []

    return [x.strip() for x in p.read_text().splitlines() if x.strip()]


def _slugs(users) -> list[str]:
    return [u.slug if hasattr(u, "slug") else str(u) for u in users]


# ── commands ──────────────────────────────────────────────────────────────────
def _cmd_enumerate(args, config):
    print_section("User Enumeration")

    with UserEnumerator(args.url, config) as e:
        users = e.enumerate_users()

    print_findings_summary(users)
    return users


def _cmd_vuln(args, config):
    print_section("Vulnerability Scan")

    with VulnScanner(args.url, config) as v:
        report = v.run()

    return report.findings


def _cmd_bruteforce(args, config, usernames):
    if not args.wordlist:
        print("[-] wordlist required")
        sys.exit(1)

    creds = []

    with XMLRPCAttack(args.url, config, wordlist=args.wordlist, usernames=usernames) as a:
        creds.extend(a.run())

    return creds


def _cmd_auto(args, config, usernames):
    if config.get("safe"):
        return _cmd_vuln(args, config)

    users = usernames or _cmd_enumerate(args, config)
    return _cmd_bruteforce(args, config, _slugs(users))


# ── entry ─────────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    _setup_logging(args.verbose)

    print_banner(VERSION)

    try:
        args.url = normalise_url(args.url)
        if not is_valid_http_url(args.url):
            raise ValueError
    except Exception:
        print("[-] Invalid URL")
        return 1

    if not args.no_confirm:
        _confirm(args.url)

    config = _merge(load_config(args.config), args)
    usernames = _load_users(args.usernames)

    results = []

    if args.command == "enumerate":
        results = _cmd_enumerate(args, config)

    elif args.command == "vuln":
        results = _cmd_vuln(args, config)

    elif args.command == "bruteforce":
        results = _cmd_bruteforce(args, config, usernames)

    elif args.command == "auto":
        results = _cmd_auto(args, config, usernames)

    print_findings_summary(results)

    if args.output:
        save_results(results, args.output, fmt=args.format, target=args.url)

    return 0


if __name__ == "__main__":
    sys.exit(main())
