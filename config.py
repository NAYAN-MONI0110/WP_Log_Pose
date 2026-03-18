"""config.py — defaults and config loader for WATT."""
from __future__ import annotations
import json, logging, os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

DEFAULT_CONFIG: dict[str, Any] = {
    "delay":           1.0,
    "jitter":          [0.1, 0.5],
    "timeout":         15,
    "retries":         3,
    "backoff_factor":  0.5,
    "batch":           50,
    "threads":         5,
    "proxy":           None,
    "verify_ssl":      True,
    "allow_redirects": True,
    "output":          None,
    "format":          "txt",
    "safe":            False,
    "stop_on_first":   True,
    "user_agents":     DEFAULT_USER_AGENTS,
}


def load_config(config_file=None) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if config_file:
        p = Path(config_file)
        if p.is_file():
            with p.open(encoding="utf-8") as f:
                user_cfg = json.load(f)
            if isinstance(user_cfg, dict):
                config.update(user_cfg)
            log.info("Config loaded from %s", p)
        else:
            log.warning("Config file not found: %s", config_file)
    return config
