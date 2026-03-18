"""core_http.py — HTTP session and request helpers for WATT."""
from __future__ import annotations
import logging, random, time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse
import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .config import DEFAULT_USER_AGENTS

log = logging.getLogger(__name__)

RETRY_STATUS_CODES = frozenset({500, 502, 503, 504})


@dataclass
class SessionConfig:
    proxy:           str | None          = None
    retries:         int                 = 3
    backoff_factor:  float               = 0.5
    timeout:         int                 = 15
    jitter:          tuple[float, float] = field(default_factory=lambda: (0.1, 0.5))
    user_agents:     list[str]           = field(default_factory=lambda: list(DEFAULT_USER_AGENTS))
    verify_ssl:      bool | str          = True
    allow_redirects: bool                = True


def create_session(config: SessionConfig | None = None) -> Session:
    if config is None:
        config = SessionConfig()
    session = Session()
    if config.proxy:
        session.proxies = {"http": config.proxy, "https": config.proxy}
    session.verify = config.verify_ssl
    retry = Retry(
        total=config.retries,
        backoff_factor=config.backoff_factor,
        status_forcelist=list(RETRY_STATUS_CODES),
        allowed_methods={"GET", "POST", "HEAD", "OPTIONS"},
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    return session


def build_headers(user_agents: list[str] | None = None,
                  extra: dict[str, str] | None = None) -> dict[str, str]:
    pool = user_agents or DEFAULT_USER_AGENTS
    h = {
        "User-Agent":      random.choice(pool),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
        "Cache-Control":   "no-cache",
    }
    if extra:
        h.update(extra)
    return h


def request(
    session: Session,
    method: str,
    url: str,
    config: SessionConfig | None = None,
    *,
    extra_headers: dict[str, str] | None = None,
    jitter: bool = True,
    **kwargs: Any,
) -> Response | None:
    cfg = config or SessionConfig()
    kwargs.setdefault("timeout", cfg.timeout)
    kwargs.setdefault("allow_redirects", cfg.allow_redirects)
    if "headers" not in kwargs:
        kwargs["headers"] = build_headers(cfg.user_agents, extra=extra_headers)
    elif extra_headers:
        kwargs["headers"].update(extra_headers)
    try:
        resp = session.request(method, url, **kwargs)
        log.debug("%s %s → %d", method.upper(), url, resp.status_code)
        return resp
    except requests.exceptions.SSLError        as e: log.warning("SSL %s: %s", url, e)
    except requests.exceptions.ConnectionError as e: log.debug("Connection %s: %s", url, e)
    except requests.exceptions.Timeout:              log.warning("Timeout %s", url)
    except requests.exceptions.RequestException as e: log.debug("Request %s: %s", url, e)
    finally:
        if jitter:
            lo, hi = cfg.jitter
            if hi > 0:
                time.sleep(random.uniform(lo, hi))
    return None


# URL utilities
def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    return urlunparse(p._replace(path=p.path.rstrip("/")))

def is_valid_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in {"http", "https"} and bool(p.netloc)
    except ValueError:
        return False

def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

def extract_domain(url: str) -> str:
    return urlparse(url).netloc
