"""base.py — Abstract base class for all WATT modules."""
from __future__ import annotations
import logging, threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from requests import Response
from .config import DEFAULT_CONFIG
from .core_http import SessionConfig, create_session, is_valid_http_url, normalise_url, request

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Credential:
    username: str
    password: str
    url:      str
    note:     str = ""

    def __str__(self) -> str:
        note = f"  [{self.note}]" if self.note else ""
        return f"{self.username}:{self.password} @ {self.url}{note}"


class WordPressTesterBase(ABC):
    def __init__(
        self,
        target: str,
        config: dict[str, Any],
        *,
        wordlist:  str | None  = None,
        usernames: list | None = None,
    ) -> None:
        self.target    = self._validate_target(target)
        self.config    = config
        self.wordlist  = wordlist or ""
        self.usernames = list(usernames or [])
        self.session_config = self._build_session_config(config)
        self.delay   = float(config.get("delay",   DEFAULT_CONFIG.get("delay",   1.0)))
        self.timeout = int  (config.get("timeout", DEFAULT_CONFIG.get("timeout", 15)))
        self._session             = create_session(self.session_config)
        self._found_credentials: list[Credential] = []
        self._lock                = threading.Lock()
        log.debug("%s initialised → %s", type(self).__name__, self.target)

    @abstractmethod
    def run(self): ...

    def __enter__(self):  return self
    def __exit__(self, *_): self.close()
    def close(self):        self._session.close()

    def _request(
        self, method: str, url: str,
        *, extra_headers: dict[str, str] | None = None,
        jitter: bool = True, **kwargs: Any,
    ) -> Response | None:
        return request(
            self._session, method, url, self.session_config,
            extra_headers=extra_headers, jitter=jitter, **kwargs,
        )

    def _add_credential(self, username: str, password: str, *, note: str = "") -> Credential:
        cred = Credential(username=username, password=password, url=self.target, note=note)
        with self._lock:
            if cred not in self._found_credentials:
                self._found_credentials.append(cred)
                log.info("Credential found: %s", cred)
        return cred

    @property
    def found_credentials(self) -> list[Credential]:
        with self._lock:
            return list(self._found_credentials)

    @staticmethod
    def _validate_target(raw: str) -> str:
        url = normalise_url(raw)
        if not is_valid_http_url(url):
            raise ValueError(f"Invalid target URL: {raw!r}")
        return url

    @staticmethod
    def _build_session_config(config: dict[str, Any]) -> SessionConfig:
        def g(k, d=None): return config.get(k, DEFAULT_CONFIG.get(k, d))
        return SessionConfig(
            proxy=g("proxy"),
            retries=int(g("retries", 3)),
            backoff_factor=float(g("backoff_factor", 0.5)),
            timeout=int(g("timeout", 15)),
            jitter=tuple(g("jitter", (0.1, 0.5))),
            user_agents=list(g("user_agents", [])),
            verify_ssl=g("verify_ssl", True),
            allow_redirects=g("allow_redirects", True),
        )
