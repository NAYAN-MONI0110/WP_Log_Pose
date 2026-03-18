"""reporting.py — console output, formatting, and result persistence for WP_Log_Pose."""
from __future__ import annotations
import csv, html as _html, json, logging, sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Sequence

log = logging.getLogger(__name__)
SUPPORTED_FORMATS = ("txt", "json", "csv", "html", "md")

def _tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

def c(text: str, *codes: str) -> str:
    if not _tty(): return text
    return "".join(codes) + str(text) + C.RESET

_SEV_COLOUR = {
    "CRITICAL": C.MAGENTA + C.BOLD,
    "HIGH":     C.RED     + C.BOLD,
    "MEDIUM":   C.YELLOW  + C.BOLD,
    "LOW":      C.BLUE    + C.BOLD,
    "INFO":     C.CYAN,
}
_SEV_HTML = {
    "CRITICAL": "#9b59b6", "HIGH": "#e74c3c",
    "MEDIUM":   "#e67e22", "LOW":  "#3498db", "INFO": "#1abc9c",
}

def _to_dict(item: Any) -> dict:
    if isinstance(item, dict): return item
    if isinstance(item, str):  return {"value": item}
    d = getattr(item, "__dict__", None)
    if d:
        return {k: (list(v) if isinstance(v, (set, frozenset)) else v)
                for k, v in d.items() if not k.startswith("_")}
    return {"repr": repr(item)}

def _split(results):
    creds, findings = [], []
    for r in results:
        (creds if (hasattr(r, "username") and hasattr(r, "password")) else findings).append(r)
    return creds, findings

def _write_txt(results, path, **_):
    creds, findings = _split(results)
    with path.open("w", encoding="utf-8") as f:
        if creds:
            f.write("# Credentials\n")
            for cr in creds:
                note = f"  [{cr.note}]" if getattr(cr, "note", "") else ""
                f.write(f"{cr.username}:{cr.password}{note}\n")
        if findings:
            f.write("\n# Findings\n")
            for fi in findings:
                d = _to_dict(fi)
                f.write(f"[{d.get('severity','')}] {d.get('title', repr(fi))}\n")
                if d.get("url"):         f.write(f"  URL : {d['url']}\n")
                if d.get("remediation"): f.write(f"  Fix : {d['remediation']}\n")

def _write_json(results, path, **_):
    data = {"generated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(results), "items": [_to_dict(r) for r in results]}
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

def _write_csv(results, path, **_):
    dicts  = [_to_dict(r) for r in results]
    fields = list(dict.fromkeys(k for d in dicts for k in d))
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(dicts)

def _write_html(results, path, target="", **_):
    creds, findings = _split(results)
    def badge(s):
        col = _SEV_HTML.get(str(s).upper(), "#7f8c8d")
        return (f'<span style="background:{col};color:#fff;padding:2px 10px;'
                f'border-radius:12px;font-size:.78em;font-weight:700">'
                f'{_html.escape(str(s))}</span>')
    rows_c = "".join(
        f"<tr><td><code>{_html.escape(cr.username)}</code></td>"
        f"<td><code>{_html.escape(cr.password)}</code></td>"
        f"<td><span class='tag'>{_html.escape(getattr(cr,'note',''))}</span></td></tr>"
        for cr in creds)
    rows_f = "".join(
        f"<tr><td>{badge(getattr(fi,'severity',''))}</td>"
        f"<td>{_html.escape(str(getattr(fi,'title',repr(fi))))}</td>"
        f"<td><a href='{_html.escape(str(getattr(fi,'url','')))}' target='_blank'>"
        f"<code>{_html.escape(str(getattr(fi,'url','')))}</code></a></td>"
        f"<td>{_html.escape(str(getattr(fi,'remediation','')))}</td></tr>"
        for fi in findings)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_counts = {}
    for fi in findings:
        s = str(getattr(fi,'severity','?'))
        sev_counts[s] = sev_counts.get(s, 0) + 1
    stat_pills = "".join(
        f'<span style="background:{_SEV_HTML.get(s,"#7f8c8d")};color:#fff;'
        f'padding:3px 12px;border-radius:20px;margin:0 4px;font-size:.85em">'
        f'{n} {s}</span>'
        for s, n in sorted(sev_counts.items(),
            key=lambda x: list(_SEV_HTML).index(x[0]) if x[0] in _SEV_HTML else 99))
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP_Log_Pose Report - {_html.escape(target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
.header{{background:linear-gradient(135deg,#1a1f2e,#0d1117);border:1px solid #30363d;border-radius:12px;padding:2rem;margin-bottom:2rem}}
.header h1{{font-size:1.8rem;color:#58a6ff}}
.meta{{color:#8b949e;font-size:.9rem;margin-top:.5rem}}
.meta strong{{color:#c9d1d9}}
.stats{{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}}
h2{{color:#58a6ff;font-size:1.1rem;margin:1.5rem 0 .75rem;padding-bottom:.4rem;border-bottom:1px solid #21262d}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse}}
th{{background:#21262d;color:#8b949e;padding:.6rem 1rem;text-align:left;font-size:.8rem;text-transform:uppercase;letter-spacing:.5px}}
td{{padding:.6rem 1rem;border-bottom:1px solid #21262d;vertical-align:top;font-size:.9rem}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:.85em;color:#79c0ff}}
a{{color:#58a6ff;text-decoration:none}}
a:hover{{text-decoration:underline}}
.tag{{background:#21262d;color:#8b949e;padding:2px 8px;border-radius:4px;font-size:.8em}}
.empty{{color:#484f58;font-style:italic;padding:1.5rem;text-align:center}}
</style></head><body>
<div class="header">
  <h1>WP_Log_Pose - WordPress Testing Toolkit</h1>
  <div class="meta">Target: <strong>{_html.escape(target)}</strong> &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; {len(findings)} finding(s) &nbsp;·&nbsp; {len(creds)} credential(s)</div>
  <div class="stats">{stat_pills}</div>
</div>
<h2>Credentials</h2>
<div class="card">
{"<table><thead><tr><th>Username</th><th>Password</th><th>Source</th></tr></thead><tbody>" + rows_c + "</tbody></table>" if creds else '<p class="empty">No credentials found.</p>'}
</div>
<h2>Vulnerability Findings</h2>
<div class="card">
{"<table><thead><tr><th>Severity</th><th>Title</th><th>URL</th><th>Remediation</th></tr></thead><tbody>" + rows_f + "</tbody></table>" if findings else '<p class="empty">No vulnerability findings.</p>'}
</div>
</body></html>"""
    path.write_text(doc, encoding="utf-8")

def _write_md(results, path, target="", **_):
    creds, findings = _split(results)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    buf = StringIO()
    buf.write(f"# WP_Log_Pose Report\n\n**Target:** `{target}`  \n**Generated:** {ts}\n\n---\n\n")
    buf.write("## Credentials\n\n")
    if creds:
        buf.write("| Username | Password | Source |\n|---|---|---|\n")
        for cr in creds: buf.write(f"| `{cr.username}` | `{cr.password}` | {getattr(cr,'note','')} |\n")
    else:
        buf.write("_No credentials found._\n")
    buf.write("\n## Vulnerability Findings\n\n")
    if findings:
        buf.write("| Severity | Title | URL |\n|---|---|---|\n")
        for fi in findings:
            buf.write(f"| **{getattr(fi,'severity','')}** | {getattr(fi,'title',repr(fi))} | {getattr(fi,'url','')} |\n")
    else:
        buf.write("_No findings._\n")
    path.write_text(buf.getvalue(), encoding="utf-8")

_WRITERS = {"txt":_write_txt,"json":_write_json,"csv":_write_csv,"html":_write_html,"md":_write_md}

def save_results(results, output_file, fmt="txt", *, target="", **_) -> Path:
    fmt  = fmt.lower().lstrip(".")
    path = Path(output_file).resolve()
    if fmt not in _WRITERS:
        raise ValueError(f"Unsupported format {fmt!r}. Choose: {', '.join(SUPPORTED_FORMATS)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    _WRITERS[fmt](results, path, target=target)
    log.info("[+] Saved -> %s", path)
    return path

def print_banner(version: str = "2.0.0") -> None:
    box = r"""
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║  ██     ██ ██████  ██       ██████   ██████  ██████   ██████  ███████ ███████  ║
║  ██     ██ ██   ██ ██      ██    ██ ██       ██   ██ ██    ██ ██      ██       ║
║  ██  █  ██ ██████  ██      ██    ██ ██   ███ ██████  ██    ██ ███████ █████    ║
║  ██ ███ ██ ██      ██      ██    ██ ██    ██ ██      ██    ██      ██ ██       ║
║   ███ ███  ██      ███████  ██████   ██████  ██       ██████  ███████ ███████  ║
║                                                                                ║
║   WordPress Testing Toolkit                                                    ║
║   by  Mr.valentine(NAYAN) "don't mind the name"                                ║
║   For authorised testing only                                                  ║
╚════════════════════════════════════════════════════════════════════════════════╝"""
    ver_line = f"                                                           ver: {version}"
    if _tty():
        print(c(box, C.CYAN))
        print(c(ver_line, C.DIM))
    else:
        print(box)
        print(ver_line)

def print_config_summary(config, target, mode, wordlist, usernames_file, user_count):
    W = 62
    print()
    print(c("+" + "-" * W + "+", C.BLUE))
    def row(icon, label, val, val_colour=C.WHITE):
        label_str = f"  {icon}  {label}"
        pad       = W - len(label_str) - len(str(val)) - 5
        val_str   = c(str(val), val_colour)
        print(c("|", C.BLUE) + f"{label_str}" + " " * max(pad, 1) +
              c("|", C.BLUE) + f" {val_str}  " + c("|", C.BLUE))
    print(c("|" + c(f"  {'CONFIG SUMMARY':^{W-2}}", C.BOLD, C.CYAN) + "|", C.BLUE))
    print(c("+" + "-" * W + "+", C.BLUE))
    row(">>", "Target",          target,              C.CYAN)
    row(">>", "Mode",            mode.upper(),        C.YELLOW)
    row(">>", "Wordlist",        wordlist or "-",     C.WHITE)
    row(">>", "Usernames file",  usernames_file or "-")
    row(">>", "Users loaded",    user_count,          C.GREEN if user_count > 0 else C.DIM)
    print(c("+" + "-" * W + "+", C.BLUE))
    row(">>", "Proxy",           config.get("proxy") or "none")
    row(">>", "Threads",         config.get("threads", 10))
    row(">>", "Delay (s)",       config.get("delay", 0.0))
    row(">>", "Batch (XMLRPC)", config.get("batch", 1))
    row(">>", "Timeout (s)",     config.get("timeout", 15))
    print(c("+" + "-" * W + "+", C.BLUE))
    row(">>", "Output file",     config.get("output") or "-")
    row(">>", "Format",          config.get("format", "txt").upper())
    row(">>", "Safe mode",       config.get("safe", False),
        C.GREEN if config.get("safe") else C.DIM)
    print(c("+" + "-" * W + "+", C.BLUE))
    print()

def print_section(title: str, icon: str = ">>") -> None:
    line = f"  {icon}  {title}"
    print()
    print(c(line, C.BOLD, C.BLUE))
    print(c("  " + "-" * (len(title) + 5), C.BLUE))

def print_findings_summary(results: Sequence[Any]) -> None:
    from collections import defaultdict
    creds, findings = _split(results)
    print()
    print(c("+" + "=" * 58 + "+", C.BLUE))
    print(c("|" + c(f"  {'SCAN SUMMARY':^56}", C.BOLD, C.CYAN) + "|", C.BLUE))
    print(c("+" + "=" * 58 + "+", C.BLUE))
    if creds:
        line = f"  [+]  {len(creds)} CREDENTIAL(S) FOUND"
        print(c("|", C.BLUE) + c(line, C.BOLD, C.GREEN) +
              " " * max(58 - len(line), 0) + c("|", C.BLUE))
        print(c("|" + " " * 58 + "|", C.BLUE))
        for cr in creds:
            note = f"  [{cr.note}]" if getattr(cr, "note", "") else ""
            cred_str = f"  {cr.username}:{cr.password}{note}"
            pad = max(57 - len(cred_str), 0)
            print(c("|", C.BLUE) +
                  c(f"  {cr.username}", C.BOLD, C.WHITE) + ":" +
                  c(cr.password, C.BOLD, C.RED) +
                  c(note, C.DIM) +
                  " " * pad +
                  c("|", C.BLUE))
    else:
        print(c("|", C.BLUE) + c("  [-]  No credentials found.", C.DIM) +
              " " * 30 + c("|", C.BLUE))
    print(c("+" + "=" * 58 + "+", C.BLUE))
    if findings:
        by_sev: dict[str, list] = defaultdict(list)
        for fi in findings:
            by_sev[str(getattr(fi, "severity", "UNKNOWN"))].append(fi)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
            items = by_sev.get(sev, [])
            if not items: continue
            sev_col = _SEV_COLOUR.get(sev, C.WHITE)
            for fi in items:
                title   = str(getattr(fi, "title", repr(fi)))[:45]
                sev_tag = c(f"[{sev[:4]:4s}]", sev_col)
                line    = f"  {sev_tag}  {title}"
                pad     = max(57 - 10 - len(title), 0)
                print(c("|", C.BLUE) + line + " " * pad + c("|", C.BLUE))
    else:
        print(c("|", C.BLUE) + c("  [*]  No vulnerability findings.", C.DIM) +
              " " * 25 + c("|", C.BLUE))
    print(c("+" + "=" * 58 + "+", C.BLUE))
    print()
