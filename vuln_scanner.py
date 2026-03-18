"""vuln_scanner.py — WordPress misconfiguration and vulnerability scanner."""
from __future__ import annotations
import logging, re
from dataclasses import dataclass, field
from .base import WordPressTesterBase, Credential

log = logging.getLogger(__name__)


@dataclass
class Finding:
    check_id:    str
    title:       str
    severity:    str
    description: str  = ""
    url:         str  = ""
    remediation: str  = ""
    evidence:    str  = ""

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}" + (f"  ({self.url})" if self.url else "")


class VulnScanner(WordPressTesterBase):
    """Passive vulnerability and misconfiguration scanner."""

    @dataclass
    class ScanReport:
        target:   str
        findings: list = field(default_factory=list)

        def summary(self) -> str:
            counts: dict[str, int] = {}
            for f in self.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            parts = ", ".join(f"{v}x {k}" for k, v in sorted(counts.items()))
            return f"Scan of {self.target} — {len(self.findings)} finding(s): {parts}"

    def run(self):
        return self.scan()

    def scan(self) -> "VulnScanner.ScanReport":
        report = VulnScanner.ScanReport(target=self.target)
        checks = [
            ("Headers",          self._check_headers),
            ("Dir listing",      self._check_dir_listing),
            ("Debug log",        self._check_debug_log),
            ("XML-RPC",          self._check_xmlrpc),
            ("REST users",       self._check_rest_users),
            ("Path disclosure",  self._check_path_disclosure),
            ("Sensitive files",  self._check_sensitive_files),
            ("wp-cron",          self._check_wpcron),
            ("Version leak",     self._check_version_leak),
            ("Login hardening",  self._check_login_hardening),
        ]
        for label, fn in checks:
            log.info("[VULN] %s", label)
            try:
                report.findings.extend(fn())
            except Exception as e:
                log.debug("[VULN] %s failed: %s", label, e)

        print(report.summary())
        for f in report.findings:
            print(f"  {f}")
        return report

    # ── checks ──────────────────────────────────────────────────────────────

    def _check_headers(self) -> list[Finding]:
        resp = self._request("GET", self.target, jitter=False)
        if not resp:
            return []
        findings = []
        for header, severity in [
            ("Content-Security-Policy",  "HIGH"),
            ("X-Frame-Options",          "MEDIUM"),
            ("X-Content-Type-Options",   "LOW"),
            ("Strict-Transport-Security","MEDIUM"),
            ("Referrer-Policy",          "LOW"),
        ]:
            if header not in resp.headers:
                findings.append(Finding(
                    check_id="header", title=f"Missing header: {header}",
                    severity=severity, url=self.target,
                    remediation=f"Add {header} to your server/plugin configuration.",
                ))
        return findings

    def _check_dir_listing(self) -> list[Finding]:
        findings = []
        for path in ["/wp-content/uploads/", "/wp-includes/", "/wp-content/plugins/"]:
            url  = self.target + path
            resp = self._request("GET", url)
            if resp and resp.status_code == 200 and "Index of" in resp.text:
                findings.append(Finding(
                    check_id="dir_listing", title=f"Directory listing enabled: {path}",
                    severity="MEDIUM", url=url,
                    remediation="Add 'Options -Indexes' to .htaccess.",
                ))
        return findings

    def _check_debug_log(self) -> list[Finding]:
        findings = []
        for path in ["/wp-content/debug.log", "/debug.log"]:
            url  = self.target + path
            resp = self._request("GET", url)
            if resp and resp.status_code == 200 and re.search(r"PHP (Notice|Warning|Fatal)", resp.text):
                findings.append(Finding(
                    check_id="debug_log", title="debug.log publicly accessible",
                    severity="HIGH", url=url,
                    remediation="Block access to debug.log via .htaccess or move it outside webroot.",
                ))
        return findings

    def _check_xmlrpc(self) -> list[Finding]:
        url     = self.target + "/xmlrpc.php"
        payload = b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
        resp    = self._request("POST", url, data=payload,
                                extra_headers={"Content-Type": "text/xml"}, jitter=False)
        if resp and resp.status_code == 200 and "<array>" in resp.text:
            methods     = re.findall(r"<string>([\w.]+)</string>", resp.text)
            multicall   = "system.multicall" in methods
            return [Finding(
                check_id="xmlrpc",
                title="XML-RPC enabled" + (" (multicall available)" if multicall else ""),
                severity="HIGH" if multicall else "MEDIUM",
                url=url,
                evidence=f"{len(methods)} methods advertised",
                remediation="Disable XML-RPC via plugin or .htaccess if not required.",
            )]
        return []

    def _check_rest_users(self) -> list[Finding]:
        url  = self.target + "/wp-json/wp/v2/users"
        resp = self._request("GET", url, jitter=False)
        if not (resp and resp.status_code == 200):
            return []
        try:
            users = resp.json()
            if isinstance(users, list) and users:
                slugs = [u.get("slug", "") for u in users if u.get("slug")]
                return [Finding(
                    check_id="rest_users",
                    title=f"REST API exposes {len(slugs)} username(s) without auth",
                    severity="MEDIUM", url=url,
                    evidence=", ".join(slugs[:5]),
                    remediation="Restrict unauthenticated REST API access via a security plugin.",
                )]
        except Exception:
            pass
        return []

    def _check_path_disclosure(self) -> list[Finding]:
        url  = self.target + "/wp-content/plugins/xxxxxxnotexist/x.php"
        resp = self._request("GET", url)
        if not resp:
            return []
        body = resp.text or ""
        if re.search(r"(Warning|Fatal error)", body) and re.search(r"/[\w/]+\.php", body):
            match = re.search(r"/[\w/]+\.php", body)
            return [Finding(
                check_id="path_disclosure", title="Full filesystem path disclosed",
                severity="LOW", url=url,
                evidence=match.group(0) if match else "",
                remediation="Set display_errors=Off in php.ini.",
            )]
        return []

    def _check_sensitive_files(self) -> list[Finding]:
        findings = []
        targets = [
            ("/readme.html",        "INFO"),
            ("/wp-config.php.bak",  "CRITICAL"),
            ("/.env",               "CRITICAL"),
            ("/.git/HEAD",          "HIGH"),
            ("/phpinfo.php",        "HIGH"),
        ]
        for path, severity in targets:
            url  = self.target + path
            resp = self._request("GET", url)
            if resp and resp.status_code == 200 and resp.text.strip():
                findings.append(Finding(
                    check_id="sensitive_file",
                    title=f"Sensitive file accessible: {path}",
                    severity=severity, url=url,
                    remediation=f"Remove or restrict access to {path}.",
                ))
        return findings

    def _check_wpcron(self) -> list[Finding]:
        url  = self.target + "/wp-cron.php?doing_wp_cron"
        resp = self._request("GET", url, jitter=False)
        if resp and resp.status_code == 200:
            return [Finding(
                check_id="wpcron", title="wp-cron.php publicly accessible",
                severity="LOW", url=url,
                remediation="Add DISABLE_WP_CRON=true to wp-config.php and use server cron.",
            )]
        return []

    def _check_version_leak(self) -> list[Finding]:
        resp = self._request("GET", self.target, jitter=False)
        if not resp:
            return []
        m = re.search(r'content="WordPress ([\d.]+)"', resp.text, re.IGNORECASE)
        if m:
            return [Finding(
                check_id="version_leak",
                title=f"WordPress version disclosed: {m.group(1)}",
                severity="INFO", url=self.target,
                remediation="Add remove_action('wp_head','wp_generator'); to functions.php",
            )]
        return []

    def _check_login_hardening(self) -> list[Finding]:
        url  = self.target + "/wp-login.php"
        resp = self._request("GET", url, jitter=False)
        if not resp:
            return []
        findings = []
        if resp.status_code == 200:
            findings.append(Finding(
                check_id="login_exposed",
                title="Default wp-login.php URL is publicly accessible",
                severity="INFO", url=url,
                remediation="Use WPS Hide Login to move the login URL.",
            ))
        rate_headers = ("X-RateLimit-Remaining", "X-Login-Limit-Remaining", "Retry-After")
        if not any(h in resp.headers for h in rate_headers):
            findings.append(Finding(
                check_id="no_ratelimit",
                title="No rate-limiting headers detected on login page",
                severity="INFO", url=url,
                remediation="Install Limit Login Attempts Reloaded or Wordfence.",
            ))
        return findings
