"""enumeration.py — WordPress user enumeration."""
from __future__ import annotations
import logging, time
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET
from .base import WordPressTesterBase, Credential

log = logging.getLogger(__name__)


@dataclass
class DiscoveredUser:
    slug:    str
    sources: set = field(default_factory=set)

    def __hash__(self):  return hash(self.slug)
    def __eq__(self, o): return isinstance(o, DiscoveredUser) and self.slug == o.slug
    def __str__(self):   return f"{self.slug}  [{', '.join(sorted(self.sources))}]"


class UserEnumerator(WordPressTesterBase):
    """Discover WordPress usernames via multiple methods."""

    def run(self):
        """Satisfy abstract requirement — delegates to enumerate_users."""
        return self.enumerate_users()

    def enumerate_users(self) -> list[DiscoveredUser]:
        merged: dict[str, DiscoveredUser] = {}

        def add(slug: str, source: str):
            slug = slug.strip("/").lower()
            if not slug:
                return
            if slug not in merged:
                merged[slug] = DiscoveredUser(slug)
            merged[slug].sources.add(source)
            log.info("[%s] Found user: %s", source, slug)

        # Method 1: REST API
        try:
            page = 1
            while True:
                url  = f"{self.target}/wp-json/wp/v2/users?per_page=100&page={page}"
                resp = self._request("GET", url, jitter=False)
                if not (resp and resp.status_code == 200):
                    break
                data = resp.json()
                if not isinstance(data, list) or not data:
                    break
                for u in data:
                    if u.get("slug"):
                        add(u["slug"], "REST")
                if len(data) < 100:
                    break
                page += 1
        except Exception as e:
            log.debug("REST enumeration error: %s", e)

        # Method 2: Author archives
        consecutive_misses = 0
        for i in range(1, 21):
            try:
                url  = f"{self.target}/?author={i}"
                resp = self._request("GET", url, allow_redirects=False)
                if resp:
                    loc = resp.headers.get("Location", "")
                    if "/author/" in loc:
                        slug = loc.split("/author/")[-1].strip("/")
                        if slug:
                            add(slug, "AUTHOR")
                            consecutive_misses = 0
                        else:
                            consecutive_misses += 1
                    else:
                        consecutive_misses += 1
                else:
                    consecutive_misses += 1
                if consecutive_misses >= 5:
                    break
                time.sleep(self.delay)
            except Exception as e:
                log.debug("Author archive error id=%d: %s", i, e)

        # Method 3: oEmbed
        try:
            url  = f"{self.target}/wp-json/oembed/1.0/embed?url={self.target}"
            resp = self._request("GET", url, jitter=False)
            if resp and resp.status_code == 200:
                data = resp.json()
                if data.get("author_name"):
                    add(data["author_name"], "OEMBED")
        except Exception as e:
            log.debug("oEmbed error: %s", e)

        # Method 4: Sitemap
        try:
            for sitemap_url in [
                f"{self.target}/sitemap.xml",
                f"{self.target}/wp-sitemap.xml",
            ]:
                resp = self._request("GET", sitemap_url, jitter=False)
                if resp and resp.status_code == 200:
                    try:
                        root = ET.fromstring(resp.content)
                        for loc in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                            if loc.text and "/author/" in loc.text:
                                slug = loc.text.split("/author/")[-1].strip("/")
                                if slug:
                                    add(slug, "SITEMAP")
                    except ET.ParseError:
                        pass
        except Exception as e:
            log.debug("Sitemap error: %s", e)

        results = sorted(merged.values(), key=lambda u: u.slug)
        log.info("Enumeration complete — %d user(s) found", len(results))
        return results
