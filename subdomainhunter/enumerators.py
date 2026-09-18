import json
import logging
import random
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .models import Finding
from .utils import in_scope, normalize_hostname, unique

log = logging.getLogger("subdomainhunter")


class Enumerator:
    def __init__(self, domain, cfg):
        self.domain = domain
        self.cfg = cfg
        self.timeout = max(0.5, float(cfg.get("timeout", 5)))
        self.workers = max(1, min(100, int(cfg.get("workers", 24))))
        self.retries = max(0, min(5, int(cfg.get("retries", 1))))
        self.ua = str(cfg.get("user_agent", "SubDomainHunter/2.0"))
        self.delay = max(0.0, float(cfg.get("rate_limit", 0)))
        self.doh = bool(cfg.get("dns_over_https", True))
        self.wildcard_ips, self.wildcard_names = self._wildcard_probe()

    def _request_json(self, url):
        req = Request(url, headers={"User-Agent": self.ua, "Accept": "application/json"})
        for attempt in range(self.retries + 1):
            try:
                with urlopen(req, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8", "replace"))
            except Exception as exc:
                if attempt >= self.retries:
                    raise
                log.debug("Retrying request after error: %s", exc)
                time.sleep(0.2 * (attempt + 1))
        return None

    def passive(self):
        url = f"https://crt.sh/?q=%25.{quote(self.domain)}&output=json"
        try:
            data = self._request_json(url)
        except Exception as exc:
            log.warning("Certificate Transparency source unavailable: %s", exc)
            return []
        out = []
        for row in data if isinstance(data, list) else []:
            for raw in str(row.get("name_value", "")).splitlines():
                name = normalize_hostname(raw)
                if name.startswith("*."):
                    name = name[2:]
                if in_scope(name, self.domain):
                    out.append(name)
        return unique(out)

    def _doh_answers(self, hostname, rrtype):
        url = f"https://dns.google/resolve?name={quote(hostname)}&type={rrtype}"
        data = self._request_json(url)
        if not isinstance(data, dict):
            return []
        return [str(ans.get("data", "")).rstrip(".") for ans in data.get("Answer", []) if ans.get("data")]

    def _wildcard_probe(self):
        ips, names = set(), set()
        for _ in range(2):
            h = f"sh-{random.randrange(10**10):010d}.{self.domain}"
            names.add(h)
            if self.doh:
                try:
                    ips.update(self._doh_answers(h, "A"))
                    ips.update(self._doh_answers(h, "AAAA"))
                except Exception:
                    pass
            else:
                # Avoid potentially unbounded platform DNS waits when the
                # user explicitly disables the controlled DoH path.
                continue
        return ips, names

    def resolve(self, hostname):
        addresses = set()
        if self.doh:
            for rrtype in ("A", "AAAA"):
                try:
                    addresses.update(self._doh_answers(hostname, rrtype))
                except Exception as exc:
                    log.debug("DoH resolution failed for %s (%s): %s", hostname, rrtype, exc)
        if not addresses:
            try:
                for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
                    addresses.add(item[4][0])
            except socket.gaierror:
                pass
        return sorted(addresses)

    def cname(self, hostname):
        try:
            url = f"https://dns.google/resolve?name={quote(hostname)}&type=CNAME"
            data = self._request_json(url)
            for ans in data.get("Answer", []) if isinstance(data, dict) else []:
                return str(ans.get("data", "")).rstrip(".")
        except Exception:
            pass
        return ""

    def probe_url(self, scheme, hostname):
        url = f"{scheme}://{hostname}/"
        req = Request(url, headers={"User-Agent": self.ua, "Accept": "text/html,*/*;q=0.8"}, method="GET")
        context = ssl.create_default_context()
        try:
            with urlopen(req, timeout=self.timeout, context=context) as r:
                body = r.read(65536).decode("utf-8", "replace")
                return self._probe_result(r.status, r.geturl(), body, dict(r.headers))
        except HTTPError as exc:
            body = exc.read(16384).decode("utf-8", "replace")
            return self._probe_result(exc.code, exc.geturl(), body, dict(exc.headers))
        except (socket.timeout, TimeoutError) as exc:
            log.warning("Connection timed out for %s: %s", url, exc)
            return None, "", "", "", "", "", None
        except Exception as exc:
            return None, "", "", "", "", "", None

    @staticmethod
    def _probe_result(status, final_url, body, headers):
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else ""
        server = headers.get("Server", "")
        ctype = headers.get("Content-Type", "")
        redirect = final_url if final_url else ""
        tech = []
        if server:
            tech.append(f"Server:{server}")
        powered = headers.get("X-Powered-By", "")
        if powered:
            tech.append(f"X-Powered-By:{powered}")
        signatures = {
            "cloudflare": ["cf-ray", "server"],
            "nginx": ["server"],
            "apache": ["server"],
            "wordpress": ["wp-content", "wp-includes"],
            "django": ["csrfmiddlewaretoken", "django"],
            "php": ["x-powered-by"],
        }
        low = body.lower()
        low_headers = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        for name, markers in signatures.items():
            if any(marker in low or marker in low_headers for marker in markers):
                tech.append(name)
        return status, title, ctype, server, redirect, unique(tech), None

    def inspect(self, hostname, source="active"):
        f = Finding(hostname=hostname, sources=[source])
        f.addresses = self.resolve(hostname)
        f.cname = self.cname(hostname) if self.doh and f.addresses else ""
        f.wildcard = bool(self.wildcard_ips.intersection(f.addresses))
        if self.cfg.get("probe", True) and (f.addresses or not self.cfg.get("include_resolved_only", False)):
            result = self.probe_url("http", hostname)
            f.http_status, f.title, f.content_type, f.server, f.http_url, tech, _ = result
            result2 = self.probe_url("https", hostname)
            f.https_status, title2, ctype2, server2, f.https_url, tech2, _ = result2
            if not f.title:
                f.title = title2
            if not f.content_type:
                f.content_type = ctype2
            if not f.server:
                f.server = server2
            f.technologies = unique(tech + tech2)
        if self.delay:
            time.sleep(self.delay)
        return f

    def run(self, candidates, source_map=None, progress=None):
        results = []
        source_map = source_map or {}
        candidates = [h for h in unique(candidates) if in_scope(h, self.domain)]
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.inspect, h, source_map.get(h, "unknown")): h for h in candidates}
            done = 0
            for fut in as_completed(futures):
                host = futures[fut]
                done += 1
                try:
                    f = fut.result()
                    f.sources = source_map.get(host, "unknown").split(",") if isinstance(source_map.get(host), str) else list(source_map.get(host, []))
                    f.sources = [s for s in f.sources if s]
                    if f.alive or self.cfg.get("include_all_candidates", False):
                        results.append(f)
                except Exception as exc:
                    log.debug("Inspection failed for %s: %s", host, exc)
                if progress:
                    progress(done, len(candidates))
        return results
