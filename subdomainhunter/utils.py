import csv
import html
import json
import re
from pathlib import Path
from urllib.parse import urlparse

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")


def normalize_domain(value: str) -> str:
    value = str(value).strip().lower().rstrip(".")
    if not value:
        raise ValueError("Domain cannot be empty.")
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0]
    if value.startswith("*."):
        value = value[2:]
    if not HOST_RE.match(value):
        raise ValueError("Invalid domain name. Example: example.com")
    return value


def normalize_hostname(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def in_scope(hostname, domain):
    h, d = normalize_hostname(hostname), normalize_hostname(domain)
    return h == d or h.endswith("." + d)


def unique(seq):
    return list(dict.fromkeys(seq))


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def read_wordlist(path, domain, max_candidates=5000):
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Wordlist not found: {p}")
    out = []
    seen = set()
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        w = raw.strip().lower()
        if not w or w.startswith("#"):
            continue
        # Allow either labels (api) or fully-qualified names already inside scope.
        if "." in w:
            host = normalize_hostname(w)
            if not in_scope(host, domain):
                continue
        else:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", w):
                continue
            host = f"{w}.{domain}"
        if host not in seen:
            seen.add(host)
            out.append(host)
            if len(out) >= max_candidates:
                break
    return out


def _status_badge(status):
    if status is None:
        return '<span class="muted">—</span>'
    return f'<span class="status s{str(status)[:1]}">{status}</span>'


def write_json(findings, path, metadata=None):
    payload = {"metadata": metadata or {}, "results": [f.to_dict() for f in findings]}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(findings, path):
    fields = ["hostname", "sources", "addresses", "cname", "http_status", "https_status", "title", "technologies", "content_type", "server", "redirect", "wildcard", "error"]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        for f in findings:
            row = f.to_dict()
            for key in ("sources", "addresses", "technologies"):
                row[key] = ";".join(row[key])
            writer.writerow({k: row.get(k, "") for k in fields})


def write_html(findings, path, domain, metadata=None):
    metadata = metadata or {}
    total = len(findings)
    live = sum(f.live for f in findings)
    resolved = sum(f.resolved for f in findings)
    wildcard = sum(f.wildcard for f in findings)
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td><strong>{html.escape(f.hostname)}</strong></td>"
            f"<td>{html.escape(', '.join(f.sources) or 'unknown')}</td>"
            f"<td>{html.escape(', '.join(f.addresses) or '—')}</td>"
            f"<td>{_status_badge(f.http_status)}</td>"
            f"<td>{_status_badge(f.https_status)}</td>"
            f"<td>{html.escape(f.title or '—')}</td>"
            f"<td>{html.escape(', '.join(f.technologies) or '—')}</td>"
            f"<td>{'Yes' if f.wildcard else 'No'}</td>"
            "</tr>"
        )
    generated = html.escape(str(metadata.get("generated_at", "")))
    duration = html.escape(str(metadata.get("duration", "")))
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SubDomainHunter | {html.escape(domain)}</title>
<style>
:root{{color-scheme:dark;--bg:#080b12;--panel:#101622;--line:#202a3a;--text:#e8edf5;--muted:#8d99aa;--accent:#67e8f9;--good:#86efac}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at top,#132033 0,#080b12 48%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}}
.wrap{{max-width:1450px;margin:auto;padding:34px}}.hero{{display:flex;justify-content:space-between;gap:24px;align-items:end;margin-bottom:28px}}h1{{font-size:38px;margin:0 0 8px}}.sub{{color:var(--muted)}}code{{color:var(--accent)}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}.card{{background:rgba(16,22,34,.88);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:0 10px 30px #0004}}.num{{font-size:30px;font-weight:800;margin-top:8px}}.label{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.12em}}
.toolbar{{display:flex;gap:10px;align-items:center;margin:18px 0}}.toolbar input,.toolbar select{{background:#101622;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:11px 13px;font:inherit}}.toolbar input{{flex:1;min-width:180px}}.toolbar select{{min-width:170px}}.panel{{background:rgba(16,22,34,.92);border:1px solid var(--line);border-radius:18px;overflow:hidden}}table{{border-collapse:collapse;width:100%}}th,td{{padding:13px 14px;border-bottom:1px solid var(--line);text-align:left;font-size:13px;vertical-align:top}}th{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;position:sticky;top:0;background:#101622}}tr:hover{{background:#151d2b}}.status{{display:inline-block;padding:4px 7px;border-radius:7px;background:#263246;font-weight:700}}.s2{{background:#123d2b;color:var(--good)}}.s3{{background:#3c3214;color:#fde68a}}.s4,.s5{{background:#42202b;color:#fda4af}}.muted{{color:#667085}}footer{{color:var(--muted);padding:20px 0;font-size:12px}}
@media(max-width:900px){{.grid{{grid-template-columns:repeat(2,1fr)}}.hero{{display:block}}.panel{{overflow:auto}}table{{min-width:1050px}}}}
</style></head><body><main class="wrap">
<section class="hero"><div><h1>SubDomainHunter</h1><div class="sub">Advanced pure-Python subdomain enumeration report for <code>{html.escape(domain)}</code></div></div><div class="sub">Generated {generated} · Duration {duration}</div></section>
<section class="grid"><div class="card"><div class="label">Unique Findings</div><div class="num">{total}</div></div><div class="card"><div class="label">Web Alive</div><div class="num">{live}</div></div><div class="card"><div class="label">DNS Resolved</div><div class="num">{resolved}</div></div><div class="card"><div class="label">Wildcard Matches</div><div class="num">{wildcard}</div></div></section>
<section class="toolbar"><input id="search" type="search" placeholder="Search hostname, title, source or technology…" aria-label="Search results"><select id="state" aria-label="Filter results"><option value="all">All results</option><option value="live">Web alive</option><option value="resolved">DNS resolved</option><option value="wildcard">Wildcard match</option></select><span id="count" class="sub"></span></section>
<section class="panel"><table id="results"><thead><tr><th>Hostname</th><th>Sources</th><th>Addresses</th><th>HTTP</th><th>HTTPS</th><th>Title</th><th>Fingerprint</th><th>Wildcard</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<footer>Generated by SubDomainHunter {html.escape(str(metadata.get('version','')))} · Use only against domains you own or are authorized to assess.</footer>
</main><script>
const q=document.getElementById('search'), state=document.getElementById('state'), count=document.getElementById('count');
function filterRows(){{const term=q.value.toLowerCase().trim(), mode=state.value; let shown=0; document.querySelectorAll('#results tbody tr').forEach(r=>{{const text=r.innerText.toLowerCase(); const live=!!r.querySelector('.s2,.s3,.s4,.s5'); const resolved=r.cells[2].innerText.trim()!=='—'; const wildcard=r.cells[7].innerText.trim()==='Yes'; let ok=!term||text.includes(term); if(mode==='live') ok=ok&&live; if(mode==='resolved') ok=ok&&resolved; if(mode==='wildcard') ok=ok&&wildcard; r.hidden=!ok; if(ok) shown++;}}); count.textContent=shown+' visible result'+(shown===1?'':'s');}}
q.addEventListener('input',filterRows); state.addEventListener('change',filterRows); filterRows();
</script></body></html>"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(doc, encoding="utf-8")
