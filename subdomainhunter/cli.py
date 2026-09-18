import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import load, write_default
from .enumerators import Enumerator
from .logging_setup import setup
from .utils import normalize_domain, read_wordlist, safe_filename, unique, write_csv, write_html, write_json

BANNER = r"""
  ____        _     ____                        _        _   _             _
 / ___| _   _| |__ |  _ \  ___  _ __ ___   __| | __ _ (_) | |__  _   _ _ __ | |_ ___ _ __
 \___ \| | | | '_ \| | | |/ _ \| '_ ` _ \ / _` |/ _` || | | '_ \| | | | '_ \| __/ _ \ '__|
  ___) | |_| | |_) | |_| | (_) | | | | | | (_| | (_| || | | | | | |_| | | | | ||  __/ |
 |____/ \__,_|_.__/|____/ \___/|_| |_| |_|\__,_|\__,_|/ | |_| |_|\__,_|_| |_|\__\___|_|
                                                       |__/
"""


def build_parser():
    p = argparse.ArgumentParser(prog="subdomainhunter", description="SubDomainHunter — advanced pure-Python subdomain enumeration.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", help="Path to a JSON configuration file.")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity.")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="Enumerate and inspect subdomains.")
    s.add_argument("domain", help="Target domain, e.g. example.com")
    s.add_argument("--wordlist", help="Wordlist path for active enumeration.")
    s.add_argument("--active", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable wordlist enumeration.")
    s.add_argument("--passive", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable Certificate Transparency enumeration.")
    s.add_argument("--probe", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable HTTP(S) probing.")
    s.add_argument("--dns-over-https", action=argparse.BooleanOptionalAction, default=None, help="Use DNS-over-HTTPS fallback and CNAME lookup.")
    s.add_argument("--workers", type=int, help="Concurrent workers (1–100).")
    s.add_argument("--timeout", type=float, help="Network timeout in seconds.")
    s.add_argument("--max-candidates", type=int, help="Maximum active candidates.")
    s.add_argument("--format", choices=["html", "json", "csv"], help="Report format.")
    s.add_argument("-o", "--output", help="Output file path.")
    s.add_argument("--show-all", action="store_true", help="Keep resolved/non-web findings in the report.")
    c = sub.add_parser("config", help="Create or show configuration.")
    csub = c.add_subparsers(dest="config_command")
    w = csub.add_parser("init", help="Write a default JSON config.")
    w.add_argument("-o", "--output", default="subdomainhunter.json")
    csub.add_parser("show", help="Show default configuration.")
    sub.add_parser("version", help="Show version.")
    return p


def _progress(done, total):
    if total:
        width = 32
        filled = int(width * done / total)
        bar = "#" * filled + "." * (width - filled)
        print(f"\r  [{bar}] {done}/{total}", end="", flush=True)
        if done == total:
            print()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        print(BANNER)
        parser.print_help()
        return 0
    if args.command == "version":
        print(f"SubDomainHunter {__version__}")
        return 0
    if args.command == "config":
        if args.config_command == "init":
            write_default(args.output)
            print(f"Created configuration: {args.output}")
        else:
            print(json.dumps(load(), indent=2, ensure_ascii=False))
        return 0

    logger = setup(args.log_level)
    try:
        domain = normalize_domain(args.domain)
        cfg = load(args.config)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    for key in ("wordlist", "workers", "timeout", "format", "active", "passive", "probe", "dns_over_https", "max_candidates"):
        value = getattr(args, key, None)
        if value is not None:
            cfg[key] = value
    if args.show_all:
        cfg["include_all_candidates"] = True

    wordlist = Path(cfg["wordlist"]).expanduser()
    if not wordlist.is_absolute():
        wordlist = Path.cwd() / wordlist
    cfg["wordlist"] = wordlist

    if cfg.get("workers", 1) < 1:
        print("[ERROR] workers must be at least 1.", file=sys.stderr)
        return 2
    if cfg.get("max_candidates", 1) < 1:
        print("[ERROR] max-candidates must be at least 1.", file=sys.stderr)
        return 2

    print(BANNER)
    print(f"  Target : {domain}")
    print(f"  Mode   : {'Passive ' if cfg.get('passive') else ''}{'Active ' if cfg.get('active') else ''}{'Probe' if cfg.get('probe') else ''}".strip())
    print()

    started = time.perf_counter()
    try:
        enum = Enumerator(domain, cfg)
        candidates = {}
        if cfg.get("passive"):
            names = enum.passive()
            print(f"  [✓] Certificate Transparency: {len(names)} names")
            for name in names:
                candidates[name] = ["crt.sh"]
        if cfg.get("active"):
            names = read_wordlist(wordlist, domain, int(cfg.get("max_candidates", 5000)))
            print(f"  [✓] Wordlist candidates: {len(names)}")
            for name in names:
                candidates.setdefault(name, []).append("wordlist")
        if not candidates:
            raise RuntimeError("No enumeration source enabled or no candidates were found.")

        source_map = {h: ",".join(unique(srcs)) for h, srcs in candidates.items()}
        print(f"  [•] Inspecting {len(candidates)} unique candidates...")
        findings = enum.run(list(candidates), source_map=source_map, progress=_progress)
        findings.sort(key=lambda f: f.hostname)

        outdir = Path(cfg.get("output", "reports")).expanduser()
        out = Path(args.output).expanduser() if args.output else outdir / f"{safe_filename(domain)}.{cfg.get('format','html')}"
        fmt = cfg.get("format", "html")
        duration = time.perf_counter() - started
        metadata = {
            "version": __version__,
            "target": domain,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration": f"{duration:.2f}s",
            "candidate_count": len(candidates),
            "finding_count": len(findings),
            "live_count": sum(f.live for f in findings),
            "resolved_count": sum(f.resolved for f in findings),
            "wildcard_count": sum(f.wildcard for f in findings),
        }
        if fmt == "html":
            write_html(findings, out, domain, metadata)
        elif fmt == "json":
            write_json(findings, out, metadata)
        else:
            write_csv(findings, out)

        print("\n  ┌─────────────────────────────────────┐")
        print(f"  │ Unique findings : {len(findings):>17} │")
        print(f"  │ Web alive       : {sum(f.live for f in findings):>17} │")
        print(f"  │ DNS resolved    : {sum(f.resolved for f in findings):>17} │")
        print(f"  │ Wildcard match  : {sum(f.wildcard for f in findings):>17} │")
        print("  └─────────────────────────────────────┘")

        # Show the actual findings in the terminal as well as in the report.
        # Keep the output readable in CMD/PowerShell by printing one finding
        # as a small, consistent block.
        if findings:
            print("\n  RESULTS")
            print("  " + "─" * 72)
            for i, f in enumerate(findings, 1):
                sources = ", ".join(f.sources) or "unknown"
                addresses = ", ".join(f.addresses) or "—"
                http = str(f.http_status) if f.http_status is not None else "—"
                https = str(f.https_status) if f.https_status is not None else "—"
                title = f.title or "—"
                tech = ", ".join(f.technologies) or "—"
                cname = f.cname or "—"

                print(f"  [{i}] {f.hostname}")
                print(f"      Source : {sources}")
                print(f"      IP     : {addresses}")
                print(f"      CNAME  : {cname}")
                print(f"      HTTP   : {http}")
                print(f"      HTTPS  : {https}")
                print(f"      Title  : {title}")
                print(f"      Tech   : {tech}")
                if f.http_url or f.https_url:
                    urls = ", ".join(u for u in (f.http_url, f.https_url) if u)
                    print(f"      URL    : {urls}")
                print("  " + "─" * 72)
        else:
            print("\n  No reachable/resolved subdomains were found.")

        print(f"\n  Report : {out.resolve()}")
        print(f"  Time   : {duration:.2f}s")
        return 0
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
