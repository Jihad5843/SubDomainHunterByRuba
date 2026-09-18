import json
from pathlib import Path

DEFAULTS = {
    "timeout": 5.0,
    "workers": 24,
    "retries": 1,
    "rate_limit": 0.0,
    "wordlist": "wordlists/common.txt",
    "passive": True,
    "active": True,
    "probe": True,
    "dns_over_https": True,
    "max_candidates": 5000,
    "output": "reports",
    "format": "html",
    "user_agent": "SubDomainHunter/2.0",
    "include_all_candidates": False,
}


def load(path=None):
    cfg = DEFAULTS.copy()
    if path:
        p = Path(path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"Config file not found: {p}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON config: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("Config must contain a JSON object.")
        cfg.update(data)
    return cfg


def write_default(path):
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(DEFAULTS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
