import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "scans"


def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def new_scan_id(target: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:40]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{safe}"


def scan_dir(scan_id: str) -> Path:
    return DATA_DIR / scan_id


def save_json(scan_id: str, name: str, data):
    d = scan_dir(scan_id)
    d.mkdir(parents=True, exist_ok=True)
    with open(d / name, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_json(scan_id: str, name: str):
    p = scan_dir(scan_id) / name
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def list_scans():
    ensure_dirs()
    out = []
    for d in sorted(DATA_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        meta = load_json(d.name, "meta.json") or {}
        out.append({"id": d.name, **meta})
    return out


def delete_scan(scan_id: str):
    d = scan_dir(scan_id)
    if d.exists():
        shutil.rmtree(d)
