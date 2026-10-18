"""
The end-of-life catalog an installation uses: the built-in one (catalog.json, from endoflife.date) with the
products it has downloaded or imported since (EolProduct rows of source online / import replace the
built-in product with the same key) and the organisation's own products (source custom).

Updating:
  online   fetch_online() asks the endoflife.date API for every built-in product (needs internet access
           from the server); a product the API does not answer for keeps what it had
  file     parse_file() reads NGCorion's own export (the format of catalog.json) or an endoflife.date API
           answer saved to a file - for servers without internet access
"""
import json
import logging
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.eol import SOURCE_CUSTOM, SOURCE_IMPORT, SOURCE_ONLINE, EolProduct

logger = logging.getLogger(__name__)

BUILTIN = Path(__file__).parent / "catalog.json"
API = "https://endoflife.date/api/v1/products/{key}"
TIMEOUT = 30
MAX_CYCLES = 300


@lru_cache(maxsize=1)
def builtin() -> dict:
    return json.loads(BUILTIN.read_text(encoding="utf-8"))


def load(db: Session) -> Tuple[Dict[str, dict], Dict[str, str]]:
    """(product key -> product, lower-cased software name -> custom product key)."""
    products = {p["key"]: {**p, "source": "builtin"} for p in builtin()["products"]}
    custom_names: Dict[str, str] = {}
    for row in db.query(EolProduct):
        products[row.key] = {"key": row.key, "name": row.name, "link": row.link, "cycles": row.cycles or [],
                             "source": row.source, "updated_at": row.updated_at.isoformat() if row.updated_at else None}
        if row.source == SOURCE_CUSTOM:
            for n in row.match_names or []:
                custom_names[n.strip().lower()] = row.key
    return products, custom_names


# ── reading endoflife.date and our own files ─────────────────────────────

def _milestone(flag, when):
    """The catalog's form of a milestone from the API: a date, True (passed, no date), None."""
    if isinstance(when, str) and len(when) >= 10:
        return when[:10]
    return True if flag is True else None


def from_api(result: dict) -> List[dict]:
    """The cycles of one product from an endoflife.date API v1 answer ({"result": {...}})."""
    out = []
    for r in (result or {}).get("releases") or []:
        latest = r.get("latest") or {}
        out.append({
            "cycle": str(r["name"]), "label": str(r.get("label") or r["name"]),
            "release": (r.get("releaseDate") or None),
            "active_until": _milestone(r.get("isEoas"), r.get("eoasFrom")),
            "security_until": _milestone(r.get("isEol"), r.get("eolFrom")),
            "extended_until": _milestone(r.get("isEoes"), r.get("eoesFrom")),
            "lts": bool(r.get("isLts")),
            "latest": latest.get("name") if isinstance(latest, dict) else (str(latest) if latest else None),
        })
    return out


def _valid_cycle(c) -> bool:
    if not isinstance(c, dict) or not isinstance(c.get("cycle"), str) or not 0 < len(c["cycle"]) <= 40:
        return False
    for f in ("release", "active_until", "security_until", "extended_until"):
        v = c.get(f)
        if v not in (None, True, False) and not (isinstance(v, str) and _is_date(v)):
            return False
    return True


def _is_date(v: str) -> bool:
    try:
        date.fromisoformat(v[:10])
        return len(v) == 10
    except ValueError:
        return False


def parse_file(raw: bytes) -> List[dict]:
    """Products from an uploaded file: NGCorion's export ({"products": [...]}) or one endoflife.date API
    answer ({"result": {"name": ..., "releases": [...]}}). Raises ValueError when it is neither."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The file is not JSON") from exc
    if isinstance(data, dict) and isinstance(data.get("result"), dict) and data["result"].get("name"):
        res = data["result"]
        products = [{"key": str(res["name"]), "name": str(res.get("label") or res["name"]),
                     "link": f"https://endoflife.date/{res['name']}", "cycles": from_api(res)}]
    elif isinstance(data, dict) and isinstance(data.get("products"), list):
        products = data["products"]
    else:
        raise ValueError("The file is neither an NGCorion end-of-life catalog nor an endoflife.date answer")
    out = []
    for p in products:
        if not isinstance(p, dict) or not isinstance(p.get("key"), str) or not 0 < len(p["key"]) <= 60:
            raise ValueError("A product has no key")
        cycles = [c for c in p.get("cycles") or [] if _valid_cycle(c)][:MAX_CYCLES]
        if not cycles:
            raise ValueError(f"The product {p['key']} has no valid release cycle")
        out.append({"key": p["key"], "name": str(p.get("name") or p["key"])[:120], "link": p.get("link"),
                    "cycles": cycles})
    return out


def store(db: Session, products: List[dict], source: str, user_id: Optional[int]) -> int:
    """Save downloaded or imported products (replacing an earlier download or import of the same key).
    Products of the organisation's own are not overwritten. Returns how many were saved."""
    builtin_keys = {p["key"] for p in builtin()["products"]}
    n = 0
    for p in products:
        row = db.query(EolProduct).filter(EolProduct.key == p["key"]).first()
        if row is not None and row.source == SOURCE_CUSTOM:
            continue
        if row is None:
            if source == SOURCE_ONLINE and p["key"] not in builtin_keys:
                continue
            row = EolProduct(key=p["key"])
            db.add(row)
        row.name, row.link, row.cycles, row.source = p["name"], p.get("link"), p["cycles"], source
        row.updated_by, row.updated_at = user_id, datetime.utcnow()
        n += 1
    return n


def fetch_online(session=None) -> Tuple[List[dict], List[str]]:
    """Every built-in product from the endoflife.date API: (products, keys that failed)."""
    import requests
    s = session or requests.Session()
    got, failed = [], []
    for p in builtin()["products"]:
        try:
            resp = s.get(API.format(key=p["key"]), timeout=TIMEOUT, headers={"Accept": "application/json"})
            resp.raise_for_status()
            cycles = [c for c in from_api(resp.json().get("result") or {}) if _valid_cycle(c)]
            if not cycles:
                raise ValueError("no release cycles")
            got.append({"key": p["key"], "name": p["name"], "link": p.get("link"), "cycles": cycles})
        except Exception as exc:   # one product failing does not stop the others
            logger.info("[eol] %s not updated: %s", p["key"], exc)
            failed.append(p["key"])
    return got, failed


SOURCE_LABELS = {"builtin": "Built in", SOURCE_ONLINE: "endoflife.date", SOURCE_IMPORT: "Imported file",
                 SOURCE_CUSTOM: "The organisation's"}
