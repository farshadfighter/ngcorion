"""
Build NGCorion's built-in end-of-life catalog (app/modules/eol/catalog.json) from the endoflife.date data.

endoflife.date (https://endoflife.date, MIT licence) keeps the published lifecycle of each product in
products/<product>.md, as YAML front matter. This reads the products NGCorion recognises from a
checkout of that repository and writes, per release cycle:

    release         release date
    active_until    end of active support (bug fixes); security fixes may go on
    security_until  end of security support - after this date the vendor publishes no more fixes
    extended_until  end of paid extended support (Ubuntu Pro, RHEL ELS, Windows ESU ...), if any
    lts, latest     long-term support release; latest version (or build) of the cycle

A date is "YYYY-MM-DD"; true means the milestone has passed on a date the source does not give, false
or null that none is announced. Run it when preparing a release:

    git clone --depth 1 https://github.com/endoflife-date/endoflife.date /tmp/eol
    python scripts/eol_catalog.py /tmp/eol

An installation updates the catalog itself from the endoflife.date API, or from a file
(app/modules/eol/catalog.py).
"""
import json
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "app" / "modules" / "eol" / "catalog.json"

# endoflife.date product -> NGCorion product key (the same, except where noted).
PRODUCTS = ["ubuntu", "debian", "rhel", "rocky-linux", "almalinux", "centos", "centos-stream", "oracle-linux",
            "amazon-linux", "sles", "opensuse", "windows-server", "windows", "fortios", "cisco-ios-xe",
            "vmware-esxi", "mssqlserver", "mongodb", "apache-http-server", "mysql", "nginx", "kubernetes",
            "docker-engine", "postgresql"]


def _value(v):
    """A milestone as the catalog stores it: ISO date, True (passed, no date) or None (not announced)."""
    if isinstance(v, date):
        return v.isoformat()
    if v is True:
        return True
    if isinstance(v, str) and len(v) == 10 and v[4] == "-":
        return v
    return None


def product(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    front = yaml.safe_load(text.split("---", 2)[1])
    cycles = []
    for r in front.get("releases") or []:
        cycles.append({
            "cycle": str(r["releaseCycle"]),
            "label": str(r.get("releaseLabel") or r["releaseCycle"]).replace("__RELEASE_CYCLE__", str(r["releaseCycle"]))
                     .replace("'__CODENAME__'", "").replace("__CODENAME__", "").strip(),
            "release": _value(r.get("releaseDate")),
            "active_until": _value(r.get("eoas")),
            "security_until": _value(r.get("eol")),
            "extended_until": _value(r.get("eoes")),
            "lts": bool(r.get("lts")),
            "latest": str(r["latest"]) if r.get("latest") else None,
        })
    return {"key": path.stem, "name": front.get("title") or path.stem, "link": f"https://endoflife.date/{path.stem}",
            "cycles": cycles}


def main(argv=None) -> int:
    src = Path((argv or sys.argv[1:])[0]) / "products"
    data = {"source": "endoflife.date (MIT licence)", "generated": date.today().isoformat(),
            "products": [product(src / f"{p}.md") for p in PRODUCTS]}
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{OUT.relative_to(ROOT)}: {len(data['products'])} products, "
          f"{sum(len(p['cycles']) for p in data['products'])} release cycles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
