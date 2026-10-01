"""
The three public feeds the CVE database is built from, and their parsers.

  NVD API 2.0    every CVE, its CVSS score and the CPE ranges it affects
  CISA KEV       CVEs known to be exploited in the wild
  FIRST EPSS     probability that a CVE is exploited in the next 30 days

Parsers turn each feed into the small normalised records the database and
the offline packages store (one format for both), and are pure so they can
be tested on captured responses. Fetchers do the network part: paging, the
NVD rate limit (5 requests per 30 s without an API key, 50 with one),
retries, and incremental windows (NVD accepts at most 120 days per query).

URLs can be overridden with NVD_API_URL / CVE_KEV_URL / CVE_EPSS_URL, e.g. to
point at an internal mirror.
"""
import csv
import gzip
import logging
import os
import time
from datetime import date, datetime, timedelta, timezone
from typing import Callable, Iterator, List, Optional

import requests

from app.modules.cve.cpe import parse_cpe23

logger = logging.getLogger(__name__)

# `or`, not a getenv default: docker-compose passes unset variables as "".
NVD_API_URL = os.getenv("NVD_API_URL") or "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = os.getenv("CVE_KEV_URL") or "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = os.getenv("CVE_EPSS_URL") or "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
TIMEOUT = 60
MAX_REFERENCES = 8
_PREFERRED_REF_TAGS = ("Vendor Advisory", "Patch", "Mitigation", "Release Notes")


class FeedError(RuntimeError):
    pass


def safe_url(url) -> bool:
    """Only http(s) links are kept: references are shown as links, and a
    javascript: or data: URL in a feed or package would be stored XSS."""
    return isinstance(url, str) and len(url) <= 2000 and url.lower().startswith(("https://", "http://"))


# ── parsers ──────────────────────────────────────────────────────────────

def _dt(value: Optional[str]) -> Optional[str]:
    """NVD timestamps -> ISO strings without microseconds (kept as text in the
    normalised record so packages are plain JSON)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None, microsecond=0).isoformat()
    except ValueError:
        return None


def _cvss(metrics: dict) -> dict:
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = (data.get("baseSeverity") or entry.get("baseSeverity") or "").lower() or None
        return {"score": data.get("baseScore"), "version": version, "severity": severity,
                "vector": data.get("vectorString")}
    return {"score": None, "version": None, "severity": None, "vector": None}


def normalize_nvd_cve(cve: dict) -> dict:
    """One `vulnerabilities[].cve` object -> the stored record. A rejected CVE
    becomes {"id", "rejected": True} so updates can remove it."""
    cve_id = cve["id"]
    status = cve.get("vulnStatus")
    if status == "Rejected":
        return {"id": cve_id, "rejected": True}

    description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)

    refs = cve.get("references", [])
    refs = sorted(refs, key=lambda r: 0 if set(r.get("tags", [])) & set(_PREFERRED_REF_TAGS) else 1)
    urls = []
    for r in refs:
        if safe_url(r.get("url")) and r["url"] not in urls:
            urls.append(r["url"])
        if len(urls) >= MAX_REFERENCES:
            break

    cpes, seen = [], set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parsed = parse_cpe23(m.get("criteria", ""))
                if not parsed:
                    continue
                row = (parsed["part"], parsed["vendor"], parsed["product"], parsed["version"],
                       m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                       m.get("versionEndIncluding"), m.get("versionEndExcluding"))
                if row not in seen:
                    seen.add(row)
                    cpes.append(dict(zip(("part", "vendor", "product", "version", "start_incl", "start_excl",
                                          "end_incl", "end_excl"), row)))

    return {
        "id": cve_id,
        "published": _dt(cve.get("published")),
        "modified": _dt(cve.get("lastModified")),
        "status": status,
        "description": description,
        "cvss": _cvss(cve.get("metrics", {})),
        "cwe": ",".join(cwes)[:200] or None,
        "refs": urls,
        "cpes": cpes,
    }


def parse_nvd_page(payload: dict) -> List[dict]:
    return [normalize_nvd_cve(v["cve"]) for v in payload.get("vulnerabilities", []) if "cve" in v]


def _date(value: Optional[str]) -> Optional[str]:
    try:
        return date.fromisoformat(value).isoformat() if value else None
    except ValueError:
        return None


def parse_kev(payload: dict) -> dict:
    items = []
    for v in payload.get("vulnerabilities", []):
        if not v.get("cveID"):
            continue
        items.append({"id": v["cveID"], "added": _date(v.get("dateAdded")), "due": _date(v.get("dueDate")),
                      "ransomware": (v.get("knownRansomwareCampaignUse") or None),
                      "action": v.get("requiredAction")})
    return {"version": payload.get("catalogVersion"), "released": payload.get("dateReleased"), "items": items}


def parse_epss_csv(text: str) -> dict:
    """The EPSS daily CSV: a "#model_version:...,score_date:..." comment line,
    then "cve,epss,percentile"."""
    score_date = None
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            if part.startswith("score_date:"):
                score_date = part.split(":", 1)[1][:10]
        lines = lines[1:]
    rows = []
    for r in csv.DictReader(lines):
        try:
            rows.append((r["cve"], float(r["epss"]), float(r["percentile"])))
        except (KeyError, TypeError, ValueError):
            continue
    return {"date": score_date, "rows": rows}


# ── fetchers ─────────────────────────────────────────────────────────────

def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


class NvdClient:
    def __init__(self, api_key: Optional[str] = None, session=None, sleep: Callable = time.sleep):
        self.session = session or requests.Session()
        self.api_key = api_key
        self.sleep = sleep
        # NVD's published guidance: 6 s between requests without a key.
        self.delay = 0.7 if api_key else 6.5

    def _get(self, params: dict) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(5):
            try:
                resp = self.session.get(NVD_API_URL, params=params, headers=headers, timeout=TIMEOUT)
            except requests.RequestException as exc:
                if attempt == 4:
                    raise FeedError(f"NVD is not reachable: {exc.__class__.__name__}") from exc
                self.sleep(10 * (attempt + 1))
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 429, 500, 502, 503, 504) and attempt < 4:
                # 403 is also NVD's rate-limit answer.
                self.sleep(15 * (attempt + 1))
                continue
            if resp.status_code == 404 and self.api_key:
                raise FeedError("NVD rejected the API key")
            raise FeedError(f"NVD answered HTTP {resp.status_code}")
        raise FeedError("NVD did not answer")

    def pages(self, start: Optional[datetime], end: datetime,
              on_page: Optional[Callable[[int, int], None]] = None,
              cancelled: Callable[[], bool] = lambda: False) -> Iterator[List[dict]]:
        """Normalised records changed in [start, end] (everything when start is
        None), one NVD page at a time."""
        windows = [(None, None)] if start is None else []
        cursor = start
        while start is not None and cursor < end:
            nxt = min(cursor + MAX_WINDOW, end)
            windows.append((cursor, nxt))
            cursor = nxt
        done = 0
        for w_start, w_end in windows:
            index, total = 0, None
            while total is None or index < total:
                if cancelled():
                    raise FeedError("Cancelled")
                params = {"startIndex": index, "resultsPerPage": PAGE_SIZE}
                if w_start is not None:
                    params["lastModStartDate"] = _fmt(w_start)
                    params["lastModEndDate"] = _fmt(w_end)
                payload = self._get(params)
                total = payload.get("totalResults", 0)
                records = parse_nvd_page(payload)
                index += payload.get("resultsPerPage", len(records)) or PAGE_SIZE
                done += len(records)
                if on_page:
                    on_page(done, total)
                yield records
                if index < total:
                    self.sleep(self.delay)

    def ping(self) -> None:
        self._get({"resultsPerPage": 1, "startIndex": 0})


def fetch_kev(session=None) -> dict:
    s = session or requests.Session()
    try:
        resp = s.get(KEV_URL, timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise FeedError(f"CISA KEV is not reachable: {exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise FeedError(f"CISA KEV answered HTTP {resp.status_code}")
    return parse_kev(resp.json())


def fetch_epss(session=None) -> dict:
    s = session or requests.Session()
    try:
        resp = s.get(EPSS_URL, timeout=TIMEOUT * 3)
    except requests.RequestException as exc:
        raise FeedError(f"EPSS is not reachable: {exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise FeedError(f"EPSS answered HTTP {resp.status_code}")
    raw = resp.content
    text = gzip.decompress(raw).decode("utf-8") if raw[:2] == b"\x1f\x8b" else raw.decode("utf-8")
    return parse_epss_csv(text)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def iso_to_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None

