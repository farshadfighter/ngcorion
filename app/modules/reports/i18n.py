"""
Report text in the report's language.

Report strings are written in English in the code; the Persian text lives in
locale/fa.json (key = the English text, like the frontend). A missing Persian
entry falls back to the English text, and tests/test_reports.py checks that
every string the templates use has a translation.

Numbers: Persian digits, the Persian decimal separator and per-cent sign in
Persian; IDs, IPs and versions are never passed through here.
"""
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.modules.reports.calendar import fa_digits

LOCALE_DIR = Path(__file__).parent / "locale"
_FIELD = re.compile(r"\{(\w+)\}")
_LATIN = re.compile(r"[A-Za-z]")
_PERSIAN = re.compile(r"[\u0600-\u06FF]")


@lru_cache(maxsize=1)
def persian() -> dict:
    return json.loads((LOCALE_DIR / "fa.json").read_text(encoding="utf-8"))


# Every key a template asked for, so the test can check the locale covers them.
USED: set = set()


class Tr:
    def __init__(self, lang: str):
        self.lang = lang if lang in ("fa", "en") else "en"
        self.rtl = self.lang == "fa"

    def __call__(self, text: str, **values) -> str:
        USED.add(text)
        out = (persian().get(text) or text) if self.lang == "fa" else text
        if values:
            out = _FIELD.sub(lambda m: self._value(values.get(m.group(1), m.group(0))), out)
        return out

    def _value(self, v) -> str:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return self.num(v)
        return self.isolate(str(v))

    def isolate(self, text: str) -> str:
        """Keep Latin text (CVE IDs, asset names, addresses) in its own order inside a Persian sentence."""
        if self.lang == "fa" and _LATIN.search(text) and not _PERSIAN.search(text):
            return f"\u2066{text}\u2069"
        return text

    def num(self, value, decimals: int = 0) -> str:
        if value is None:
            return "—"
        if isinstance(value, float) and decimals == 0 and not float(value).is_integer():
            decimals = 1
        text = f"{value:,.{decimals}f}" if isinstance(value, (int, float)) else str(value)
        if self.lang == "fa":
            text = fa_digits(text).replace(",", "٬").replace(".", "٫")
        return text

    def pct(self, value, decimals: int = 0) -> str:
        if value is None:
            return "—"
        return f"{self.num(round(value, decimals), decimals)}{'٪' if self.lang == 'fa' else '%'}"

    def signed(self, value, decimals: int = 0, unit: str = "") -> str:
        """+3 / −3 with the sign on the reading side."""
        if value is None:
            return "—"
        sign = "+" if value > 0 else ("−" if value < 0 else "")
        body = self.num(abs(round(value, decimals)), decimals) + unit
        return f"{body}{sign}" if self.lang == "fa" and sign else f"{sign}{body}"

    def severity(self, s: Optional[str]) -> str:
        return self({"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
                     "info": "Info", "informational": "Informational"}.get((s or "").lower(), s or "—"))
