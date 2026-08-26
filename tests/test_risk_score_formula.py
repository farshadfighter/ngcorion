"""Pure (DB-independent) unit tests for the Risk Score engine.

These exercise the arithmetic defined by the NGCorion Risk Score Calculation
Specification (risk.pdf) directly against the service's pure helpers and the
``DEFAULT_SETTINGS`` fallback map, so they run without a database, driver, or
migrated schema:

    cd /home/sina/netease && .venv/bin/python -m pytest tests/test_risk_score_formula.py -q

The DB-backed behavior (persistence, triggers, AF/HF over real audit results)
is covered by tests/test_risk_module.py, which needs a migrated PostgreSQL DB.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app.modules.risk.service import (
    DEFAULT_SETTINGS,
    risk_calculation_service as svc,
)


@pytest.fixture
def settings() -> dict:
    return dict(DEFAULT_SETTINGS)


# ----------------------------------------------------------------------
# Weights (PDF sections 2/4): AC 20, AR 20, AZ 15, OP 10, AF 25, HF 10 = 100
# ----------------------------------------------------------------------

def test_factor_weights_are_pdf_values(settings):
    assert float(settings["criticality_weight"]) == 20
    assert float(settings["asset_risk_weight"]) == 20
    assert float(settings["zone_weight"]) == 15
    assert float(settings["open_port_weight"]) == 10
    assert float(settings["audit_weight"]) == 25
    assert float(settings["hardening_weight"]) == 10


def test_factor_weights_sum_to_100(settings):
    total = sum(
        float(settings[k])
        for k in (
            "criticality_weight", "asset_risk_weight", "zone_weight",
            "open_port_weight", "audit_weight", "hardening_weight",
        )
    )
    assert total == 100


# ----------------------------------------------------------------------
# Asset Criticality (AC) and Asset Risk (AR): Low 25 / Med 50 / High 75 / Crit 100
# ----------------------------------------------------------------------

@pytest.mark.parametrize("level,expected", [
    ("low", 25), ("medium", 50), ("high", 75), ("critical", 100),
])
def test_criticality_level_scores(settings, level, expected):
    assert svc._criticality_score(level, settings) == expected


@pytest.mark.parametrize("level,expected", [
    ("low", 25), ("medium", 50), ("high", 75), ("critical", 100),
])
def test_asset_risk_level_scores(settings, level, expected):
    asset = SimpleNamespace(risk_level=level)
    _level, score, is_unknown = svc._asset_risk_score(asset, settings)
    assert _level == level
    assert score == expected
    assert is_unknown is False


def test_asset_risk_unknown_falls_back(settings):
    asset = SimpleNamespace(risk_level=None)
    _level, score, is_unknown = svc._asset_risk_score(asset, settings)
    assert is_unknown is True
    assert score == float(settings["unknown_asset_risk_score"])


# ----------------------------------------------------------------------
# Finding severity scale (AF/HF): Low 1 / Medium 4 / High 7 / Critical 10 (PDF 7/8)
# ----------------------------------------------------------------------

@pytest.mark.parametrize("severity,expected", [
    ("low", 1), ("medium", 4), ("high", 7), ("critical", 10),
])
def test_finding_severity_weights(settings, severity, expected):
    assert svc._severity_weight(severity, settings) == expected


# ----------------------------------------------------------------------
# Open-port severity scale: Std/Low 1 / Medium 3 / High 5 / Critical 10 (PDF 6)
# ----------------------------------------------------------------------

@pytest.mark.parametrize("severity,expected", [
    ("low", 1), ("medium", 3), ("high", 5), ("critical", 10),
])
def test_port_severity_weights(settings, severity, expected):
    assert svc._port_severity_weight(severity, settings) == expected


# ----------------------------------------------------------------------
# Risk levels (PDF 10): 0-20 info | 21-40 low | 41-60 med | 61-80 high | 81-100 crit
# ----------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (0, "informational"),
    (20, "informational"),   # boundary belongs to the lower band
    (21, "low"),
    (40, "low"),
    (41, "medium"),
    (60, "medium"),
    (61, "high"),
    (80, "high"),
    (81, "critical"),
    (100, "critical"),
    (75, "high"),            # PDF section 9 result
])
def test_risk_level_bands(settings, score, expected):
    assert svc._risk_level(score, settings) == expected


# ----------------------------------------------------------------------
# Final weighted score — PDF section 9 worked example
#   AC=100, AR=75, AZ=80, OP=40, AF=72, HF=60
#   -> 20 + 15 + 12 + 4 + 18 + 6 = 75  -> High
# ----------------------------------------------------------------------

def test_pdf_section9_example(settings):
    components = {
        "criticality": 100, "asset_risk": 75, "zone": 80,
        "open_port": 40, "audit": 72, "hardening": 60,
    }
    final, contrib = svc._final_score(components, settings)
    assert contrib["criticality"] == 20
    assert contrib["asset_risk"] == 15
    assert contrib["zone"] == 12
    assert contrib["open_port"] == 4
    assert contrib["audit"] == 18
    assert contrib["hardening"] == 6
    assert final == 75
    assert svc._risk_level(final, settings) == "high"


def test_final_score_rounds_to_integer(settings):
    # A component set that yields a fractional weighted sum must round to int.
    # All-50 components -> 50 * (sum weights / 100) = 50.0
    components = {k: 50 for k in (
        "criticality", "asset_risk", "zone", "open_port", "audit", "hardening"
    )}
    final, _ = svc._final_score(components, settings)
    assert final == 50
    assert float(final).is_integer()


def test_final_score_clamped_0_100(settings):
    hi = {k: 100 for k in (
        "criticality", "asset_risk", "zone", "open_port", "audit", "hardening"
    )}
    lo = {k: 0 for k in hi}
    assert svc._final_score(hi, settings)[0] == 100
    assert svc._final_score(lo, settings)[0] == 0


# ----------------------------------------------------------------------
# AF raw — PDF section 7 worked example
#   Critical 2, High 5, Medium 8, Low 10
#   AF_Raw = 2*10 + 5*7 + 8*4 + 10*1 = 20 + 35 + 32 + 10 = 97
# ----------------------------------------------------------------------

def test_af_raw_pdf_section7(settings):
    counts = {"critical": 2, "high": 5, "medium": 8, "low": 10}
    af_raw = sum(
        n * svc._severity_weight(sev, settings) for sev, n in counts.items()
    )
    assert af_raw == 97


def test_af_normalization_ratio(settings):
    # AF = 100 * AF_Raw / MaxPossibleAuditScore. If every applicable control
    # failed, AF == 100; if half the weight failed, AF == 50.
    max_possible = 200.0
    assert round(100.0 * 97.0 / max_possible, 4) == 48.5
    assert round(100.0 * max_possible / max_possible, 4) == 100.0


# ----------------------------------------------------------------------
# OP — PDF section 6 worked example
#   22/SSH=3, 80/HTTP=3, 445/SMB=10, 3389/RDP=10  -> sum 26 -> OP = 26
#   and the 0-100 cap
# ----------------------------------------------------------------------

def test_op_pdf_section6_example(settings):
    labels = ["medium", "medium", "critical", "critical"]  # SSH, HTTP, SMB, RDP
    raw = sum(svc._port_severity_weight(s, settings) for s in labels)
    assert raw == 26
    factor = float(settings["open_port_normalization_factor"])
    assert factor == 1
    op = min(100.0, raw * factor)
    assert op == 26


def test_op_capped_at_100(settings):
    # 12 critical ports -> raw 120 -> capped to 100
    raw = 12 * svc._port_severity_weight("critical", settings)
    factor = float(settings["open_port_normalization_factor"])
    assert min(100.0, raw * factor) == 100
