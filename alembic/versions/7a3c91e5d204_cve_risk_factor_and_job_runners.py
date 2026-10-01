"""CVE risk factor (CV), cross-process job control

Revision ID: 7a3c91e5d204
Revises: d41e7b9c2a58
Create Date: 2026-10-01

1. Risk: a seventh factor, CV (known vulnerabilities from the CVE module).
   asset_risk_scores / asset_risk_history gain its columns, and risk_settings
   gains vulnerability_weight. The weights must keep summing to 100:
     - an install still on the published defaults (AC 20, AR 20, AZ 15,
       OP 10, AF 25, HF 10) moves to AC 20, AR 15, AZ 15, OP 10, AF 20,
       HF 5, CV 15;
     - an install whose admin changed the weights keeps them, with CV at 0
       until an admin gives it a share.
   Stored scores keep their old values until the next calculation; CVE
   database updates trigger one for every asset.

2. Jobs: cve_update_jobs.cancel_requested (Cancel reaches a job running in
   another uvicorn worker) and a runner tag on CVE and restore jobs (a worker
   starting up fails only jobs whose process is gone).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "7a3c91e5d204"
down_revision: Union[str, Sequence[str], None] = "d41e7b9c2a58"
branch_labels = None
depends_on = None

_OLD = {"criticality_weight": 20, "asset_risk_weight": 20, "zone_weight": 15,
        "open_port_weight": 10, "audit_weight": 25, "hardening_weight": 10}
_NEW = {"criticality_weight": 20, "asset_risk_weight": 15, "zone_weight": 15,
        "open_port_weight": 10, "audit_weight": 20, "hardening_weight": 5}
_CV_DESCRIPTION = "CV: weight of known vulnerabilities (CVE findings) in the final risk score (%)"


def _weights(conn):
    rows = conn.execute(sa.text(
        "SELECT setting_key, setting_value FROM risk_settings WHERE setting_key = ANY(:keys)"
    ), {"keys": list(_OLD)}).all()
    out = {}
    for key, value in rows:
        try:
            out[key] = float(value)
        except (TypeError, ValueError):
            out[key] = None
    return out


def upgrade() -> None:
    op.add_column("asset_risk_scores", sa.Column("vulnerability_score", sa.Numeric(5, 2), nullable=True))
    op.add_column("asset_risk_scores", sa.Column("vulnerability_weight", sa.Numeric(5, 2), nullable=True))
    op.add_column("asset_risk_scores", sa.Column("vulnerability_contribution", sa.Numeric(5, 2), nullable=True))
    op.add_column("asset_risk_scores", sa.Column("cve_findings_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("asset_risk_scores", sa.Column("cve_kev_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("asset_risk_history", sa.Column("vulnerability_score", sa.Numeric(5, 2), nullable=True))
    op.add_column("asset_risk_history", sa.Column("vulnerability_contribution", sa.Numeric(5, 2), nullable=True))

    op.add_column("cve_update_jobs", sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("cve_update_jobs", sa.Column("runner", sa.String(160), nullable=True))
    op.add_column("backup_restores", sa.Column("runner", sa.String(160), nullable=True))

    conn = op.get_bind()
    current = _weights(conn)
    untouched = all(current.get(k) == float(v) for k, v in _OLD.items())
    if untouched:
        for key, value in _NEW.items():
            conn.execute(sa.text("UPDATE risk_settings SET setting_value = :v, updated_at = now() WHERE setting_key = :k"),
                         {"k": key, "v": str(value)})
    cv = 15 if untouched or not current else 0
    conn.execute(sa.text(
        "INSERT INTO risk_settings (setting_key, setting_value, value_type, description, is_editable, created_at, updated_at) "
        "VALUES ('vulnerability_weight', :v, 'int', :d, true, now(), now()) ON CONFLICT (setting_key) DO NOTHING"
    ), {"v": str(cv), "d": _CV_DESCRIPTION})


def downgrade() -> None:
    conn = op.get_bind()
    current = _weights(conn)
    cv = conn.execute(sa.text("SELECT setting_value FROM risk_settings WHERE setting_key = 'vulnerability_weight'")).scalar()
    if all(current.get(k) == float(v) for k, v in _NEW.items()) and cv is not None and float(cv) == 15:
        for key, value in _OLD.items():
            conn.execute(sa.text("UPDATE risk_settings SET setting_value = :v WHERE setting_key = :k"),
                         {"k": key, "v": str(value)})
    conn.execute(sa.text("DELETE FROM risk_settings WHERE setting_key = 'vulnerability_weight'"))

    op.drop_column("backup_restores", "runner")
    op.drop_column("cve_update_jobs", "runner")
    op.drop_column("cve_update_jobs", "cancel_requested")
    op.drop_column("asset_risk_history", "vulnerability_contribution")
    op.drop_column("asset_risk_history", "vulnerability_score")
    for col in ("cve_kev_count", "cve_findings_count", "vulnerability_contribution", "vulnerability_weight",
                "vulnerability_score"):
        op.drop_column("asset_risk_scores", col)
