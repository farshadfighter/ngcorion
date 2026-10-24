"""Architecture Validation Service - the topology against Cisco SAFE (rules/safe.yaml), findings CRUD."""
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import Asset, ArchitectureFinding
from app.modules.architecture_validation.engine import load_rules, run_rules
from app.modules.architecture_validation.topology import load as load_topology


class ArchitectureValidationService:
    """Architecture Validation Service."""

    @staticmethod
    def get_findings(db: Session, status: Optional[str] = None, severity: Optional[str] = None):
        """Findings, newest first, optionally by status and severity."""
        query = db.query(ArchitectureFinding)
        if status:
            query = query.filter(ArchitectureFinding.status == status)
        if severity:
            query = query.filter(ArchitectureFinding.severity == severity)
        return query.order_by(ArchitectureFinding.created_at.desc()).all()

    @staticmethod
    def get_finding(db: Session, finding_id: int) -> Optional[ArchitectureFinding]:
        return db.query(ArchitectureFinding).filter(ArchitectureFinding.id == finding_id).first()

    @staticmethod
    def resolve_finding(db: Session, finding: ArchitectureFinding, status: str, user_id: int, reason: str = None):
        """Close a finding as accepted or ignored, recording who and when."""
        finding.status = status
        finding.ignored_reason = reason
        finding.resolved_by = user_id
        finding.resolved_at = datetime.utcnow()
        db.commit()
        db.refresh(finding)
        return finding

    # ==========================================
    # Context building
    # ==========================================

    @staticmethod
    def build_asset_context(asset: Asset, facts: dict) -> dict:
        """Every name a rule's condition may reference (rules/safe.yaml): what the topology says
        about the asset (topology.py, Topology.facts) and who it is."""
        return {"asset_name": asset.asset_name, **facts}

    # ==========================================
    # Analysis run
    # ==========================================

    @staticmethod
    def analyze(db: Session) -> list[ArchitectureFinding]:
        """Re-run every rule against every asset, replacing all open findings.

        Findings the operator already accepted or ignored are left alone
        (re-running shouldn't erase a triage decision); resolved findings
        for a condition that no longer applies simply aren't re-created.
        Findings of a rule that is no longer in the rule set go, whatever
        their status.
        """
        rules = load_rules()
        codes = {r["code"] for r in rules}
        topology = load_topology(db)
        assets = list(topology.assets.values())
        facts = topology.facts({a.id: a.is_critical for a in assets})

        db.query(ArchitectureFinding).filter(ArchitectureFinding.status == "open").delete()
        db.query(ArchitectureFinding).filter(ArchitectureFinding.rule_code.notin_(codes)).delete(
            synchronize_session=False)

        resolved_keys = {
            (f.rule_code, f.asset_id)
            for f in db.query(ArchitectureFinding).filter(ArchitectureFinding.status != "open").all()
        }

        new_findings = []
        for asset in sorted(assets, key=lambda a: a.id):
            context = ArchitectureValidationService.build_asset_context(asset, facts[asset.id])
            for rule in run_rules(context, rules):
                if (rule["code"], asset.id) in resolved_keys:
                    continue
                evidence = context.get(rule["evidence"]) if rule.get("evidence") else None
                new_findings.append(
                    ArchitectureFinding(
                        rule_code=rule["code"],
                        title=rule["title"],
                        severity=rule.get("severity", "medium"),
                        category=rule.get("category"),
                        recommendation=rule.get("recommendation"),
                        evidence=str(evidence) if evidence is not None else None,
                        asset_id=asset.id,
                        asset_name=asset.asset_name,
                        status="open",
                    )
                )

        db.add_all(new_findings)
        db.commit()
        for finding in new_findings:
            db.refresh(finding)
        return new_findings
