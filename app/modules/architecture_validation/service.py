"""Architecture Validation Service - context building, rule runs, findings CRUD."""
from collections import defaultdict
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import Asset, TopologyLink, DeviceBackup, ArchitectureFinding
from app.models.audit import AuditSession
from app.modules.architecture_validation.engine import load_rules, run_rules


class ArchitectureValidationService:
    """Architecture Validation Service."""

    @staticmethod
    def get_findings(db: Session, status: Optional[str] = None, severity: Optional[str] = None):
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
    def _topology_degree_map(db: Session) -> dict:
        degree = defaultdict(int)
        links = db.query(TopologyLink).filter(TopologyLink.status != "planned").all()
        for link in links:
            degree[link.source_asset_id] += 1
            degree[link.destination_asset_id] += 1
        return degree

    @staticmethod
    def _assets_with_backup(db: Session) -> set:
        rows = db.query(DeviceBackup.asset_id).distinct().all()
        return {row[0] for row in rows}

    @staticmethod
    def _latest_audit_by_asset(db: Session) -> dict:
        sessions = db.query(AuditSession).filter(AuditSession.asset_id.isnot(None)).all()
        latest = {}
        for session in sessions:
            current = latest.get(session.asset_id)
            if current is None or (session.started_at and (current.started_at is None or session.started_at > current.started_at)):
                latest[session.asset_id] = session
        return latest

    @staticmethod
    def build_asset_context(
        asset: Asset,
        topology_degree: int,
        has_backup: bool,
        latest_audit: Optional[AuditSession],
    ) -> dict:
        """Every name a rule's condition may reference. Keep in sync with rules/*.yaml."""
        days_since_audit = None
        last_audit_status = None
        if latest_audit is not None:
            last_audit_status = latest_audit.status
            if latest_audit.started_at:
                days_since_audit = (datetime.utcnow() - latest_audit.started_at).days

        return {
            "asset_name": asset.asset_name,
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "type_name": asset.asset_type.type_name if asset.asset_type else None,
            "manufacturer": asset.manufacturer,
            "os_name": asset.os_name,
            "risk_level": asset.risk_level.value if asset.risk_level else None,
            "confidentiality_level": asset.confidentiality_level.value if asset.confidentiality_level else None,
            "status": asset.status.value if asset.status else None,
            "is_critical": asset.is_critical,
            "has_owner": asset.owner_id is not None,
            "topology_degree": topology_degree,
            "has_backup": has_backup,
            "last_audit_status": last_audit_status,
            "days_since_audit": days_since_audit,
        }

    # ==========================================
    # Analysis run
    # ==========================================

    @staticmethod
    def analyze(db: Session) -> list[ArchitectureFinding]:
        """Re-run every rule against every asset, replacing all open findings.

        Findings the operator already accepted or ignored are left alone
        (re-running shouldn't erase a triage decision); resolved findings
        for a condition that no longer applies simply aren't re-created.
        """
        rules = load_rules()
        degree_map = ArchitectureValidationService._topology_degree_map(db)
        backed_up = ArchitectureValidationService._assets_with_backup(db)
        latest_audits = ArchitectureValidationService._latest_audit_by_asset(db)

        db.query(ArchitectureFinding).filter(ArchitectureFinding.status == "open").delete()

        resolved_keys = {
            (f.rule_code, f.asset_id)
            for f in db.query(ArchitectureFinding).filter(ArchitectureFinding.status != "open").all()
        }

        new_findings = []
        for asset in db.query(Asset).all():
            context = ArchitectureValidationService.build_asset_context(
                asset,
                degree_map.get(asset.id, 0),
                asset.id in backed_up,
                latest_audits.get(asset.id),
            )
            for rule in run_rules(context, rules):
                if (rule["code"], asset.id) in resolved_keys:
                    continue
                new_findings.append(
                    ArchitectureFinding(
                        rule_code=rule["code"],
                        title=rule["title"],
                        severity=rule.get("severity", "medium"),
                        category=rule.get("category"),
                        recommendation=rule.get("recommendation"),
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
