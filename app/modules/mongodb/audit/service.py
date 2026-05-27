"""
MongoDB Audit Service Layer

Orchestrates the end-to-end MongoDB CIS audit workflow:
  1. Resolve asset → target IP
  2. Create an AuditSession record (status: running)
  3. SSH to host, collect audit data
  4. Redact sensitive values from the dump
  5. Evaluate CIS rules against the dump
  6. Update session with compliance metrics
  7. Bulk-insert individual AuditResult rows
"""

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import AuditResult, AuditSession, Asset
from app.models.audit import CheckStatus, DeviceType

from .mongo_client import MongoDBSSHClient, redact_sensitive_mongo_data
from .rules import (
    MongoDBCISRule,
    build_all_mongodb_cis_rules,
    evaluate_compliance,
    filter_rules_by_profile,
)

logger = logging.getLogger(__name__)


# ============================================================ #
#  Custom exceptions                                            #
# ============================================================ #

class MongoAuditError(Exception):
    """Base exception for MongoDB audit errors."""


class MongoAuditConnectionError(MongoAuditError):
    """SSH or MongoDB connection failure."""


class MongoAuditValidationError(MongoAuditError):
    """Invalid input before connection is attempted."""


# ============================================================ #
#  Service class                                               #
# ============================================================ #

class MongoDBSHAuditService:
    """Service for executing and managing MongoDB CIS security audits."""

    CACHE_TTL = 3600   # seconds
    BATCH_SIZE = 100
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    # Class-level rule cache
    _rules_cache: Dict[str, List[MongoDBCISRule]] = {}
    _cache_timestamp: Dict[str, float] = {}

    # ---------------------------------------------------------------- #
    #  Internal helpers                                                 #
    # ---------------------------------------------------------------- #

    @staticmethod
    @contextmanager
    def _timed_op(name: str):
        start = time.time()
        logger.info(f"Starting: {name}")
        try:
            yield
        finally:
            logger.info(f"Completed: {name} ({time.time() - start:.2f}s)")

    @staticmethod
    def _get_cached_rules(profile: str) -> List[MongoDBCISRule]:
        cache_key = f"mongodb_{profile}"
        now = time.time()

        if cache_key in MongoDBSHAuditService._rules_cache:
            age = now - MongoDBSHAuditService._cache_timestamp.get(cache_key, 0)
            if age < MongoDBSHAuditService.CACHE_TTL:
                logger.debug(f"Using cached MongoDB rules for {profile} (age {age:.0f}s)")
                return MongoDBSHAuditService._rules_cache[cache_key]

        logger.info(f"Building MongoDB CIS rules for profile={profile}")
        all_rules = build_all_mongodb_cis_rules()
        filtered = filter_rules_by_profile(all_rules, profile)
        MongoDBSHAuditService._rules_cache[cache_key] = filtered
        MongoDBSHAuditService._cache_timestamp[cache_key] = now
        logger.info(f"Cached {len(filtered)} MongoDB rules for {profile}")
        return filtered

    @staticmethod
    def _bulk_insert_results(
        db: Session,
        session_id: int,
        findings: List[Dict],
        batch_size: int = None,
    ) -> None:
        batch_size = batch_size or MongoDBSHAuditService.BATCH_SIZE
        batch = []

        for finding in findings:
            result = AuditResult(
                session_id=session_id,
                check_number=finding["id"],
                check_title=finding["title"],
                severity=finding["severity"],
                level=finding.get("level", "L1"),
                status=CheckStatus.PASS if finding["compliant"] else CheckStatus.FAIL,
                evidence_snippet=finding["evidence"],
                checked_at=datetime.now(timezone.utc),
            )
            batch.append(result)

            if len(batch) >= batch_size:
                db.bulk_save_objects(batch)
                db.commit()
                batch = []

        if batch:
            db.bulk_save_objects(batch)
            db.commit()

        logger.info(f"Inserted {len(findings)} audit results for session {session_id}")

    @staticmethod
    def _sanitize_error(exc: Exception) -> str:
        msg = str(exc)
        if any(kw in msg.lower() for kw in ("password", "secret", "token")):
            return f"{type(exc).__name__}: Authentication or connection error"
        return f"{type(exc).__name__}: {msg}"[:500]

    # ---------------------------------------------------------------- #
    #  Primary audit execution                                          #
    # ---------------------------------------------------------------- #

    @staticmethod
    def execute_mongodb_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        mongo_username: Optional[str] = None,
        mongo_password: Optional[str] = None,
        mongo_port: int = 27017,
        profile: str = "L1",
        job_name: Optional[str] = None,
        ssh_port: int = 22,
    ) -> AuditSession:
        """
        Execute a CIS MongoDB compliance audit.

        Args:
            db:             PostgreSQL session (SQLAlchemy)
            asset_id:       Asset record that hosts the MongoDB instance
            user_id:        Authenticated user performing the audit
            ssh_username:   OS-level SSH credentials (not stored)
            ssh_password:   OS-level SSH credentials (not stored)
            mongo_username: MongoDB admin username (optional, not stored)
            mongo_password: MongoDB admin password (optional, not stored)
            mongo_port:     MongoDB listen port (default 27017)
            profile:        CIS profile – "L1" or "FULL"
            job_name:       Optional human-readable label for this audit run

        Returns:
            AuditSession with status="completed" and compliance metrics set.

        Raises:
            ValueError:  Asset not found or has no IP address.
            Exception:   SSH / rule evaluation failure (session marked failed).
        """
        # 1. Resolve asset
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(
                f"Asset '{asset.asset_name}' has no IP address configured"
            )
        target_ip = asset.ip_address

        # 2. Create session
        session = AuditSession(
            template_id=None,
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.MONGODB,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. SSH to host & collect data
            with MongoDBSHAuditService._timed_op("SSH connect & collect audit data"):
                with MongoDBSSHClient(
                    ip=target_ip,
                    username=ssh_username,
                    password=ssh_password,
                    mongo_username=mongo_username,
                    mongo_password=mongo_password,
                    mongo_port=mongo_port,
                    ssh_port=ssh_port,
                ) as client:
                    raw_dump = client.collect_audit_data()

            # 4. Redact sensitive values
            clean_dump = redact_sensitive_mongo_data(raw_dump)

            # 5. Load rules
            rules = MongoDBSHAuditService._get_cached_rules(profile)

            # 6. Evaluate compliance
            with MongoDBSHAuditService._timed_op(
                f"Evaluate {len(rules)} MongoDB CIS rules"
            ):
                report = evaluate_compliance(clean_dump, rules)

            summary = report["summary"]

            # 7. Persist session metrics
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = summary["total_rules_scored"]
            session.passed_checks = summary["passed_scored"]
            session.failed_checks = summary["failed_scored"]
            session.error_checks = 0
            session.compliance_pct = summary["compliance_pct"]
            session.weighted_compliance_pct = summary["weighted_compliance_pct"]
            session.turbo_dump = clean_dump
            db.commit()

            # 8. Persist individual check results
            with MongoDBSHAuditService._timed_op("Bulk insert audit results"):
                MongoDBSHAuditService._bulk_insert_results(
                    db, session.id, report["findings"]
                )

            db.refresh(session)
            logger.info(
                f"MongoDB audit completed for asset {asset_id} ({target_ip}): "
                f"{summary['compliance_pct']}% compliance"
            )
            return session

        except Exception as exc:
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)
            session.connection_error = MongoDBSHAuditService._sanitize_error(exc)
            db.commit()
            db.refresh(session)
            logger.error(
                f"MongoDB audit failed for asset {asset_id}: {type(exc).__name__}"
            )
            raise

    # ---------------------------------------------------------------- #
    #  Query helpers                                                    #
    # ---------------------------------------------------------------- #

    @staticmethod
    def get_audit_session(db: Session, session_id: int) -> Optional[AuditSession]:
        return db.query(AuditSession).filter(AuditSession.id == session_id).first()

    @staticmethod
    def get_audit_results(db: Session, session_id: int) -> List[AuditResult]:
        return (
            db.query(AuditResult)
            .filter(AuditResult.session_id == session_id)
            .all()
        )

    @staticmethod
    def get_all_sessions(
        db: Session, limit: int = 50, offset: int = 0
    ) -> List[AuditSession]:
        return (
            db.query(AuditSession)
            .filter(AuditSession.device_type == DeviceType.MONGODB)
            .order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_sessions_count(db: Session) -> int:
        return (
            db.query(AuditSession)
            .filter(AuditSession.device_type == DeviceType.MONGODB)
            .count()
        )

    @staticmethod
    def get_asset_audit_history(
        db: Session, asset_id: int, limit: int = 10
    ) -> List[AuditSession]:
        return (
            db.query(AuditSession)
            .filter(
                AuditSession.asset_id == asset_id,
                AuditSession.device_type == DeviceType.MONGODB,
            )
            .order_by(AuditSession.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_session_summary(
        db: Session, session_id: int
    ) -> Optional[Dict[str, Any]]:
        """Return a JSON-serialisable summary of a single audit session."""
        session = MongoDBSHAuditService.get_audit_session(db, session_id)
        if not session:
            return None

        asset = (
            db.query(Asset).filter(Asset.id == session.asset_id).first()
            if session.asset_id
            else None
        )
        results = MongoDBSHAuditService.get_audit_results(db, session_id)

        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        errors = sum(1 for r in results if r.status == CheckStatus.ERROR)

        return {
            "session_id": session.id,
            "job_name": session.job_name,
            "asset_id": session.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "target_ip": session.target_ip,
            "device_type": session.device_type.value,
            "status": session.status,
            "started_at": (
                session.started_at.isoformat() if session.started_at else None
            ),
            "completed_at": (
                session.completed_at.isoformat() if session.completed_at else None
            ),
            "duration_seconds": (
                (session.completed_at - session.started_at).total_seconds()
                if session.completed_at and session.started_at
                else None
            ),
            "compliance": {
                "total_checks": session.total_checks,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "compliance_pct": session.compliance_pct,
                "weighted_compliance_pct": session.weighted_compliance_pct,
            },
            "connection_error": session.connection_error,
        }

    @staticmethod
    def delete_audit_session(db: Session, session_id: int) -> bool:
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Audit session {session_id} not found")
        db.delete(session)
        db.commit()
        return True
