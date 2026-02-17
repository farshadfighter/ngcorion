"""
FortiGate Audit Service Layer

Orchestrates the complete FortiGate audit workflow:
1. Fetch asset details
2. Establish SSH connection (with optional VDOM context)
3. Collect command outputs
4. Evaluate FortiGate security controls
5. Store results in database
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from contextlib import contextmanager
import logging
import time
import re

from app.models import AuditSession, AuditResult, Asset
from app.models.audit import DeviceType, CheckStatus
from .ssh_client import FortiGateSSHClient
from .rules import (
    get_fortinet_controls,
    get_controls_by_level,
    get_controls_by_pack,
    get_unique_commands,
    FortiGateControl,
    FortiGateRule
)

logger = logging.getLogger(__name__)


class FortinetAuditError(Exception):
    """Base exception for FortiGate audit errors."""
    pass


class FortinetConnectionError(FortinetAuditError):
    """Raised when SSH connection fails."""
    pass


class FortinetEvaluationError(FortinetAuditError):
    """Raised when rule evaluation fails."""
    pass


class FortinetValidationError(FortinetAuditError):
    """Raised when input validation fails."""
    pass


class FortinetAuditService:
    """Service for executing and managing FortiGate security audits."""

    # Configuration constants
    CACHE_TTL = 3600  # 1 hour cache for security controls
    BATCH_SIZE = 100  # Bulk insert batch size
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    # Class-level cache for security controls
    _controls_cache: Dict[str, List[FortiGateControl]] = {}
    _cache_timestamp: Dict[str, float] = {}

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        """
        Context manager for timing operations.

        Usage:
            with FortinetAuditService._timed_operation("Evaluate rules"):
                # operation code

        Logs start and completion with duration.
        """
        start_time = time.time()
        logger.info(f"Starting: {operation_name}")

        try:
            yield
        finally:
            elapsed = time.time() - start_time
            logger.info(f"Completed: {operation_name} ({elapsed:.2f}s)")

    @staticmethod
    def _get_cached_controls(profile: str, pack: str = "BASELINE") -> List[FortiGateControl]:
        """
        Get security controls from cache or build fresh.

        Args:
            profile: Audit profile (L1, L2, or FULL)
            pack: Control pack filter (BASELINE, HA, SDWAN, etc.)

        Returns:
            List of filtered security controls

        Cache is invalidated after CACHE_TTL seconds.
        """
        cache_key = f"fortinet_{profile}_{pack}"
        current_time = time.time()

        # Check if cache exists and is still valid
        if (cache_key in FortinetAuditService._controls_cache and
            cache_key in FortinetAuditService._cache_timestamp):

            cache_age = current_time - FortinetAuditService._cache_timestamp[cache_key]

            if cache_age < FortinetAuditService.CACHE_TTL:
                logger.debug(
                    f"Using cached controls for {profile}/{pack} "
                    f"(age: {cache_age:.1f}s, {len(FortinetAuditService._controls_cache[cache_key])} controls)"
                )
                return FortinetAuditService._controls_cache[cache_key]
            else:
                logger.debug(f"Cache expired for {profile}/{pack} (age: {cache_age:.1f}s)")

        # Build fresh controls and cache
        logger.info(f"Building fresh FortiGate controls for {profile}/{pack}")
        with FortinetAuditService._timed_operation(f"Build controls ({profile}/{pack})"):
            all_controls = get_fortinet_controls()

            # Filter by profile
            if profile == "L1":
                filtered_controls = [c for c in all_controls if c.level == "L1"]
            elif profile == "L2":
                filtered_controls = [c for c in all_controls if c.level in ("L1", "L2")]
            else:  # FULL
                filtered_controls = all_controls

            # Filter by pack if not FULL
            if pack != "FULL":
                filtered_controls = [c for c in filtered_controls if c.pack == pack]

        FortinetAuditService._controls_cache[cache_key] = filtered_controls
        FortinetAuditService._cache_timestamp[cache_key] = current_time

        logger.info(f"Cached {len(filtered_controls)} controls for {profile}/{pack}")
        return filtered_controls

    @staticmethod
    def _redact_sensitive_data(outputs: Dict[str, str]) -> Dict[str, str]:
        """
        Redact passwords, secrets, and keys from command outputs.

        Patterns to redact:
        - set password <value>
        - set key <value>
        - set community <value>
        - set secret <value>
        - set auth-password <value>
        - set enc-password <value>
        - set private-key <value>
        - set passwd <value>
        """
        redaction_patterns = [
            (re.compile(r"(set password\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set key\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set community\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set secret\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set auth-password\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set enc-password\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set private-key\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set passwd\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
            (re.compile(r"(set psksecret\s+)[^\s]+", re.IGNORECASE | re.MULTILINE), r"\1<REDACTED>"),
        ]

        redacted_outputs = {}
        for command, output in outputs.items():
            redacted_output = output
            for pattern, replacement in redaction_patterns:
                redacted_output = pattern.sub(replacement, redacted_output)
            redacted_outputs[command] = redacted_output

        return redacted_outputs

    @staticmethod
    def _evaluate_rule(rule: FortiGateRule, command_output: str) -> bool:
        """
        Evaluate a single rule against command output.

        Args:
            rule: FortiGate rule to evaluate
            command_output: Command output string

        Returns:
            True if rule passes, False otherwise
        """
        try:
            if rule.type == "set_bool":
                # Check if "set <key> <expected>" exists
                expected_val = "enable" if rule.expected else "disable"
                pattern = rf"set {rule.key}\s+{expected_val}"
                return bool(re.search(pattern, command_output, re.IGNORECASE | re.MULTILINE))

            elif rule.type == "set_int_le":
                # Check if integer value <= expected
                pattern = rf"set {rule.key}\s+(\d+)"
                match = re.search(pattern, command_output, re.IGNORECASE | re.MULTILINE)
                if match:
                    actual = int(match.group(1))
                    return actual <= rule.expected
                return False

            elif rule.type == "set_int_ge":
                # Check if integer value >= expected
                pattern = rf"set {rule.key}\s+(\d+)"
                match = re.search(pattern, command_output, re.IGNORECASE | re.MULTILINE)
                if match:
                    actual = int(match.group(1))
                    return actual >= rule.expected
                return False

            elif rule.type == "set_eq":
                # Check if string value equals expected
                pattern = rf"set {rule.key}\s+(\S+)"
                match = re.search(pattern, command_output, re.IGNORECASE | re.MULTILINE)
                if match:
                    actual = match.group(1).strip('"')
                    return actual == rule.expected
                return False

            elif rule.type == "set_in":
                # Check if value is in list
                pattern = rf"set {rule.key}\s+(\S+)"
                match = re.search(pattern, command_output, re.IGNORECASE | re.MULTILINE)
                if match:
                    actual = match.group(1).strip('"')
                    return actual in (rule.any_of or [])
                return False

            elif rule.type == "regex_present":
                # Check if pattern exists
                return bool(re.search(rule.pattern, command_output, re.IGNORECASE | re.MULTILINE))

            elif rule.type == "regex_absent":
                # Check if pattern does NOT exist
                return not bool(re.search(rule.pattern, command_output, re.IGNORECASE | re.MULTILINE))

            else:
                logger.warning(f"Unknown rule type: {rule.type}")
                return False

        except Exception as e:
            logger.error(f"Error evaluating rule {rule.type}: {e}")
            return False

    @staticmethod
    def _extract_evidence(control: FortiGateControl, outputs: Dict[str, str]) -> str:
        """
        Extract relevant evidence snippet from command outputs.

        Args:
            control: Security control
            outputs: Command outputs dictionary

        Returns:
            Evidence string (up to 500 characters)
        """
        evidence_lines = []

        for rule in control.rules:
            command_output = outputs.get(rule.cmd, "")
            if not command_output:
                continue

            # Extract relevant lines based on rule key
            if rule.key:
                pattern = rf".*{rule.key}.*"
                matches = re.findall(pattern, command_output, re.IGNORECASE | re.MULTILINE)
                evidence_lines.extend(matches[:3])  # Max 3 lines per rule
            elif rule.pattern:
                matches = re.findall(rule.pattern, command_output, re.IGNORECASE | re.MULTILINE)
                if matches:
                    evidence_lines.append(f"Pattern match: {matches[0]}")

        # Join and truncate
        evidence = " | ".join(evidence_lines)
        if len(evidence) > 500:
            evidence = evidence[:497] + "..."

        return evidence if evidence else "No evidence found"

    @staticmethod
    def _evaluate_control(control: FortiGateControl, outputs: Dict[str, str]) -> Dict[str, Any]:
        """
        Evaluate a security control (may have multiple rules).

        Args:
            control: Security control to evaluate
            outputs: Command outputs dictionary

        Returns:
            Dict with evaluation results
        """
        rule_results = []
        for rule in control.rules:
            command_output = outputs.get(rule.cmd, "")
            passed = FortinetAuditService._evaluate_rule(rule, command_output)
            rule_results.append(passed)

        # Control passes if ALL rules pass
        overall_passed = all(rule_results) if rule_results else False

        # Extract evidence
        evidence = FortinetAuditService._extract_evidence(control, outputs)

        return {
            "control_id": control.id,
            "title": control.title,
            "passed": overall_passed,
            "evidence": evidence,
            "severity": control.severity,
            "level": control.level,
            "cis_id": control.cis_id,
            "remediation": control.remediation
        }

    @staticmethod
    def _bulk_insert_results(
        db: Session,
        session_id: int,
        findings: List[Dict],
        batch_size: int = None
    ):
        """
        Bulk insert audit results for better performance.

        Args:
            db: Database session
            session_id: Audit session ID
            findings: List of finding dictionaries
            batch_size: Records per batch (default: BATCH_SIZE)

        Inserts records in batches to reduce database round trips.
        """
        batch_size = batch_size or FortinetAuditService.BATCH_SIZE
        results = []

        logger.info(f"Bulk inserting {len(findings)} audit results (batch size: {batch_size})")

        for idx, finding in enumerate(findings, 1):
            result = AuditResult(
                session_id=session_id,
                check_number=finding["control_id"],
                check_title=finding["title"],
                severity=finding["severity"],
                level=finding["level"],
                status=CheckStatus.PASS if finding["passed"] else CheckStatus.FAIL,
                evidence_snippet=finding["evidence"][:1000] if finding["evidence"] else None,
                checked_at=datetime.now(timezone.utc)
            )
            results.append(result)

            # Commit batch
            if len(results) >= batch_size:
                db.bulk_save_objects(results)
                db.commit()
                logger.debug(f"Committed batch: {idx - len(results) + 1} to {idx}")
                results = []

        # Commit final batch
        if results:
            db.bulk_save_objects(results)
            db.commit()
            logger.debug(f"Committed final batch: {len(results)} records")

        logger.info(f"Successfully inserted {len(findings)} audit results")

    @staticmethod
    def execute_fortinet_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        vdom: Optional[str] = None,
        profile: str = "L1",
        job_name: Optional[str] = None
    ) -> AuditSession:
        """
        Execute FortiGate security audit.

        Workflow:
        1. Fetch asset from database
        2. Create audit session (status: running)
        3. Connect via SSH using FortiGateSSHClient
        4. If vdom specified: enter VDOM context
        5. Collect command outputs
        6. Exit VDOM context if needed
        7. Redact sensitive data
        8. Load controls from fortinet_rules
        9. Evaluate each control against output
        10. Calculate compliance percentage
        11. Update session (status: completed)
        12. Bulk insert results
        13. Return session

        Args:
            db: Database session
            asset_id: Target asset ID
            user_id: User performing audit
            ssh_username: SSH username (not stored)
            ssh_password: SSH password (not stored)
            vdom: Optional VDOM name (defaults to root/global context)
            profile: Audit profile (L1, L2, or FULL)

        Returns:
            AuditSession: Completed audit session with results

        Raises:
            ValueError: If asset not found or missing IP
            Exception: If SSH connection or audit fails
        """
        # 1. Fetch asset details
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        target_ip = asset.ip_address

        # 2. Create audit session (status: running)
        session = AuditSession(
            template_id=None,  # Direct audit (not template-based)
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.FORTINET,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc)
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. Get controls to audit
            controls = FortinetAuditService._get_cached_controls(profile, pack="FULL")
            if not controls:
                raise FortinetEvaluationError(f"No controls found for profile {profile}")

            # Get unique commands to execute
            commands = get_unique_commands(controls)
            logger.info(f"Executing {len(commands)} unique FortiGate commands")

            # 4. Establish SSH connection and collect outputs
            with FortinetAuditService._timed_operation("SSH connection and command collection"):
                with FortiGateSSHClient(
                    host=target_ip,
                    username=ssh_username,
                    password=ssh_password
                ) as ssh_client:
                    ssh_client.connect()

                    # Enter VDOM context if specified
                    if vdom:
                        logger.info(f"Entering VDOM context: {vdom}")
                        ssh_client.enter_vdom(vdom)

                    # Collect command outputs
                    raw_outputs = {}
                    for command in commands:
                        try:
                            output = ssh_client.send_command(command)
                            raw_outputs[command] = output
                        except Exception as e:
                            logger.warning(f"Command failed: {command}: {e}")
                            raw_outputs[command] = f"ERROR: {type(e).__name__}"

                    # Exit VDOM context if needed
                    if vdom:
                        logger.info(f"Exiting VDOM context: {vdom}")
                        ssh_client.exit_vdom()

            # 5. Redact sensitive data
            redacted_outputs = FortinetAuditService._redact_sensitive_data(raw_outputs)

            # 6. Evaluate controls
            findings = []
            with FortinetAuditService._timed_operation(f"Evaluate {len(controls)} controls"):
                for control in controls:
                    finding = FortinetAuditService._evaluate_control(control, redacted_outputs)
                    findings.append(finding)

            # 7. Calculate compliance metrics
            total = len(findings)
            passed = sum(1 for f in findings if f["passed"])
            failed = total - passed
            compliance_pct = round(100.0 * passed / total, 2) if total > 0 else 0.0

            # 8. Update session with results
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = total
            session.passed_checks = passed
            session.failed_checks = failed
            session.error_checks = 0
            session.compliance_pct = compliance_pct

            # Store redacted outputs as JSON string
            import json
            session.turbo_dump = json.dumps(redacted_outputs, indent=2)

            db.commit()

            # 9. Bulk insert check results
            with FortinetAuditService._timed_operation("Insert audit results"):
                FortinetAuditService._bulk_insert_results(db, session.id, findings)

            db.refresh(session)

            logger.info(
                f"Audit completed for asset {asset_id} ({target_ip}): "
                f"{compliance_pct}% compliance ({passed}/{total} passed)"
            )
            return session

        except Exception as e:
            # Mark session as failed
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)

            # Sanitize error message to avoid exposing credentials
            error_msg = str(e)
            if "password" in error_msg.lower() or "secret" in error_msg.lower():
                error_msg = f"{type(e).__name__}: Authentication or connection error"
            else:
                error_msg = f"{type(e).__name__}: {error_msg}"

            # Truncate very long error messages
            if len(error_msg) > 500:
                error_msg = error_msg[:500] + "..."

            session.connection_error = error_msg
            db.commit()
            db.refresh(session)

            logger.error(f"Audit failed for asset {asset_id} ({target_ip}): {type(e).__name__}")
            raise

    @staticmethod
    def discover_vdoms(
        db: Session,
        asset_id: int,
        ssh_username: str,
        ssh_password: str
    ) -> List[str]:
        """
        Discover VDOMs on a FortiGate device.

        Used by frontend to populate VDOM selector before audit.

        Args:
            db: Database session
            asset_id: Target asset ID
            ssh_username: SSH username (not stored)
            ssh_password: SSH password (not stored)

        Returns:
            List of VDOM names

        Raises:
            ValueError: If asset not found or missing IP
            Exception: If SSH connection fails
        """
        # Fetch asset details
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        target_ip = asset.ip_address

        # Connect and discover VDOMs
        try:
            with FortiGateSSHClient(
                host=target_ip,
                username=ssh_username,
                password=ssh_password
            ) as ssh_client:
                ssh_client.connect()
                vdoms = ssh_client.discover_vdoms()

            logger.info(f"Discovered {len(vdoms)} VDOMs on {target_ip}: {vdoms}")
            return vdoms

        except Exception as e:
            logger.error(f"VDOM discovery failed for {target_ip}: {type(e).__name__}")
            raise

    @staticmethod
    def get_audit_session(db: Session, session_id: int) -> Optional[AuditSession]:
        """Get audit session by ID."""
        return db.query(AuditSession).filter(AuditSession.id == session_id).first()

    @staticmethod
    def get_audit_results(db: Session, session_id: int) -> List[AuditResult]:
        """Get all results for an audit session."""
        return db.query(AuditResult).filter(
            AuditResult.session_id == session_id
        ).all()

    @staticmethod
    def get_all_sessions(
        db: Session,
        device_type: Optional[DeviceType] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[AuditSession]:
        """
        Get all audit sessions with pagination.

        Args:
            db: Database session
            device_type: Filter by device type (FORTINET)
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip

        Returns:
            List of audit sessions (most recent first)
        """
        query = db.query(AuditSession)

        if device_type:
            query = query.filter(AuditSession.device_type == device_type)

        return (
            query
            .order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_sessions_count(db: Session, device_type: DeviceType = DeviceType.FORTINET) -> int:
        """Get total count of FortiGate audit sessions."""
        return db.query(AuditSession).filter(AuditSession.device_type == device_type).count()

    @staticmethod
    def get_session_summary(db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        """
        Get formatted summary of an audit session.

        Returns:
            Dict with session details and compliance summary
        """
        session = FortinetAuditService.get_audit_session(db, session_id)
        if not session:
            return None

        # Get asset details
        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None

        # Calculate duration
        duration_seconds = None
        if session.started_at and session.completed_at:
            duration = session.completed_at - session.started_at
            duration_seconds = duration.total_seconds()

        return {
            "session_id": session.id,
            "job_name": session.job_name,
            "asset_id": session.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "target_ip": session.target_ip,
            "device_type": session.device_type.value,
            "status": session.status,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "duration_seconds": duration_seconds,
            "compliance": {
                "total_checks": session.total_checks or 0,
                "passed": session.passed_checks or 0,
                "failed": session.failed_checks or 0,
                "compliance_pct": session.compliance_pct or 0.0
            },
            "connection_error": session.connection_error
        }

    @staticmethod
    def delete_audit_session(db: Session, session_id: int) -> bool:
        """
        Delete an audit session and all its results.

        Args:
            db: Database session
            session_id: Audit session ID to delete

        Returns:
            True if deleted, False if not found
        """
        session = FortinetAuditService.get_audit_session(db, session_id)
        if not session:
            return False

        # Delete all results first (cascade should handle this, but being explicit)
        db.query(AuditResult).filter(
            AuditResult.session_id == session_id
        ).delete()

        # Delete session
        db.delete(session)
        db.commit()

        logger.info(f"Deleted audit session {session_id}")
        return True
