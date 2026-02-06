#!/usr/bin/env python3
"""
Create Mock FortiGate Audit Data

Creates test audit data for the FortiGate hardening functionality
without connecting to a real device.
"""

import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.models.audit import AuditSession, AuditResult, DeviceType, CheckStatus


# Mock check results with realistic data
MOCK_CHECKS = [
    # PASS checks (60%)
    {"check_number": "FG-BL-001", "check_title": "Admin HTTPS enabled", "severity": "High", "level": "L1", "status": CheckStatus.PASS, "evidence": "admin-https: enable"},
    {"check_number": "FG-BL-008", "check_title": "Admin SSH enabled for CLI access", "severity": "Low", "level": "L1", "status": CheckStatus.PASS, "evidence": "admin-ssh: enable"},
    {"check_number": "FG-BL-010", "check_title": "System status readable", "severity": "Low", "level": "L1", "status": CheckStatus.PASS, "evidence": "Version: v7.2.4"},
    {"check_number": "FG-BL-030", "check_title": "Password policy enabled", "severity": "High", "level": "L1", "status": CheckStatus.PASS, "evidence": "status: enable"},
    {"check_number": "FG-BL-031", "check_title": "Password min length >= 12", "severity": "High", "level": "L1", "status": CheckStatus.PASS, "evidence": "minimum-length: 12"},
    {"check_number": "FG-BL-032", "check_title": "Password must contain uppercase", "severity": "Medium", "level": "L1", "status": CheckStatus.PASS, "evidence": "must-contain-uppercase: enable"},
    {"check_number": "FG-BL-033", "check_title": "Password must contain lowercase", "severity": "Medium", "level": "L1", "status": CheckStatus.PASS, "evidence": "must-contain-lowercase: enable"},
    {"check_number": "FG-BL-034", "check_title": "Password must contain numbers", "severity": "Medium", "level": "L1", "status": CheckStatus.PASS, "evidence": "must-contain-number: enable"},
    {"check_number": "FG-BL-040", "check_title": "NTP enabled", "severity": "Medium", "level": "L1", "status": CheckStatus.PASS, "evidence": "status: enable"},
    {"check_number": "FG-BL-041", "check_title": "NTP server configured", "severity": "Medium", "level": "L1", "status": CheckStatus.PASS, "evidence": "server: pool.ntp.org"},
    {"check_number": "FG-BL-043", "check_title": "DNS primary configured", "severity": "Low", "level": "L1", "status": CheckStatus.PASS, "evidence": "primary: 8.8.8.8"},
    {"check_number": "FG-BL-044", "check_title": "DNS secondary configured", "severity": "Low", "level": "L1", "status": CheckStatus.PASS, "evidence": "secondary: 8.8.4.4"},
    {"check_number": "FG-BL-060", "check_title": "Remote syslog enabled", "severity": "High", "level": "L1", "status": CheckStatus.PASS, "evidence": "status: enable"},
    {"check_number": "FG-BL-061", "check_title": "Remote syslog server set", "severity": "High", "level": "L1", "status": CheckStatus.PASS, "evidence": "server: 10.0.0.50"},
    {"check_number": "FG-BL-063", "check_title": "Local disk logging enabled", "severity": "Medium", "level": "L2", "status": CheckStatus.PASS, "evidence": "local-disk-enable: enable"},
    {"check_number": "FG-BL-064", "check_title": "Log invalid traffic enabled", "severity": "Medium", "level": "L2", "status": CheckStatus.PASS, "evidence": "log-invalid-packet: enable"},
    {"check_number": "FG-BL-051", "check_title": "SNMPv3 user exists", "severity": "Medium", "level": "L1", "status": CheckStatus.PASS, "evidence": "edit snmpv3user"},
    {"check_number": "FG-BL-020", "check_title": "Admin trusthost configured", "severity": "High", "level": "L1", "status": CheckStatus.PASS, "evidence": "trusthost1: 10.0.0.0/24"},

    # FAIL checks (40%) - These will need hardening
    {"check_number": "FG-BL-002", "check_title": "Admin HTTP disabled", "severity": "Critical", "level": "L1", "status": CheckStatus.FAIL, "evidence": "admin-http: enable"},
    {"check_number": "FG-BL-003", "check_title": "Admin Telnet disabled", "severity": "Critical", "level": "L1", "status": CheckStatus.FAIL, "evidence": "admin-telnet: enable"},
    {"check_number": "FG-BL-004", "check_title": "Admin idle timeout <= 10 minutes", "severity": "Medium", "level": "L1", "status": CheckStatus.FAIL, "evidence": "admintimeout: 60"},
    {"check_number": "FG-BL-005", "check_title": "Admin GUI TLS 1.0/1.1 disabled", "severity": "High", "level": "L2", "status": CheckStatus.FAIL, "evidence": "admin-https-ssl-versions: tlsv1-0 tlsv1-1 tlsv1-2"},
    {"check_number": "FG-BL-006", "check_title": "Weak SSH ciphers disabled", "severity": "High", "level": "L2", "status": CheckStatus.FAIL, "evidence": "ssh-enc-algo: 3des-cbc aes128-ctr"},
    {"check_number": "FG-BL-021", "check_title": "Default 'admin' account disabled/renamed", "severity": "High", "level": "L2", "status": CheckStatus.FAIL, "evidence": 'edit "admin"'},
    {"check_number": "FG-BL-022", "check_title": "Multi-factor authentication configured", "severity": "High", "level": "L2", "status": CheckStatus.FAIL, "evidence": "two-factor: disable"},
    {"check_number": "FG-BL-035", "check_title": "Password must contain special chars", "severity": "Medium", "level": "L1", "status": CheckStatus.FAIL, "evidence": "must-contain-non-alphanumeric: disable"},
    {"check_number": "FG-BL-036", "check_title": "Password min changed characters >= 4", "severity": "Medium", "level": "L2", "status": CheckStatus.FAIL, "evidence": "min-changed-characters: 0"},
    {"check_number": "FG-BL-050", "check_title": "SNMPv2 community disabled", "severity": "High", "level": "L1", "status": CheckStatus.FAIL, "evidence": 'edit 1\n name "public"'},
    {"check_number": "FG-BL-080", "check_title": "No Any/Any/ALL ACCEPT policy", "severity": "Critical", "level": "L1", "status": CheckStatus.FAIL, "evidence": 'srcaddr "all" dstaddr "all" action accept'},
    {"check_number": "FG-BL-082", "check_title": "Policy logging enabled", "severity": "Medium", "level": "L1", "status": CheckStatus.FAIL, "evidence": "logtraffic: disable"},
]


def create_mock_audit_session(db):
    """Create a mock FortiGate audit session with results."""

    # Calculate stats
    total_checks = len(MOCK_CHECKS)
    passed_checks = sum(1 for c in MOCK_CHECKS if c["status"] == CheckStatus.PASS)
    failed_checks = sum(1 for c in MOCK_CHECKS if c["status"] == CheckStatus.FAIL)
    compliance_pct = (passed_checks / total_checks) * 100 if total_checks > 0 else 0

    # Create session
    session = AuditSession(
        user_id=1,  # Assuming admin user
        asset_id=58,  # Host-192.168.1.1
        target_ip="192.168.1.1",
        device_type=DeviceType.FORTINET,
        started_at=datetime.utcnow() - timedelta(minutes=5),
        completed_at=datetime.utcnow(),
        status="completed",
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        error_checks=0,
        compliance_pct=round(compliance_pct, 2),
        weighted_compliance_pct=round(compliance_pct, 2),
    )

    db.add(session)
    db.flush()  # Get session.id

    print(f"Created audit session ID: {session.id}")
    print(f"  Device type: {session.device_type.value}")
    print(f"  Target IP: {session.target_ip}")
    print(f"  Total checks: {total_checks}")
    print(f"  Passed: {passed_checks}")
    print(f"  Failed: {failed_checks}")
    print(f"  Compliance: {compliance_pct:.1f}%")

    # Create results
    for check in MOCK_CHECKS:
        result = AuditResult(
            session_id=session.id,
            check_number=check["check_number"],
            check_title=check["check_title"],
            severity=check["severity"],
            level=check["level"],
            status=check["status"],
            evidence_snippet=check["evidence"],
            checked_at=datetime.utcnow(),
        )
        db.add(result)

    db.commit()
    print(f"\nCreated {len(MOCK_CHECKS)} audit results")

    return session


def main():
    """Main entry point."""
    print("=" * 60)
    print("Creating Mock FortiGate Audit Data")
    print("=" * 60)

    db = SessionLocal()
    try:
        # Check for existing FortiGate sessions
        existing = db.query(AuditSession).filter(
            AuditSession.device_type == DeviceType.FORTINET
        ).count()

        if existing > 0:
            print(f"\nNote: {existing} existing FortiGate session(s) found")

        # Create new mock session
        session = create_mock_audit_session(db)

        print("\n" + "=" * 60)
        print("Mock data created successfully!")
        print("=" * 60)
        print(f"\nSession ID: {session.id}")
        print(f"Use this session for testing hardening functionality")

    except Exception as e:
        print(f"\nError: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
