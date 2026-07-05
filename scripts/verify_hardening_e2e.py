#!/usr/bin/env python3
"""
End-to-end verification of the PRODUCTION FortiGate hardening flow
(preview_hardening + execute_hardening) against a genuinely NON-COMPLIANT
device, confirming the verify + DB-write layer.

Flow:
  1. Reuse an existing audit session for the device (valid user_id/asset_id FKs),
     or create one from the first user + asset.
  2. Make FG-BL-090 genuinely NON-COMPLIANT: read strong-crypto live; if enabled,
     `set strong-crypto disable` via the real SSH client, and confirm it read back
     disabled.
  3. Seed an AuditResult(status=FAIL) reflecting that verified-live state.
  4. FortiGateHardeningService.preview_hardening(...)  -> pending HardeningAction.
  5. FortiGateHardeningService.execute_hardening(...)  -> connect, backup, apply,
     VERIFY, and write results to the DB (the layer under test).
  6. Re-read the rows from a fresh session and assert the DB writes.
  7. Clean up seeded rows. A finally block ALWAYS re-enables strong-crypto so the
     device cannot be left weakened even if the test errors midway.

Requires a DB migrated to head (needs the audit_results.vdom column).

Usage:  FG_PASS=xxx python3 scripts/verify_hardening_e2e.py <host> <user>
"""
import os
import re
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal  # noqa: E402
from app.models import User, Asset  # noqa: E402
from app.models.audit import AuditSession, AuditResult, CheckStatus  # noqa: E402
from app.models.hardening import HardeningAction  # noqa: E402
from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient, SCOPE_GLOBAL  # noqa: E402
from app.modules.fortinet.hardening.service import FortiGateHardeningService  # noqa: E402

CHECK = "FG-BL-090"
SEP = "=" * 72


def read_strong_crypto(client):
    out = client.collect(["get system global"], scope=SCOPE_GLOBAL, use_cache=False)["get system global"]
    m = re.search(r"strong-crypto\s*:\s*(\w+)", out, re.IGNORECASE)
    return (m.group(1).lower() if m else None)


def set_strong_crypto(client, value):
    return client.run_config(
        ["config system global", f"set strong-crypto {value}", "end"],
        scope=SCOPE_GLOBAL,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("user")
    ap.add_argument("--port", type=int, default=22)
    args = ap.parse_args()
    password = os.environ["FG_PASS"]

    control = FortiGateHardeningService._get_control_by_id(CHECK)
    db = SessionLocal()

    seeded_result_id = None
    action_id = None
    created_session_id = None
    device_client = None

    try:
        # --- 1. reuse an existing session (valid user_id + asset_id) ---------
        session = (db.query(AuditSession)
                   .filter(AuditSession.target_ip == args.host,
                           AuditSession.asset_id.isnot(None))
                   .order_by(AuditSession.id.desc()).first())
        if session:
            print(f"[setup] reusing audit session id={session.id} "
                  f"(user_id={session.user_id}, asset_id={session.asset_id})")
        else:
            user = db.query(User).order_by(User.id).first()
            asset = db.query(Asset).order_by(Asset.id).first()
            if not user or not asset:
                print("[abort] no existing session for host and no user/asset to create one")
                return 2
            session = AuditSession(user_id=user.id, asset_id=asset.id,
                                   target_ip=args.host, device_type="fortinet",
                                   status="completed")
            db.add(session); db.commit(); db.refresh(session)
            created_session_id = session.id
            print(f"[setup] created audit session id={session.id}")
        user_id = session.user_id

        # --- 2. make the device genuinely NON-COMPLIANT ---------------------
        device_client = FortiGateSSHClient(args.host, args.user, password, port=args.port)
        device_client.connect()
        before = read_strong_crypto(device_client)
        print(f"[device] strong-crypto currently: {before!r}")
        if before != "disable":
            print("[device] disabling strong-crypto to create a real NON-COMPLIANT finding ...")
            set_strong_crypto(device_client, "disable")
            after = read_strong_crypto(device_client)
            print(f"[device] strong-crypto now: {after!r}")
            if after != "disable":
                print("[abort] could not put device into non-compliant state")
                return 2

        # --- 3. seed a NON-COMPLIANT (FAIL) audit result --------------------
        seeded = AuditResult(
            session_id=session.id, check_number=CHECK,
            check_title=control.title, severity=getattr(control, "severity", None),
            level=getattr(control, "level", None), vdom=None,
            status=CheckStatus.FAIL,
            evidence_snippet="strong-crypto : disable (seeded for e2e verification)",
        )
        db.add(seeded); db.commit(); db.refresh(seeded)
        seeded_result_id = seeded.id
        print(f"[setup] seeded NON-COMPLIANT AuditResult id={seeded.id} status={seeded.status}")

        # --- 4. PRODUCTION preview ------------------------------------------
        print(f"\n{SEP}\n[preview_hardening]\n{SEP}")
        preview = FortiGateHardeningService.preview_hardening(db, seeded.id, user_id)
        action_id = preview["action_id"]
        print(f"  action_id={action_id}  commands={preview['commands']}  scope={preview['vdom_context']}")

        # --- 5. PRODUCTION execute (connect + backup + apply + VERIFY + DB) --
        print(f"\n{SEP}\n[execute_hardening]\n{SEP}")
        exec_result = FortiGateHardeningService.execute_hardening(
            db=db, action_id=action_id, user_id=user_id,
            ssh_username=args.user, ssh_password=password,
            parameters={}, skip_backup=False, ssh_port=args.port,
        )
        print(f"  returned: status={exec_result['status']} "
              f"verification_passed={exec_result['verification_passed']} "
              f"backup_created={exec_result['backup_created']}")

        # --- 6. assert the DB writes from a FRESH session -------------------
        print(f"\n{SEP}\n[DB verification — re-read from a fresh session]\n{SEP}")
        db2 = SessionLocal()
        try:
            a = db2.query(HardeningAction).filter(HardeningAction.id == action_id).first()
            r = db2.query(AuditResult).filter(AuditResult.id == seeded_result_id).first()
            checks = {
                "action.status == success": a.status == "success",
                "action.verification_passed is True": a.verification_passed is True,
                "action.verification_evidence present": bool(a.verification_evidence),
                "action.output present": bool(a.output),
                "action.backup_config present": bool(a.backup_config),
                "action.completed_at set": a.completed_at is not None,
                "audit_result.status == PASS": r.status == CheckStatus.PASS,
                "audit_result.evidence updated": bool(r.evidence_snippet) and "seeded" not in (r.evidence_snippet or ""),
            }
            for k, v in checks.items():
                print(f"  [{'PASS' if v else 'FAIL'}] {k}")
            print(f"\n  action.error_message: {a.error_message!r}")
            print(f"  verification_evidence (first 240 chars):\n    {(a.verification_evidence or '')[:240].replace(chr(10), ' ')}")
            all_ok = all(checks.values())
        finally:
            db2.close()

        print(f"\n{SEP}")
        print("RESULT:", "END-TO-END PASS" if all_ok else "SOME CHECKS FAILED")
        print(SEP)
        return 0 if all_ok else 1

    finally:
        # --- 7. teardown: re-harden device, then remove seeded DB rows ------
        try:
            if device_client is not None:
                cur = read_strong_crypto(device_client)
                if cur != "enable":
                    print(f"\n[teardown] restoring strong-crypto=enable (was {cur!r}) ...")
                    set_strong_crypto(device_client, "enable")
                    print(f"[teardown] strong-crypto now: {read_strong_crypto(device_client)!r}")
                else:
                    print("\n[teardown] device already strong-crypto=enable (hardened)")
                device_client.disconnect()
        except Exception as e:  # noqa: BLE001
            print(f"[teardown] WARNING could not confirm/restore strong-crypto: {e}")

        try:
            if action_id is not None:
                db.query(HardeningAction).filter(HardeningAction.id == action_id).delete()
            if seeded_result_id is not None:
                db.query(AuditResult).filter(AuditResult.id == seeded_result_id).delete()
            if created_session_id is not None:
                db.query(AuditSession).filter(AuditSession.id == created_session_id).delete()
            db.commit()
            print(f"[teardown] removed seeded rows (action={action_id}, result={seeded_result_id}, "
                  f"session={created_session_id})")
        except Exception as e:  # noqa: BLE001
            db.rollback()
            print(f"[teardown] WARNING DB cleanup failed: {e}")
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
