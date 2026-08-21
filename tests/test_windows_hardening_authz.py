"""
Windows hardening/audit authorization surface.

Hardening reports success by flipping an audit session's AuditResult rows to
PASS, so the session id in the request body is a write target — it has to be
authorized, not just accepted. The listing endpoints are the other half: the
detail endpoint refused other users' sessions while the list handed them over.
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.dependencies import assert_session_access, owner_scope
from app.models.audit import DeviceType
from app.modules.windows.hardening.router import _assert_windows_session


def _user(uid, role="user"):
    return SimpleNamespace(id=uid, role=SimpleNamespace(value=role))


def _session(uid, device_type=DeviceType.WINDOWS):
    return SimpleNamespace(id=7, user_id=uid, device_type=device_type)


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *a, **k):
        return self

    def first(self):
        return self._result


class _FakeDb:
    def __init__(self, result):
        self._result = result

    def query(self, *a, **k):
        return _FakeQuery(self._result)


# ================================================================== #
#  List scoping                                                      #
# ================================================================== #

class TestOwnerScope:

    def test_admin_sees_everything(self):
        assert owner_scope(_user(1, "admin")) is None

    def test_everyone_else_is_scoped_to_themselves(self):
        assert owner_scope(_user(42)) == 42

    def test_matches_the_detail_endpoint_rule(self):
        """owner_scope and assert_session_access must agree on who is privileged."""
        admin, owner, other = _user(1, "admin"), _user(2), _user(3)
        session = _session(uid=2)

        assert assert_session_access(session, admin) is session
        assert assert_session_access(session, owner) is session
        with pytest.raises(HTTPException):
            assert_session_access(session, other)

        assert owner_scope(admin) is None
        assert owner_scope(owner) == 2
        assert owner_scope(other) == 3


# ================================================================== #
#  Hardening session guard                                           #
# ================================================================== #

class TestWindowsSessionGuard:

    def test_no_session_id_is_allowed(self):
        """execute-single without a session only touches the host, not the DB."""
        _assert_windows_session(_FakeDb(None), None, _user(1))

    def test_owner_may_harden_their_own_session(self):
        db = _FakeDb(_session(uid=5))
        _assert_windows_session(db, 7, _user(5))

    def test_admin_may_harden_any_session(self):
        db = _FakeDb(_session(uid=5))
        _assert_windows_session(db, 7, _user(1, "admin"))

    def test_another_users_session_is_refused(self):
        db = _FakeDb(_session(uid=5))
        with pytest.raises(HTTPException) as exc:
            _assert_windows_session(db, 7, _user(6))
        assert exc.value.status_code == 404

    def test_missing_session_is_refused(self):
        with pytest.raises(HTTPException) as exc:
            _assert_windows_session(_FakeDb(None), 7, _user(5))
        assert exc.value.status_code == 404

    def test_a_foreign_device_family_is_refused(self):
        """Check numbers mean different things per family."""
        db = _FakeDb(_session(uid=5, device_type=DeviceType.LINUX))
        with pytest.raises(HTTPException) as exc:
            _assert_windows_session(db, 7, _user(5))
        assert exc.value.status_code == 400
        assert "not a Windows audit session" in exc.value.detail


# ================================================================== #
#  TLS validation is configurable                                    #
# ================================================================== #

class TestVerifySslPlumbing:

    def test_batch_executor_forwards_the_flag(self):
        from app.modules.windows.hardening.winrm_executor import (
            WindowsHardeningBatchExecutor,
        )

        batch = WindowsHardeningBatchExecutor(
            ip="10.0.0.1", username="u", password="p", verify_ssl=True
        )
        assert batch._make_executor().verify_ssl is True

    @pytest.mark.parametrize("verify_ssl,expected", [(True, "validate"), (False, "ignore")])
    def test_flag_selects_the_pywinrm_mode(self, verify_ssl, expected, monkeypatch):
        """connect() maps verify_ssl onto pywinrm's server_cert_validation."""
        from app.modules.windows.hardening import winrm_executor as we

        captured = {}

        class _FakeResult:
            status_code = 0
            std_out = b"HOST"
            std_err = b""

        class _FakeSession:
            def __init__(self, *a, **kw):
                captured.update(kw)

            def run_ps(self, _):
                return _FakeResult()

        monkeypatch.setitem(
            __import__("sys").modules, "winrm", SimpleNamespace(Session=_FakeSession)
        )
        ex = we.WindowsWinRMExecutor(
            ip="10.0.0.1", username="u", password="p", verify_ssl=verify_ssl
        )
        ex.connect()
        assert captured["server_cert_validation"] == expected

    def test_request_models_accept_an_override(self):
        from app.modules.windows.audit.router import WindowsAuditRequest
        from app.modules.windows.hardening.router import SingleFixRequest

        audit = WindowsAuditRequest(
            asset_id=1, windows_username="u", windows_password="p", verify_ssl=True
        )
        assert audit.verify_ssl is True

        # Omitted means "use the server default", not "off".
        fix = SingleFixRequest(
            asset_id=1, windows_username="u", windows_password="p", check_id="X"
        )
        assert fix.verify_ssl is None


# ================================================================== #
#  Blocking work must not run on the event loop                      #
# ================================================================== #

def test_hardening_handlers_are_sync():
    """WinRM calls block; an async handler would stall the whole event loop."""
    import inspect

    from app.modules.windows.hardening.router import router

    coroutines = [
        r.name for r in router.routes if inspect.iscoroutinefunction(r.endpoint)
    ]
    assert coroutines == []


# ================================================================== #
#  Doomed-transaction recovery                                       #
# ================================================================== #

class TestEnsureSessionUsable:
    """The audit failure handler writes status='failed' right after whatever
    blew up. If that was a DB error the transaction is doomed, and the write
    used to raise PendingRollbackError over the top of the real error."""

    class _Db:
        def __init__(self, is_active):
            self.is_active = is_active
            self.rollbacks = 0

        def rollback(self):
            self.rollbacks += 1

    def test_a_doomed_transaction_is_rolled_back(self):
        from app.core.database import ensure_session_usable

        db = self._Db(is_active=False)
        ensure_session_usable(db)
        assert db.rollbacks == 1

    def test_a_healthy_transaction_is_left_alone(self):
        from app.core.database import ensure_session_usable

        db = self._Db(is_active=True)
        ensure_session_usable(db)
        assert db.rollbacks == 0

    def test_it_never_raises(self):
        """It runs inside an exception handler; it must not add a second error."""
        from app.core.database import ensure_session_usable

        class _Broken:
            is_active = False

            def rollback(self):
                raise RuntimeError("connection already gone")

        ensure_session_usable(_Broken())


# ================================================================== #
#  Post-hardening session stats (M1)                                 #
# ================================================================== #

class TestRecomputeSessionStats:
    """compliance_pct and weighted_compliance_pct have to move together —
    updating only the simple one left a session reporting 95% beside 41%."""

    class _Row:
        def __init__(self, status, severity, level="L1"):
            self.status = status
            self.severity = severity
            self.level = level

    class _Db:
        def __init__(self, session, rows):
            self._session = session
            self._rows = rows

        def query(self, model):
            from app.models import AuditSession as _S
            outer = self

            class _Q:
                def filter(self, *a, **k):
                    return self

                def first(self):
                    return outer._session

                def all(self):
                    return outer._rows

            return _Q()

    def _run(self, rows):
        from app.modules.windows.hardening.service import _recompute_session_stats

        session = SimpleNamespace(
            id=1, passed_checks=0, failed_checks=0, error_checks=0,
            compliance_pct=None, weighted_compliance_pct=41.0,
        )
        _recompute_session_stats(self._Db(session, rows), 1)
        return session

    def test_both_percentages_are_refreshed(self):
        from app.models.audit import CheckStatus

        # one high (weight 3) passing, one low (weight 1) failing
        session = self._run([
            self._Row(CheckStatus.PASS, "high"),
            self._Row(CheckStatus.FAIL, "low"),
        ])
        assert session.compliance_pct == 50.0
        assert session.weighted_compliance_pct == 75.0   # 3 of 4

    def test_all_passing_reaches_a_hundred(self):
        from app.models.audit import CheckStatus

        session = self._run([
            self._Row(CheckStatus.PASS, "high"),
            self._Row(CheckStatus.PASS, "low"),
        ])
        assert session.compliance_pct == 100.0
        assert session.weighted_compliance_pct == 100.0

    def test_unscored_rows_are_excluded_from_both(self):
        from app.models.audit import CheckStatus

        session = self._run([
            self._Row(CheckStatus.PASS, "high"),
            self._Row(CheckStatus.NOT_APPLICABLE, "high"),   # manual
            self._Row(CheckStatus.ERROR, "high"),            # not evaluated
        ])
        assert session.passed_checks == 1
        assert session.error_checks == 1
        assert session.compliance_pct == 100.0
        assert session.weighted_compliance_pct == 100.0

    def test_weights_match_the_audit_engine(self):
        from app.modules.windows.audit.rules import SEVERITY_WEIGHTS

        assert SEVERITY_WEIGHTS == {"high": 3, "medium": 2, "low": 1, "info": 0}


# ================================================================== #
#  Parameter validation (M4)                                         #
# ================================================================== #

class TestNumericParameterBounds:
    """min_value/max_value were advertised to the UI but only enforced by the
    browser, so an out-of-range value reached `net accounts`."""

    def _validate(self, **params):
        from app.modules.windows.hardening.winrm_executor import (
            _validate_windows_parameters,
        )
        return _validate_windows_parameters(params)

    def test_in_range_is_accepted(self):
        assert self._validate(MAX_PASSWORD_AGE="365") is None
        assert self._validate(LOCKOUT_THRESHOLD="5") is None

    def test_zero_max_password_age_is_rejected(self):
        """`net accounts /maxpwage:0` means 'never expires' — the opposite of
        what the control asks for, and the verify step would then say FAIL."""
        error = self._validate(MAX_PASSWORD_AGE="0")
        assert error is not None and "below the minimum" in error

    @pytest.mark.parametrize("name,value,word", [
        ("MAX_PASSWORD_AGE", "999", "above the maximum"),
        ("MAX_PASSWORD_AGE", "-5", "below the minimum"),
        ("LOCKOUT_THRESHOLD", "50", "above the maximum"),
        ("LOCKOUT_DURATION", "5", "below the minimum"),
        ("LOCKOUT_WINDOW", "1", "below the minimum"),
    ])
    def test_out_of_range_is_rejected(self, name, value, word):
        error = self._validate(**{name: value})
        assert error is not None and word in error

    def test_non_numeric_is_still_rejected(self):
        assert "not a number" in self._validate(MAX_PASSWORD_AGE="abc")

    def test_every_shipped_default_passes_its_own_bounds(self):
        from app.modules.windows.hardening.command_templates import (
            get_all_supported_checks,
        )
        from app.modules.windows.hardening.parameter_metadata import (
            get_windows_check_defaults,
        )

        for check_id in sorted(get_all_supported_checks()):
            defaults = get_windows_check_defaults(check_id)
            if defaults:
                assert self._validate(**defaults) is None, check_id

    def test_text_parameters_still_reject_quoting(self):
        assert self._validate(NEW_ADMIN_NAME="ok_name") is None
        assert self._validate(NEW_ADMIN_NAME="a'; rm") is not None


# ================================================================== #
#  Statement execution (M11)                                         #
# ================================================================== #

class TestExecuteFailsLoudly:

    def _executor(self, status_code, stdout=b"", stderr=b""):
        from app.modules.windows.hardening.winrm_executor import WindowsWinRMExecutor

        class _Result:
            pass

        r = _Result()
        r.status_code, r.std_out, r.std_err = status_code, stdout, stderr

        ex = WindowsWinRMExecutor(ip="10.0.0.1", username="u", password="p")
        ex._session = SimpleNamespace(run_ps=lambda _: r)
        return ex

    def test_a_silent_failure_is_not_success(self):
        """status_code != 0 with no stdout and no stderr used to return "(ok)"."""
        ex = self._executor(1)
        with pytest.raises(RuntimeError, match="no output"):
            ex._execute("Set-ItemProperty ...")

    def test_stderr_failures_still_raise(self):
        ex = self._executor(1, stderr=b"Access is denied")
        with pytest.raises(RuntimeError, match="Access is denied"):
            ex._execute("Set-ItemProperty ...")

    def test_output_is_kept_even_on_a_non_zero_exit(self):
        """Verification reads the PASS/FAIL the script printed."""
        ex = self._executor(1, stdout=b"PASS", stderr=b"a warning")
        assert ex._execute("... 'PASS' ...") == "PASS"

    def test_success_returns_output(self):
        assert self._executor(0, stdout=b"PASS")._execute("x") == "PASS"
        assert self._executor(0)._execute("x") == "(ok)"


# ================================================================== #
#  Preview / result response shape (M8, M9)                          #
# ================================================================== #

class TestResponseShapes:

    def test_preview_returns_parameter_defaults(self):
        """FixSingleModal pre-fills optional inputs from this; without it the
        UI rendered "MAX_PASSWORD_AGE = undefined"."""
        from app.modules.windows.hardening.router import (
            WindowsPreviewRequest,
            preview_windows_hardening,
        )

        out = preview_windows_hardening(
            WindowsPreviewRequest(check_id="WIN-2025-1.1.2"), current_user=_user(1)
        )
        assert out["parameter_defaults"] == {"MAX_PASSWORD_AGE": "365"}
        assert "MAX_PASSWORD_AGE" in out["optional_parameters"]

    def test_defaults_cover_every_optional_parameter(self):
        from app.modules.windows.hardening.router import (
            WindowsPreviewRequest,
            preview_windows_hardening,
        )
        from app.modules.windows.hardening.command_templates import (
            WINDOWS_HARDENING_TEMPLATES,
        )

        for check_id, template in WINDOWS_HARDENING_TEMPLATES.items():
            if template.manual_only:
                continue
            out = preview_windows_hardening(
                WindowsPreviewRequest(check_id=check_id), current_user=_user(1)
            )
            for param in out["optional_parameters"]:
                assert param in out["parameter_defaults"], f"{check_id}/{param}"

    def test_result_model_tolerates_nullable_columns(self):
        """Every one of these is nullable in audit_results; requiring them
        turned a missing value into a 500 on a read endpoint."""
        from app.modules.windows.audit.router import WindowsAuditResultResponse

        row = WindowsAuditResultResponse(id=1, status="pass")
        assert row.check_number is None
        assert row.checked_at is None
        assert row.severity is None
