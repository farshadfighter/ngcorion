"""
Security regression tests for checklist item 1.3: SSH host-key verification.

Before this change every SSH client accepted whatever host key a device
presented (paramiko ``AutoAddPolicy`` explicitly, netmiko's identical default
implicitly), so anyone on the network path could transparently intercept an
audit/hardening session, capture the device credentials it sends and rewrite the
remediation commands in flight.

These tests cover, for every SSH path in the product:

1. an unknown host key is not silently trusted,
2. a correct, previously pinned host key still connects normally,
3. a changed host key is rejected,
4. normal authentication/command behaviour is unaffected once verification
   passes,
5. the audit and hardening paths enforce the same policy against the same store
   (and the hardening "preview"/dry-run path opens no SSH connection at all).

No real network connection is made anywhere in this file.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

pytest.importorskip("paramiko")
pytest.importorskip("netmiko")

import paramiko  # noqa: E402

from app.core import ssh_host_keys as hk  # noqa: E402
from app.core.ssh_exceptions import (  # noqa: E402
    SSHAuthenticationError,
    SSHConnectionError,
    SSHHostKeyError,
)
from app.core.ssh_host_keys import (  # noqa: E402
    HostKeyPolicyMode,
    KnownHostsStore,
    SSHHostKeyMismatchError,
    SSHHostKeyUnknownError,
    VerificationResult,
    VerifyingHostKeyPolicy,
    classify_netmiko_auth_failure,
    ensure_host_key_trusted,
    evaluate_host_key,
    host_key_entry_name,
    key_fingerprint,
    netmiko_host_key_kwargs,
)


# --------------------------------------------------------------------------- #
#  Fixtures                                                                    #
# --------------------------------------------------------------------------- #

@pytest.fixture
def host_key():
    """A stable "device" host key."""
    return paramiko.ECDSAKey.generate()


@pytest.fixture
def other_key():
    """A different key — stands in for an interceptor or a reinstalled device."""
    return paramiko.ECDSAKey.generate()


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    """Point the whole module at a throwaway known-hosts file."""
    path = tmp_path / "known_hosts"
    monkeypatch.setattr(hk.settings, "SSH_KNOWN_HOSTS_FILE", str(path))
    monkeypatch.setattr(hk.settings, "SSH_HOST_KEY_POLICY", "tofu")
    hk.reset_store_cache()
    yield path
    hk.reset_store_cache()


@pytest.fixture
def strict_mode(store_path, monkeypatch):
    monkeypatch.setattr(hk.settings, "SSH_HOST_KEY_POLICY", "strict")
    hk.reset_store_cache()
    return store_path


# --------------------------------------------------------------------------- #
#  Store primitives                                                            #
# --------------------------------------------------------------------------- #

class TestEntryNaming:
    def test_default_port_uses_bare_host(self):
        # Must match paramiko's own convention or netmiko's lookup misses ours.
        assert host_key_entry_name("10.0.0.1", 22) == "10.0.0.1"

    def test_non_default_port_is_bracketed(self):
        assert host_key_entry_name("10.0.0.1", 2222) == "[10.0.0.1]:2222"

    def test_matches_paramiko_convention(self, tmp_path, host_key):
        """A key we write must be found by paramiko's own known_hosts lookup —
        this is what makes netmiko's RejectPolicy path work."""
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 2222, host_key)
        keys = paramiko.HostKeys(str(store.path))
        assert keys.lookup("[10.0.0.1]:2222") is not None


class TestStore:
    def test_unknown_host(self, tmp_path, host_key):
        store = KnownHostsStore(tmp_path / "kh")
        assert store.verify("10.0.0.1", 22, host_key) is VerificationResult.UNKNOWN

    def test_pinned_key_matches(self, tmp_path, host_key):
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        assert store.verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH

    def test_changed_key_mismatches(self, tmp_path, host_key, other_key):
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        assert store.verify("10.0.0.1", 22, other_key) is VerificationResult.MISMATCH

    def test_same_host_different_port_is_separate(self, tmp_path, host_key):
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        assert store.verify("10.0.0.1", 2222, host_key) is VerificationResult.UNKNOWN

    def test_unpinned_key_type_is_a_mismatch_not_a_match(self, tmp_path, host_key):
        """An attacker must not be able to downgrade to a key type we never
        pinned for a host we already know."""
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        rsa = paramiko.RSAKey.generate(2048)
        assert rsa.get_name() != host_key.get_name()
        assert store.verify("10.0.0.1", 22, rsa) is VerificationResult.MISMATCH

    def test_store_file_is_private(self, tmp_path, host_key):
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        assert (store.path.stat().st_mode & 0o777) == 0o600

    def test_add_preserves_other_hosts(self, tmp_path, host_key, other_key):
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        store.add("10.0.0.2", 22, other_key)
        assert store.verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH
        assert store.verify("10.0.0.2", 22, other_key) is VerificationResult.MATCH

    def test_forget_removes_only_that_host(self, tmp_path, host_key, other_key):
        store = KnownHostsStore(tmp_path / "kh")
        store.add("10.0.0.1", 22, host_key)
        store.add("10.0.0.2", 22, other_key)
        assert store.forget("10.0.0.1", 22) is True
        assert store.verify("10.0.0.1", 22, host_key) is VerificationResult.UNKNOWN
        assert store.verify("10.0.0.2", 22, other_key) is VerificationResult.MATCH

    def test_forget_unknown_host_is_a_noop(self, tmp_path):
        store = KnownHostsStore(tmp_path / "kh")
        assert store.forget("10.0.0.9", 22) is False

    def test_corrupt_store_does_not_disable_verification(self, tmp_path, host_key):
        """A damaged file must fail closed (treated as empty), never 'allow'."""
        path = tmp_path / "kh"
        path.write_text("this is not a known_hosts file\n\x00\x01garbage\n")
        store = KnownHostsStore(path)
        assert store.verify("10.0.0.1", 22, host_key) is VerificationResult.UNKNOWN


# --------------------------------------------------------------------------- #
#  Policy decisions                                                            #
# --------------------------------------------------------------------------- #

class TestEvaluateHostKey:
    def test_tofu_pins_unknown_host_and_allows_it(self, store_path, host_key):
        evaluate_host_key("10.0.0.1", 22, host_key)  # must not raise
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH

    def test_pinned_key_is_accepted_on_later_connections(self, store_path, host_key):
        evaluate_host_key("10.0.0.1", 22, host_key)
        for _ in range(3):
            evaluate_host_key("10.0.0.1", 22, host_key)  # still no raise

    def test_changed_key_is_rejected(self, store_path, host_key, other_key):
        evaluate_host_key("10.0.0.1", 22, host_key)
        with pytest.raises(SSHHostKeyMismatchError) as exc:
            evaluate_host_key("10.0.0.1", 22, other_key)
        # The operator gets both fingerprints to compare out of band.
        assert key_fingerprint(other_key) in str(exc.value)

    def test_mismatch_does_not_overwrite_the_pinned_key(self, store_path, host_key, other_key):
        """A rejected key must never end up trusted as a side effect."""
        evaluate_host_key("10.0.0.1", 22, host_key)
        with pytest.raises(SSHHostKeyMismatchError):
            evaluate_host_key("10.0.0.1", 22, other_key)
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH
        assert hk.get_store().verify("10.0.0.1", 22, other_key) is VerificationResult.MISMATCH

    def test_strict_mode_refuses_unknown_host(self, strict_mode, host_key):
        with pytest.raises(SSHHostKeyUnknownError):
            evaluate_host_key("10.0.0.1", 22, host_key)
        # And refusing must not pin it.
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.UNKNOWN

    def test_strict_mode_accepts_a_provisioned_host(self, strict_mode, host_key):
        hk.get_store().add("10.0.0.1", 22, host_key)
        evaluate_host_key("10.0.0.1", 22, host_key)  # must not raise

    def test_strict_mode_still_rejects_a_changed_key(self, strict_mode, host_key, other_key):
        hk.get_store().add("10.0.0.1", 22, host_key)
        with pytest.raises(SSHHostKeyMismatchError):
            evaluate_host_key("10.0.0.1", 22, other_key)

    def test_invalid_policy_value_fails_closed_to_strict(self, store_path, monkeypatch, host_key):
        monkeypatch.setattr(hk.settings, "SSH_HOST_KEY_POLICY", "off")
        assert hk.policy_mode() is HostKeyPolicyMode.STRICT
        with pytest.raises(SSHHostKeyUnknownError):
            evaluate_host_key("10.0.0.1", 22, host_key)

    def test_host_key_errors_are_ssh_host_key_errors(self, store_path, host_key, other_key):
        """Routers already catch SSHHostKeyError; both new errors must inherit
        from it so existing error handling keeps working."""
        assert issubclass(SSHHostKeyUnknownError, SSHHostKeyError)
        assert issubclass(SSHHostKeyMismatchError, SSHHostKeyError)


# --------------------------------------------------------------------------- #
#  paramiko path (Linux / Apache / MongoDB hardening)                          #
# --------------------------------------------------------------------------- #

class _FakeParamikoClient:
    """
    Stands in for paramiko.SSHClient, reproducing the part of connect() that
    matters here: with no host keys loaded, paramiko hands *every* server key to
    the missing-host-key policy.
    """

    def __init__(self, server_key, auth_error=None):
        self.server_key = server_key
        self.auth_error = auth_error
        self.policy = None
        self.connected_kwargs = None
        self.closed = False

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connected_kwargs = kwargs
        # paramiko consults the policy before authenticating, and passes the
        # *already formatted* server_hostkey_name — "[host]:port" whenever the
        # port is not 22. Reproduced exactly, because getting this wrong silently
        # re-pins on every connection instead of detecting a changed key.
        host, port = kwargs["hostname"], kwargs.get("port", 22)
        server_hostkey_name = host if port == 22 else f"[{host}]:{port}"
        self.policy.missing_host_key(self, server_hostkey_name, self.server_key)
        if self.auth_error:
            raise self.auth_error

    def get_transport(self):
        class _T:
            def is_active(self_inner):
                return True
        return _T()

    def close(self):
        self.closed = True


@pytest.fixture
def runner_module(monkeypatch):
    from app.modules.linux.common import fast_ssh_runner
    return fast_ssh_runner


class TestHardeningRunnerHostKeys:
    """HardeningSSHRunner backs Linux, Apache and MongoDB hardening."""

    def _runner(self, runner_module, monkeypatch, server_key, auth_error=None):
        fake = _FakeParamikoClient(server_key, auth_error=auth_error)
        monkeypatch.setattr(runner_module.paramiko, "SSHClient", lambda: fake)
        runner = runner_module.HardeningSSHRunner(
            ip="10.0.0.1", username="u", password="pw", max_retries=1
        )
        return runner, fake

    def test_uses_the_verifying_policy_not_autoadd(self, store_path, runner_module,
                                                   monkeypatch, host_key):
        runner, fake = self._runner(runner_module, monkeypatch, host_key)
        runner.connect()
        assert isinstance(fake.policy, VerifyingHostKeyPolicy)
        assert not isinstance(fake.policy, paramiko.AutoAddPolicy)

    def test_first_connection_pins_and_succeeds(self, store_path, runner_module,
                                                monkeypatch, host_key):
        runner, _ = self._runner(runner_module, monkeypatch, host_key)
        runner.connect()
        assert runner.is_connected()
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH

    def test_second_connection_with_same_key_succeeds(self, store_path, runner_module,
                                                       monkeypatch, host_key):
        runner, _ = self._runner(runner_module, monkeypatch, host_key)
        runner.connect()
        runner2, _ = self._runner(runner_module, monkeypatch, host_key)
        runner2.connect()
        assert runner2.is_connected()

    def test_changed_key_is_rejected(self, store_path, runner_module, monkeypatch,
                                      host_key, other_key):
        runner, _ = self._runner(runner_module, monkeypatch, host_key)
        runner.connect()
        runner2, fake2 = self._runner(runner_module, monkeypatch, other_key)
        with pytest.raises(SSHHostKeyMismatchError):
            runner2.connect()
        assert not runner2.is_connected()
        assert fake2.closed

    def test_unknown_host_is_rejected_in_strict_mode(self, strict_mode, runner_module,
                                                     monkeypatch, host_key):
        runner, _ = self._runner(runner_module, monkeypatch, host_key)
        with pytest.raises(SSHHostKeyUnknownError):
            runner.connect()
        assert not runner.is_connected()

    def test_host_key_failure_is_not_retried(self, store_path, runner_module,
                                              monkeypatch, host_key, other_key):
        """A device's key will not change between retries — burning the retry
        budget only delays the operator's error."""
        runner, _ = self._runner(runner_module, monkeypatch, host_key)
        runner.connect()

        attempts = {"n": 0}
        fake = _FakeParamikoClient(other_key)
        original_connect = fake.connect

        def counting_connect(**kwargs):
            attempts["n"] += 1
            return original_connect(**kwargs)

        fake.connect = counting_connect
        monkeypatch.setattr(runner_module.paramiko, "SSHClient", lambda: fake)
        runner2 = runner_module.HardeningSSHRunner(
            ip="10.0.0.1", username="u", password="pw", max_retries=3
        )
        with pytest.raises(SSHHostKeyMismatchError):
            runner2.connect()
        assert attempts["n"] == 1

    def test_authentication_still_behaves_normally_after_verification(
        self, store_path, runner_module, monkeypatch, host_key
    ):
        """Verification must not swallow or mask a genuine credential failure."""
        runner, _ = self._runner(
            runner_module, monkeypatch, host_key,
            auth_error=paramiko.AuthenticationException("bad password"),
        )
        with pytest.raises(SSHAuthenticationError):
            runner.connect()
        # The key was still pinned — verification happens before auth.
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH

    def test_normal_connection_parameters_are_preserved(self, store_path, runner_module,
                                                         monkeypatch, host_key):
        """Existing behaviour: password auth only, no agent/key probing."""
        runner, fake = self._runner(runner_module, monkeypatch, host_key)
        runner.connect()
        kw = fake.connected_kwargs
        assert kw["hostname"] == "10.0.0.1"
        assert kw["username"] == "u"
        assert kw["password"] == "pw"
        assert kw["look_for_keys"] is False
        assert kw["allow_agent"] is False

    def test_non_default_port_is_verified_per_port(self, store_path, runner_module,
                                                    monkeypatch, host_key):
        fake = _FakeParamikoClient(host_key)
        monkeypatch.setattr(runner_module.paramiko, "SSHClient", lambda: fake)
        runner = runner_module.HardeningSSHRunner(
            ip="10.0.0.1", username="u", password="pw", port=2222, max_retries=1
        )
        runner.connect()
        assert hk.get_store().verify("10.0.0.1", 2222, host_key) is VerificationResult.MATCH
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.UNKNOWN

    def test_non_default_port_entry_is_not_double_bracketed(self, store_path, runner_module,
                                                             monkeypatch, host_key):
        """
        Regression: paramiko hands the policy "[host]:port" for a non-22 port.
        Re-deriving an entry name from that without unpacking it first wrote
        "[[host]:port]:port", so every connection looked unknown and was
        silently re-pinned — defeating change detection on non-standard ports.
        """
        fake = _FakeParamikoClient(host_key)
        monkeypatch.setattr(runner_module.paramiko, "SSHClient", lambda: fake)
        runner_module.HardeningSSHRunner(
            ip="10.0.0.1", username="u", password="pw", port=2222, max_retries=1
        ).connect()
        entries = store_path.read_text().split()
        assert entries[0] == "[10.0.0.1]:2222", entries[0]

    def test_changed_key_on_non_default_port_is_rejected(self, store_path, runner_module,
                                                          monkeypatch, host_key, other_key):
        """The mismatch path must work on non-22 ports too, not just port 22."""
        fake = _FakeParamikoClient(host_key)
        monkeypatch.setattr(runner_module.paramiko, "SSHClient", lambda: fake)
        runner_module.HardeningSSHRunner(
            ip="10.0.0.1", username="u", password="pw", port=2222, max_retries=1
        ).connect()

        evil = _FakeParamikoClient(other_key)
        monkeypatch.setattr(runner_module.paramiko, "SSHClient", lambda: evil)
        with pytest.raises(SSHHostKeyMismatchError):
            runner_module.HardeningSSHRunner(
                ip="10.0.0.1", username="u", password="pw", port=2222, max_retries=1
            ).connect()

    def test_split_entry_name_round_trips(self):
        assert hk.split_entry_name("10.0.0.1", 22) == ("10.0.0.1", 22)
        assert hk.split_entry_name("[10.0.0.1]:2222", 22) == ("10.0.0.1", 2222)
        # IPv6 literals keep their own brackets inside the port form.
        assert hk.split_entry_name("[fe80::1]:2222", 22) == ("fe80::1", 2222)


# --------------------------------------------------------------------------- #
#  netmiko path (Linux/Apache audit, Cisco, FortiGate, MongoDB audit)          #
# --------------------------------------------------------------------------- #

class TestNetmikoWiring:
    def test_kwargs_enable_strict_checking_against_our_store(self, store_path):
        kw = netmiko_host_key_kwargs()
        # ssh_strict=True is what swaps netmiko's AutoAddPolicy for RejectPolicy.
        assert kw["ssh_strict"] is True
        assert kw["alt_host_keys"] is True
        assert kw["alt_key_file"] == str(store_path)
        # The container user's ambient ~/.ssh/known_hosts must not grant trust.
        assert kw["system_host_keys"] is False

    def test_preflight_pins_unknown_host(self, store_path, monkeypatch, host_key):
        monkeypatch.setattr(hk, "_fetch_remote_host_key",
                            lambda host, port, timeout: host_key)
        ensure_host_key_trusted("10.0.0.1", 22)
        assert hk.get_store().verify("10.0.0.1", 22, host_key) is VerificationResult.MATCH

    def test_preflight_is_a_noop_for_known_hosts(self, store_path, monkeypatch, host_key):
        """No extra handshake once a host is pinned — the steady state must not
        pay for an additional round trip."""
        hk.get_store().add("10.0.0.1", 22, host_key)
        called = {"n": 0}

        def _boom(host, port, timeout):
            called["n"] += 1
            raise AssertionError("should not probe a known host")

        monkeypatch.setattr(hk, "_fetch_remote_host_key", _boom)
        ensure_host_key_trusted("10.0.0.1", 22)
        assert called["n"] == 0

    def test_preflight_rejects_unknown_host_in_strict_mode_without_probing(
        self, strict_mode, monkeypatch
    ):
        def _boom(host, port, timeout):
            raise AssertionError("strict mode must refuse before touching the network")

        monkeypatch.setattr(hk, "_fetch_remote_host_key", _boom)
        with pytest.raises(SSHHostKeyUnknownError):
            ensure_host_key_trusted("10.0.0.1", 22)

    def test_probe_failure_refuses_rather_than_trusting(self, store_path, monkeypatch):
        """If we cannot read the key we must not connect anyway."""
        def _fail(host, port, timeout):
            raise OSError("network unreachable")

        monkeypatch.setattr(hk, "_fetch_remote_host_key", _fail)
        with pytest.raises(SSHConnectionError):
            ensure_host_key_trusted("10.0.0.1", 22)
        # ...and nothing was trusted as a side effect.
        assert hk.get_store().lookup("10.0.0.1", 22) is None

    def test_unreachable_device_reports_the_real_error_not_a_trust_error(
        self, store_path, monkeypatch
    ):
        """
        A device that is simply switched off must not be reported as a host-key
        problem — the operator would go hunting for a MITM that isn't there.
        """
        import socket

        def _refused(host, port, timeout):
            raise socket.timeout("timed out")

        monkeypatch.setattr(hk, "_fetch_remote_host_key", _refused)
        with pytest.raises(SSHConnectionError) as exc:
            ensure_host_key_trusted("10.0.0.1", 22)
        assert not isinstance(exc.value, SSHHostKeyError)

    def test_probe_pins_a_changed_key_as_a_mismatch(self, store_path, monkeypatch,
                                                     host_key, other_key):
        hk.get_store().add("10.0.0.1", 22, host_key)
        # Known host -> no probe; the mismatch is caught by netmiko's own
        # RejectPolicy and classified below. Verify the store agrees.
        assert hk.get_store().verify("10.0.0.1", 22, other_key) is VerificationResult.MISMATCH


class TestNetmikoErrorClassification:
    """
    netmiko funnels every paramiko SSHException — including BadHostKeyException
    and RejectPolicy's rejection — into NetmikoAuthenticationException. Without
    reclassification a MITM would be reported to the operator as a bad password.
    """

    def test_bad_host_key_message_is_classified_as_host_key_failure(self, store_path):
        from netmiko.exceptions import NetmikoAuthenticationException
        err = NetmikoAuthenticationException(
            'Authentication to device failed.\n\n'
            'Host key for server "10.0.0.1" does not match: got "AAA", expected "BBB"'
        )
        result = classify_netmiko_auth_failure(err, "10.0.0.1")
        assert isinstance(result, SSHHostKeyMismatchError)

    def test_unknown_host_message_is_classified_as_host_key_failure(self, store_path):
        from netmiko.exceptions import NetmikoAuthenticationException
        err = NetmikoAuthenticationException(
            "Authentication to device failed.\n\n"
            "Server '10.0.0.1' not found in known_hosts"
        )
        result = classify_netmiko_auth_failure(err, "10.0.0.1")
        assert isinstance(result, SSHHostKeyMismatchError)

    def test_real_authentication_failure_is_left_alone(self, store_path):
        from netmiko.exceptions import NetmikoAuthenticationException
        err = NetmikoAuthenticationException(
            "Authentication to device 10.0.0.1 failed.\n\nBad password."
        )
        assert classify_netmiko_auth_failure(err, "10.0.0.1") is None


class _FakeNetmikoConnection:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.base_prompt = "host"

    def send_command(self, *a, **kw):
        return ""

    def disconnect(self):
        pass


@pytest.mark.parametrize("module_path,client_factory,host_attr", [
    (
        "app.modules.linux.common.ssh_client",
        lambda mod: mod.LinuxSSHClient("10.0.0.1", "u", "pw"),
        "10.0.0.1",
    ),
    (
        "app.modules.cisco.audit.ssh_client",
        lambda mod: mod.CiscoSSHClient("10.0.0.2", "u", "pw"),
        "10.0.0.2",
    ),
    (
        "app.modules.mongodb.audit.mongo_client",
        lambda mod: mod.MongoDBSSHClient("10.0.0.3", "u", "pw"),
        "10.0.0.3",
    ),
])
class TestEveryNetmikoClientEnforcesTheStore:
    """
    Each netmiko client must (a) run the pre-flight and (b) hand netmiko the
    strict host-key kwargs. A future client that forgets either one fails here.
    """

    def _patch(self, monkeypatch, module_path, host_key):
        import importlib
        mod = importlib.import_module(module_path)
        captured = {}

        def fake_connect_handler(**kwargs):
            captured["kwargs"] = kwargs
            return _FakeNetmikoConnection(**kwargs)

        monkeypatch.setattr(mod, "ConnectHandler", fake_connect_handler)
        monkeypatch.setattr(hk, "_fetch_remote_host_key",
                            lambda host, port, timeout: host_key)
        return mod, captured

    def test_passes_strict_host_key_kwargs_to_netmiko(
        self, store_path, monkeypatch, host_key, module_path, client_factory, host_attr
    ):
        mod, captured = self._patch(monkeypatch, module_path, host_key)
        client = client_factory(mod)
        connect = getattr(client, "connect", None) or getattr(client, "_connect")
        connect()
        kw = captured["kwargs"]
        assert kw["ssh_strict"] is True
        assert kw["alt_host_keys"] is True
        assert kw["alt_key_file"] == str(store_path)
        assert kw["system_host_keys"] is False

    def test_pins_the_host_key_on_first_connection(
        self, store_path, monkeypatch, host_key, module_path, client_factory, host_attr
    ):
        mod, _ = self._patch(monkeypatch, module_path, host_key)
        client = client_factory(mod)
        connect = getattr(client, "connect", None) or getattr(client, "_connect")
        connect()
        assert hk.get_store().verify(host_attr, 22, host_key) is VerificationResult.MATCH

    def test_refuses_unknown_host_in_strict_mode(
        self, strict_mode, monkeypatch, host_key, module_path, client_factory, host_attr
    ):
        mod, _ = self._patch(monkeypatch, module_path, host_key)
        client = client_factory(mod)
        connect = getattr(client, "connect", None) or getattr(client, "_connect")
        # MongoDB's audit client converts our error into ConnectionError; the
        # others propagate SSHHostKeyError. Both are hard failures.
        with pytest.raises((SSHHostKeyError, ConnectionError)):
            connect()


class TestFortiGateClientEnforcesTheStore:
    """FortiGate is separate: it retries across two netmiko device_types."""

    def _patch(self, monkeypatch, host_key):
        from app.modules.fortinet.audit import ssh_client as mod
        captured = {}

        def fake_connect_handler(**kwargs):
            captured["kwargs"] = kwargs
            conn = _FakeNetmikoConnection(**kwargs)
            conn._vdoms = False
            return conn

        monkeypatch.setattr(mod, "ConnectHandler", fake_connect_handler)
        monkeypatch.setattr(mod.FortiGateSSHClient, "_prime_session", lambda self: None)
        monkeypatch.setattr(hk, "_fetch_remote_host_key",
                            lambda host, port, timeout: host_key)
        return mod, captured

    def test_passes_strict_host_key_kwargs(self, store_path, monkeypatch, host_key):
        mod, captured = self._patch(monkeypatch, host_key)
        client = mod.FortiGateSSHClient("10.0.0.4", "u", "pw")
        client.connect()
        assert captured["kwargs"]["ssh_strict"] is True
        assert captured["kwargs"]["alt_key_file"] == str(store_path)

    def test_pins_on_first_connection(self, store_path, monkeypatch, host_key):
        mod, _ = self._patch(monkeypatch, host_key)
        mod.FortiGateSSHClient("10.0.0.4", "u", "pw").connect()
        assert hk.get_store().verify("10.0.0.4", 22, host_key) is VerificationResult.MATCH

    def test_refuses_unknown_host_in_strict_mode(self, strict_mode, monkeypatch, host_key):
        mod, _ = self._patch(monkeypatch, host_key)
        with pytest.raises(SSHHostKeyError):
            mod.FortiGateSSHClient("10.0.0.4", "u", "pw").connect()

    def test_host_key_failure_is_not_retried_across_device_types(
        self, strict_mode, monkeypatch, host_key
    ):
        mod, _ = self._patch(monkeypatch, host_key)
        calls = {"n": 0}

        def counting(**kwargs):
            calls["n"] += 1
            return _FakeNetmikoConnection(**kwargs)

        monkeypatch.setattr(mod, "ConnectHandler", counting)
        with pytest.raises(SSHHostKeyError):
            mod.FortiGateSSHClient("10.0.0.4", "u", "pw").connect()
        assert calls["n"] == 0  # refused before either device_type was tried


# --------------------------------------------------------------------------- #
#  Audit vs hardening: one policy, one store                                   #
# --------------------------------------------------------------------------- #

class TestAuditAndHardeningSharePolicy:
    def test_key_pinned_by_the_audit_path_is_honoured_by_the_hardening_path(
        self, store_path, monkeypatch, host_key
    ):
        """An audit (netmiko) and a fix (paramiko) against the same device must
        agree about that device's identity."""
        from app.modules.linux.common import ssh_client as audit_mod
        from app.modules.linux.common import fast_ssh_runner as harden_mod

        monkeypatch.setattr(audit_mod, "ConnectHandler",
                            lambda **kw: _FakeNetmikoConnection(**kw))
        monkeypatch.setattr(hk, "_fetch_remote_host_key",
                            lambda host, port, timeout: host_key)
        audit_mod.LinuxSSHClient("10.0.0.1", "u", "pw").connect()

        # Same key -> hardening connects.
        fake_ok = _FakeParamikoClient(host_key)
        monkeypatch.setattr(harden_mod.paramiko, "SSHClient", lambda: fake_ok)
        harden_mod.HardeningSSHRunner("10.0.0.1", "u", "pw", max_retries=1).connect()

    def test_key_changed_between_audit_and_hardening_is_rejected(
        self, store_path, monkeypatch, host_key, other_key
    ):
        from app.modules.linux.common import ssh_client as audit_mod
        from app.modules.linux.common import fast_ssh_runner as harden_mod

        monkeypatch.setattr(audit_mod, "ConnectHandler",
                            lambda **kw: _FakeNetmikoConnection(**kw))
        monkeypatch.setattr(hk, "_fetch_remote_host_key",
                            lambda host, port, timeout: host_key)
        audit_mod.LinuxSSHClient("10.0.0.1", "u", "pw").connect()

        fake_evil = _FakeParamikoClient(other_key)
        monkeypatch.setattr(harden_mod.paramiko, "SSHClient", lambda: fake_evil)
        with pytest.raises(SSHHostKeyMismatchError):
            harden_mod.HardeningSSHRunner("10.0.0.1", "u", "pw", max_retries=1).connect()

    def test_hardening_dry_run_preview_opens_no_ssh_connection(self, store_path, monkeypatch):
        """
        The hardening "preview" path builds the command list without touching
        the device, so there is no second, unverified SSH path to secure — this
        test locks that in: if a preview ever starts connecting, it must go
        through the verified clients like everything else.
        """
        from app.modules.linux.hardening import service as svc

        def _boom(*a, **kw):
            raise AssertionError("dry-run preview must not open an SSH connection")

        monkeypatch.setattr(svc, "LinuxHardeningBatchExecutor", _boom)
        result = svc._dry_run_check_result("LNX-L1-5.2.10", "ubuntu", {})
        assert result["dry_run"] is True
        assert result["commands"]
