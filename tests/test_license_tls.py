"""
The license server's certificate (product decision, 2026-10-31).

lic.ngcorion.com sends an incomplete chain (a Let's Encrypt "Generation Y" certificate without the
cross-signed root) that cannot be changed there, so every activation failed with
CERTIFICATE_VERIFY_FAILED. NGCorion no longer checks that one server's certificate; what makes a
license is still only an answer signed by a built-in key, for this license and this machine.

Protected here: the exemption is for the fixed license server only (no setting, any other server
is verified); urllib3's warning is silenced for that host only; an answer that is not signed is
refused over the unverified connection just as before.
"""
import warnings

import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

from app.core import license_client as lc
from app.core import machine_fingerprint as mf
from app.core.license_keys import LICENSE_SERVER_URL
from tests.license_signing_helpers import (  # noqa: F401  (fixture)
    LICENSE_KEY,
    OTHER_KEY,
    make_token,
    trusted_test_key,
)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    monkeypatch.setattr(mf, "HW_UUID_FILE", tmp_path / "none-hw")
    monkeypatch.setattr(mf, "DMI_UUID_FILE", tmp_path / "none-dmi")
    host = tmp_path / "machine-id"
    host.write_text("0123456789abcdef0123456789abcdef\n")
    monkeypatch.setattr(mf, "HOST_MACHINE_ID_FILE", host)
    return tmp_path


def test_only_the_fixed_license_server_is_not_verified(machine):
    fixed = lc.LicenseClient(LICENSE_SERVER_URL, str(machine / "a"))
    assert fixed.session.verify is False and fixed.idempotent_session.verify is False

    other = lc.LicenseClient("https://license.example", str(machine / "b"))
    assert other.session.verify is True and other.idempotent_session.verify is True

    # A look-alike is not the license server.
    lookalike = lc.LicenseClient("https://lic.ngcorion.com.example.net", str(machine / "c"))
    assert lookalike.session.verify is True


def test_a_ca_bundle_given_by_a_test_is_used_as_before(machine):
    bundle = machine / "ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n")
    client = lc.LicenseClient(LICENSE_SERVER_URL, str(machine / "a"), ca_bundle=str(bundle))
    assert client.session.verify == str(bundle)


def test_nothing_in_the_settings_turns_it_on_or_off(machine):
    from app.core.config import Settings
    assert not [name for name in Settings.model_fields
                if name.startswith("LICENSE") and ("VERIFY" in name or "INSECURE" in name or "TLS" in name)]


def test_the_warning_is_silenced_for_the_license_server_only():
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("default")
        # the module's filter, put back in front (catch_warnings copied the list; simplefilter
        # inserted "default" before it)
        warnings.filterwarnings(
            "ignore", category=InsecureRequestWarning,
            message=r"Unverified HTTPS request is being made to host 'lic\.ngcorion\.com'")
        warnings.warn("Unverified HTTPS request is being made to host 'lic.ngcorion.com'. Adding "
                      "certificate verification is strongly advised.", InsecureRequestWarning)
        warnings.warn("Unverified HTTPS request is being made to host 'elsewhere.example'. Adding "
                      "certificate verification is strongly advised.", InsecureRequestWarning)
    assert [str(w.message).split("'")[1] for w in seen] == ["elsewhere.example"]
    assert any(f[2] is InsecureRequestWarning and f[1] is not None and f[1].search(
        "Unverified HTTPS request is being made to host 'lic.ngcorion.com'") for f in warnings.filters)


class _Answer:
    def __init__(self, body):
        self.status_code, self._body, self.text = 200, body, ""

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


@pytest.mark.parametrize("token", [
    lambda c: None,                                                       # no signature at all
    lambda c: make_token(key=OTHER_KEY, fp=c.machine_fingerprint),         # someone else's key
    lambda c: make_token(fp="f" * 64),                                     # another machine
])
@pytest.mark.usefixtures("trusted_test_key")
def test_an_answer_that_is_not_signed_for_this_machine_is_still_refused(machine, monkeypatch, token):
    client = lc.LicenseClient(LICENSE_SERVER_URL, str(machine / "a"))
    client.storage.save_license({"license_key": LICENSE_KEY, "organization_token": "org",
                                 "vm_fingerprint": client.machine_fingerprint})
    body = {"valid": True, "plan_type": "NGC-ENT-UNL-1Y", "max_assets": None}
    if token(client):
        body["signed_token"] = token(client)
    monkeypatch.setattr(requests.Session, "request", lambda self, *a, **k: _Answer(body))
    with pytest.raises(lc.LicenseAnswerUntrusted):
        client.validate()
