"""CIS Cisco 2.1.1.1.3 — RSA key modulus must be >= 2048 bits.

Hardening this control kept reporting "Detected key size: 1024 bit" right after
running `crypto key generate rsa modulus 2048`. Two independent defects made
that happen, and both are covered here:

1. Detection read the wrong number. The only "<n> bits" text in the collected
   output is usually "Minimum expected Diffie Hellman key size : 1024 bits" from
   `show ip ssh` — the DH key-exchange floor, not the RSA modulus — so every
   device looked like it had a 1024-bit key no matter what key it held.
2. The key was never actually replaced. When a keypair already exists IOS asks
   "Do you really want to replace them? [yes/no]:" and waits; nothing answered
   it, so generation was abandoned and the old key survived.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app.modules.cisco.audit.rules import (
    _extract_ssh_key_bits,
    build_all_cisco_cis_rules,
    build_cis_benchmark_rules,
)
from app.modules.cisco.audit.ssh_client import CiscoSSHClient
from app.modules.cisco.hardening.command_parser import (
    RemediationParser,
    validate_parameter_values,
)
from app.modules.cisco.hardening.command_templates import get_template
from app.modules.cisco.hardening.parameter_metadata import get_parameters_for_check


CIS_ID = "CIS-2.1.1.1.3"
IOS_ID = "IOS-L1-0120"

# Real public keys, printed the way IOS prints them.
KEY_HEX_1024 = """\
  30819F30 0D06092A 864886F7 0D010101 05000381 8D003081
  89028181 00A7C712 0B5DC692 9DC58A8D BD9BCFB6 E9A1FA8B
  532DB0AC 73504D34 157575C7 0348D20D 64769052 57716033
  7E6EB133 87EA03C1 DF0AF362 44DF02E5 CB351B30 E17274BC
  A179671B AB52C132 591B4BBD 53E6F13F CE52DF96 351DDED5
  56F13E5B 82643EB9 EB248EAB 1F027AF3 654F74C1 BB972BA5
  0102D4FD 1BD5311D A23C54E0 F1020301 0001"""

SECSH_1024 = """\
AAAAB3NzaC1yc2EAAAADAQABAAAAgQCnxxILXcaSncWKjb2bz7bpofqLUy2wrHNQ
TTQVdXXHA0jSDWR2kFJXcWAzfm6xM4fqA8HfCvNiRN8C5cs1GzDhcnS8oXlnG6tS
wTJZG0u9U+bxP85S35Y1Hd7VVvE+W4JkPrnrJI6rHwJ682VPdMG7lyulAQLU/RvV
MR2iPFTg8Q=="""

KEY_HEX_2048 = """\
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00
  3082010A 02820101 00EFE008 A25E3DE6 CB895E41 3422835A
  09FC9A97 F7B974A1 FD1F743E 6D8D23BA F922BF53 0D95B7BB
  D1C965A7 B4C5D115 E168A7BA 4FFDA4FC 9AEC20AC 661C4F20
  369C21AC FA999C4A BC2C096A 8CFD3FD5 A2CBF461 D735707A
  1CA498D8 9AA0A422 5FA87110 210EE002 41AA433D 62BD93B9
  1AB870F3 4E39C1C7 2FC0C90F 0DCFC492 382CD41A 2503FA61
  5BCE7C05 EAFF4336 AD1B57CD DC63917D 54C6ACCA 1CA0FD5E
  467E57C5 81FF3565 4FC748A6 F818F64C B456D17D FB2F2CF2
  1D73A2D2 61988D1E 0D3CABC4 A76184A9 F600BE49 69600960
  23BD9712 45FED9A5 32E3B9C7 D7123AB8 78B8FEBE AD976D19
  0808ACDE 9EA46F1D 90CF8494 10066BBE 0AA38FB7 925D9C16
  81020301 0001"""

SECSH_2048 = """\
AAAAB3NzaC1yc2EAAAADAQABAAABAQDv4AiiXj3my4leQTQig1oJ/JqX97l0of0f
dD5tjSO6+SK/Uw2Vt7vRyWWntMXRFeFop7pP/aT8muwgrGYcTyA2nCGs+pmcSrws
CWqM/T/Vosv0Ydc1cHocpJjYmqCkIl+ocRAhDuACQapDPWK9k7kauHDzTjnBxy/A
yQ8Nz8SSOCzUGiUD+mFbznwF6v9DNq0bV83cY5F9VMasyhyg/V5GflfFgf81ZU/H
SKb4GPZMtFbRffsvLPIdc6LSYZiNHg08q8SnYYSp9gC+SWlgCWAjvZcSRf7ZpTLj
ucfXEjq4eLj+vq2XbRkICKzenqRvHZDPhJQQBmu+CqOPt5JdnBaB"""


def device_dump(secsh: str, key_hex: str, dh_floor: str = "1024") -> str:
    """The verification dump collect_config_dump() returns for a real device."""
    return f"""hostname R1
ip domain-name lab.local
ip ssh version 2
!
!! show ip ssh
SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : {dh_floor} bits
IOS Keys in SECSH format(ssh-rsa, base64 encoded): R1.lab.local
{secsh}

!! show crypto key mypubkey rsa
% Key pair was generated at: 06:47:12 UTC Aug 29 2026
Key name: R1.lab.local
Key type: RSA KEYS
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
{key_hex}
"""


@pytest.fixture(scope="module")
def rules():
    return {
        rule.id: rule
        for rule in [*build_cis_benchmark_rules(), *build_all_cisco_cis_rules()]
    }


# ==================== key size detection ====================

def test_dh_floor_is_not_read_as_the_rsa_key_size():
    """The reported regression: a 2048-bit key detected as 1024 bit."""
    dump = device_dump(SECSH_2048, KEY_HEX_2048, dh_floor="1024")
    assert _extract_ssh_key_bits(dump) == 2048


def test_dh_floor_alone_is_not_evidence_of_any_key():
    """With no key material the size is unknown, never the DH floor."""
    dump = (
        "!! show ip ssh\n"
        "Minimum expected Diffie Hellman key size : 1024 bits\n"
    )
    assert _extract_ssh_key_bits(dump) is None


def test_small_key_is_still_detected_as_small():
    """The fix must not turn every device into a pass."""
    dump = device_dump(SECSH_1024, KEY_HEX_1024)
    assert _extract_ssh_key_bits(dump) == 1024


def test_key_size_read_from_secsh_blob_alone():
    dump = (
        "IOS Keys in SECSH format(ssh-rsa, base64 encoded): R1.lab.local\n"
        f"{SECSH_2048}\n"
    )
    assert _extract_ssh_key_bits(dump) == 2048


def test_key_size_read_from_mypubkey_hex_alone():
    """Platforms whose 'show ip ssh' prints no SECSH blob still resolve."""
    dump = f"Key name: R1.lab.local\n Key Data:\n{KEY_HEX_2048}\n"
    assert _extract_ssh_key_bits(dump) == 2048
    dump_small = f"Key name: R1.lab.local\n Key Data:\n{KEY_HEX_1024}\n"
    assert _extract_ssh_key_bits(dump_small) == 1024


def test_textual_modulus_size_still_recognised():
    """Platforms that print the size in words keep working."""
    dump = (
        "!! show ip ssh\n"
        "Minimum expected Diffie Hellman key size : 1024 bits\n"
        "!! show crypto key mypubkey rsa\n"
        "Key name: R1.lab.local\n"
        " Modulus Size : 2048 bits\n"
    )
    assert _extract_ssh_key_bits(dump) == 2048


def test_garbled_key_material_does_not_crash():
    dump = "Key name: R1\n Key Data:\n  ZZZZZZZZ 30820122\n"
    assert _extract_ssh_key_bits(dump) is None


# ==================== the CIS checks ====================

@pytest.mark.parametrize("check_id", [CIS_ID, IOS_ID])
def test_check_passes_on_a_2048_bit_device(rules, check_id):
    dump = device_dump(SECSH_2048, KEY_HEX_2048)
    assert rules[check_id].check(dump) is True
    assert "2048" in rules[check_id].evidence(dump)


@pytest.mark.parametrize("check_id", [CIS_ID, IOS_ID])
def test_check_fails_on_a_1024_bit_device(rules, check_id):
    dump = device_dump(SECSH_1024, KEY_HEX_1024)
    assert rules[check_id].check(dump) is False
    assert "1024" in rules[check_id].evidence(dump)


@pytest.mark.parametrize("check_id", [CIS_ID, IOS_ID])
def test_check_fails_closed_when_no_key_is_visible(rules, check_id):
    """Unknown key size must never be reported compliant."""
    assert rules[check_id].check("hostname R1\n") is False


# ==================== the interactive replace confirmation ====================

class FakeConnection:
    """Minimal netmiko stand-in that replays an IOS key-generation exchange."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.read_timeout_override = None
        self.sent = []
        self.config_mode_entered = False
        self.exited_config_mode = False

    def check_config_mode(self):
        return self.config_mode_entered

    def config_mode(self):
        self.config_mode_entered = True
        return "R1(config)#"

    def exit_config_mode(self):
        self.exited_config_mode = True
        return "R1#"

    def send_command_timing(self, command, **kwargs):
        self.sent.append(command)
        return self.responses.pop(0) if self.responses else "R1(config)#"

    def send_config_set(self, commands, **kwargs):
        self.sent.extend(commands)
        return "R1(config)#"

    def read_until_pattern(self, pattern="", **kwargs):
        return ""


def make_client(responses):
    client = CiscoSSHClient(ip="10.0.0.1", username="u", password="p", secret="s")
    client.connection = FakeConnection(responses)
    client._in_enable_mode = True
    client.is_connected = lambda: True
    return client


def test_replace_confirmation_is_answered_yes():
    """Without the 'yes' the device keeps its old key and the check stays failing."""
    client = make_client([
        "crypto key generate rsa modulus 2048\n"
        "% You already have RSA keys defined named R1.lab.local.\n"
        "% Do you really want to replace them? [yes/no]: ",
        "\n% Generating 2048 bit RSA keys, keys will be non-exportable...\n"
        "[OK] (elapsed time was 2 seconds)\nR1(config)#",
    ])

    output = client.send_config_commands(["crypto key generate rsa modulus 2048"])

    assert client.connection.sent == [
        "crypto key generate rsa modulus 2048",
        "yes",
    ]
    assert "[OK]" in output
    assert client.connection.exited_config_mode is True


def test_modulus_prompt_is_answered_with_the_requested_size():
    """Accepting the IOS default here would create a 512-bit key."""
    client = make_client([
        "How many bits in the modulus [512]: ",
        "\n% Generating 4096 bit RSA keys ...\n[OK]\nR1(config)#",
    ])

    client.send_config_commands(["crypto key generate rsa modulus 4096"])

    assert client.connection.sent == ["crypto key generate rsa modulus 4096", "4096"]


def test_no_confirmation_is_sent_when_the_device_does_not_ask():
    client = make_client([
        "\n% Generating 2048 bit RSA keys ...\n[OK]\nR1(config)#",
    ])

    client.send_config_commands(["crypto key generate rsa modulus 2048"])

    assert client.connection.sent == ["crypto key generate rsa modulus 2048"]


def test_ordinary_commands_still_go_through_send_config_set():
    client = make_client([])

    client.send_config_commands(["ip ssh version 2", "ip ssh time-out 60"])

    assert client.connection.sent == ["ip ssh version 2", "ip ssh time-out 60"]
    assert client.connection.exited_config_mode is True


def test_confirmation_answers_are_capped():
    """A device stuck re-asking must not loop forever."""
    client = make_client(["[yes/no]: "] * 20)

    client.send_config_commands(["crypto key generate rsa modulus 2048"])

    answers = [c for c in client.connection.sent if c == "yes"]
    assert len(answers) == CiscoSSHClient.MAX_CONFIRMATIONS


# ==================== the modulus parameter ====================

def test_template_defaults_to_a_compliant_modulus():
    template = get_template(CIS_ID)
    assert template["defaults"]["MODULUS"] == "2048"
    assert "crypto key generate rsa modulus {MODULUS}" in template["commands"]


def test_below_benchmark_modulus_is_rejected():
    """A 1024-bit key cannot satisfy the control, so it must not be applied."""
    with pytest.raises(ValueError, match="at least 2048"):
        validate_parameter_values({"MODULUS": "1024"})

    with pytest.raises(ValueError, match="at least 2048"):
        RemediationParser.substitute_parameters(
            ["crypto key generate rsa modulus {MODULUS}"],
            {"MODULUS": "1024"},
        )


def test_compliant_modulus_values_are_accepted():
    for value in ("2048", "4096"):
        assert RemediationParser.substitute_parameters(
            ["crypto key generate rsa modulus {MODULUS}"],
            {"MODULUS": value},
        ) == [f"crypto key generate rsa modulus {value}"]


def test_non_numeric_modulus_is_rejected():
    with pytest.raises(ValueError, match="must be a number"):
        validate_parameter_values({"MODULUS": "big"})


def test_modulus_is_offered_as_a_compliant_choice_in_the_ui():
    """The form must not let an operator pick a size the control rejects."""
    params = {p.name: p for p in get_parameters_for_check(CIS_ID)}
    modulus = params["MODULUS"]
    assert modulus.input_type == "select"
    assert modulus.options == ["2048", "4096"]
    assert modulus.default == "2048"
    assert all(int(o) >= 2048 for o in modulus.options)
