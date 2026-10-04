"""Benchmark engine parameters: what reaches the device is the validated,
canonical form of each value."""
import pytest

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, ParameterSecurityError, TemplateSet


def _set():
    ts = TemplateSet()
    ts.param(ParamMeta(name="LIMIT", input_type="number", label="Limit", description="", min_value=1,
                       max_value=100, default="5"))
    ts.param(ParamMeta(name="NAME", input_type="text", label="Name", description="", default="web"))
    ts.add(HardeningTemplate(check_id="X-1", description="d", statements=["set limit {LIMIT} name {NAME}"],
                             verify_statements=["check {LIMIT}"], parameters=["LIMIT", "NAME"]))
    return ts


@pytest.mark.parametrize("raw,expected", [("7", "7"), (" 8\n", "8"), ("۹", "9"), (10, "10")])
def test_numbers_reach_the_device_in_canonical_form(raw, expected):
    assert _set().statements("X-1", {"LIMIT": raw}) == [f"set limit {expected} name web"]


@pytest.mark.parametrize("bad", ["5; reboot", "5\nreboot", "0x10", "1e3"])
def test_non_numbers_are_refused(bad):
    with pytest.raises(ParameterSecurityError):
        _set().statements("X-1", {"LIMIT": bad})


def test_out_of_range_is_refused():
    with pytest.raises(ParameterSecurityError):
        _set().statements("X-1", {"LIMIT": "101"})


@pytest.mark.parametrize("bad", ["a;b", "a|b", "$(id)", "`id`", "a\nb", "{LIMIT}"])
def test_shell_characters_in_text_are_refused(bad):
    with pytest.raises(ParameterSecurityError):
        _set().statements("X-1", {"NAME": bad})


def test_windows_and_mssql_substitute_canonical_numbers():
    from app.modules.mssql.hardening.command_templates import _validated_parameters as mssql
    from app.modules.windows.hardening.command_templates import _validated_parameters as windows
    assert windows({"MAX_PASSWORD_AGE": " 60\n"}) == {"MAX_PASSWORD_AGE": "60"}
    assert mssql({"NUM_ERROR_LOGS": "۱۲"}) == {"NUM_ERROR_LOGS": "12"}
