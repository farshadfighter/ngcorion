"""PowerShell building blocks shared by the Windows Server role modules."""

from typing import Dict, List


def guarded(body: str) -> str:
    """Run `body` with terminating errors, and print a PS_ERROR marker instead
    of a stack trace when it fails, so the rule engine reports the section as
    not collected rather than parsing an error message as data."""
    return (
        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; "
        "try { " + body + " } catch { 'PS_ERROR: ' + ($_.Exception.Message -replace '\\s+', ' ') }"
    )


def json_of(expr: str, depth: int = 5) -> str:
    return f"({expr}) | ConvertTo-Json -Depth {depth} -Compress"


def registry_script(props: Dict[str, List[str]]) -> str:
    """{path: <json of the named values>} for the given (path -> names) map.

    Only the named values are read, never whole keys, so neighbouring secrets
    (Winlogon DefaultPassword and the like) never reach the stored dump."""
    spec = "\n".join(f"{path}={'|'.join(names)}" for path, names in props.items())
    return (
        "$spec = @'\n" + spec + "\n'@\n"
        "$result = @{}; "
        "foreach ($line in ($spec -split \"`r?`n\")) { "
        "  if (-not $line.Trim()) { continue }; $i = $line.IndexOf('='); if ($i -lt 1) { continue }; "
        "  $p = $line.Substring(0, $i); $names = $line.Substring($i + 1) -split '\\|'; "
        "  try { if (Test-Path -LiteralPath $p) { "
        "    $props = Get-ItemProperty -LiteralPath $p -Name $names -ErrorAction SilentlyContinue; "
        "    if ($props) { $o = @{}; foreach ($n in $names) { $pp = $props.PSObject.Properties[$n]; "
        "      if ($pp) { $o[$n] = $pp.Value } }; $result[$p] = ($o | ConvertTo-Json -Compress -Depth 3) } "
        "  } } catch {} "
        "}; $result | ConvertTo-Json -Depth 4"
    )


def registry_value(dump_json, path: str, name: str):
    """Look a value up in a registry_script() section (already parsed)."""
    import json
    if not isinstance(dump_json, dict):
        return None
    raw = dump_json.get(path)
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    return raw.get(name) if isinstance(raw, dict) else None
