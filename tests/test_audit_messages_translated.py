"""Every sentence NGCorion writes into its audit trail is shown in Persian on the audit trail page.

The trail stores English (audit_logs.detail, login_logs.message); the UI translates it with tb()
from front/src/i18n/backendText.js, whose keys get their Persian in front/src/i18n/locales/fa (and
`npm run i18n:check` fails on a key without one). This test closes the loop from the other side:
a new log_action(... detail=f"...") whose sentence is not listed there fails here.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import audit_messages  # noqa: E402

BACKEND_TEXT = ROOT / "front/src/i18n/backendText.js"
FA = ROOT / "front/src/i18n/locales/fa"

# Details the source does not spell out. Each is either a value, not a sentence (a code, a name),
# or built from sentences listed by hand in backendText.js. Adding to this list is a decision:
# say which of the two it is.
DYNAMIC = {
    ("app/modules/cve/jobs.py", "_summary(self.kind, status, self.stats, error)"),  # summaries listed by hand
    ("app/modules/cve/router.py", "'; '.join(changes)"),  # settings changes listed by hand, tbDetail() splits
    ("app/modules/cve/router.py", "release"),  # a release name
    ("app/modules/license/router.py", "exc.detail"),  # the license server's or the verifier's own reason
    ("app/modules/alerts/router.py", "'; '.join(changed)"),  # delivery policy settings changed, as values
    ("app/modules/remediation/router.py", "acc.ref"),  # a reference such as RA-2026-0007
    ("app/modules/reports/router.py", "code"),  # a report code
    ("app/modules/reports/router.py", "s.name"),  # a schedule name
    ("app/modules/reports/router.py", "name"),  # a schedule name
}


def _listed() -> set[str]:
    source = BACKEND_TEXT.read_text(encoding="utf-8")
    return {json.loads(m) for m in re.findall(r'msg\(("(?:[^"\\]|\\.)*")\)', source)}


def _translated() -> dict[str, str]:
    out: dict[str, str] = {}
    for f in FA.glob("*.json"):
        out.update(json.loads(f.read_text(encoding="utf-8")))
    return out


def test_every_audit_sentence_has_a_persian_translation():
    listed, fa = _listed(), _translated()
    missing = sorted({f"{f.where}: {f.text}" for f in audit_messages.find()
                      if f.kind != "dynamic" and audit_messages.is_sentence(f.text)
                      # a fixed sentence is found by exact key wherever the UI already has it; a
                      # template must be in backendText.js, which turns it into a pattern
                      and (not fa.get(f.text) or (f.kind == "template" and f.text not in listed))})
    assert not missing, ("audit trail sentences with no Persian: add each to backendText.js "
                         "(msg(...), templates in TEMPLATES), run npm run i18n:extract and translate:\n"
                         + "\n".join(missing))


def test_no_new_audit_detail_the_source_does_not_spell_out():
    found = {(f.where.rsplit(":", 1)[0], f.text) for f in audit_messages.find() if f.kind == "dynamic"}
    assert found <= DYNAMIC, ("audit details built at run time: write the sentence at the call "
                              f"(log_action(..., detail=f\"...\")) or list it in DYNAMIC: {sorted(found - DYNAMIC)}")


def test_the_extractor_reads_the_shapes_the_code_uses():
    texts = {f.text for f in audit_messages.find()}
    # f-string with an attribute chain, conditional sentence, string + conditional suffix,
    # a local variable assigned before the row is deleted, and a positional detail
    assert "Login successful (role={{role}})" in texts
    assert {"Turned on rule '{{name}}'", "Turned off rule '{{name}}'"} <= texts
    assert {"Updated webhook '{{name}}'", "Updated webhook '{{name}}' and replaced its secret"} <= texts
    assert "asset {{asset_id}}: {{vendor}} {{product}} {{version}}" in texts
    assert "Incorrect username or password" in texts


def test_data_records_are_not_taken_for_sentences():
    assert audit_messages.is_sentence("Deleted rule '{{name}}'")
    assert not audit_messages.is_sentence("{{code}} {{template}}")
    assert not audit_messages.is_sentence("old_value={{value}}; new_value=started; score={{score}}")
