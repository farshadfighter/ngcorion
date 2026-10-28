/**
 * The conformity cards of an audit result: over the checks the score counts (passed or failed, not
 * informational and required by the benchmark policy; app/modules/audit_policy/service.py is_scored),
 * so conformity and non-conformity add up to 100 and the conformity is the session's score, the one
 * the reports, dashboards and Asset 360 show. Not applicable checks, errors, informational checks and
 * the ones the policy makes optional or excludes are counted apart.
 */

const isPass = (r) => ["PASS", "PASSED", "SUCCESS"].includes(r.status?.toString().toUpperCase());
const isFail = (r) => ["FAIL", "FAILED"].includes(r.status?.toString().toUpperCase());

/** compliance: the session's `compliance` (GET /api/audit/sessions/{id}); results: its result rows. */
export function auditScore(compliance, results) {
    const rows = Array.isArray(results) ? results : [];
    let passed, failed, total, pct;
    if (compliance && compliance.scored != null) {
        passed = compliance.scored_passed || 0;
        failed = compliance.scored_failed || 0;
        total = compliance.results ?? rows.length;
        pct = compliance.compliance_pct;
    } else {
        // an older server: the same rule over the rows
        const scored = rows.filter((r) => !r.policy && (r.level || "").toUpperCase() !== "INFO");
        passed = scored.filter(isPass).length;
        failed = scored.filter(isFail).length;
        total = rows.length || compliance?.total_checks || 0;
        pct = compliance?.compliance_pct;
    }
    const scored = passed + failed;
    const conformity = scored ? Math.round(pct ?? (100 * passed) / scored) : 0;
    return {
        total,
        passed,
        failed,
        scored,
        notScored: Math.max(total - scored, 0),
        conformity,
        nonConformity: scored ? 100 - conformity : 0,
        // what hardening can fix: every failed row, optional ones included
        failedRows: rows.filter(isFail).length || compliance?.failed || 0,
    };
}

export default auditScore;
