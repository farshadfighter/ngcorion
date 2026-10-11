/**
 * Password helpers for the temporary-password dialog (TempPasswordModal.jsx): a generator and the
 * password policy checked in the browser before the server checks it again.
 */
import { t } from "../../i18n";

const SETS = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*-_=+?"];

/** A uniform random integer in [0, n) from the browser's CSPRNG (rejection sampling: no modulo bias). */
function randomBelow(n) {
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / n) * n;
    do crypto.getRandomValues(buf); while (buf[0] >= limit);
    return buf[0] % n;
}

/** 16 characters from the CSPRNG, at least one of each kind the password policy asks for, shuffled. */
export function generatePassword(length = 16) {
    const all = SETS.join("");
    const out = SETS.map((chars) => chars[randomBelow(chars.length)]);
    while (out.length < length) out.push(all[randomBelow(all.length)]);
    for (let i = out.length - 1; i > 0; i -= 1) {
        const j = randomBelow(i + 1);
        [out[i], out[j]] = [out[j], out[i]];
    }
    return out.join("");
}

/** The password policy (app/schemas/user.py validate_password_strength), checked before sending. */
export function policyProblems(password) {
    const problems = [];
    if (password.length < 8) problems.push(t("At least 8 characters"));
    if (!/[A-Z]/.test(password)) problems.push(t("An uppercase letter"));
    if (!/[a-z]/.test(password)) problems.push(t("A lowercase letter"));
    if (!/\d/.test(password)) problems.push(t("A digit"));
    if (!/[!@#$%^&*()_+=\-[\]{};':"\\|,.<>/?]/.test(password)) problems.push(t("A special character"));
    return problems;
}
