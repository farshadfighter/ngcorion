import { describe, expect, it } from "vitest";

import reducer, { cancelMfa, loginMfa, loginUser, sessionReplaced } from "./authSlice";
import { asciiDigits } from "../utils/digits";

const session = {
    access_token: "tok", token_type: "bearer", username: "sara", role: "manager",
    permissions: {}, language: "fa", language_chosen: true, must_change_password: false,
};

describe("two-step sign-in in the auth slice", () => {
    it("a password answer that asks for a code opens no session", () => {
        const s = reducer(undefined, loginUser.fulfilled({ mfa_required: true, mfa_token: "m", username: "sara" }));
        expect(s.token).toBeNull();
        expect(s.mfaChallenge).toEqual({ token: "m", username: "sara" });
        expect(reducer(s, cancelMfa()).mfaChallenge).toBeNull();
    });

    it("the code step opens the session and carries the recovery-code warning", () => {
        let s = reducer(undefined, loginUser.fulfilled({ mfa_required: true, mfa_token: "m", username: "sara" }));
        s = reducer(s, loginMfa.fulfilled({ ...session, mfa_recovery_codes_left: 3 }));
        expect(s.token).toBe("tok");
        expect(s.mfaChallenge).toBeNull();
        expect(s.recoveryCodesLeft).toBe(3);
    });

    it("an expired step goes back to the password", () => {
        let s = reducer(undefined, loginUser.fulfilled({ mfa_required: true, mfa_token: "m", username: "sara" }));
        s = reducer(s, loginMfa.rejected(null, "", {}, { expired: true, message: "expired" }));
        expect(s.mfaChallenge).toBeNull();
        expect(s.error).toBe("expired");
    });

    it("setup due at sign-in, cleared by the fresh session after setup", () => {
        let s = reducer(undefined, loginUser.fulfilled({ ...session, mfa_enrolment_due: true }));
        expect(s.mfaEnrolmentDue).toBe(true);
        s = reducer(s, sessionReplaced({ ...session, access_token: "new" }));
        expect(s.mfaEnrolmentDue).toBe(false);
        expect(s.token).toBe("new");
    });
});

describe("digits typed on a Persian keyboard", () => {
    it("become ASCII", () => {
        expect(asciiDigits("۱۲۳٤٥٦")).toBe("123456");
        expect(asciiDigits("ab-12")).toBe("ab-12");
    });
});
