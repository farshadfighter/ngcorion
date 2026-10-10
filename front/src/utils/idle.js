// Shared by IdleLogout (signs out after inactivity) and Login (learns the timeout from the server
// and shows the notice after an idle sign-out).
export const IDLE_MINUTES_KEY = "idleTimeoutMinutes";
export const IDLE_NOTICE_KEY = "signedOutForInactivity";

export const idleMinutes = () => {
    const stored = Number(localStorage.getItem(IDLE_MINUTES_KEY));
    return stored > 0 ? stored : 30;
};
