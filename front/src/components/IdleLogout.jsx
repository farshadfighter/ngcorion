/**
 * Signs the user out after a period without keyboard, mouse or touch input
 * (the server's SESSION_IDLE_TIMEOUT_MINUTES, learned from /auth/login-banner).
 *
 * The server ends an unused session by itself, but the pages refresh on their
 * own (NOC, jobs in progress), and those requests count as use there. Only the
 * browser knows whether a person is still at the screen, so it signs out too.
 */
import { useEffect } from "react";
import { useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";
import { logoutUser } from "../store/authSlice";
import { IDLE_NOTICE_KEY, idleMinutes } from "../utils/idle";

const EVENTS = ["mousedown", "keydown", "wheel", "touchstart"];

export const IdleLogout = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();

    useEffect(() => {
        let timer;
        const arm = () => {
            clearTimeout(timer);
            timer = setTimeout(async () => {
                sessionStorage.setItem(IDLE_NOTICE_KEY, "1");
                await dispatch(logoutUser());
                navigate("/");
            }, idleMinutes() * 60 * 1000);
        };
        arm();
        EVENTS.forEach((ev) => window.addEventListener(ev, arm, { passive: true }));
        return () => {
            clearTimeout(timer);
            EVENTS.forEach((ev) => window.removeEventListener(ev, arm));
        };
    }, [dispatch, navigate]);

    return null;
};
