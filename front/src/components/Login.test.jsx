import { describe, expect, it } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { Provider } from "react-redux";
import { configureStore, createSlice } from "@reduxjs/toolkit";
import { MemoryRouter } from "react-router-dom";
import { Login } from "./Login.jsx";

// A stand-in auth slice: Login only reads isLoading / error / token and
// dispatches clearError (type "auth/clearError").
const auth = createSlice({
    name: "auth",
    initialState: { isLoading: false, error: null, token: null },
    reducers: {
        clearError: (s) => { s.error = null; },
        fail: (s, a) => { s.error = a.payload; },
    },
});

const setup = () => {
    const store = configureStore({ reducer: { auth: auth.reducer } });
    render(<Provider store={store}><MemoryRouter><Login /></MemoryRouter></Provider>);
    return store;
};

describe("Login error dialog", () => {
    it("is hidden until a login fails", () => {
        setup();
        expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("opens when an error arrives and closes again", () => {
        const store = setup();
        act(() => { store.dispatch(auth.actions.fail("Invalid username or password")); });
        expect(screen.getByRole("dialog")).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: /ok|close|try again/i }));
        expect(screen.queryByRole("dialog")).toBeNull();
    });
});
