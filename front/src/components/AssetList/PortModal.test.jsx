import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Provider } from "react-redux";
import { configureStore } from "@reduxjs/toolkit";
import { PortModal } from "./PortModal.jsx";

const store = configureStore({ reducer: { assets: (s = {}) => s } });
const renderModal = (props) => render(<Provider store={store}><PortModal asset={{ id: 1 }} onClose={() => {}} {...props} /></Provider>);

describe("PortModal", () => {
    it("starts empty for a new port", () => {
        renderModal({ port: null });
        expect(document.querySelector('[name="port_number"]').value).toBe("");
        expect(document.querySelector('[name="protocol"]').value).toBe("TCP");
    });

    it("shows the port being edited, and follows a switch to another port", () => {
        const { rerender } = renderModal({ port: { id: 7, protocol: "UDP", port_number: 161 } });
        expect(document.querySelector('[name="port_number"]').value).toBe("161");
        expect(document.querySelector('[name="protocol"]').value).toBe("UDP");
        rerender(<Provider store={store}><PortModal asset={{ id: 1 }} onClose={() => {}} port={{ id: 8, protocol: "TCP", port_number: 22 }} /></Provider>);
        expect(document.querySelector('[name="port_number"]').value).toBe("22");
        expect(screen.getAllByRole("combobox")[0].value).toBe("TCP");
    });
});
