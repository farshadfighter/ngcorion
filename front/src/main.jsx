// src/main.jsx
import React from "react";
import ReactDOM from "react-dom/client";

// Font Awesome and Open Sans ship with the bundle rather than loading from a
// CDN: this product is installed on closed networks with no internet access,
// where a remote stylesheet leaves every icon invisible. Imported before the
// project's own CSS so those files can still override.
// Latin subsets only — the cyrillic/greek/vietnamese ones this UI never renders
// would otherwise add ~1MB of fonts to the bundle.
import "@fortawesome/fontawesome-free/css/all.min.css";
import "@fontsource/open-sans/latin-400.css";
import "@fontsource/open-sans/latin-500.css";
import "@fontsource/open-sans/latin-600.css";
import "@fontsource/open-sans/latin-700.css";

import App from "./App.jsx";
import "./assets/Login.css";
import "./assets/Dashboard.css";
import "./assets/UserManagement.css";

ReactDOM.createRoot(document.getElementById("root")).render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);
