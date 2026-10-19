import React from "react";
import { t } from "../i18n";

/**
 * Keeps one page's crash inside that page: the menu and header stay, and the page shows what happened
 * with a way back, instead of the whole window going white. DashboardLayout keys it by the address, so
 * moving to another page starts clean. A page chunk missing after an update (the browser still holds
 * the old file names) lands here too, and reloading fixes it.
 */
export class PageErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { error: null };
    }

    static getDerivedStateFromError(error) {
        return { error };
    }

    componentDidCatch(error, info) {
        console.error("[page] render failed", error, info?.componentStack);
    }

    render() {
        const { error } = this.state;
        if (!error) return this.props.children;
        return (
            <div className="page-crash" role="alert">
                <h2>{t("This page ran into a problem")}</h2>
                <p>{t("Nothing was lost: what was saved stays saved. Reload the page; if it happens again, tell your administrator what you did just before.")}</p>
                <div className="page-crash-actions">
                    <button type="button" className="page-crash-btn is-primary" onClick={() => window.location.reload()}>
                        {t("Reload page")}
                    </button>
                    <button type="button" className="page-crash-btn" onClick={() => window.history.back()}>
                        {t("Go back")}
                    </button>
                </div>
                <details>
                    <summary>{t("Technical details")}</summary>
                    <pre dir="ltr">{String(error?.message || error)}</pre>
                </details>
            </div>
        );
    }
}

export default PageErrorBoundary;
