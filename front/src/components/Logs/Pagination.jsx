import React from "react";

/**
 * Page bar for client-side paginated tables.
 *
 * Shows first/last and a window around the current page, with ellipses in
 * between, so the control stays a fixed width however many pages there are.
 */
const pageWindow = (current, total) => {
    if (total <= 7) {
        return Array.from({ length: total }, (_, i) => i + 1);
    }
    const pages = [1];
    const from = Math.max(2, current - 1);
    const to = Math.min(total - 1, current + 1);

    if (from > 2) pages.push("…");
    for (let p = from; p <= to; p += 1) pages.push(p);
    if (to < total - 1) pages.push("…");

    pages.push(total);
    return pages;
};

export const Pagination = ({
    page,
    pageSize,
    totalItems,
    onPageChange,
    onPageSizeChange,
    pageSizeOptions = [25, 50, 100],
}) => {
    const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
    if (totalItems === 0) return null;

    const firstRow = (page - 1) * pageSize + 1;
    const lastRow = Math.min(page * pageSize, totalItems);

    return (
        <div className="pagination">
            <span className="pagination-info">
                {firstRow}–{lastRow} of {totalItems}
            </span>

            <div className="pagination-pages">
                <button
                    type="button"
                    className="pagination-btn"
                    onClick={() => onPageChange(page - 1)}
                    disabled={page <= 1}
                    aria-label="Previous page"
                >
                    ‹
                </button>

                {pageWindow(page, totalPages).map((entry, i) =>
                    entry === "…" ? (
                        <span key={`gap-${i}`} className="pagination-gap">
                            …
                        </span>
                    ) : (
                        <button
                            key={entry}
                            type="button"
                            className={`pagination-btn ${entry === page ? "is-active" : ""}`}
                            onClick={() => onPageChange(entry)}
                            aria-current={entry === page ? "page" : undefined}
                        >
                            {entry}
                        </button>
                    )
                )}

                <button
                    type="button"
                    className="pagination-btn"
                    onClick={() => onPageChange(page + 1)}
                    disabled={page >= totalPages}
                    aria-label="Next page"
                >
                    ›
                </button>
            </div>

            {onPageSizeChange && (
                <label className="pagination-size">
                    Rows
                    <select
                        value={pageSize}
                        onChange={(e) => onPageSizeChange(Number(e.target.value))}
                    >
                        {pageSizeOptions.map((size) => (
                            <option key={size} value={size}>
                                {size}
                            </option>
                        ))}
                    </select>
                </label>
            )}
        </div>
    );
};

export default Pagination;
