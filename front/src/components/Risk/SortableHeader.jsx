import React from "react";

/**
 * Table header cell. Columns with a `key` are clickable and cycle
 * desc -> asc -> desc; the rest render as plain headings.
 *
 * Sorting is done by the backend (GET /api/risk/assets?sort_by=…), so the arrow
 * reflects the query that produced the current rows, not a client-side sort.
 */
export const SortableHeader = ({ columns, sortBy, sortOrder, onSort }) => (
    <thead>
        <tr>
            {columns.map((col) => {
                const label = typeof col === "string" ? col : col.label;
                const key = typeof col === "string" ? null : col.key;
                const isActive = key && key === sortBy;

                if (!key) return <th key={label}>{label}</th>;

                return (
                    <th
                        key={label}
                        className={`risk-th-sortable${isActive ? " is-active" : ""}`}
                        onClick={() => onSort(key)}
                        title={`Sort by ${label}`}
                        aria-sort={
                            isActive
                                ? sortOrder === "asc"
                                    ? "ascending"
                                    : "descending"
                                : "none"
                        }
                    >
                        {label}
                        <i
                            className={`fa-solid risk-sort-icon ${
                                isActive
                                    ? sortOrder === "asc"
                                        ? "fa-arrow-up-short-wide"
                                        : "fa-arrow-down-wide-short"
                                    : "fa-sort"
                            }`}
                            aria-hidden="true"
                        />
                    </th>
                );
            })}
        </tr>
    </thead>
);

export default SortableHeader;
