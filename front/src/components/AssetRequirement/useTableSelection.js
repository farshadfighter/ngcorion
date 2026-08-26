import { useEffect, useState } from "react";

/**
 * Paging + row selection for the Asset Requirement tabs.
 *
 * All six tabs render the same shape of table, so the behaviour lives here
 * rather than being copied six times: page slicing, a "select all" that only
 * covers the rows on screen, and selection that drops ids which have gone.
 *
 * `rows` must already be filtered and sorted — this only slices the result.
 */
export const useTableSelection = (rows) => {
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);
    const [selectedIds, setSelectedIds] = useState(() => new Set());

    const list = Array.isArray(rows) ? rows : [];

    const totalPages = Math.max(1, Math.ceil(list.length / pageSize));
    const safePage = Math.min(page, totalPages);

    // Plain slice: callers pass a freshly sorted array each render, so
    // memoising on it would never hit anyway.
    const paged = list.slice((safePage - 1) * pageSize, safePage * pageSize);

    // A search or a delete can shrink the list past the current page.
    useEffect(() => {
        if (page > totalPages) setPage(1);
    }, [totalPages, page]);

    // Rows removed elsewhere must not stay selected, or the delete count and
    // the "select all" tick would both be wrong.
    //
    // Keyed on the joined ids rather than the array: callers build their list
    // with [...data].sort(), so the array identity changes on every render
    // while its contents usually do not.
    const idKey = list.map((r) => r.id).join(",");
    useEffect(() => {
        setSelectedIds((prev) => {
            if (prev.size === 0) return prev;
            const live = new Set(idKey ? idKey.split(",") : []);
            const next = new Set(
                [...prev].filter((id) => live.has(String(id)))
            );
            return next.size === prev.size ? prev : next;
        });
    }, [idKey]);

    // Scoped to the visible page: ticking rows the user cannot see would make
    // the delete count a surprise.
    const pageIds = paged.map((r) => r.id);
    const allSelected =
        pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));

    const toggleOne = (id) =>
        setSelectedIds((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });

    const toggleAll = () =>
        setSelectedIds((prev) => {
            const next = new Set(prev);
            if (allSelected) pageIds.forEach((id) => next.delete(id));
            else pageIds.forEach((id) => next.add(id));
            return next;
        });

    const clearSelection = () => setSelectedIds(new Set());

    return {
        page: safePage,
        setPage,
        pageSize,
        setPageSize: (size) => {
            setPageSize(size);
            setPage(1);
        },
        paged,
        total: list.length,
        selectedIds,
        selectedCount: selectedIds.size,
        allSelected,
        toggleOne,
        toggleAll,
        clearSelection,
    };
};

export default useTableSelection;
