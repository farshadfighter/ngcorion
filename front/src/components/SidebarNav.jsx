/**
 * The sidebar menu (sidebarMenu.js has its content and order).
 *
 * Expanded: each group is a heading that opens and closes it, one group at a time: opening a group
 * closes the one that was open, and going to a page opens that page's group. Entries are real
 * links, so they can be opened in a new tab.
 * Collapsed: one icon per group; pointing at it (or focusing it) shows its entries beside it.
 */
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { n, t } from "../i18n";
import { groupOf, isActive, visibleMenu } from "./sidebarMenu";
import "../assets/SidebarNav.css";

function AlertBadge({ summary }) {
    const count = summary?.unacknowledged || 0;
    if (!count) return null;
    return (
        <span className={`alr-nav-badge ${summary?.critical ? "" : "is-calm"}`}
              aria-label={t("{{unacknowledged}} not acknowledged", { unacknowledged: count })}>
            {count > 99 ? n("99+") : n(count)}
        </span>
    );
}

export function SidebarNav({ auth, pageKey, collapsed, alertSummary }) {
    const { top, groups } = visibleMenu(auth);
    const activeGroup = groupOf(pageKey);
    const [openId, setOpenId] = useState(activeGroup ?? null);
    const [flyout, setFlyout] = useState(null); // { id, top } while a collapsed group shows its entries
    const closeTimer = useRef(null);

    useEffect(() => () => clearTimeout(closeTimer.current), []);

    // Another page (from the menu, the search, an alert's link or Back): its group opens and the
    // others close. Another page, or the rail opened or closed: no flyout left hanging. Compared
    // while rendering, so nothing shows the stale state.
    const [seenPage, setSeenPage] = useState(pageKey);
    if (seenPage !== pageKey) {
        setSeenPage(pageKey);
        setOpenId(activeGroup ?? null);
    }
    const navState = `${pageKey}|${collapsed}`;
    const [seenNav, setSeenNav] = useState(navState);
    if (seenNav !== navState) {
        setSeenNav(navState);
        setFlyout(null);
    }

    const toggle = (id) => setOpenId((current) => (current === id ? null : id));

    const showFlyout = (id, el) => {
        clearTimeout(closeTimer.current);
        setFlyout({ id, top: el.getBoundingClientRect().top });
    };
    const hideFlyout = () => {
        clearTimeout(closeTimer.current);
        closeTimer.current = setTimeout(() => setFlyout(null), 180);
    };

    const alertTitle = (item) => (item.badge === "alerts" && alertSummary?.unacknowledged
        ? t("Alerts - {{unacknowledged}} not acknowledged", { unacknowledged: alertSummary.unacknowledged })
        : item.label);

    return (
        <nav className="sidebar-nav" aria-label={t("Main menu")}>
            {top.map((item) => (
                <Link key={item.key} to={item.path} title={alertTitle(item)}
                      className={`nav-item ${isActive(item, pageKey) ? "active" : ""}`}
                      aria-current={isActive(item, pageKey) ? "page" : undefined}>
                    <img src={item.icon} alt="" className="nav-icon-img" />
                    {!collapsed && <span>{item.label}</span>}
                    {!collapsed && item.badge === "alerts" && <AlertBadge summary={alertSummary} />}
                    {collapsed && item.badge === "alerts" && alertSummary?.unacknowledged > 0 && (
                        <span className="sbn-dot" aria-hidden="true" />
                    )}
                </Link>
            ))}

            {groups.map((group) => {
                const isOpen = group.id === openId;
                const holdsActive = group.id === activeGroup;
                const listId = `sbn-${group.id}`;

                if (collapsed) {
                    return (
                        <div key={group.id} className="sbn-rail"
                             onMouseEnter={(e) => showFlyout(group.id, e.currentTarget)} onMouseLeave={hideFlyout}>
                            <button type="button" className={`nav-item sbn-rail-btn ${holdsActive ? "active" : ""}`}
                                    title={group.label} aria-label={group.label} aria-haspopup="true"
                                    aria-expanded={flyout?.id === group.id}
                                    onFocus={(e) => showFlyout(group.id, e.currentTarget)}
                                    onClick={(e) => (flyout?.id === group.id ? setFlyout(null) : showFlyout(group.id, e.currentTarget))}
                                    onKeyDown={(e) => { if (e.key === "Escape") setFlyout(null); }}>
                                <img src={group.icon} alt="" className="nav-icon-img" />
                            </button>
                            {flyout?.id === group.id && (
                                <div className="sbn-flyout" role="menu" aria-label={group.label} style={{ top: flyout.top }}
                                     onMouseEnter={() => clearTimeout(closeTimer.current)} onMouseLeave={hideFlyout}
                                     onKeyDown={(e) => { if (e.key === "Escape") setFlyout(null); }}>
                                    <div className="sbn-flyout-title">{group.label}</div>
                                    {group.items.map((item) => (
                                        <Link key={item.key} to={item.path} role="menuitem" onBlur={hideFlyout}
                                              onFocus={() => clearTimeout(closeTimer.current)}
                                              className={`sbn-flyout-item ${isActive(item, pageKey) ? "active" : ""}`}
                                              aria-current={isActive(item, pageKey) ? "page" : undefined}>
                                            {item.label}
                                        </Link>
                                    ))}
                                </div>
                            )}
                        </div>
                    );
                }

                return (
                    <div key={group.id} className={`sbn-group ${isOpen ? "is-open" : ""}`}>
                        <button type="button" className={`nav-section sbn-head ${holdsActive ? "nav-section-active" : ""}`}
                                aria-expanded={isOpen} aria-controls={listId} title={group.label}
                                onClick={() => toggle(group.id)}>
                            <img src={group.icon} alt="" className="section-icon" />
                            <span className="nav-section-title">{group.label}</span>
                            <i className="fa-solid fa-chevron-down sbn-caret" aria-hidden="true" />
                        </button>
                        {isOpen && (
                            <div id={listId} className="sbn-items">
                                {group.items.map((item) => (
                                    <Link key={item.key} to={item.path}
                                          className={`nav-item sub-item ${isActive(item, pageKey) ? "active" : ""}`}
                                          aria-current={isActive(item, pageKey) ? "page" : undefined}>
                                        <span>{item.label}</span>
                                    </Link>
                                ))}
                            </div>
                        )}
                    </div>
                );
            })}
        </nav>
    );
}

export default SidebarNav;
