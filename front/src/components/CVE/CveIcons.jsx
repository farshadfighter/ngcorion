// Stroke icons used by the CVE pages (24px grid, currentColor).
const PATHS = {
    check: "m5 12 5 5 9-10",
    x: "M6 6l12 12M18 6 6 18",
    warn: "M12 3 2 21h20L12 3ZM12 10v5m0 3v.01",
    cloud: "M7 18.5a4.5 4.5 0 0 1-.4-9 6 6 0 0 1 11.3 1.3A3.9 3.9 0 0 1 17.5 18.5zM12 10v6M9.5 13.5 12 16l2.5-2.5",
    package: "M4 7.5 12 3l8 4.5v9L12 21l-8-4.5zM4 7.5l8 4.5 8-4.5M12 12v9",
    upload: "M12 16V4M7.5 8.5 12 4l4.5 4.5M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3",
    download: "M12 4v12M7.5 11.5 12 16l4.5-4.5M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3",
    database: "M5.5 6.5c0-1.4 2.9-2.5 6.5-2.5s6.5 1.1 6.5 2.5S15.6 9 12 9 5.5 7.9 5.5 6.5zM5.5 6.5v11c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5v-11M5.5 12c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5",
    search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-3.5-3.5",
    key: "M14.5 3a6.5 6.5 0 0 0-6.2 8.4L3 16.7V21h4.3v-2.2h2.2v-2.2h2.2l1-1A6.5 6.5 0 1 0 14.5 3zM16.5 7.5h.01",
    shield: "M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3z",
    flame: "M12 21c-3.9 0-7-2.7-7-6.6 0-3.1 2.2-5.3 3.6-6.8.4 1.6 1.4 2.8 2.6 3.2C11 7.6 12.4 5 15 3c-.3 3 1.8 4.6 3 6.6.7 1.2 1 2.4 1 3.8 0 4.4-3.1 7.6-7 7.6z",
    plus: "M12 5v14M5 12h14",
    trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
    copy: "M9 9h10v10H9zM5 15V5h10",
    refresh: "M20 11a8 8 0 0 0-14.9-3.9M4 4v4h4M4 13a8 8 0 0 0 14.9 3.9M20 20v-4h-4",
    link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
    chevron: "m9 6 6 6-6 6",
    clock: "M12 7v5l3 2M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",
    external: "M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5",
};

export function Icon({ name, size = 18, stroke = "currentColor", width = 2, style }) {
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth={width}
             strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={style}>
            <path d={PATHS[name] || ""} />
        </svg>
    );
}
