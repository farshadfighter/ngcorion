/**
 * Date fields that follow the interface language. In English: the browser's own date input. In
 * Persian: the date in the Jalali calendar with Persian digits ("۱۴۰۵/۰۷/۱۹"), typed or picked from a
 * month calendar that starts on Saturday.
 *
 * Either way the value going in and out is the ISO date the API uses ("2026-10-11"), and onChange
 * receives { target: { name, value } } like an input's change event, so a form's own handler
 * (handleChange(e) reading e.target.name / e.target.value) works unchanged.
 *
 * DateTimeInput does the same for "2026-10-11T14:30" (an <input type="datetime-local"> value): a
 * date field as above plus the browser's time field, which has no calendar.
 */
import React, { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { currentLanguage, t } from "../../i18n";
import {
    JALALI_MONTHS, PERSIAN_WEEKDAYS, PERSIAN_WEEKDAY_NAMES, formatJalali, isoToJalali, jalaliMonthLength,
    jalaliToIso, parseJalali, persianWeekday, toPersianDigits, todayIso,
} from "../../utils/jalali.js";
import "../../assets/DateInput.css";

const changeEvent = (name, value) => ({ target: { name, value }, currentTarget: { name, value } });

const inRange = (iso, min, max) => (!min || iso >= min) && (!max || iso <= max);

/** The days of one Jalali month laid out in weeks (Saturday first); null fills the gaps. */
function monthGrid(jy, jm) {
    const first = jalaliToIso(jy, jm, 1);
    const cells = Array(persianWeekday(first)).fill(null);
    for (let d = 1; d <= jalaliMonthLength(jy, jm); d += 1) cells.push(jalaliToIso(jy, jm, d));
    while (cells.length % 7) cells.push(null);
    return cells;
}

/** Move an ISO date by whole days, staying in the calendar's arithmetic (no time zones). */
function addDays(iso, days) {
    const [y, m, d] = iso.split("-").map(Number);
    const date = new Date(Date.UTC(y, m - 1, d + days));
    return date.toISOString().slice(0, 10);
}

function Calendar({ value, min, max, onPick, onClose, anchor }) {
    const today = todayIso();
    const start = isoToJalali(value) || isoToJalali(today);
    const [view, setView] = useState({ jy: start.jy, jm: start.jm });
    const [focus, setFocus] = useState(value || today);
    const [pos, setPos] = useState(null);
    const panel = useRef(null);

    // Open below the field, or above it when there is no room; follow it when the page scrolls.
    useLayoutEffect(() => {
        const place = () => {
            const box = anchor.current?.getBoundingClientRect();
            const height = panel.current?.offsetHeight || 320;
            const width = panel.current?.offsetWidth || 280;
            if (!box) return;
            const below = box.bottom + 4 + height <= window.innerHeight || box.top < height + 4;
            const rtl = document.documentElement.dir === "rtl";
            let left = rtl ? box.right - width : box.left;
            left = Math.max(8, Math.min(left, window.innerWidth - width - 8));
            setPos({ top: below ? box.bottom + 4 : box.top - height - 4, left });
        };
        place();
        window.addEventListener("scroll", place, true);
        window.addEventListener("resize", place);
        return () => {
            window.removeEventListener("scroll", place, true);
            window.removeEventListener("resize", place);
        };
    }, [anchor]);

    // A click anywhere else closes it.
    useEffect(() => {
        const away = (e) => {
            if (!panel.current?.contains(e.target) && !anchor.current?.contains(e.target)) onClose(false);
        };
        document.addEventListener("mousedown", away);
        return () => document.removeEventListener("mousedown", away);
    }, [anchor, onClose]);

    useEffect(() => {
        panel.current?.querySelector(`[data-iso="${focus}"]`)?.focus();
    }, [focus, view]);

    const shift = (months) => setView(({ jy, jm }) => {
        const index = jy * 12 + (jm - 1) + months;
        return { jy: Math.floor(index / 12), jm: (index % 12) + 1 };
    });

    const moveFocus = (days) => {
        const next = addDays(focus, days);
        const j = isoToJalali(next);
        setView({ jy: j.jy, jm: j.jm });
        setFocus(next);
    };

    const onKey = (e) => {
        const keys = { ArrowRight: -1, ArrowLeft: 1, ArrowUp: -7, ArrowDown: 7 }; // right-to-left week
        if (keys[e.key] !== undefined) {
            e.preventDefault();
            moveFocus(keys[e.key]);
        } else if (e.key === "PageUp" || e.key === "PageDown") {
            e.preventDefault();
            shift(e.key === "PageUp" ? -1 : 1);
        } else if (e.key === "Escape") {
            e.preventDefault();
            onClose(true);
        }
    };

    const cells = monthGrid(view.jy, view.jm);
    const label = `${JALALI_MONTHS[view.jm - 1]} ${toPersianDigits(view.jy)}`;

    return createPortal(
        <div ref={panel} className="di-panel" role="dialog" aria-modal="false" aria-label={t("Choose a date")}
             dir="rtl" style={pos ? { top: pos.top, left: pos.left } : { visibility: "hidden" }} onKeyDown={onKey}>
            <div className="di-head">
                <button type="button" className="di-nav" onClick={() => shift(-1)} aria-label={t("Previous month")}>
                    <i className="fa-solid fa-chevron-right" aria-hidden="true" />
                </button>
                <span className="di-title" aria-live="polite">{label}</span>
                <button type="button" className="di-nav" onClick={() => shift(1)} aria-label={t("Next month")}>
                    <i className="fa-solid fa-chevron-left" aria-hidden="true" />
                </button>
            </div>
            <div className="di-grid" role="grid" aria-label={label}>
                {PERSIAN_WEEKDAYS.map((d, i) => (
                    <span key={d} className="di-weekday" role="columnheader" title={PERSIAN_WEEKDAY_NAMES[i]}>{d}</span>
                ))}
                {cells.map((iso, i) => {
                    if (!iso) return <span key={`gap-${i}`} className="di-gap" />;
                    const allowed = inRange(iso, min, max);
                    const classes = ["di-day", iso === value && "is-selected", iso === today && "is-today",
                        i % 7 === 6 && "is-friday"].filter(Boolean).join(" ");
                    return (
                        <button key={iso} type="button" data-iso={iso} className={classes} disabled={!allowed}
                                tabIndex={iso === focus ? 0 : -1} aria-pressed={iso === value}
                                aria-label={formatJalali(iso)} onClick={() => onPick(iso)}>
                            {toPersianDigits(isoToJalali(iso).jd)}
                        </button>
                    );
                })}
            </div>
            <div className="di-foot">
                <button type="button" className="di-link" disabled={!inRange(today, min, max)} onClick={() => onPick(today)}>
                    {t("Today")}
                </button>
                <button type="button" className="di-link" onClick={() => onPick("")}>{t("Clear")}</button>
            </div>
        </div>,
        document.body,
    );
}

function JalaliDateInput({ value = "", onChange, name, id, className = "", min, max, disabled, required,
                           placeholder, "aria-label": ariaLabel, style }) {
    const shown = formatJalali(value);
    const [text, setText] = useState(shown);
    const [invalid, setInvalid] = useState(false);
    const [open, setOpen] = useState(false);
    const wrap = useRef(null);
    const field = useRef(null);
    const ownId = useId();

    // A new value from the form (a reset, a load) replaces what was typed. Comparing during render
    // (not in an effect) keeps the text and the value from ever showing different dates.
    const [lastShown, setLastShown] = useState(shown);
    if (shown !== lastShown) {
        setLastShown(shown);
        setText(shown);
        setInvalid(false);
    }

    const commit = (iso) => {
        setText(formatJalali(iso));
        setInvalid(false);
        if (iso !== value) onChange?.(changeEvent(name, iso));
    };

    // Typed text becomes the value when the field is left or Enter is pressed.
    const settle = () => {
        const iso = parseJalali(text);
        if (iso === "" && !required) return commit("");
        if (iso && inRange(iso, min, max)) return commit(iso);
        setInvalid(text.trim() !== "" || required);
    };

    const close = (refocus) => {
        setOpen(false);
        if (refocus) field.current?.focus();
    };

    return (
        <span ref={wrap} className={`di-wrap ${invalid ? "is-invalid" : ""}`} style={style}>
            <input ref={field} id={id || ownId} type="text" inputMode="numeric" dir="ltr" autoComplete="off"
                   className={`${className} di-field`} name={name} value={text} disabled={disabled}
                   required={required} aria-label={ariaLabel} aria-invalid={invalid || undefined}
                   placeholder={placeholder || t("yyyy/mm/dd")} title={invalid ? t("Enter a date such as 1405/07/19") : undefined}
                   onChange={(e) => { setText(e.target.value); setInvalid(false); }}
                   onBlur={settle}
                   onKeyDown={(e) => {
                       if (e.key === "Enter") { e.preventDefault(); settle(); }
                       if (e.key === "ArrowDown" && e.altKey) { e.preventDefault(); setOpen(true); }
                   }} />
            <button type="button" className="di-toggle" disabled={disabled} aria-haspopup="dialog" aria-expanded={open}
                    aria-label={t("Choose a date")} onClick={() => setOpen((o) => !o)}>
                <i className="fa-regular fa-calendar" aria-hidden="true" />
            </button>
            {open && (
                <Calendar value={value} min={min} max={max} anchor={wrap} onClose={close}
                          onPick={(iso) => { commit(iso); close(true); }} />
            )}
        </span>
    );
}

/** A date field: the browser's in English, Jalali in Persian. Value and onChange as an <input type="date">. */
export function DateInput(props) {
    if (currentLanguage() !== "fa") {
        const { value = "", ...rest } = props;
        return <input type="date" value={value} {...rest} />;
    }
    return <JalaliDateInput {...props} />;
}

/** A date and time field; value and onChange as an <input type="datetime-local"> ("2026-10-11T14:30"). */
export function DateTimeInput({ value = "", onChange, name, className = "", style, disabled, min, max, ...rest }) {
    if (currentLanguage() !== "fa") {
        return <input type="datetime-local" value={value} onChange={onChange} name={name} className={className}
                      style={style} disabled={disabled} min={min} max={max} {...rest} />;
    }
    const [date, time = ""] = (value || "").split("T");
    const emit = (d, tm) => onChange?.(changeEvent(name, d ? `${d}T${tm || "00:00"}` : ""));
    return (
        <span className="di-datetime">
            <JalaliDateInput value={date} className={className} style={style} disabled={disabled}
                             min={min?.slice(0, 10)} max={max?.slice(0, 10)} aria-label={rest["aria-label"]}
                             onChange={(e) => emit(e.target.value, time)} />
            <input type="time" dir="ltr" className={`${className} di-time`} style={style} value={time.slice(0, 5)}
                   disabled={disabled || !date} aria-label={t("Time")} onChange={(e) => emit(date, e.target.value)} />
        </span>
    );
}

export default DateInput;
