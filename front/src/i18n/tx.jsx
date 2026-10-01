import { Fragment } from "react";
import { t } from "./index";

const MARK = "\u0001";

/**
 * Translate a sentence that contains elements, keeping it one sentence for
 * the translator: tx("Delete {{count}} assets?", { count: <b>3</b> }).
 * Placeholders whose value is a React element are put back as elements;
 * plain values interpolate as in t().
 */
export function tx(key, values = {}) {
    const nodes = {};
    const plain = {};
    for (const [k, v] of Object.entries(values)) {
        if (v !== null && typeof v === "object") {
            nodes[k] = v;
            plain[k] = `${MARK}${k}${MARK}`;
        } else {
            plain[k] = v;
        }
    }
    const text = t(key, plain);
    if (!Object.keys(nodes).length) return text;
    return text.split(MARK).map((part, i) => (i % 2 ? <Fragment key={i}>{nodes[part]}</Fragment> : part));
}
