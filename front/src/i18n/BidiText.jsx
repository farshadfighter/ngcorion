/**
 * Shows a sentence tb() / tbDetail() translated: the Latin values in it (device, port, user names) are
 * already isolated with U+2068 ... U+2069; here each becomes a <bdi>, and a one-word value such as
 * "dist-switch-02" or "GigabitEthernet1/0/2" is kept on one line instead of breaking at its hyphen
 * or slash. Text without isolated values is returned as it is.
 */
const ISOLATED = /⁨([^⁩]*)⁩/;
const ISOLATED_ALL = /⁨[^⁩]*⁩/g;
const PERSIAN = /[؀-ۿ]/;
const ONE_LINE_MAX = 40;    // longer single words may still wrap, so they never widen a table

export function BidiText({ text }) {
    if (typeof text !== "string" || !ISOLATED.test(text)) return text ?? null;
    const parts = text.split(/⁨([^⁩]*)⁩/).map((part, i) => {
        if (i % 2 === 0) return part;
        const word = !/\s/.test(part) && part.length <= ONE_LINE_MAX;
        return <bdi key={i} className={word ? "bidi-word" : undefined}>{part}</bdi>;
    });
    // A Persian sentence that opens with a Latin word ("MAC …", "SNMP …") would otherwise be laid
    // out left to right where the surrounding cell takes its direction from its first letter.
    return PERSIAN.test(text.replace(ISOLATED_ALL, "")) ? <span dir="rtl">{parts}</span> : parts;
}

export default BidiText;
