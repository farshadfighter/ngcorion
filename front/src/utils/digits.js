/** Persian or Arabic-Indic digits (typed on a Persian keyboard) as the ASCII digits the server reads. */
export const asciiDigits = (s) => String(s || "")
    .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06F0))
    .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660));
