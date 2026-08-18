/**
 * IANA zone names for the Time dialog's dropdown.
 *
 * Modern browsers can enumerate the full tz database themselves; the short list
 * is the fallback for those that cannot, and leads with the zones this product
 * is actually deployed in. The backend validates the name against
 * /usr/share/zoneinfo either way.
 */
const FALLBACK = [
    "Asia/Tehran",
    "UTC",
    "Europe/London",
    "Europe/Berlin",
    "Europe/Moscow",
    "Asia/Dubai",
    "Asia/Baghdad",
    "Asia/Istanbul",
    "Asia/Kolkata",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
];

const supported =
    typeof Intl !== "undefined" && typeof Intl.supportedValuesOf === "function"
        ? (() => {
              try {
                  return Intl.supportedValuesOf("timeZone");
              } catch {
                  return null;
              }
          })()
        : null;

export const TIMEZONES =
    supported && supported.length
        ? // Keep Tehran at the top of an otherwise alphabetical list.
          ["Asia/Tehran", ...supported.filter((tz) => tz !== "Asia/Tehran")]
        : FALLBACK;

export default TIMEZONES;
