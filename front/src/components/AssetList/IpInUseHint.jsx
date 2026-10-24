/**
 * Under an asset form's IP field: the other assets that already have this address (their IP or one of
 * their other addresses). Saving is allowed - NAT and virtual addresses share IPs - but syslog and
 * devices seen at the address are matched to only one asset, so the form says so.
 */
import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { t } from "../../i18n";

const IPV4_OR_6 = /^[0-9a-fA-F:.]{3,45}$/;

export function IpInUseHint({ ip, excludeId }) {
    // The answer is kept with the address it is about, so one for an address since changed is not shown.
    const [answer, setAnswer] = useState({ ip: null, assets: [] });
    const value = (ip || "").trim();
    useEffect(() => {
        if (!IPV4_OR_6.test(value)) return undefined;
        const timer = setTimeout(() => {
            api.get("/api/assets/ip-in-use", { params: { ip: value, exclude_id: excludeId || undefined } })
                .then(({ data }) => setAnswer({ ip: value, assets: data?.assets || [] }))
                .catch(() => setAnswer({ ip: value, assets: [] }));
        }, 400);
        return () => clearTimeout(timer);
    }, [value, excludeId]);
    const others = answer.ip === value ? answer.assets : [];
    if (!others.length) return null;
    return (
        <span className="ip-in-use-hint" role="status">
            {t("{{address}} is also the IP address of {{assets}}. It can be saved, but syslog and devices seen at this address are matched to only one of them.",
               { address: value, assets: others.map((a) => a.asset_name).join("، ") })}
        </span>
    );
}

export default IpInUseHint;
