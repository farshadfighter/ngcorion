import { t } from "../../i18n";
// Asset Management has no license entitlement — plans only track Auditing
// and Hardening. Keep this in sync with the backend catalog:
// license_server/app/crud.py (get_plan_limits) / license_server/app/models.py
// (PlanType enum).
export const LICENSE_TYPES = {
    pilot: {
        name: t("Pilot licence"),
        color: '#6B7280',
        borderColor: '#6B7280',
        bgColor: '#F3F4F6',
        limits: {
            hardening: 2,
            auditing: 2,
        },
        duration: t("1 month"),
    },
    plan_100: {
        name: t("{{count}} audits / {{count}} hardenings", { count: 100 }),
        color: '#3B82F6',
        borderColor: '#3B82F6',
        bgColor: '#EFF6FF',
        limits: {
            hardening: 100,
            auditing: 100,
        },
        duration: t("1 year"),
    },
    plan_250: {
        name: t("{{count}} audits / {{count}} hardenings", { count: 250 }),
        color: '#10B981',
        borderColor: '#10B981',
        bgColor: '#ECFDF5',
        limits: {
            hardening: 250,
            auditing: 250,
        },
        duration: t("1 year"),
    },
    plan_500: {
        name: t("{{count}} audits / {{count}} hardenings", { count: 500 }),
        color: '#F59E0B',
        borderColor: '#F59E0B',
        bgColor: '#FFFBEB',
        limits: {
            hardening: 500,
            auditing: 500,
        },
        duration: t("1 year"),
    },
    unlimited: {
        name: t("Unlimited licence"),
        color: '#8B5CF6',
        borderColor: '#8B5CF6',
        bgColor: '#F5F3FF',
        limits: {
            hardening: Infinity,
            auditing: Infinity,
        },
        duration: t("1 year"),
    },
};

export const MODULE_LABELS = {
    hardening: t("Hardening"),
    auditing: t("Auditing"),
};

export const MODULE_ICONS = {
    hardening: 'fa-shield-halved',
    auditing: 'fa-clipboard-list',
};

export const API_FIELD_MAP = {
    hardening: { used: 'used_hardens', max: 'max_hardens' },
    auditing: { used: 'used_audits', max: 'max_audits' },
};
