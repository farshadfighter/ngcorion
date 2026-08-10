// Asset Management has no license entitlement — plans only track Auditing
// and Hardening. Keep this in sync with the backend catalog:
// license_server/app/crud.py (get_plan_limits) / license_server/app/models.py
// (PlanType enum).
export const LICENSE_TYPES = {
    pilot: {
        name: 'pilot licence',
        color: '#6B7280',
        borderColor: '#6B7280',
        bgColor: '#F3F4F6',
        limits: {
            hardening: 2,
            auditing: 2,
        },
        duration: '1month',
    },
    plan_100: {
        name: '100 audit / 100 hardening',
        color: '#3B82F6',
        borderColor: '#3B82F6',
        bgColor: '#EFF6FF',
        limits: {
            hardening: 100,
            auditing: 100,
        },
        duration: '1year',
    },
    plan_250: {
        name: '250 audit / 250 hardening',
        color: '#10B981',
        borderColor: '#10B981',
        bgColor: '#ECFDF5',
        limits: {
            hardening: 250,
            auditing: 250,
        },
        duration: '1year',
    },
    plan_500: {
        name: '500 audit / 500 hardening',
        color: '#F59E0B',
        borderColor: '#F59E0B',
        bgColor: '#FFFBEB',
        limits: {
            hardening: 500,
            auditing: 500,
        },
        duration: '1year',
    },
    unlimited: {
        name: 'unlimited licence',
        color: '#8B5CF6',
        borderColor: '#8B5CF6',
        bgColor: '#F5F3FF',
        limits: {
            hardening: Infinity,
            auditing: Infinity,
        },
        duration: '1year',
    },
};

export const MODULE_LABELS = {
    hardening: 'Hardening',
    auditing: 'Auditing',
};

export const MODULE_ICONS = {
    hardening: 'fa-shield-halved',
    auditing: 'fa-clipboard-list',
};

export const API_FIELD_MAP = {
    hardening: { used: 'used_hardens', max: 'max_hardens' },
    auditing: { used: 'used_audits', max: 'max_audits' },
};
