export const LICENSE_TYPES = {
    pilot: {
        name: 'pilot licence',
        color: '#6B7280',
        borderColor: '#6B7280',
        bgColor: '#F3F4F6',
        limits: {
            hardening: 2,
            auditing: 2,
            assetList: 5,
            autoDiscovery: 2,
        },
        duration: '1month',
    },
    basic1: {
        name: 'base licence',
        color: '#3B82F6',
        borderColor: '#3B82F6',
        bgColor: '#EFF6FF',
        limits: {
            hardening: 15,
            auditing: 15,
            assetList: 15,
            autoDiscovery: 15,
        },
        duration: '1year',
    },
    basic2: {
        name: 'pro licence',
        color: '#10B981',
        borderColor: '#10B981',
        bgColor: '#ECFDF5',
        limits: {
            hardening: 50,
            auditing: 50,
            assetList: 50,
            autoDiscovery: 50,
        },
        duration: '1year',
    },
    basic3: {
        name: 'pro plus licence',
        color: '#F59E0B',
        borderColor: '#F59E0B',
        bgColor: '#FFFBEB',
        limits: {
            hardening: 150,
            auditing: 150,
            assetList: 150,
            autoDiscovery: 150,
        },
        duration: '1year',
    },
    enterprise: {
        name: 'unlimited licence',
        color: '#8B5CF6',
        borderColor: '#8B5CF6',
        bgColor: '#F5F3FF',
        limits: {
            hardening: Infinity,
            auditing: Infinity,
            assetList: Infinity,
            autoDiscovery: Infinity,
        },
        duration: '1year',
    },
};

export const MODULE_LABELS = {
    hardening: 'Hardening',
    auditing: 'Auditing',
    assetList: 'Asset list',
    autoDiscovery: 'Asset Auto Discovery',
};

export const MODULE_ICONS = {
    hardening: 'fa-shield-halved',
    auditing: 'fa-clipboard-list',
    assetList: 'fa-box-archive',
    autoDiscovery: 'fa-magnifying-glass',
};

export const API_FIELD_MAP = {
    hardening: { used: 'used_hardens', max: 'max_hardens' },
    auditing: { used: 'used_audits', max: 'max_audits' },
    assetList: { used: 'used_assets', max: 'max_assets' },
    autoDiscovery: { used: 'used_discoveries', max: 'max_discoveries' },
};

export const OPERATION_TYPES = {
    hardening: 'harden',
    auditing: 'audit',
    assetList: 'asset',
    autoDiscovery: 'discovery',
};