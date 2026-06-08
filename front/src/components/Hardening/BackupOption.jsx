import React from 'react';

// Optional configuration backup toggle for Cisco/Fortinet hardening.
// Taking a backup connects to the device and pulls the running config before
// applying changes, which adds time to every run. Leaving it unchecked skips
// that step so hardening completes faster. Shared by FixSingleModal and
// HardenAllModal to keep the wording and behaviour identical.
const BackupOption = ({ checked, onChange }) => (
    <label
        style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
            marginTop: '16px',
            padding: '12px 14px',
            background: '#f8f9fb',
            border: '1px solid #e8edf5',
            borderRadius: '8px',
            cursor: 'pointer',
        }}
    >
        <input
            type="checkbox"
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            style={{ marginTop: '2px', cursor: 'pointer' }}
        />
        <span style={{ fontSize: '13px', color: '#1f2937', lineHeight: '1.5' }}>
            <strong>Back up device configuration before hardening</strong>
            <span style={{ display: 'block', color: '#6b7280', fontSize: '12px', marginTop: '2px' }}>
                Recommended for rollback. Leave unchecked to skip the backup and run faster.
            </span>
        </span>
    </label>
);

export default BackupOption;
