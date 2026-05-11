import React from 'react';

const alertStyles = {
    overlay: {
        position: 'fixed',
        inset: 0,
        background: 'rgba(10, 20, 40, 0.45)',
        backdropFilter: 'blur(3px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 2000,
    },
    modal: {
        background: '#ffffff',
        borderRadius: '16px',
        width: '90%',
        maxWidth: '420px',
        boxShadow: '0 24px 60px rgba(10,20,40,0.18)',
        overflow: 'hidden',
        fontFamily: "'DM Sans', 'Segoe UI', sans-serif",
    },
    header: {
        background: 'linear-gradient(135deg, #1e3a5f 0%, #2d5490 100%)',
        padding: '18px 24px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
    },
    headerIcon: {
        width: '36px',
        height: '36px',
        borderRadius: '10px',
        background: 'rgba(255,255,255,0.15)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
    },
    headerTitle: {
        margin: 0,
        fontSize: '16px',
        fontWeight: 600,
        color: '#ffffff',
    },
    body: {
        padding: '24px',
    },
    message: {
        fontSize: '14px',
        color: '#374151',
        lineHeight: 1.6,
        margin: 0,
    },
    footer: {
        padding: '0 24px 20px',
        display: 'flex',
        justifyContent: 'flex-end',
    },
    btnOk: {
        padding: '10px 32px',
        borderRadius: '10px',
        border: 'none',
        background: 'linear-gradient(135deg, #1e3a5f, #2d5490)',
        color: 'white',
        fontSize: '14px',
        fontWeight: 600,
        cursor: 'pointer',
        boxShadow: '0 4px 12px rgba(30,58,95,0.3)',
        transition: 'opacity 0.15s',
    },
};

// آیکون بر اساس نوع
const icons = {
    success: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4ade80" strokeWidth="2.5">
            <path d="M20 6L9 17l-5-5" />
        </svg>
    ),
    error: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2.5">
            <circle cx="12" cy="12" r="10" />
            <path d="M15 9l-6 6M9 9l6 6" />
        </svg>
    ),
    warning: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" strokeWidth="2.5">
            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            <path d="M12 9v4M12 17h.01" />
        </svg>
    ),
    info: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#93c5fd" strokeWidth="2.5">
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4M12 8h.01" />
        </svg>
    ),
};

const titles = {
    success: 'Success',
    error: 'Error',
    warning: 'Warning',
    info: 'Information',
};

/**
 * ConfirmAlert — جایگزین alert() مرورگر
 *
 * Props:
 *   message  : string   — متن پیام
 *   type     : 'success' | 'error' | 'warning' | 'info'  (پیش‌فرض: 'info')
 *   onClose  : function — تابعی که موقع بستن صدا زده میشه
 */
const ConfirmAlert = ({ message, type = 'info', onClose }) => {
    if (!message) return null;

    return (
        <div style={alertStyles.overlay} onClick={onClose}>
            <div style={alertStyles.modal} onClick={(e) => e.stopPropagation()}>

                {/* Header */}
                <div style={alertStyles.header}>
                    <div style={alertStyles.headerIcon}>
                        {icons[type]}
                    </div>
                    <h3 style={alertStyles.headerTitle}>{titles[type]}</h3>
                </div>

                {/* Body */}
                <div style={alertStyles.body}>
                    <p style={alertStyles.message}>{message}</p>
                </div>

                {/* Footer */}
                <div style={alertStyles.footer}>
                    <button
                        style={alertStyles.btnOk}
                        onClick={onClose}
                        onMouseEnter={e => e.target.style.opacity = '0.85'}
                        onMouseLeave={e => e.target.style.opacity = '1'}
                    >
                        OK
                    </button>
                </div>

            </div>
        </div>
    );
};

export default ConfirmAlert;