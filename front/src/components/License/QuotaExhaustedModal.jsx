import React, { useState, useEffect, useRef, useCallback } from 'react';

const QuotaExhaustedModal = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [message, setMessage] = useState('');
    const [isClosing, setIsClosing] = useState(false);
    const modalRef = useRef(null);
    const closeButtonRef = useRef(null);
    const upgradeButtonRef = useRef(null);

    const handleClose = useCallback(() => {
        setIsClosing(true);
        setTimeout(() => {
            setIsOpen(false);
            setMessage('');
            setIsClosing(false);
        }, 300);
    }, []);

    useEffect(() => {
        const handleQuotaExhausted = (event) => {
            setMessage(event.detail?.message || 'You have reached your quota limit.');
            setIsOpen(true);
            setIsClosing(false);
        };

        window.addEventListener('quota-exhausted', handleQuotaExhausted);

        return () => {
            window.removeEventListener('quota-exhausted', handleQuotaExhausted);
        };
    }, []);

    // Lock body scroll when modal is open
    useEffect(() => {
        if (isOpen) {
            document.body.style.overflow = 'hidden';
            // Focus first interactive element when modal opens
            setTimeout(() => {
                closeButtonRef.current?.focus();
            }, 100);
        } else {
            document.body.style.overflow = '';
        }

        return () => {
            document.body.style.overflow = '';
        };
    }, [isOpen]);

    // Handle Escape key
    useEffect(() => {
        const handleEscape = (e) => {
            if (e.key === 'Escape' && isOpen) {
                handleClose();
            }
        };

        document.addEventListener('keydown', handleEscape);
        return () => document.removeEventListener('keydown', handleEscape);
    }, [isOpen, handleClose]);

    // Focus trap
    useEffect(() => {
        if (!isOpen) return;

        const handleTab = (e) => {
            if (e.key !== 'Tab') return;

            const focusableElements = modalRef.current?.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );

            if (!focusableElements || focusableElements.length === 0) return;

            const firstElement = focusableElements[0];
            const lastElement = focusableElements[focusableElements.length - 1];

            if (e.shiftKey) {
                if (document.activeElement === firstElement) {
                    e.preventDefault();
                    lastElement.focus();
                }
            } else {
                if (document.activeElement === lastElement) {
                    e.preventDefault();
                    firstElement.focus();
                }
            }
        };

        document.addEventListener('keydown', handleTab);
        return () => document.removeEventListener('keydown', handleTab);
    }, [isOpen]);

    const handleUpgrade = () => {
        try {
            // Navigate to upgrade page or trigger upgrade flow
            window.location.href = '/license';
        } catch (error) {
            console.error('Failed to navigate to upgrade page:', error);
            // Show user-friendly error instead of alert
            setMessage('Unable to navigate to upgrade page. Please try again.');
        }
    };

    const handleBackdropClick = (e) => {
        if (e.target === e.currentTarget) {
            handleClose();
        }
    };

    if (!isOpen) return null;

    return (
        <div
            style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: 'rgba(0, 0, 0, 0.5)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 1000,
                animation: isClosing ? 'fadeOut 0.3s ease-out' : 'fadeIn 0.3s ease-out',
            }}
            onClick={handleBackdropClick}
            aria-modal="true"
            role="dialog"
            aria-labelledby="modal-title"
            aria-describedby="modal-description"
        >
            <div
                ref={modalRef}
                style={{
                    backgroundColor: 'white',
                    padding: '32px',
                    borderRadius: '8px',
                    maxWidth: '500px',
                    width: '90%',
                    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
                    animation: isClosing ? 'slideOut 0.3s ease-out' : 'slideIn 0.3s ease-out',
                }}
                onClick={(e) => e.stopPropagation()}
            >
                <h2 id="modal-title">Quota Limit Reached</h2>

                <p id="modal-description">
                    {message}
                </p>

                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '24px' }}>
                    <button
                        ref={closeButtonRef}
                        onClick={handleClose}
                    >
                        Close
                    </button>

                    <button
                        ref={upgradeButtonRef}
                        onClick={handleUpgrade}
                    >
                        Upgrade Plan
                    </button>
                </div>
            </div>
        </div>
    );
};

export default QuotaExhaustedModal;
