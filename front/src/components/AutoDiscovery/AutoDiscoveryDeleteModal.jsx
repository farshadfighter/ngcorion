import React from 'react';
import '../../assets/autoDiscoveryStyle/AutoDiscoveryDeleteModal.css';

const AutoDiscoveryDeleteModal = ({ isOpen, title, message, onConfirm, onCancel }) => {
    if (!isOpen) return null;

    return (
        <div className="ad-del-modal-overlay">
            <div className="ad-del-modal-box">
                <h3 className="ad-del-modal-title">{title}</h3>
                <p className="ad-del-modal-text">{message}</p>
                <div className="ad-del-modal-actions">
                    <button className="ad-del-modal-btn-cancel" onClick={onCancel}>
                        Cancel
                    </button>
                    <button className="ad-del-modal-btn-danger" onClick={onConfirm}>
                        Delete
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AutoDiscoveryDeleteModal;
