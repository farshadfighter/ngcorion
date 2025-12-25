export const DeleteConfirmModal = ({ user, onConfirm, onCancel }) => {
    return (
        <div className="modal-overlay" onClick={onCancel}>
            <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Confirm Delete</h3>
                    <button className="modal-close" onClick={onCancel}>✕</button>
                </div>

                <div className="modal-body">
                    <p>Are you sure you want to delete user <strong>{user.username}</strong>?</p>
                    <p className="warning-text">This action cannot be undone.</p>
                </div>

                <div className="modal-actions">
                    <button className="btn-cancel" onClick={onCancel}>
                        Cancel
                    </button>
                    <button className="btn-delete" onClick={onConfirm}>
                        Delete
                    </button>
                </div>
            </div>
        </div>
    );
};