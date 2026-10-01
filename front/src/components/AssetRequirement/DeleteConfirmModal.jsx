import { t } from "../../i18n";
export const DeleteConfirmModal = ({ title, message, onConfirm, onCancel }) => {
    return (
        <div className="modal-overlay" onClick={onCancel}>
            <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{title || t("Confirm Delete")}</h2>
                    <button className="modal-close" onClick={onCancel}>
                        ×
                    </button>
                </div>

                <div className="modal-body">
                    <p className="delete-message">{message}</p>
                </div>

                <div className="modal-footer">
                    <button className="btn-cancel" onClick={onCancel}>
                       {t("Cancel")}
                    </button>
                    <button className="btn-delete-confirm" onClick={onConfirm}>
                       {t("Delete")}
                    </button>
                </div>
            </div>
        </div>
    );
};
