import { t } from "../../i18n";
import { tx } from "../../i18n/tx";
export const DeleteConfirmModal = ({ user, onConfirm, onCancel }) => {
    return (
        <div className="modal-overlay" onClick={onCancel} >
            <div className="modal-content modal-small"  onClick={(e) => e.stopPropagation()} >
                <div className="modal-header">
                    <h3>{t("Confirm Delete")}</h3>
                    <button className="modal-close" onClick={onCancel}>✕</button>
                </div>

                <div className="modal-body">
                    <p>{tx("Are you sure you want to delete user {{name}}?", { name: <strong>{user.username}</strong> })}</p>
                    <p className="warning-text">{t("This action cannot be undone.")}</p>
                </div>

                <div className="modal-actions">
                    <button className="btn-cancel" onClick={onCancel}>
                       {t("Cancel")}
                    </button>
                    <button className="btn-delete" onClick={onConfirm} style={{ backgroundColor: "#0A234E",paddingInlineStart: 23, paddingInlineEnd: 23,color: "white"
                    }}
                    >
                       {t("Delete")}
                    </button>
                </div>
            </div>
        </div>
    );
};