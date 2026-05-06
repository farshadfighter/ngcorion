import React, { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssetPorts, deleteAssetPort } from "../../store/assetSlice";
import { PortModal } from "./PortModal";

export const ManagePortsModal = ({ asset, onClose }) => {
    const dispatch = useDispatch();
    const { ports, isLoadingPorts } = useSelector((state) => state.assets);

    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [deletingPort, setDeletingPort] = useState(null);
    const [deleteError, setDeleteError] = useState(null);
    const [deleteSuccess, setDeleteSuccess] = useState(false);

    const [showPortModal, setShowPortModal] = useState(false);
    const [editingPort, setEditingPort] = useState(null);

    const hasFetchedPorts = useRef(false);

    useEffect(() => {
        if (!hasFetchedPorts.current && asset?.id) {
            dispatch(fetchAssetPorts(asset.id));
            hasFetchedPorts.current = true;
        }
    }, []);

    const handleAddPort = () => {
        setEditingPort(null);
        setShowPortModal(true);
    };

    const handleEditPort = (port) => {
        setEditingPort(port);
        setShowPortModal(true);
    };

    const handleClosePortModal = () => {
        setShowPortModal(false);
        setEditingPort(null);
    };

    const handleDelete = (port) => {
        setDeleteError(null);
        setDeleteSuccess(false);
        setDeletingPort(port);
        setShowDeleteConfirm(true);
    };

    const confirmDelete = async () => {
        if (!deletingPort) return;

        setDeleteError(null);

        try {
            await dispatch(deleteAssetPort({
                assetId: asset.id,
                portId: deletingPort.id
            })).unwrap();

            setDeleteSuccess(true);
            setShowDeleteConfirm(false);
            setDeletingPort(null);

            await dispatch(fetchAssetPorts(asset.id));

            setTimeout(() => {
                setDeleteSuccess(false);
            }, 3000);

        } catch (error) {
            setDeleteError(error.message || 'Failed to delete port');
        }
    };

    const cancelDelete = () => {
        setShowDeleteConfirm(false);
        setDeletingPort(null);
        setDeleteError(null);
    };

    return (
        <>
            <div
                style={{
                    position: 'fixed',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    background: 'rgba(0, 0, 0, 0.5)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 9999
                }}
                onClick={(e) => {
                    if (e.target === e.currentTarget) onClose();
                }}
            >
                <div
                    style={{
                        background: 'white',
                        borderRadius: '12px',
                        width: '90%',
                        maxWidth: '600px',
                        maxHeight: '85vh',
                        display: 'flex',
                        flexDirection: 'column',
                        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)'
                    }}
                    onClick={(e) => e.stopPropagation()}
                >
                    {/* Header */}
                    <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '20px 24px',
                        borderBottom: '1px solid #e5e7eb'
                    }}>
                        <h2 style={{ fontSize: '18px', fontWeight: '600', color: '#111827', margin: 0 }}>
                            Manage Ports
                        </h2>
                        <button onClick={onClose} style={{
                            background: 'none',
                            border: 'none',
                            fontSize: '24px',
                            cursor: 'pointer',
                            padding: '0',
                            color: '#6b7280'
                        }}>
                            ✕
                        </button>
                    </div>

                    {/* Success Message */}
                    {deleteSuccess && (
                        <div style={{
                            margin: '16px 24px 0',
                            padding: '12px 16px',
                            background: '#dcfce7',
                            border: '1px solid #86efac',
                            borderRadius: '8px',
                            color: '#166534',
                            fontSize: '14px',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px'
                        }}>
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                            Port deleted successfully!
                        </div>
                    )}

                    {/* Add Port Button */}
                    <div style={{ padding: '16px 24px', display: 'flex', justifyContent: 'flex-end' }}>
                        <button
                            onClick={handleAddPort}
                            style={{
                                background: '#1e3a5f',
                                color: 'white',
                                border: 'none',
                                padding: '10px 20px',
                                borderRadius: '8px',
                                fontSize: '14px',
                                fontWeight: '500',
                                cursor: 'pointer'
                            }}
                        >
                            + Add Port
                        </button>
                    </div>

                    {/* Table */}
                    <div style={{ flex: 1, overflowY: 'auto', padding: '0 24px', minHeight: '200px' }}>
                        {isLoadingPorts ? (
                            <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                                <div style={{
                                    width: '40px',
                                    height: '40px',
                                    border: '3px solid #e5e7eb',
                                    borderTopColor: '#1e3a5f',
                                    borderRadius: '50%',
                                    animation: 'spin 0.8s linear infinite',
                                    margin: '0 auto 16px'
                                }}></div>
                                Loading ports...
                            </div>
                        ) : !ports || ports.length === 0 ? (
                            <div style={{ textAlign: 'center', padding: '40px', color: '#9ca3af', fontStyle: 'italic' }}>
                                No ports added yet. Click "+ Add Port" to add one.
                            </div>
                        ) : (
                            <table style={{
                                width: '100%',
                                borderCollapse: 'collapse',
                                margin: '16px 0'
                            }}>
                                <thead>
                                <tr style={{ background: '#f9fafb' }}>
                                    <th style={{
                                        padding: '12px 16px',
                                        textAlign: 'left',
                                        fontSize: '13px',
                                        fontWeight: '600',
                                        color: '#6b7280',
                                        textTransform: 'uppercase',
                                        borderBottom: '1px solid #e5e7eb',
                                        borderRight: '1px solid #e5e7eb'  // ← خط عمودی
                                    }}>Protocol</th>
                                    <th style={{
                                        padding: '12px 16px',
                                        textAlign: 'left',
                                        fontSize: '13px',
                                        fontWeight: '600',
                                        color: '#6b7280',
                                        textTransform: 'uppercase',
                                        borderBottom: '1px solid #e5e7eb',
                                        borderRight: '1px solid #e5e7eb'  // ← خط عمودی
                                    }}>Port</th>
                                    <th style={{
                                        padding: '12px 16px',
                                        textAlign: 'right',
                                        fontSize: '13px',
                                        fontWeight: '600',
                                        color: '#6b7280',
                                        textTransform: 'uppercase',
                                        borderBottom: '1px solid #e5e7eb'
                                        // بدون borderRight - آخرین ستون
                                    }}>Actions</th>
                                </tr>
                                </thead>
                                <tbody>
                                {ports.map((port) => (
                                    <tr key={port.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                                        <td style={{
                                            padding: '14px 16px',
                                            fontSize: '14px',
                                            color: '#111827',
                                            fontWeight: '500',
                                            borderRight: '1px solid #e5e7eb'  // ← خط عمودی
                                        }}>
                                            {port.protocol}
                                        </td>
                                        <td style={{
                                            padding: '14px 16px',
                                            fontSize: '14px',
                                            color: '#374151',
                                            borderRight: '1px solid #e5e7eb'
                                        }}>
                                            {port.port_number}
                                        </td>
                                        <td style={{
                                            padding: '14px 16px',
                                            textAlign: 'center'

                                        }}>
                                            <div style={{ display: 'flex', gap: '8px', justifyContent: "center" }}>
                                                {/* Edit Button */}
                                                <button
                                                    onClick={() => handleEditPort(port)}
                                                    style={{
                                                        background: 'none',
                                                        border: 'none',
                                                        padding: '6px',
                                                        cursor: 'pointer',
                                                        borderRadius: '6px',
                                                        color: '#3b82f6'
                                                    }}
                                                    title="Edit Port"
                                                >
                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                                                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                                                    </svg>
                                                </button>

                                                {/* Delete Button */}
                                                <button
                                                    onClick={() => handleDelete(port)}
                                                    style={{
                                                        background: 'none',
                                                        border: 'none',
                                                        padding: '6px',
                                                        cursor: 'pointer',
                                                        borderRadius: '6px',
                                                        color: '#ef4444'
                                                    }}
                                                    title="Delete Port"
                                                >
                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <polyline points="3 6 5 6 21 6" />
                                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                                                    </svg>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        )}
                    </div>

                    {/* Footer */}
                    <div style={{
                        padding: '16px 24px',
                        borderTop: '1px solid #e5e7eb',
                        display: 'flex',
                        justifyContent: 'center'
                    }}>
                        <button
                            onClick={onClose}
                            style={{
                                background: '#1e3a5f',
                                color: 'white',
                                border: 'none',
                                padding: '12px 48px',
                                borderRadius: '8px',
                                fontSize: '15px',
                                fontWeight: '500',
                                cursor: 'pointer'
                            }}
                        >
                            Close
                        </button>
                    </div>
                </div>
            </div>

            {/* Port Add/Edit Modal */}
            {showPortModal && (
                <PortModal
                    asset={asset}
                    port={editingPort}
                    onClose={handleClosePortModal}
                />
            )}

            {/* Delete Confirmation Modal */}
            {showDeleteConfirm && (
                <div
                    style={{
                        position: 'fixed',
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        background: 'rgba(0, 0, 0, 0.6)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        zIndex: 10000
                    }}
                    onClick={(e) => {
                        if (e.target === e.currentTarget) cancelDelete();
                    }}
                >
                    <div style={{
                        background: 'white',
                        borderRadius: '12px',
                        width: '90%',
                        maxWidth: '400px',
                        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)'
                    }}
                         onClick={(e) => e.stopPropagation()}>
                        <div style={{ padding: '20px 24px', borderBottom: '1px solid #e5e7eb' }}>
                            <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#111827', margin: 0 }}>
                                Confirm Delete
                            </h3>
                        </div>
                        <div style={{ padding: '24px' }}>
                            <p style={{ margin: '0 0 12px 0', color: '#374151', fontSize: '14px' }}>
                                Are you sure you want to delete port{' '}
                                <strong>{deletingPort?.protocol} {deletingPort?.port_number}</strong>?
                            </p>
                            <p style={{ margin: 0, color: '#ef4444', fontSize: '13px', fontWeight: '500' }}>
                                This action cannot be undone.
                            </p>

                            {deleteError && (
                                <div style={{
                                    marginTop: '12px',
                                    padding: '8px 12px',
                                    background: '#fef2f2',
                                    border: '1px solid #fca5a5',
                                    borderRadius: '6px',
                                    color: '#dc2626',
                                    fontSize: '13px'
                                }}>
                                    {deleteError}
                                </div>
                            )}
                        </div>
                        <div style={{
                            padding: '16px 24px',
                            borderTop: '1px solid #e5e7eb',
                            display: 'flex',
                            gap: '12px',
                            justifyContent: 'flex-end'
                        }}>
                            <button
                                onClick={cancelDelete}
                                style={{
                                    background: 'white',
                                    color: '#6b7280',
                                    border: '1px solid #d1d5db',
                                    padding: '10px 20px',
                                    borderRadius: '8px',
                                    fontSize: '14px',
                                    fontWeight: '500',
                                    cursor: 'pointer'
                                }}
                            >
                                Cancel
                            </button>
                            <button
                                onClick={confirmDelete}
                                style={{
                                    background: '#ef4444',
                                    color: 'white',
                                    border: 'none',
                                    padding: '10px 20px',
                                    borderRadius: '8px',
                                    fontSize: '14px',
                                    fontWeight: '500',
                                    cursor: 'pointer'
                                }}
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <style>{`
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            `}</style>
        </>
    );
};