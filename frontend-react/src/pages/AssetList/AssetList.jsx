/* ==========================================
   NGCORION - Asset List Page (Fixed)
   ========================================== */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  fetchAssets,
  fetchAsset,
  fetchOverviewView,
  fetchNetworkView,
  fetchLocationView,
  fetchSecurityView,
  deleteAsset,
  setCurrentView,
  clearSelectedAsset,
} from '../../store/slices/assetsSlice';
import { fetchAssetTypes } from '../../store/slices/assetTypesSlice';
import { fetchOwners } from '../../store/slices/ownersSlice';
import { fetchLocations } from '../../store/slices/locationsSlice';
import { fetchAllEnums } from '../../store/slices/enumsSlice';
import { useAuth } from '../../hooks/useAuth';
import Button from '../../components/common/Button';
import Tabs from '../../components/common/Tabs';
import Table from '../../components/common/Table';
import Modal from '../../components/common/Modal';
import SearchBox from '../../components/common/SearchBox';
import AssetForm from './components/AssetForm';
import './AssetList.css';

const AssetList = () => {
  const dispatch = useDispatch();
  const { canWrite, canDelete, hasPermission } = useAuth();

  // Check permissions for asset_list module
  const hasWritePermission = canWrite('asset_list');
  const hasDeletePermission = canDelete('asset_list');
  const { assets, selectedAsset, currentView, loading } = useSelector((state) => state.assets);
  const { items: assetTypes } = useSelector((state) => state.assetTypes);
  const { items: owners } = useSelector((state) => state.owners);
  const { items: locations } = useSelector((state) => state.locations);

  const [searchQuery, setSearchQuery] = useState('');
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [deletingAsset, setDeletingAsset] = useState(null);
  const [isLoadingAsset, setIsLoadingAsset] = useState(false);

  useEffect(() => {
    dispatch(fetchAssetTypes());
    dispatch(fetchOwners());
    dispatch(fetchLocations());
    dispatch(fetchAllEnums());
    loadViewData(currentView);
  }, [dispatch]);

  // When selectedAsset changes and we're waiting for it, open the form
  useEffect(() => {
    if (selectedAsset && isLoadingAsset) {
      setEditingAsset(selectedAsset);
      setIsLoadingAsset(false);
      setIsFormOpen(true);
    }
  }, [selectedAsset, isLoadingAsset]);

  const loadViewData = (view) => {
    switch (view) {
      case 'overview':
        dispatch(fetchOverviewView());
        break;
      case 'network':
        dispatch(fetchNetworkView());
        break;
      case 'location':
        dispatch(fetchLocationView());
        break;
      case 'security':
        dispatch(fetchSecurityView());
        break;
      default:
        dispatch(fetchAssets());
    }
  };

  const handleViewChange = (view) => {
    dispatch(setCurrentView(view));
    loadViewData(view);
  };

  const viewTabs = [
    { key: 'overview', label: 'Overview' },
    { key: 'network', label: 'Network & System' },
    { key: 'location', label: 'Location & Owner' },
    { key: 'security', label: 'Security & Audit' },
  ];

  const getColumns = () => {
    const baseColumns = [
      { key: 'asset_name', title: 'Asset Name', width: '200px' },
    ];

    switch (currentView) {
      case 'overview':
        return [
          ...baseColumns,
          { key: 'hostname', title: 'Hostname' },
          { key: 'asset_type', title: 'Type' },
          { key: 'role', title: 'Role' },
          { key: 'vendor', title: 'Vendor' },
          { key: 'model', title: 'Model' },
        ];
      case 'network':
        return [
          { key: 'asset_name', title: 'Asset Name', width: '180px' },
          { key: 'ip_address', title: 'IP Address', width: '130px' },
          { key: 'hostname', title: 'Hostname', width: '150px' },
          { key: 'serial_number', title: 'Serial' },
          { key: 'os', title: 'OS' },
          { key: 'mac_address', title: 'MAC Address' },
          {
            key: 'ports',
            title: 'Ports',
            render: (value, row) => {
              if (!value) return <span className="text-muted">No ports</span>;
              return (
                <span className="ports-summary" title={value}>
                  {value}
                </span>
              );
            }
          },
          {
            key: 'protocols',
            title: 'Protocols',
            render: (value) => {
              if (!value) return <span className="text-muted">-</span>;
              return <span className="protocols-summary">{value}</span>;
            }
          },
        ];
      case 'location':
        return [
          ...baseColumns,
          { key: 'location', title: 'Location' },
          { key: 'network_zone', title: 'Zone' },
          { key: 'owner', title: 'Owner' },
          {
            key: 'status',
            title: 'Status',
            render: (value) => (
              <span className={`status-badge ${value || 'unknown'}`}>{value || '-'}</span>
            ),
          },
        ];
      case 'security':
        return [
          ...baseColumns,
          { key: 'confidentiality', title: 'Confidentiality' },
          { key: 'risk_level', title: 'Risk' },
          {
            key: 'antivirus_status',
            title: 'Antivirus',
            render: (value, row) => {
              if (!row.antivirus_installed) return <span className="text-muted">Not Installed</span>;
              return <span className={`status-badge ${value?.toLowerCase() || 'unknown'}`}>{value || 'Unknown'}</span>;
            },
          },
          {
            key: 'firewall_enabled',
            title: 'Firewall',
            render: (value) => (
              <span className={`status-badge ${value ? 'active' : 'inactive'}`}>
                {value ? 'Enabled' : 'Disabled'}
              </span>
            ),
          },
          {
            key: 'backup_enabled',
            title: 'Backup',
            render: (value) => (
              <span className={`status-badge ${value ? 'active' : 'inactive'}`}>
                {value ? 'Enabled' : 'Disabled'}
              </span>
            ),
          },
          {
            key: 'vulnerability_score',
            title: 'Vuln Score',
            render: (value) => {
              if (value === null || value === undefined) return '-';
              const level = value >= 7 ? 'high' : value >= 4 ? 'medium' : 'low';
              return <span className={`vuln-score ${level}`}>{value.toFixed(1)}</span>;
            },
          },
          {
            key: 'compliance_status',
            title: 'Compliance',
            render: (value) => (
              <span className={`status-badge ${value?.toLowerCase()?.replace(' ', '-') || 'unknown'}`}>
                {value || 'Unknown'}
              </span>
            ),
          },
          { key: 'last_audit_date', title: 'Last Audit' },
          { key: 'last_patch_date', title: 'Last Patch' },
        ];
      default:
        return baseColumns;
    }
  };

  const columns = [
    ...getColumns(),
    {
      key: 'asset_id',
      title: 'ID',
      width: '60px',
      render: (value) => <span className="text-muted" style={{ fontSize: '0.85em' }}>{value}</span>,
    },
    {
      key: 'actions',
      title: 'Actions',
      width: '100px',
      render: (_, row) => (
        <div className="table-actions">
          {hasWritePermission && (
            <button
              className="table-action-btn edit"
              onClick={() => handleEdit(row)}
              disabled={isLoadingAsset}
              title="Edit asset"
            >
              {isLoadingAsset ? (
                <svg className="spinner" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" opacity="0.25"/>
                  <path fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" opacity="0.75"/>
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" fill="currentColor">
                  <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
                </svg>
              )}
            </button>
          )}
          {hasDeletePermission && (
            <button className="table-action-btn delete" onClick={() => handleDeleteClick(row)}>
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
              </svg>
            </button>
          )}
        </div>
      ),
    },
  ];

  const filteredAssets = assets.filter(
    (asset) =>
      asset.asset_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.hostname?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.ip_address?.includes(searchQuery)
  );

  const handleCreate = () => {
    setEditingAsset(null);
    dispatch(clearSelectedAsset());
    setIsFormOpen(true);
  };

  // FIXED: Fetch complete asset data before editing
  const handleEdit = async (asset) => {
    const assetId = asset.asset_id || asset.id;
    if (!assetId) {
      setError('Invalid asset ID');
      return;
    }

    setIsLoadingAsset(true);
    try {
      // Fetch complete asset data from API
      await dispatch(fetchAsset(assetId)).unwrap();
      // The useEffect above will handle opening the form
    } catch (err) {
      console.error('Failed to fetch asset:', err);
      // Show error instead of dangerous fallback
      setError(err || 'Failed to load asset details. Please try again.');
    } finally {
      setIsLoadingAsset(false);
    }
  };

  const handleDeleteClick = (asset) => {
    setDeletingAsset(asset);
    setIsDeleteModalOpen(true);
  };

  const handleDelete = async () => {
    try {
      await dispatch(deleteAsset(deletingAsset.asset_id || deletingAsset.id)).unwrap();
      setIsDeleteModalOpen(false);
      setDeletingAsset(null);
      loadViewData(currentView);
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const handleFormClose = () => {
    setIsFormOpen(false);
    setEditingAsset(null);
    dispatch(clearSelectedAsset());
    loadViewData(currentView);
  };

  const handleExport = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/api/assets/export/excel', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `assets_export_${new Date().toISOString().slice(0, 10)}.xlsx`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        console.error('Export failed');
      }
    } catch (error) {
      console.error('Export error:', error);
    }
  };

  const handleDownloadTemplate = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:8000/api/assets/export/template', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'asset_import_template.xlsx';
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        console.error('Template download failed');
      }
    } catch (error) {
      console.error('Template download error:', error);
    }
  };

  const handleImport = async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.xlsx,.xls';
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const formData = new FormData();
      formData.append('file', file);

      try {
        const token = localStorage.getItem('token');
        const response = await fetch('http://localhost:8000/api/assets/import/excel', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          },
          body: formData
        });

        if (response.ok) {
          const result = await response.json();
          alert(`Import successful!\n${JSON.stringify(result.summary, null, 2)}`);

          // Refresh asset list
          loadViewData(currentView);
        } else {
          const error = await response.json();
          alert('Failed to import: ' + (error.detail || 'Unknown error'));
        }
      } catch (err) {
        console.error('Import failed:', err);
        alert('Failed to import: ' + err.message);
      }
    };
    input.click();
  };

  return (
    <div className="asset-list-page">
      <div className="page-header">
        <h1 className="page-title">Asset List</h1>
        <div className="header-actions">
          <Button onClick={handleExport} variant="secondary">📤 Export</Button>
          <Button onClick={handleDownloadTemplate} variant="secondary">📋 Template</Button>
          {hasWritePermission && <Button onClick={handleImport} variant="secondary">📥 Import</Button>}
          {hasWritePermission && <Button onClick={handleCreate}>Add Asset</Button>}
        </div>
      </div>

      <Tabs tabs={viewTabs} activeTab={currentView} onChange={handleViewChange} />

      <div className="asset-toolbar">
        <SearchBox
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder="Search assets..."
        />
      </div>

      <Table
        columns={columns}
        data={filteredAssets}
        loading={loading || isLoadingAsset}
        emptyMessage="No assets found"
      />

      {/* Asset Form Modal */}
      <Modal
        isOpen={isFormOpen}
        onClose={handleFormClose}
        title={editingAsset ? 'Edit Asset' : 'Create Asset'}
        size="large"
      >
        <AssetForm
          asset={editingAsset}
          assetTypes={assetTypes}
          owners={owners}
          locations={locations}
          onClose={handleFormClose}
        />
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        title="Delete Asset"
        size="small"
      >
        <p>Are you sure you want to delete "{deletingAsset?.asset_name}"?</p>
        <div className="form-actions">
          <Button variant="secondary" onClick={() => setIsDeleteModalOpen(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleDelete}>
            Delete
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default AssetList;
