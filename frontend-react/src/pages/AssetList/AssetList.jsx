/* ==========================================
   NGCORION - Asset List Page
   ========================================== */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  fetchAssets,
  fetchOverviewView,
  fetchNetworkView,
  fetchLocationView,
  fetchSecurityView,
  deleteAsset,
  setCurrentView,
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
  const { canWrite, canDelete } = useAuth();
  const { assets, currentView, loading } = useSelector((state) => state.assets);
  const { items: assetTypes } = useSelector((state) => state.assetTypes);
  const { items: owners } = useSelector((state) => state.owners);
  const { items: locations } = useSelector((state) => state.locations);

  const [searchQuery, setSearchQuery] = useState('');
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [deletingAsset, setDeletingAsset] = useState(null);

  useEffect(() => {
    dispatch(fetchAssetTypes());
    dispatch(fetchOwners());
    dispatch(fetchLocations());
    dispatch(fetchAllEnums());
    loadViewData(currentView);
  }, [dispatch]);

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
      { key: 'asset_id', title: 'ID', width: '70px' },
      { key: 'asset_name', title: 'Asset Name' },
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
          ...baseColumns,
          { key: 'serial_number', title: 'Serial' },
          { key: 'os', title: 'OS' },
          { key: 'ip_address', title: 'IP Address' },
          { key: 'mac_address', title: 'MAC Address' },
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
          { key: 'last_audit_date', title: 'Last Audit' },
          { key: 'last_patch_date', title: 'Last Patch' },
          { key: 'asset_value', title: 'Value' },
        ];
      default:
        return baseColumns;
    }
  };

  const columns = [
    ...getColumns(),
    {
      key: 'actions',
      title: 'Actions',
      width: '100px',
      render: (_, row) => (
        <div className="table-actions">
          {canWrite && (
            <button className="table-action-btn edit" onClick={() => handleEdit(row)}>
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
              </svg>
            </button>
          )}
          {canDelete && (
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
    setIsFormOpen(true);
  };

  const handleEdit = (asset) => {
    setEditingAsset(asset);
    setIsFormOpen(true);
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
    loadViewData(currentView);
  };

  return (
    <div className="asset-list-page">
      <div className="page-header">
        <h1 className="page-title">Asset List</h1>
        {canWrite && <Button onClick={handleCreate}>Add Asset</Button>}
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
        loading={loading}
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
