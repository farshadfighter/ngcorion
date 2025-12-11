/* ==========================================
   NGCORION - Asset Requirement Page
   ========================================== */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchAssetTypes, createAssetType, deleteAssetType } from '../../store/slices/assetTypesSlice';
import { fetchOwners, createOwner, deleteOwner } from '../../store/slices/ownersSlice';
import { fetchLocations, createLocation, deleteLocation } from '../../store/slices/locationsSlice';
import { fetchZones, createZone, deleteZone } from '../../store/slices/zonesSlice';
import { fetchOSCatalog, createOS, deleteOS } from '../../store/slices/osCatalogSlice';
import { fetchVendors, createVendor, deleteVendor } from '../../store/slices/vendorsSlice';
import { fetchAllEnums } from '../../store/slices/enumsSlice';
import { fetchAllDependencies, createDependency, deleteDependency } from '../../store/slices/dependenciesSlice';
import { fetchAssets } from '../../store/slices/assetsSlice';
import { useAuth } from '../../hooks/useAuth';
import api from '../../api/axios';
import Tabs from '../../components/common/Tabs';
import Button from '../../components/common/Button';
import Table from '../../components/common/Table';
import Modal from '../../components/common/Modal';
import Input from '../../components/common/Input';
import Select from '../../components/common/Select';
import SearchBox from '../../components/common/SearchBox';
import './AssetRequirement.css';

const AssetRequirement = () => {
  const dispatch = useDispatch();
  const { canWrite, canDelete } = useAuth();

  // Check permissions for asset_requirement module
  const hasWritePermission = canWrite('asset_requirement');
  const hasDeletePermission = canDelete('asset_requirement');
  const [activeTab, setActiveTab] = useState('types');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [formData, setFormData] = useState({});
  const [formError, setFormError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Redux state
  const { items: assetTypes, loading: typesLoading } = useSelector((state) => state.assetTypes);
  const { items: owners, loading: ownersLoading } = useSelector((state) => state.owners);
  const { items: locations, loading: locationsLoading } = useSelector((state) => state.locations);
  const { items: zones, loading: zonesLoading } = useSelector((state) => state.zones);
  const { items: osCatalog, loading: osLoading } = useSelector((state) => state.osCatalog);
  const { items: vendors, loading: vendorsLoading } = useSelector((state) => state.vendors);
  const { items: dependencies, loading: dependenciesLoading } = useSelector((state) => state.dependencies);
  const { assets } = useSelector((state) => state.assets);
  const { status, confidentiality, risk, relationTypes } = useSelector((state) => state.enums);

  useEffect(() => {
    dispatch(fetchAssetTypes());
    dispatch(fetchOwners());
    dispatch(fetchLocations());
    dispatch(fetchZones());
    dispatch(fetchOSCatalog());
    dispatch(fetchVendors());
    dispatch(fetchAssets());
    dispatch(fetchAllDependencies());
    dispatch(fetchAllEnums());
  }, [dispatch]);

  const tabs = [
    { key: 'types', label: 'Asset Types' },
    { key: 'owners', label: 'Owners' },
    { key: 'locations', label: 'Locations' },
    { key: 'zones', label: 'Network Zones' },
    { key: 'os', label: 'OS Catalog' },
    { key: 'vendors', label: 'Vendors' },
    { key: 'dependencies', label: 'Dependencies' },
    { key: 'enums', label: 'Enums' },
  ];

  const getTableConfig = () => {
    switch (activeTab) {
      case 'types':
        return {
          data: assetTypes,
          loading: typesLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            { key: 'type_name', title: 'Type Name' },
            { key: 'category', title: 'Category' },
            { key: 'description', title: 'Description' },
          ],
          formFields: [
            { name: 'type_name', label: 'Type Name', required: true },
            { name: 'category', label: 'Category', required: true },
            { name: 'description', label: 'Description' },
          ],
          createAction: createAssetType,
          deleteAction: deleteAssetType,
        };
      case 'owners':
        return {
          data: owners,
          loading: ownersLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            { key: 'full_name', title: 'Full Name' },
            { key: 'department', title: 'Department' },
            { key: 'email', title: 'Email' },
            { key: 'phone', title: 'Phone' },
          ],
          formFields: [
            { name: 'full_name', label: 'Full Name', required: true },
            { name: 'department', label: 'Department' },
            { name: 'role', label: 'Role' },
            { name: 'email', label: 'Email', type: 'email' },
            { name: 'phone', label: 'Phone' },
          ],
          createAction: createOwner,
          deleteAction: deleteOwner,
        };
      case 'locations':
        return {
          data: locations,
          loading: locationsLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            { key: 'site_name', title: 'Site' },
            { key: 'rack_name', title: 'Rack' },
            { key: 'room', title: 'Room' },
            { key: 'floor', title: 'Floor' },
            { key: 'network_zone', title: 'Zone' },
          ],
          formFields: [
            { name: 'site_name', label: 'Site Name', required: true },
            { name: 'rack_name', label: 'Rack Name' },
            { name: 'room', label: 'Room' },
            { name: 'floor', label: 'Floor' },
            { name: 'network_zone', label: 'Network Zone' },
            { name: 'vlan_id', label: 'VLAN ID' },
            { name: 'subnet', label: 'Subnet' },
          ],
          createAction: createLocation,
          deleteAction: deleteLocation,
        };
      case 'zones':
        return {
          data: zones,
          loading: zonesLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            { key: 'zone_name', title: 'Zone Name' },
          ],
          formFields: [{ name: 'zone_name', label: 'Zone Name', required: true }],
          createAction: createZone,
          deleteAction: deleteZone,
        };
      case 'os':
        return {
          data: osCatalog,
          loading: osLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            { key: 'os_name', title: 'OS Name' },
          ],
          formFields: [{ name: 'os_name', label: 'OS Name', required: true }],
          createAction: createOS,
          deleteAction: deleteOS,
        };
      case 'vendors':
        return {
          data: vendors,
          loading: vendorsLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            { key: 'vendor_name', title: 'Vendor Name' },
          ],
          formFields: [{ name: 'vendor_name', label: 'Vendor Name', required: true }],
          createAction: createVendor,
          deleteAction: deleteVendor,
        };
      case 'dependencies':
        return {
          data: dependencies,
          loading: dependenciesLoading,
          columns: [
            { key: 'id', title: 'ID', width: '60px' },
            {
              key: 'asset_id',
              title: 'Asset',
              render: (value) => {
                const asset = assets?.find((a) => a.id === value);
                return asset ? asset.asset_name : `Asset ${value}`;
              }
            },
            {
              key: 'depends_on_id',
              title: 'Depends On',
              render: (value) => {
                const asset = assets?.find((a) => a.id === value);
                return asset ? asset.asset_name : `Asset ${value}`;
              }
            },
            {
              key: 'relation_type',
              title: 'Relation Type',
              render: (value) => {
                const rt = relationTypes?.find((r) => r.value === value);
                return rt ? rt.label : value;
              }
            },
            { key: 'description', title: 'Description' },
          ],
          formFields: [
            {
              name: 'asset_id',
              label: 'Asset',
              type: 'select',
              options: assets?.map((a) => ({ value: a.id, label: a.asset_name })) || [],
              required: true
            },
            {
              name: 'depends_on_id',
              label: 'Depends On',
              type: 'select',
              options: assets?.map((a) => ({ value: a.id, label: a.asset_name })) || [],
              required: true
            },
            {
              name: 'relation_type',
              label: 'Relation Type',
              type: 'select',
              options: relationTypes?.map((r) => ({ value: r.value, label: r.label })) || [],
              required: true
            },
            { name: 'description', label: 'Description' },
          ],
          createAction: createDependency,
          deleteAction: deleteDependency,
        };
      case 'enums':
        return { isEnums: true };
      default:
        return { data: [], columns: [] };
    }
  };

  const config = getTableConfig();

  const handleCreate = () => {
    setFormData({});
    setFormError('');
    setIsModalOpen(true);
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this item?')) {
      try {
        await dispatch(config.deleteAction(id)).unwrap();
      } catch (err) {
        console.error('Delete failed:', err);
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');

    const requiredFields = config.formFields?.filter((f) => f.required) || [];
    for (const field of requiredFields) {
      if (!formData[field.name]) {
        setFormError(`${field.label} is required`);
        return;
      }
    }

    try {
      // Convert numeric fields to integers for dependencies
      const submitData = { ...formData };
      if (activeTab === 'dependencies') {
        if (submitData.asset_id) submitData.asset_id = parseInt(submitData.asset_id, 10);
        if (submitData.depends_on_id) submitData.depends_on_id = parseInt(submitData.depends_on_id, 10);
      }

      await dispatch(config.createAction(submitData)).unwrap();
      setIsModalOpen(false);
    } catch (err) {
      setFormError(err || 'Failed to create');
    }
  };

  const handleExport = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/asset-requirements/export/excel', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error('Export failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `asset_requirements_export_${new Date().toISOString().slice(0,10)}.xlsx`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Export failed:', err);
      alert('Failed to export asset requirements');
    }
  };

  const handleDownloadTemplate = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/asset-requirements/export/template', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error('Template download failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'asset_requirements_template.xlsx';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Template download failed:', err);
      alert('Failed to download template');
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
        const response = await fetch('/api/asset-requirements/import/excel', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          },
          body: formData
        });

        const result = await response.json();

        if (!response.ok) {
          throw new Error(result.detail || 'Import failed');
        }

        alert(`Import successful!\n${JSON.stringify(result.summary, null, 2)}`);

        // Refresh data
        dispatch(fetchAssetTypes());
        dispatch(fetchOwners());
        dispatch(fetchLocations());
        dispatch(fetchZones());
        dispatch(fetchOSCatalog());
        dispatch(fetchVendors());
        dispatch(fetchAllDependencies());
      } catch (err) {
        console.error('Import failed:', err);
        alert('Failed to import: ' + err.message);
      }
    };
    input.click();
  };

  const columnsWithActions = config.columns
    ? [
        ...config.columns,
        {
          key: 'actions',
          title: 'Actions',
          width: '80px',
          render: (_, row) =>
            hasDeletePermission && (
              <button className="table-action-btn delete" onClick={() => handleDelete(row.id)}>
                <svg viewBox="0 0 24 24" fill="currentColor">
                  <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
                </svg>
              </button>
            ),
        },
      ]
    : [];

  // Render Enums tab
  if (config.isEnums) {
    return (
      <div className="asset-requirement-page">
        <div className="page-header">
          <h1 className="page-title">Asset Requirement</h1>
        </div>
        <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />
        <div className="enums-grid">
          <div className="enum-card">
            <h3>Status</h3>
            <ul>{status.map((s) => <li key={s.value}>{s.label}</li>)}</ul>
          </div>
          <div className="enum-card">
            <h3>Confidentiality Levels</h3>
            <ul>{confidentiality.map((c) => <li key={c.value}>{c.label}</li>)}</ul>
          </div>
          <div className="enum-card">
            <h3>Risk Levels</h3>
            <ul>{risk.map((r) => <li key={r.value}>{r.label}</li>)}</ul>
          </div>
          <div className="enum-card">
            <h3>Relation Types</h3>
            <ul>{relationTypes.map((rt) => <li key={rt.value}>{rt.label}</li>)}</ul>
          </div>
        </div>
      </div>
    );
  }

  // Filter data based on search query
  const filteredData = config.data?.filter((item) => {
    if (!searchQuery) return true;
    const searchLower = searchQuery.toLowerCase();
    return Object.values(item).some((value) =>
      String(value).toLowerCase().includes(searchLower)
    );
  }) || [];

  return (
    <div className="asset-requirement-page">
      <div className="page-header">
        <h1 className="page-title">Asset Requirement</h1>
        <div className="header-actions">
          <Button onClick={handleExport} variant="secondary">📤 Export</Button>
          <Button onClick={handleDownloadTemplate} variant="secondary">📋 Template</Button>
          {hasWritePermission && <Button onClick={handleImport} variant="secondary">📥 Import</Button>}
          {hasWritePermission && <Button onClick={handleCreate}>Add New</Button>}
        </div>
      </div>

      <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      <div className="asset-toolbar">
        <SearchBox
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder="Search..."
        />
      </div>

      <Table
        columns={columnsWithActions}
        data={filteredData}
        loading={config.loading}
        emptyMessage="No data found"
      />

      {/* Create Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={`Add ${tabs.find((t) => t.key === activeTab)?.label}`}
      >
        <form onSubmit={handleSubmit} className="requirement-form">
          {formError && <div className="error-message">{formError}</div>}

          {config.formFields?.map((field) =>
            field.type === 'select' ? (
              <Select
                key={field.name}
                label={field.label}
                name={field.name}
                value={formData[field.name] || ''}
                onChange={(e) => setFormData({ ...formData, [field.name]: e.target.value })}
                options={field.options}
                required={field.required}
              />
            ) : (
              <Input
                key={field.name}
                label={field.label}
                type={field.type || 'text'}
                name={field.name}
                value={formData[field.name] || ''}
                onChange={(e) => setFormData({ ...formData, [field.name]: e.target.value })}
                required={field.required}
              />
            )
          )}

          <div className="form-actions">
            <Button variant="secondary" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button type="submit">Create</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default AssetRequirement;
