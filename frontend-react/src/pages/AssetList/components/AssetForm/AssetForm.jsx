/* ==========================================
   NGCORION - Asset Form Component (Fixed)
   ========================================== */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { createAsset, updateAsset } from '../../../../store/slices/assetsSlice';
import Button from '../../../../components/common/Button';
import Input from '../../../../components/common/Input';
import Select from '../../../../components/common/Select';
import './AssetForm.css';

const AssetForm = ({ asset, assetTypes, owners, locations, onClose }) => {
  const dispatch = useDispatch();
  const { status, confidentiality, risk } = useSelector((state) => state.enums);
  const [currentStep, setCurrentStep] = useState(1);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Helper to format date for input (YYYY-MM-DD)
  const formatDateForInput = (dateString) => {
    if (!dateString) return '';
    try {
      const date = new Date(dateString);
      return date.toISOString().split('T')[0];
    } catch {
      return '';
    }
  };

  // Helper to get field value with fallbacks
  const getFieldValue = (primary, ...fallbacks) => {
    return primary || fallbacks.find(v => v) || '';
  };

  // Initialize form data from asset prop
  const getInitialFormData = (assetData) => ({
    // Step 1: Basic Info
    asset_name: assetData?.asset_name || '',
    hostname: assetData?.hostname || '',
    asset_type_id: assetData?.asset_type_id || '',
    asset_role: getFieldValue(assetData?.asset_role, assetData?.role),
    manufacturer: getFieldValue(assetData?.manufacturer, assetData?.vendor),
    model: assetData?.model || '',
    // Step 2: System Info
    serial_number: assetData?.serial_number || '',
    os_name: getFieldValue(assetData?.os_name, assetData?.os),
    os_version: assetData?.os_version || '',
    ip_address: assetData?.ip_address || '',
    mac_address: assetData?.mac_address || '',
    // Step 3: Location & Ownership
    location_id: assetData?.location_id || '',
    owner_id: assetData?.owner_id || '',
    status: assetData?.status || 'active',
    // Step 4: Security
    confidentiality_level: getFieldValue(assetData?.confidentiality_level, assetData?.confidentiality),
    risk_level: getFieldValue(assetData?.risk_level, assetData?.risk),
    last_audit_date: formatDateForInput(assetData?.last_audit_date),
    last_patch_date: formatDateForInput(assetData?.last_patch_date),
    asset_value: assetData?.asset_value || '',
    description: assetData?.description || '',
  });

  const [formData, setFormData] = useState(() => getInitialFormData(asset));

  // Reset form when asset changes
  useEffect(() => {
    setFormData(getInitialFormData(asset));
    setCurrentStep(1);
    setError('');
  }, [asset]);

  const steps = [
    { num: 1, title: 'Basic Info' },
    { num: 2, title: 'System Info' },
    { num: 3, title: 'Location & Owner' },
    { num: 4, title: 'Security & Audit' },
  ];

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    // Clear error when user types
    if (error) setError('');
  };

  const validateStep = (step) => {
    switch (step) {
      case 1:
        if (!formData.asset_name.trim()) {
          setError('Asset name is required');
          return false;
        }
        if (!formData.asset_type_id) {
          setError('Asset type is required');
          return false;
        }
        break;
      case 2:
        // Optional: Validate IP address format if provided
        if (formData.ip_address && !formData.ip_address.match(/^(\d{1,3}\.){3}\d{1,3}$/)) {
          setError('Invalid IP address format (expected: xxx.xxx.xxx.xxx)');
          return false;
        }
        // Optional: Validate MAC address format if provided
        if (formData.mac_address && !formData.mac_address.match(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)) {
          setError('Invalid MAC address format (expected: XX:XX:XX:XX:XX:XX)');
          return false;
        }
        break;
      case 3:
        // No required fields in step 3
        break;
      case 4:
        // Optional: Validate asset value is positive
        if (formData.asset_value && parseFloat(formData.asset_value) < 0) {
          setError('Asset value must be a positive number');
          return false;
        }
        break;
    }
    return true;
  };

  const handleNext = () => {
    if (!validateStep(currentStep)) {
      return;
    }
    setError('');
    setCurrentStep((prev) => Math.min(prev + 1, 4));
  };

  const handleBack = () => {
    setCurrentStep((prev) => Math.max(prev - 1, 1));
  };

  const handleSubmit = async () => {
    // Validate all required fields before submitting
    if (!formData.asset_name.trim()) {
      setError('Asset name is required');
      setCurrentStep(1);
      return;
    }
    if (!formData.asset_type_id) {
      setError('Asset type is required');
      setCurrentStep(1);
      return;
    }

    setError('');
    setLoading(true);

    try {
      // Prepare submit data
      const submitData = {
        asset_name: formData.asset_name.trim(),
        hostname: formData.hostname.trim() || null,
        asset_type_id: parseInt(formData.asset_type_id) || null,
        asset_role: formData.asset_role.trim() || null,
        manufacturer: formData.manufacturer.trim() || null,
        model: formData.model.trim() || null,
        serial_number: formData.serial_number.trim() || null,
        os_name: formData.os_name.trim() || null,
        os_version: formData.os_version.trim() || null,
        ip_address: formData.ip_address.trim() || null,
        mac_address: formData.mac_address.trim() || null,
        location_id: parseInt(formData.location_id) || null,
        owner_id: parseInt(formData.owner_id) || null,
        status: formData.status || 'active',
        confidentiality_level: formData.confidentiality_level || null,
        risk_level: formData.risk_level || null,
        last_audit_date: formData.last_audit_date || null,
        last_patch_date: formData.last_patch_date || null,
        asset_value: formData.asset_value ? parseFloat(formData.asset_value) : null,
        description: formData.description.trim() || null,
      };

      if (asset) {
        // UPDATE - get the correct ID (check both formats)
        const assetId = asset.asset_id || asset.id;
        if (!assetId) {
          throw new Error('Asset ID not found for update');
        }
        await dispatch(updateAsset({ assetId, assetData: submitData })).unwrap();
      } else {
        // CREATE
        await dispatch(createAsset(submitData)).unwrap();
      }
      onClose();
    } catch (err) {
      console.error('Save error:', err);
      setError(typeof err === 'string' ? err : err.message || 'Failed to save asset');
    } finally {
      setLoading(false);
    }
  };

  // Check if field was auto-discovered
  const isDiscoveredField = (fieldName) => {
    return asset?.discovered_fields?.[fieldName] === true;
  };

  const renderStep = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="form-step">
            <Input
              label="Asset Name"
              name="asset_name"
              value={formData.asset_name}
              onChange={handleChange}
              required
            />
            <Input
              label="Hostname"
              name="hostname"
              value={formData.hostname}
              onChange={handleChange}
              className={isDiscoveredField('hostname') ? 'discovered' : ''}
            />
            <Select
              label="Asset Type"
              name="asset_type_id"
              value={formData.asset_type_id}
              onChange={handleChange}
              options={assetTypes?.map((t) => ({ value: t.id, label: t.type_name })) || []}
              required
            />
            <Input
              label="Role"
              name="asset_role"
              value={formData.asset_role}
              onChange={handleChange}
              placeholder="e.g., Core Network Switch"
            />
            <Input
              label="Manufacturer"
              name="manufacturer"
              value={formData.manufacturer}
              onChange={handleChange}
              className={isDiscoveredField('manufacturer') ? 'discovered' : ''}
            />
            <Input
              label="Model"
              name="model"
              value={formData.model}
              onChange={handleChange}
            />
          </div>
        );
      case 2:
        return (
          <div className="form-step">
            <Input
              label="Serial Number"
              name="serial_number"
              value={formData.serial_number}
              onChange={handleChange}
            />
            <Input
              label="OS Name"
              name="os_name"
              value={formData.os_name}
              onChange={handleChange}
              className={isDiscoveredField('os_name') ? 'discovered' : ''}
            />
            <Input
              label="OS Version"
              name="os_version"
              value={formData.os_version}
              onChange={handleChange}
              className={isDiscoveredField('os_version') ? 'discovered' : ''}
            />
            <Input
              label="IP Address"
              name="ip_address"
              value={formData.ip_address}
              onChange={handleChange}
            />
            <Input
              label="MAC Address"
              name="mac_address"
              value={formData.mac_address}
              onChange={handleChange}
              className={isDiscoveredField('mac_address') ? 'discovered' : ''}
            />
          </div>
        );
      case 3:
        return (
          <div className="form-step">
            <Select
              label="Location"
              name="location_id"
              value={formData.location_id}
              onChange={handleChange}
              options={locations?.map((l) => ({ value: l.id, label: l.site_name })) || []}
            />
            <Select
              label="Owner"
              name="owner_id"
              value={formData.owner_id}
              onChange={handleChange}
              options={owners?.map((o) => ({ value: o.id, label: o.full_name })) || []}
            />
            <Select
              label="Status"
              name="status"
              value={formData.status}
              onChange={handleChange}
              options={status?.map((s) => ({ value: s.value, label: s.label })) || [
                { value: 'active', label: 'Active' },
                { value: 'inactive', label: 'Inactive' },
                { value: 'maintenance', label: 'Maintenance' },
                { value: 'retired', label: 'Retired' },
              ]}
            />
          </div>
        );
      case 4:
        return (
          <div className="form-step">
            <Select
              label="Confidentiality Level"
              name="confidentiality_level"
              value={formData.confidentiality_level}
              onChange={handleChange}
              options={confidentiality?.map((c) => ({ value: c.value, label: c.label })) || [
                { value: 'public', label: 'Public' },
                { value: 'internal', label: 'Internal' },
                { value: 'confidential', label: 'Confidential' },
                { value: 'critical', label: 'Critical' },
              ]}
            />
            <Select
              label="Risk Level"
              name="risk_level"
              value={formData.risk_level}
              onChange={handleChange}
              options={risk?.map((r) => ({ value: r.value, label: r.label })) || [
                { value: 'low', label: 'Low' },
                { value: 'medium', label: 'Medium' },
                { value: 'high', label: 'High' },
                { value: 'critical', label: 'Critical' },
              ]}
            />
            <Input
              label="Last Audit Date"
              type="date"
              name="last_audit_date"
              value={formData.last_audit_date}
              onChange={handleChange}
            />
            <Input
              label="Last Patch Date"
              type="date"
              name="last_patch_date"
              value={formData.last_patch_date}
              onChange={handleChange}
            />
            <Input
              label="Asset Value"
              type="number"
              name="asset_value"
              value={formData.asset_value}
              onChange={handleChange}
            />
            <div className="input-group">
              <label className="input-label">Description</label>
              <textarea
                className="input"
                name="description"
                value={formData.description}
                onChange={handleChange}
                rows={3}
              />
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="asset-form">
      {/* Step Indicator */}
      <div className="step-indicator">
        {steps.map((step) => (
          <div
            key={step.num}
            className={`step ${currentStep === step.num ? 'active' : ''} ${
              currentStep > step.num ? 'completed' : ''
            }`}
            onClick={() => {
              // Allow clicking on completed steps to go back
              if (step.num < currentStep) {
                setCurrentStep(step.num);
              }
            }}
            style={{ cursor: step.num < currentStep ? 'pointer' : 'default' }}
          >
            <div className="step-num">{step.num}</div>
            <span className="step-title">{step.title}</span>
          </div>
        ))}
      </div>

      {/* Edit Mode Indicator */}
      {asset && (
        <div className="edit-indicator">
          ✏️ Editing: <strong>{asset.asset_name}</strong> (ID: {asset.id || asset.asset_id})
        </div>
      )}

      {/* Error */}
      {error && <div className="error-message">{error}</div>}

      {/* Form Content */}
      {renderStep()}

      {/* Actions */}
      <div className="form-actions">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        {currentStep > 1 && (
          <Button variant="outline" onClick={handleBack}>
            Back
          </Button>
        )}
        {currentStep < 4 ? (
          <Button onClick={handleNext}>Next</Button>
        ) : (
          <Button onClick={handleSubmit} loading={loading}>
            {asset ? 'Update Asset' : 'Create Asset'}
          </Button>
        )}
      </div>
    </div>
  );
};

export default AssetForm;
