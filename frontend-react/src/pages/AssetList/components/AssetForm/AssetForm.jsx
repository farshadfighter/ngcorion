/* ==========================================
   NGCORION - Asset Form Component (Multi-step)
   ========================================== */

import { useState } from 'react';
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

  const [formData, setFormData] = useState({
    // Step 1: Basic Info
    asset_name: asset?.asset_name || '',
    hostname: asset?.hostname || '',
    asset_type_id: asset?.asset_type_id || '',
    asset_role: asset?.asset_role || '',
    manufacturer: asset?.manufacturer || '',
    model: asset?.model || '',
    // Step 2: System Info
    serial_number: asset?.serial_number || '',
    os_name: asset?.os_name || '',
    os_version: asset?.os_version || '',
    ip_address: asset?.ip_address || '',
    mac_address: asset?.mac_address || '',
    // Step 3: Location & Ownership
    location_id: asset?.location_id || '',
    owner_id: asset?.owner_id || '',
    status: asset?.status || 'active',
    // Step 4: Ports (simplified)
    // Step 5: Security
    confidentiality_level: asset?.confidentiality_level || '',
    risk_level: asset?.risk_level || '',
    last_audit_date: asset?.last_audit_date || '',
    last_patch_date: asset?.last_patch_date || '',
    asset_value: asset?.asset_value || '',
    description: asset?.description || '',
  });

  const steps = [
    { num: 1, title: 'Basic Info' },
    { num: 2, title: 'System Info' },
    { num: 3, title: 'Location & Owner' },
    { num: 4, title: 'Security & Audit' },
  ];

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleNext = () => {
    if (currentStep === 1 && !formData.asset_name) {
      setError('Asset name is required');
      return;
    }
    if (currentStep === 1 && !formData.asset_type_id) {
      setError('Asset type is required');
      return;
    }
    setError('');
    setCurrentStep((prev) => Math.min(prev + 1, 4));
  };

  const handleBack = () => {
    setCurrentStep((prev) => Math.max(prev - 1, 1));
  };

  const handleSubmit = async () => {
    setError('');
    setLoading(true);

    try {
      const submitData = {
        ...formData,
        asset_type_id: parseInt(formData.asset_type_id) || null,
        location_id: parseInt(formData.location_id) || null,
        owner_id: parseInt(formData.owner_id) || null,
        asset_value: parseFloat(formData.asset_value) || null,
      };

      if (asset) {
        await dispatch(updateAsset({ assetId: asset.id || asset.asset_id, assetData: submitData })).unwrap();
      } else {
        await dispatch(createAsset(submitData)).unwrap();
      }
      onClose();
    } catch (err) {
      setError(err || 'Failed to save asset');
    } finally {
      setLoading(false);
    }
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
            />
            <Select
              label="Asset Type"
              name="asset_type_id"
              value={formData.asset_type_id}
              onChange={handleChange}
              options={assetTypes.map((t) => ({ value: t.id, label: t.type_name }))}
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
            />
            <Input
              label="OS Version"
              name="os_version"
              value={formData.os_version}
              onChange={handleChange}
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
              options={locations.map((l) => ({ value: l.id, label: l.site_name }))}
            />
            <Select
              label="Owner"
              name="owner_id"
              value={formData.owner_id}
              onChange={handleChange}
              options={owners.map((o) => ({ value: o.id, label: o.full_name }))}
            />
            <Select
              label="Status"
              name="status"
              value={formData.status}
              onChange={handleChange}
              options={status.map((s) => ({ value: s.value, label: s.label }))}
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
              options={confidentiality.map((c) => ({ value: c.value, label: c.label }))}
            />
            <Select
              label="Risk Level"
              name="risk_level"
              value={formData.risk_level}
              onChange={handleChange}
              options={risk.map((r) => ({ value: r.value, label: r.label }))}
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
          >
            <div className="step-num">{step.num}</div>
            <span className="step-title">{step.title}</span>
          </div>
        ))}
      </div>

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
