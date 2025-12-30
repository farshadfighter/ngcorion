/* ==========================================
   Port Management Modal
   Manage ports and protocols for an asset
   ========================================== */

import { useState, useEffect } from 'react';
import api from '../../../api/axios';
import './PortManagementModal.css';

const PortManagementModal = ({ asset, onClose, onUpdate }) => {
  const [ports, setPorts] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  // New port form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [newPort, setNewPort] = useState({
    port_number: '',
    protocol: 'TCP',
    service_name: '',
    service_product: '',
    service_version: '',
    state: 'open'
  });

  useEffect(() => {
    if (asset?.id) {
      loadPorts();
      loadProtocols();
    }
  }, [asset]);

  const loadPorts = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/api/discovery/assets/${asset.id}/ports`);
      setPorts(response.data.ports || []);
      setError('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load ports');
      setPorts([]);
    } finally {
      setLoading(false);
    }
  };

  const loadProtocols = async () => {
    try {
      // Load available protocols (TCP, UDP, SCTP)
      setProtocols([
        { value: 'TCP', label: 'TCP' },
        { value: 'UDP', label: 'UDP' },
        { value: 'SCTP', label: 'SCTP' }
      ]);
    } catch (err) {
      console.error('Failed to load protocols:', err);
    }
  };

  const handleAddPort = async () => {
    if (!newPort.port_number || newPort.port_number < 1 || newPort.port_number > 65535) {
      setError('Port number must be between 1 and 65535');
      return;
    }

    try {
      setSaving(true);
      setError('');

      const requestData = {
        asset_id: asset.id,
        ports: [
          {
            port_number: parseInt(newPort.port_number),
            protocol: newPort.protocol,
            service_name: newPort.service_name || null,
            service_product: newPort.service_product || null,
            service_version: newPort.service_version || null,
            state: newPort.state
          }
        ]
      };

      await api.post('/api/discovery/ports/add', requestData);

      setSuccessMessage('Port added successfully');
      setTimeout(() => setSuccessMessage(''), 3000);

      // Reset form
      setNewPort({
        port_number: '',
        protocol: 'TCP',
        service_name: '',
        service_product: '',
        service_version: '',
        state: 'open'
      });
      setShowAddForm(false);

      // Reload ports
      await loadPorts();

      // Notify parent to refresh
      if (onUpdate) onUpdate();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to add port');
    } finally {
      setSaving(false);
    }
  };

  const handleDeletePort = async (portId) => {
    if (!window.confirm('Are you sure you want to delete this port?')) {
      return;
    }

    try {
      setSaving(true);
      setError('');

      await api.delete(`/api/discovery/ports/${portId}`);

      setSuccessMessage('Port deleted successfully');
      setTimeout(() => setSuccessMessage(''), 3000);

      // Reload ports
      await loadPorts();

      // Notify parent to refresh
      if (onUpdate) onUpdate();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete port');
    } finally {
      setSaving(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewPort(prev => ({ ...prev, [name]: value }));
    if (error) setError('');
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-large port-management-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h3>🔌 Manage Ports</h3>
            <p className="modal-subtitle">
              Asset: {asset?.asset_name} {asset?.ip_address && `(${asset.ip_address})`}
            </p>
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="modal-body">
          {error && (
            <div className="error-message">
              ⚠️ {error}
            </div>
          )}

          {successMessage && (
            <div className="success-message">
              ✓ {successMessage}
            </div>
          )}

          {/* Add Port Button */}
          {!showAddForm && (
            <div className="add-port-section">
              <button
                className="btn btn-primary btn-small"
                onClick={() => setShowAddForm(true)}
                disabled={saving}
              >
                ➕ Add New Port
              </button>
            </div>
          )}

          {/* Add Port Form */}
          {showAddForm && (
            <div className="add-port-form">
              <h4>Add New Port</h4>
              <div className="form-grid">
                <div className="form-group">
                  <label>Port Number *</label>
                  <input
                    type="number"
                    name="port_number"
                    value={newPort.port_number}
                    onChange={handleInputChange}
                    placeholder="e.g., 80"
                    min="1"
                    max="65535"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Protocol *</label>
                  <select
                    name="protocol"
                    value={newPort.protocol}
                    onChange={handleInputChange}
                  >
                    {protocols.map(p => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label>Service Name</label>
                  <input
                    type="text"
                    name="service_name"
                    value={newPort.service_name}
                    onChange={handleInputChange}
                    placeholder="e.g., http, ssh"
                  />
                </div>

                <div className="form-group">
                  <label>Service Product</label>
                  <input
                    type="text"
                    name="service_product"
                    value={newPort.service_product}
                    onChange={handleInputChange}
                    placeholder="e.g., nginx, Apache"
                  />
                </div>

                <div className="form-group">
                  <label>Service Version</label>
                  <input
                    type="text"
                    name="service_version"
                    value={newPort.service_version}
                    onChange={handleInputChange}
                    placeholder="e.g., 1.18.0"
                  />
                </div>

                <div className="form-group">
                  <label>State</label>
                  <select
                    name="state"
                    value={newPort.state}
                    onChange={handleInputChange}
                  >
                    <option value="open">Open</option>
                    <option value="closed">Closed</option>
                    <option value="filtered">Filtered</option>
                  </select>
                </div>
              </div>

              <div className="form-actions">
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    setShowAddForm(false);
                    setNewPort({
                      port_number: '',
                      protocol: 'TCP',
                      service_name: '',
                      service_product: '',
                      service_version: '',
                      state: 'open'
                    });
                  }}
                  disabled={saving}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleAddPort}
                  disabled={saving || !newPort.port_number}
                >
                  {saving ? 'Adding...' : 'Add Port'}
                </button>
              </div>
            </div>
          )}

          {/* Ports List */}
          <div className="ports-list-section">
            <h4>Current Ports ({ports.length})</h4>

            {loading ? (
              <div className="loading-state">Loading ports...</div>
            ) : ports.length === 0 ? (
              <div className="no-ports">
                <p>📭 No ports configured for this asset</p>
                <p className="text-muted">Click "Add New Port" to add ports</p>
              </div>
            ) : (
              <table className="ports-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>State</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((port) => (
                    <tr key={port.id}>
                      <td><strong>{port.port_number}</strong></td>
                      <td><span className="protocol-badge">{port.protocol}</span></td>
                      <td>{port.service_name || '-'}</td>
                      <td>{port.service_product || '-'}</td>
                      <td>{port.service_version || '-'}</td>
                      <td>
                        <span className={`state-badge state-${port.state}`}>
                          {port.state}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn-icon delete"
                          onClick={() => handleDeletePort(port.id)}
                          disabled={saving}
                          title="Delete port"
                        >
                          🗑️
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default PortManagementModal;
