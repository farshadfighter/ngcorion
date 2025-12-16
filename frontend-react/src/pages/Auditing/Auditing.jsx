/* ==========================================
   NGCORION - Auditing Page
   ========================================== */

import { useState, useEffect } from 'react';
import api from '../../api/axios';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Select from '../../components/common/Select';
import Table from '../../components/common/Table';
import './Auditing.css';

const Auditing = () => {
  const [assets, setAssets] = useState([]);
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [credentials, setCredentials] = useState({
    username: '',
    password: '',
    enable_secret: ''
  });
  const [loading, setLoading] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [auditSession, setAuditSession] = useState(null);
  const [auditResults, setAuditResults] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchAssets();
  }, []);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/assets/');
      setAssets(response.data);
    } catch (err) {
      setError('Failed to load assets');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleExecuteAudit = async () => {
    if (!selectedAssetId) {
      setError('Please select an asset');
      return;
    }
    if (!credentials.username || !credentials.password) {
      setError('Please enter SSH username and password');
      return;
    }

    setError('');
    setExecuting(true);
    setAuditSession(null);
    setAuditResults([]);

    try {
      const response = await api.post('/api/audit/cisco/execute', {
        asset_id: parseInt(selectedAssetId),
        ssh_username: credentials.username,
        ssh_password: credentials.password,
        enable_secret: credentials.enable_secret || credentials.password
      });

      const sessionId = response.data.session_id;

      // Fetch session details
      const sessionResponse = await api.get(`/api/audit/sessions/${sessionId}`);
      setAuditSession(sessionResponse.data);

      // Fetch detailed results
      const resultsResponse = await api.get(`/api/audit/sessions/${sessionId}/results`);
      setAuditResults(resultsResponse.data);

    } catch (err) {
      setError(err.response?.data?.detail || 'Audit execution failed');
      console.error(err);
    } finally {
      setExecuting(false);
    }
  };

  const assetOptions = assets.map(asset => ({
    value: asset.asset_id,
    label: `${asset.asset_name} (${asset.ip_address || asset.hostname || 'No IP'})`
  }));

  const resultsColumns = [
    {
      key: 'rule_id',
      title: 'Rule ID',
      width: '100px'
    },
    {
      key: 'status',
      title: 'Status',
      width: '100px',
      render: (value) => (
        <span className={`audit-status ${value.toLowerCase()}`}>
          {value === 'PASS' ? '✓' : value === 'FAIL' ? '✗' : '○'} {value}
        </span>
      )
    },
    {
      key: 'title',
      title: 'Check Title'
    },
    {
      key: 'description',
      title: 'Description',
      render: (value) => <span className="description-cell">{value}</span>
    },
    {
      key: 'level',
      title: 'Level',
      width: '80px',
      render: (value) => (
        <span className={`level-badge ${value?.toLowerCase()}`}>
          {value}
        </span>
      )
    }
  ];

  const getComplianceColor = (pct) => {
    if (pct >= 90) return 'success';
    if (pct >= 70) return 'warning';
    return 'danger';
  };

  return (
    <div className="auditing-page">
      <div className="page-header">
        <h1 className="page-title">Security Auditing - Cisco CIS Compliance</h1>
      </div>

      {error && (
        <div className="alert alert-error">
          {error}
        </div>
      )}

      <div className="card audit-form-card">
        <h3>Execute Audit</h3>

        <div className="form-grid">
          <Select
            label="Select Asset"
            value={selectedAssetId}
            onChange={setSelectedAssetId}
            options={assetOptions}
            disabled={loading || executing}
            placeholder="Choose an asset..."
          />

          <Input
            label="SSH Username"
            value={credentials.username}
            onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
            placeholder="Enter SSH username"
            disabled={executing}
          />

          <Input
            label="SSH Password"
            type="password"
            value={credentials.password}
            onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
            placeholder="Enter SSH password"
            disabled={executing}
          />

          <Input
            label="Enable Secret (optional)"
            type="password"
            value={credentials.enable_secret}
            onChange={(e) => setCredentials({ ...credentials, enable_secret: e.target.value })}
            placeholder="Enter enable secret"
            disabled={executing}
          />
        </div>

        <div className="form-actions">
          <Button
            onClick={handleExecuteAudit}
            disabled={executing || !selectedAssetId}
          >
            {executing ? 'Executing Audit...' : 'Execute Audit'}
          </Button>
        </div>
      </div>

      {auditSession && (
        <div className="audit-results">
          <div className="results-summary">
            <div className="summary-cards">
              <div className={`summary-card ${getComplianceColor(auditSession.compliance_pct)}`}>
                <div className="card-label">Compliance Score</div>
                <div className="card-value">{auditSession.compliance_pct.toFixed(1)}%</div>
                <div className="card-sub">
                  {auditSession.passed_count} of {auditSession.total_checks} checks passed
                </div>
              </div>

              <div className="summary-card info">
                <div className="card-label">Weighted Score</div>
                <div className="card-value">{auditSession.weighted_compliance_pct.toFixed(1)}%</div>
                <div className="card-sub">Priority-weighted compliance</div>
              </div>

              <div className="summary-card">
                <div className="card-label">Failed Checks</div>
                <div className="card-value danger-text">{auditSession.failed_count}</div>
                <div className="card-sub">Need attention</div>
              </div>

              <div className="summary-card">
                <div className="card-label">Informational</div>
                <div className="card-value">{auditSession.info_count}</div>
                <div className="card-sub">For review</div>
              </div>
            </div>

            <div className="audit-meta">
              <p><strong>Asset:</strong> {auditSession.asset_name}</p>
              <p><strong>IP Address:</strong> {auditSession.ip_address}</p>
              <p><strong>Audit Date:</strong> {new Date(auditSession.audit_date).toLocaleString()}</p>
              <p><strong>Template:</strong> {auditSession.template_name}</p>
            </div>
          </div>

          <div className="card">
            <h3>Detailed Results ({auditResults.length} checks)</h3>
            <Table
              columns={resultsColumns}
              data={auditResults}
              emptyMessage="No results available"
            />
          </div>
        </div>
      )}

      {!auditSession && !executing && (
        <div className="card">
          <div className="placeholder-content">
            <svg viewBox="0 0 24 24" fill="currentColor" className="placeholder-icon">
              <path d="M19.43 12.98c.04-.32.07-.64.07-.98s-.03-.66-.07-.98l2.11-1.65c.19-.15.24-.42.12-.64l-2-3.46c-.12-.22-.39-.3-.61-.22l-2.49 1c-.52-.4-1.08-.73-1.69-.98l-.38-2.65C14.46 2.18 14.25 2 14 2h-4c-.25 0-.46.18-.49.42l-.38 2.65c-.61.25-1.17.59-1.69.98l-2.49-1c-.23-.09-.49 0-.61.22l-2 3.46c-.13.22-.07.49.12.64l2.11 1.65c-.04.32-.07.65-.07.98s.03.66.07.98l-2.11 1.65c-.19.15-.24.42-.12.64l2 3.46c.12.22.39.3.61.22l2.49-1c.52.4 1.08.73 1.69.98l.38 2.65c.03.24.24.42.49.42h4c.25 0 .46-.18.49-.42l.38-2.65c.61-.25 1.17-.59 1.69-.98l2.49 1c.23.09.49 0 .61-.22l2-3.46c.12-.22.07-.49-.12-.64l-2.11-1.65zM12 15.5c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5z"/>
            </svg>
            <h3>No Audit Results</h3>
            <p>Select an asset and execute an audit to see results here.</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Auditing;
