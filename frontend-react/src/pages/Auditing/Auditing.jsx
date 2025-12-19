/* ==========================================
   NGCORION - Auditing Page
   ========================================== */

import { useState, useEffect, useCallback } from 'react';
import api from '../../api/axios';
import Button from '../../components/common/Button';
import Input from '../../components/common/Input';
import Select from '../../components/common/Select';
import Table from '../../components/common/Table';
import CISBenchmarkTable from './CISBenchmarkTable';
import { mockAuditSession, mockAuditResults } from './mockCISData';
import './Auditing.css';

// ============================================
// LocalStorage Persistence Helpers
// ============================================
const AUDIT_STORAGE_KEY = 'audit_session';

const loadAuditFromStorage = () => {
  try {
    const saved = localStorage.getItem(AUDIT_STORAGE_KEY);
    if (saved) {
      return JSON.parse(saved);
    }
  } catch (e) {
    console.warn('Failed to load audit from localStorage:', e);
  }
  return null;
};

const saveAuditToStorage = (session, results) => {
  try {
    if (session) {
      localStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify({ session, results }));
    }
  } catch (e) {
    console.warn('Failed to save audit to localStorage:', e);
  }
};

const clearAuditFromStorage = () => {
  try {
    localStorage.removeItem(AUDIT_STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear audit from localStorage:', e);
  }
};

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
  const [viewMode, setViewMode] = useState('detailed'); // 'detailed' or 'cis-table'

  // Restore audit session from localStorage on mount
  useEffect(() => {
    fetchAssets();

    // Restore saved audit session
    const saved = loadAuditFromStorage();
    if (saved && saved.session) {
      setAuditSession(saved.session);
      setAuditResults(saved.results || []);
      // Set the selected asset to match the restored session
      if (saved.session.asset_id) {
        setSelectedAssetId(String(saved.session.asset_id));
      }
    }
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
      console.log('Executing audit for asset:', selectedAssetId);

      const requestData = {
        asset_id: parseInt(selectedAssetId),
        ssh_username: credentials.username,
        ssh_password: credentials.password,
        ssh_secret: credentials.enable_secret || null,
        profile: 'L1'
      };
      console.log('Request data:', { ...requestData, ssh_password: '***' });

      const response = await api.post('/api/audit/cisco/execute', requestData);
      console.log('Audit response:', response.data);

      // The execute endpoint returns the session directly
      const sessionData = response.data;
      setAuditSession(sessionData);

      // Fetch detailed results using the session_id from response
      if (sessionData.session_id) {
        const resultsResponse = await api.get(`/api/audit/sessions/${sessionData.session_id}/results`);
        console.log('Results:', resultsResponse.data);
        setAuditResults(resultsResponse.data);
        // Save to localStorage for persistence across page refreshes
        saveAuditToStorage(sessionData, resultsResponse.data);
      }

    } catch (err) {
      console.error('Audit error:', err);
      const errorMsg = err.response?.data?.detail || err.message || 'Audit execution failed';
      setError(errorMsg);
    } finally {
      setExecuting(false);
    }
  };

  const handleLoadDemoData = () => {
    setError('');
    setAuditSession(mockAuditSession);
    setAuditResults(mockAuditResults);
    saveAuditToStorage(mockAuditSession, mockAuditResults);
    console.log('Demo data loaded');
  };

  // Clear audit session and localStorage
  const handleClearSession = () => {
    setAuditSession(null);
    setAuditResults([]);
    clearAuditFromStorage();
  };

  const assetOptions = assets.map(asset => ({
    value: asset.id || asset.asset_id,
    label: `${asset.asset_name} (${asset.ip_address || asset.hostname || 'No IP'})`
  }));

  const resultsColumns = [
    {
      key: 'check_number',
      title: 'Check ID',
      width: '100px'
    },
    {
      key: 'status',
      title: 'Status',
      width: '100px',
      render: (value) => (
        <span className={`audit-status ${value?.toLowerCase()}`}>
          {value === 'PASS' ? '✓' : value === 'FAIL' ? '✗' : '○'} {value}
        </span>
      )
    },
    {
      key: 'check_title',
      title: 'Check Title'
    },
    {
      key: 'severity',
      title: 'Severity',
      width: '100px',
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
            onChange={(e) => setSelectedAssetId(e.target.value)}
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
            onClick={handleLoadDemoData}
            variant="secondary"
            disabled={executing}
          >
            Load Demo Data
          </Button>
          {auditSession && (
            <Button
              onClick={handleClearSession}
              variant="secondary"
              disabled={executing}
            >
              Clear Results
            </Button>
          )}
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
          {/* View Toggle */}
          <div className="view-toggle">
            <button
              className={`toggle-btn ${viewMode === 'detailed' ? 'active' : ''}`}
              onClick={() => setViewMode('detailed')}
            >
              Detailed View
            </button>
            <button
              className={`toggle-btn ${viewMode === 'cis-table' ? 'active' : ''}`}
              onClick={() => setViewMode('cis-table')}
            >
              CIS Benchmark Table
            </button>
          </div>

          <div className="results-summary">
            <div className="summary-cards">
              <div className={`summary-card ${getComplianceColor(auditSession.compliance?.compliance_pct || 0)}`}>
                <div className="card-label">Compliance Score</div>
                <div className="card-value">{(auditSession.compliance?.compliance_pct || 0).toFixed(1)}%</div>
                <div className="card-sub">
                  {auditSession.compliance?.passed || 0} of {auditSession.compliance?.total_checks || 0} checks passed
                </div>
              </div>

              <div className="summary-card info">
                <div className="card-label">Weighted Score</div>
                <div className="card-value">{(auditSession.compliance?.weighted_compliance_pct || 0).toFixed(1)}%</div>
                <div className="card-sub">Priority-weighted compliance</div>
              </div>

              <div className="summary-card">
                <div className="card-label">Failed Checks</div>
                <div className="card-value danger-text">{auditSession.compliance?.failed || 0}</div>
                <div className="card-sub">Need attention</div>
              </div>

              <div className="summary-card">
                <div className="card-label">Errors</div>
                <div className="card-value">{auditSession.compliance?.errors || 0}</div>
                <div className="card-sub">For review</div>
              </div>
            </div>

            <div className="audit-meta">
              <p><strong>Asset:</strong> {auditSession.asset_name}</p>
              <p><strong>IP Address:</strong> {auditSession.target_ip}</p>
              <p><strong>Audit Date:</strong> {auditSession.started_at ? new Date(auditSession.started_at).toLocaleString() : 'N/A'}</p>
              <p><strong>Device Type:</strong> {auditSession.device_type}</p>
              <p><strong>Status:</strong> {auditSession.status}</p>
              {auditSession.connection_error && (
                <p className="error-text"><strong>Error:</strong> {auditSession.connection_error}</p>
              )}
            </div>
          </div>

          {/* Conditional View Rendering */}
          {viewMode === 'detailed' ? (
            <div className="card">
              <h3>Detailed Results ({auditResults.length} checks)</h3>
              <Table
                columns={resultsColumns}
                data={auditResults}
                emptyMessage="No results available"
              />
            </div>
          ) : (
            <CISBenchmarkTable
              sessionId={auditSession.session_id}
              apiClient={api}
            />
          )}
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
