/* ==========================================
   NGCORION - CIS Benchmark Table View
   Displays audit results in CIS Benchmark format
   ========================================== */

import { useState, useEffect } from 'react';
import './CISBenchmarkTable.css';

const CISBenchmarkTable = ({ sessionId, apiClient }) => {
  const [benchmarkData, setBenchmarkData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (sessionId) {
      fetchBenchmarkTable();
    }
  }, [sessionId]);

  const fetchBenchmarkTable = async () => {
    try {
      setLoading(true);
      setError('');
      const response = await apiClient.get(`/api/audit/sessions/${sessionId}/cis-table`);
      setBenchmarkData(response.data);
    } catch (err) {
      console.error('Failed to load CIS benchmark table:', err);
      setError(err.response?.data?.detail || 'Failed to load CIS Benchmark table');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="cis-loading">Loading CIS Benchmark table...</div>;
  }

  if (error) {
    return <div className="cis-error">{error}</div>;
  }

  if (!benchmarkData) {
    return null;
  }

  const getComplianceColor = (pct) => {
    if (pct >= 90) return '#28a745';
    if (pct >= 70) return '#ffc107';
    return '#dc3545';
  };

  return (
    <div className="cis-benchmark-container">
      {/* Header */}
      <div className="cis-header">
        <h2>{benchmarkData.benchmark_version}</h2>
        <div className="cis-meta">
          <span><strong>Asset:</strong> {benchmarkData.asset_name}</span>
          <span><strong>IP:</strong> {benchmarkData.target_ip}</span>
          <span><strong>Date:</strong> {new Date(benchmarkData.audit_date).toLocaleString()}</span>
        </div>
      </div>

      {/* Summary Card */}
      <div className="cis-summary" style={{ borderColor: getComplianceColor(benchmarkData.summary.compliance_percentage) }}>
        <div className="summary-item">
          <div className="summary-label">Compliance</div>
          <div className="summary-value" style={{ color: getComplianceColor(benchmarkData.summary.compliance_percentage) }}>
            {benchmarkData.summary.compliance_percentage.toFixed(1)}%
          </div>
        </div>
        <div className="summary-item">
          <div className="summary-label">Passed</div>
          <div className="summary-value success">{benchmarkData.summary.passed}</div>
        </div>
        <div className="summary-item">
          <div className="summary-label">Failed</div>
          <div className="summary-value danger">{benchmarkData.summary.failed}</div>
        </div>
        <div className="summary-item">
          <div className="summary-label">Total</div>
          <div className="summary-value">{benchmarkData.summary.total_checks}</div>
        </div>
      </div>

      {/* CIS Benchmark Table */}
      <div className="cis-table-wrapper">
        <table className="cis-table">
          <thead>
            <tr>
              <th style={{ width: '120px' }}>Section</th>
              <th>Recommendation</th>
              <th style={{ width: '140px', textAlign: 'center' }}>Set Correctly</th>
            </tr>
          </thead>
          <tbody>
            {benchmarkData.sections.map((section, index) => (
              <tr key={index} className={section.set_correctly === false ? 'failed' : ''}>
                <td className="section-cell">{section.section}</td>
                <td className="recommendation-cell">{section.recommendation}</td>
                <td className="checkbox-cell">
                  {section.set_correctly === true && (
                    <span className="checkbox checked">☑ Yes</span>
                  )}
                  {section.set_correctly === false && (
                    <span className="checkbox unchecked">☐ No</span>
                  )}
                  {section.set_correctly === null && (
                    <span className="checkbox na">- N/A</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default CISBenchmarkTable;
