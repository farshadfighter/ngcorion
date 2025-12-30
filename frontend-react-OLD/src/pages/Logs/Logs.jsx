/* ==========================================
   NGCORION - Logs Page
   ========================================== */

import { useState, useEffect } from 'react';
import api from '../../api/axios';
import Table from '../../components/common/Table';
import './Logs.css';

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, success, failed

  useEffect(() => {
    loadLogs();
  }, [filter]);

  const loadLogs = async () => {
    setLoading(true);
    try {
      let url = '/api/logs/?limit=100';
      if (filter === 'success') url += '&success_only=true';
      if (filter === 'failed') url += '&success_only=false';
      
      const response = await api.get(url);
      setLogs(response.data);
    } catch (error) {
      console.error('Error loading logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    { key: 'id', title: 'ID', width: '60px' },
    { key: 'username', title: 'Username' },
    { 
      key: 'success', 
      title: 'Status',
      render: (value) => (
        <span className={`status-badge ${value ? 'active' : 'decommissioned'}`}>
          {value ? 'Success' : 'Failed'}
        </span>
      )
    },
    { key: 'ip_address', title: 'IP Address' },
    { key: 'message', title: 'Message' },
    { 
      key: 'timestamp', 
      title: 'Time',
      render: (value) => new Date(value).toLocaleString()
    },
  ];

  return (
    <div className="logs-page">
      <div className="page-header">
        <h1 className="page-title">System Logs</h1>
        <div className="logs-filter">
          <button 
            className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            All
          </button>
          <button 
            className={`filter-btn ${filter === 'success' ? 'active' : ''}`}
            onClick={() => setFilter('success')}
          >
            Success
          </button>
          <button 
            className={`filter-btn ${filter === 'failed' ? 'active' : ''}`}
            onClick={() => setFilter('failed')}
          >
            Failed
          </button>
        </div>
      </div>

      <Table 
        columns={columns} 
        data={logs} 
        loading={loading}
        emptyMessage="No logs found"
      />
    </div>
  );
};

export default Logs;
