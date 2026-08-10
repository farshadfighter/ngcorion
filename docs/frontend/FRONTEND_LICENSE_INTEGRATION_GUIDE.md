# Frontend License Integration Guide

## Overview

This guide explains how to integrate the license system into the frontend application. The license system requires users to activate a license before they can use the application.

---

## Architecture Overview

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Frontend      │─────▶│   Main Backend   │─────▶│ License Server  │
│   (React/Vue)   │      │   (Port 8001)    │      │   (Port 8000)   │
└─────────────────┘      └──────────────────┘      └─────────────────┘
```

**Important:** Frontend communicates with the **Main Backend** (your app), NOT directly with the License Server.

---

## API Endpoints for Frontend

### Base URL
```javascript
const API_BASE_URL = 'http://localhost:8001'; // Your main app
```

### 1. Activate License
**Endpoint:** `POST /api/license/activate`  
**Purpose:** Activate a new license key  
**Authentication:** Not required (this is the first step)

**Request:**
```javascript
POST /api/license/activate
Content-Type: application/json

{
  "license_key": "XXXX-XXXX-XXXX-XXXX"
}
```

**Response (Success - 200):**
```json
{
  "success": true,
  "message": "License activated successfully",
  "license_info": {
    "plan_type": "plan_250",
    "is_pilot_mode": false,
    "expires_at": "2026-05-12T10:30:00Z",
    "limits": {
      "max_audits": 250,
      "max_hardens": 250
    },
    "usage": {
      "used_audits": 0,
      "used_hardens": 0
    }
  }
}
```

**Response (Error - 400/403):**
```json
{
  "detail": "License key not found"
}
// OR
{
  "detail": "License has expired"
}
// OR
{
  "detail": "This license is already activated on another VM"
}
```

---

### 2. Get License Status
**Endpoint:** `GET /api/license/status`  
**Purpose:** Check current license status and quota usage  
**Authentication:** Required (JWT token)

**Request:**
```javascript
GET /api/license/status
Authorization: Bearer <jwt_token>
```

**Response (Success - 200):**
```json
{
  "valid": true,
  "plan_type": "plan_250",
  "is_pilot_mode": false,
  "expires_at": "2026-05-12T10:30:00Z",
  "limits": {
    "max_audits": 250,
    "max_hardens": 250
  },
  "usage": {
    "used_audits": 15,
    "used_hardens": 5
  },
  "remaining": {
    "audits": 235,
    "hardens": 245
  },
  "message": "License is valid"
}
```

**Response (No License - 200):**
```json
{
  "valid": false,
  "message": "No license activated"
}
```

---

### 3. Handle License Errors on API Calls
When making any API call to `/api/*` endpoints, you may receive:

**Response (403 - No License):**
```json
{
  "detail": "No valid license. Please activate a license first.",
  "license_required": true
}
```

**Response (403 - Quota Exhausted):**
```json
{
  "detail": "Audit quota exhausted (250/250). Upgrade your plan."
}
// OR
{
  "detail": "Hardening quota exhausted (250/250). Upgrade your plan."
}
```

Note: Asset Management (asset creation and Auto Discovery) is not license-gated, so these endpoints never return quota-exhausted errors — only audit and hardening operations can.

---

## Implementation Guide

### Step 1: Create License Activation Screen

This should be the first screen users see if no license is activated.

**Component: `LicenseActivation.jsx` (React example)**

```jsx
import React, { useState } from 'react';
import axios from 'axios';

const LicenseActivation = ({ onActivated }) => {
  const [licenseKey, setLicenseKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleActivate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post('/api/license/activate', {
        license_key: licenseKey.trim()
      });

      if (response.data.success) {
        // License activated successfully
        onActivated(response.data.license_info);
      }
    } catch (err) {
      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Failed to activate license. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="license-activation-container">
      <div className="license-activation-card">
        <h1>Activate Your License</h1>
        <p>Please enter your license key to continue</p>

        <form onSubmit={handleActivate}>
          <div className="form-group">
            <label>License Key</label>
            <input
              type="text"
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value)}
              placeholder="XXXX-XXXX-XXXX-XXXX"
              maxLength={19}
              required
              disabled={loading}
            />
          </div>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <button type="submit" disabled={loading || !licenseKey}>
            {loading ? 'Activating...' : 'Activate License'}
          </button>
        </form>

        <div className="help-text">
          <p>Don't have a license key? Contact your administrator.</p>
        </div>
      </div>
    </div>
  );
};

export default LicenseActivation;
```

**CSS Example:**
```css
.license-activation-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.license-activation-card {
  background: white;
  padding: 40px;
  border-radius: 12px;
  box-shadow: 0 10px 40px rgba(0,0,0,0.1);
  max-width: 500px;
  width: 100%;
}

.license-activation-card h1 {
  margin-bottom: 10px;
  color: #333;
}

.license-activation-card p {
  color: #666;
  margin-bottom: 30px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 600;
  color: #333;
}

.form-group input {
  width: 100%;
  padding: 12px;
  border: 2px solid #e0e0e0;
  border-radius: 6px;
  font-size: 16px;
  font-family: monospace;
  letter-spacing: 2px;
  text-transform: uppercase;
}

.form-group input:focus {
  outline: none;
  border-color: #667eea;
}

.error-message {
  background: #fee;
  color: #c33;
  padding: 12px;
  border-radius: 6px;
  margin-bottom: 20px;
  border-left: 4px solid #c33;
}

button[type="submit"] {
  width: 100%;
  padding: 14px;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 6px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.3s;
}

button[type="submit"]:hover:not(:disabled) {
  background: #5568d3;
}

button[type="submit"]:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.help-text {
  margin-top: 20px;
  text-align: center;
  color: #999;
  font-size: 14px;
}
```

---

### Step 2: Create License Status Display

Show license information in the dashboard or settings.

**Component: `LicenseStatus.jsx`**

```jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';

const LicenseStatus = () => {
  const [license, setLicense] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLicenseStatus();
  }, []);

  const fetchLicenseStatus = async () => {
    try {
      const response = await axios.get('/api/license/status', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`
        }
      });
      setLicense(response.data);
    } catch (err) {
      console.error('Failed to fetch license status:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading license info...</div>;
  if (!license?.valid) return <div>No valid license</div>;

  const getPlanName = (planType) => {
    const plans = {
      pilot: 'Pilot',
      plan_100: '100 Audit / 100 Hardening',
      plan_250: '250 Audit / 250 Hardening',
      plan_500: '500 Audit / 500 Hardening',
      unlimited: 'Unlimited'
    };
    return plans[planType] || planType;
  };

  const getUsagePercentage = (used, max) => {
    if (max === null) return 0; // Unlimited
    return (used / max) * 100;
  };

  const getUsageColor = (percentage) => {
    if (percentage >= 90) return '#e74c3c';
    if (percentage >= 70) return '#f39c12';
    return '#27ae60';
  };

  return (
    <div className="license-status-container">
      <div className="license-header">
        <h2>License Information</h2>
        <span className={`license-badge ${license.is_pilot_mode ? 'pilot' : 'active'}`}>
          {license.is_pilot_mode ? 'PILOT MODE' : 'ACTIVE'}
        </span>
      </div>

      <div className="license-details">
        <div className="detail-row">
          <span className="label">Plan:</span>
          <span className="value">{getPlanName(license.plan_type)}</span>
        </div>
        <div className="detail-row">
          <span className="label">Expires:</span>
          <span className="value">
            {new Date(license.expires_at).toLocaleDateString()}
          </span>
        </div>
      </div>

      <div className="quota-section">
        <h3>Quota Usage</h3>

        {/* Note: Asset Management (asset creation and Auto Discovery) is not
            license-gated, so there is no quota to display for it. Only
            audits and hardens are tracked. */}

        {/* Audits */}
        <div className="quota-item">
          <div className="quota-header">
            <span>Audits</span>
            <span>
              {license.usage.used_audits} / {license.limits.max_audits || '∞'}
            </span>
          </div>
          {license.limits.max_audits && (
            <div className="progress-bar">
              <div 
                className="progress-fill"
                style={{
                  width: `${getUsagePercentage(license.usage.used_audits, license.limits.max_audits)}%`,
                  backgroundColor: getUsageColor(getUsagePercentage(license.usage.used_audits, license.limits.max_audits))
                }}
              />
            </div>
          )}
        </div>

        {/* Hardens */}
        <div className="quota-item">
          <div className="quota-header">
            <span>Hardens</span>
            <span>
              {license.usage.used_hardens} / {license.limits.max_hardens || '∞'}
            </span>
          </div>
          {license.limits.max_hardens && (
            <div className="progress-bar">
              <div 
                className="progress-fill"
                style={{
                  width: `${getUsagePercentage(license.usage.used_hardens, license.limits.max_hardens)}%`,
                  backgroundColor: getUsageColor(getUsagePercentage(license.usage.used_hardens, license.limits.max_hardens))
                }}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LicenseStatus;
```

**CSS for License Status:**
```css
.license-status-container {
  background: white;
  border-radius: 8px;
  padding: 24px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.license-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 2px solid #f0f0f0;
}

.license-badge {
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}

.license-badge.active {
  background: #d4edda;
  color: #155724;
}

.license-badge.pilot {
  background: #fff3cd;
  color: #856404;
}

.license-details {
  margin-bottom: 24px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
}

.detail-row .label {
  color: #666;
  font-weight: 500;
}

.detail-row .value {
  color: #333;
  font-weight: 600;
}

.quota-section h3 {
  margin-bottom: 16px;
  color: #333;
}

.quota-item {
  margin-bottom: 16px;
}

.quota-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
  font-size: 14px;
}

.quota-header span:first-child {
  color: #666;
  font-weight: 500;
}

.quota-header span:last-child {
  color: #333;
  font-weight: 600;
  font-family: monospace;
}

.progress-bar {
  height: 8px;
  background: #f0f0f0;
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  transition: width 0.3s ease, background-color 0.3s ease;
  border-radius: 4px;
}
```

---

### Step 3: Handle License Errors Globally

Create an Axios interceptor to handle license errors.

**File: `api/axiosConfig.js`**

```javascript
import axios from 'axios';

// Create axios instance
const api = axios.create({
  baseURL: 'http://localhost:8001',
  timeout: 10000
});

// Request interceptor - add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - handle license errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 403) {
      const data = error.response.data;
      
      // License required
      if (data.license_required) {
        // Redirect to license activation page
        window.location.href = '/activate-license';
        return Promise.reject(error);
      }
      
      // Quota exhausted
      if (data.detail?.includes('limit reached') || 
          data.detail?.includes('quota exhausted')) {
        // Show quota exhausted modal/notification
        showQuotaExhaustedNotification(data.detail);
        return Promise.reject(error);
      }
    }
    
    return Promise.reject(error);
  }
);

function showQuotaExhaustedNotification(message) {
  // Implement your notification system here
  // Example: toast notification, modal, etc.
  alert(message); // Replace with your notification library
}

export default api;
```

---

### Step 4: App Initialization Flow

**File: `App.jsx`**

```jsx
import React, { useState, useEffect } from 'react';
import axios from './api/axiosConfig';
import LicenseActivation from './components/LicenseActivation';
import Dashboard from './components/Dashboard';
import Login from './components/Login';

const App = () => {
  const [licenseStatus, setLicenseStatus] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkLicenseAndAuth();
  }, []);

  const checkLicenseAndAuth = async () => {
    try {
      // Check if user is logged in
      const token = localStorage.getItem('token');
      if (!token) {
        setLoading(false);
        return;
      }

      setIsAuthenticated(true);

      // Check license status
      const response = await axios.get('/api/license/status');
      setLicenseStatus(response.data);
    } catch (err) {
      console.error('Failed to check license:', err);
      setLicenseStatus({ valid: false });
    } finally {
      setLoading(false);
    }
  };

  const handleLicenseActivated = (licenseInfo) => {
    setLicenseStatus({
      valid: true,
      ...licenseInfo
    });
  };

  const handleLogin = () => {
    setIsAuthenticated(true);
    checkLicenseAndAuth();
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  // Not authenticated - show login
  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  // No valid license - show activation screen
  if (!licenseStatus?.valid) {
    return <LicenseActivation onActivated={handleLicenseActivated} />;
  }

  // Everything OK - show main app
  return <Dashboard licenseStatus={licenseStatus} />;
};

export default App;
```

---

### Step 5: Show Quota Warnings

Create a component to warn users when quota is running low.

**Component: `QuotaWarning.jsx`**

```jsx
import React from 'react';

const QuotaWarning = ({ license }) => {
  const getWarnings = () => {
    const warnings = [];
    
    if (!license?.limits || !license?.usage) return warnings;

    const checkQuota = (name, used, max) => {
      if (max === null) return; // Unlimited
      const percentage = (used / max) * 100;
      
      if (percentage >= 90) {
        warnings.push({
          type: 'danger',
          message: `${name} quota almost exhausted (${used}/${max})`
        });
      } else if (percentage >= 70) {
        warnings.push({
          type: 'warning',
          message: `${name} quota running low (${used}/${max})`
        });
      }
    };

    checkQuota('Audits', license.usage.used_audits, license.limits.max_audits);
    checkQuota('Hardens', license.usage.used_hardens, license.limits.max_hardens);

    return warnings;
  };

  const warnings = getWarnings();

  if (warnings.length === 0) return null;

  return (
    <div className="quota-warnings">
      {warnings.map((warning, index) => (
        <div key={index} className={`alert alert-${warning.type}`}>
          <span className="alert-icon">⚠️</span>
          <span>{warning.message}</span>
          <button className="upgrade-btn">Upgrade Plan</button>
        </div>
      ))}
    </div>
  );
};

export default QuotaWarning;
```

---

## Error Handling Reference

### Common Error Scenarios

| Error | Status | Response | Action |
|-------|--------|----------|--------|
| No license | 403 | `{"detail": "No valid license...", "license_required": true}` | Redirect to activation page |
| License expired | 403 | `{"detail": "License has expired"}` | Show renewal message |
| Quota exhausted | 403 | `{"detail": "Audit quota exhausted (250/250)..."}` | Show upgrade prompt |
| Invalid license key | 400 | `{"detail": "License key not found"}` | Show error in activation form |
| Already activated | 400 | `{"detail": "...already activated on another VM"}` | Contact support message |

---

## Testing Checklist

- [ ] License activation with valid key works
- [ ] License activation with invalid key shows error
- [ ] App redirects to activation if no license
- [ ] License status displays correctly
- [ ] Quota usage updates after operations
- [ ] Quota warnings appear at 70% and 90%
- [ ] Quota exhausted errors are handled gracefully
- [ ] License expiration is displayed correctly
- [ ] Pilot mode badge shows when applicable

---

## Vue.js Example (Alternative)

If you're using Vue.js instead of React:

**Component: `LicenseActivation.vue`**

```vue
<template>
  <div class="license-activation-container">
    <div class="license-activation-card">
      <h1>Activate Your License</h1>
      <p>Please enter your license key to continue</p>

      <form @submit.prevent="handleActivate">
        <div class="form-group">
          <label>License Key</label>
          <input
            v-model="licenseKey"
            type="text"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            maxlength="19"
            required
            :disabled="loading"
          />
        </div>

        <div v-if="error" class="error-message">
          {{ error }}
        </div>

        <button type="submit" :disabled="loading || !licenseKey">
          {{ loading ? 'Activating...' : 'Activate License' }}
        </button>
      </form>

      <div class="help-text">
        <p>Don't have a license key? Contact your administrator.</p>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  name: 'LicenseActivation',
  data() {
    return {
      licenseKey: '',
      loading: false,
      error: ''
    };
  },
  methods: {
    async handleActivate() {
      this.loading = true;
      this.error = '';

      try {
        const response = await axios.post('/api/license/activate', {
          license_key: this.licenseKey.trim()
        });

        if (response.data.success) {
          this.$emit('activated', response.data.license_info);
        }
      } catch (err) {
        if (err.response?.data?.detail) {
          this.error = err.response.data.detail;
        } else {
          this.error = 'Failed to activate license. Please try again.';
        }
      } finally {
        this.loading = false;
      }
    }
  }
};
</script>
```

---

## Summary

**What Frontend Needs to Implement:**

1. **License Activation Screen** - First-time setup
2. **License Status Display** - Show quota usage in dashboard/settings
3. **Global Error Handler** - Intercept 403 errors for license issues
4. **Quota Warnings** - Alert users when running low
5. **App Initialization** - Check license before showing main app

**API Endpoints to Use:**
- `POST /api/license/activate` - Activate license
- `GET /api/license/status` - Get current status

**No Direct Communication with License Server** - All requests go through your main backend.

---

## Need Help?

- Backend API documentation: See `LICENSE_SYSTEM_COMPLETE_GUIDE.md`
- License plans: See `LICENSE_PLANS_SUMMARY.md`
- Questions? Contact the backend team
