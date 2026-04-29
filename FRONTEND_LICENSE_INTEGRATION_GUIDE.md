# Frontend License Integration Guide

Complete guide for integrating the license system into the frontend application.

---

## Table of Contents

1. [Overview](#overview)
2. [API Endpoints](#api-endpoints)
3. [Application Startup Flow](#application-startup-flow)
4. [License Activation Screen](#license-activation-screen)
5. [Global Error Handling](#global-error-handling)
6. [License Status Display](#license-status-display)
7. [TypeScript Interfaces](#typescript-interfaces)
8. [React Component Examples](#react-component-examples)
9. [Quota Management](#quota-management)
10. [What Frontend Does NOT Need](#what-frontend-does-not-need)

---

## Overview

### How the License System Works

1. **User cannot generate their own license** — Admin generates license keys and gives them to users
2. **License is machine-locked** — Each license is tied to the VM fingerprint where the main app runs
3. **Backend handles everything** — Fingerprint generation, heartbeat, validation all happen server-side
4. **Frontend only needs 2 endpoints**:
   - `GET /api/license/status` — Check current license state
   - `POST /api/license/activate` — Activate a license key

### Key Rules

- **All plans require activation** — Even Pilot (trial) users must activate a license key first
- **No license = blocked** — Without a valid license, all `/api/*` endpoints return `403` (except login, health, and license endpoints)
- **Quota enforcement** — Operations (discovery, audit, harden) consume quota; assets have a ceiling limit
- **Backend auto-validates** — Heartbeat runs every hour in the background; frontend doesn't need to call it

---

## API Endpoints

### Main App Endpoints (Port 8000)

#### 1. Get License Status

```http
GET /api/license/status
```

**No authentication required** — This endpoint is always accessible.

**Response:**

```json
{
  "valid": true,
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "message": "License is valid",
  "limits": {
    "max_assets": 50,
    "max_discoveries": 200,
    "max_audits": 500,
    "max_hardens": 200,
    "max_monitors": 50
  },
  "usage": {
    "used_assets": 12,
    "used_discoveries": 5,
    "used_audits": 8,
    "used_hardens": 3,
    "used_monitors": 2
  }
}
```

**When no license is activated:**

```json
{
  "valid": false,
  "plan_type": null,
  "is_pilot_mode": false,
  "message": "No license activated",
  "limits": null,
  "usage": null
}
```


---

#### 2. Activate License

```http
POST /api/license/activate
Content-Type: application/json
```

**No authentication required** — Users must activate before they can login.

**Request Body:**

```json
{
  "license_key": "XXXX-XXXX-XXXX-XXXX"
}
```

**Success Response (200):**

```json
{
  "valid": true,
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "message": "License activated successfully",
  "limits": {
    "max_assets": 50,
    "max_discoveries": 200,
    "max_audits": 500,
    "max_hardens": 200,
    "max_monitors": 50
  },
  "usage": {
    "used_assets": 0,
    "used_discoveries": 0,
    "used_audits": 0,
    "used_hardens": 0,
    "used_monitors": 0
  }
}
```

**Error Responses:**

```json
// 400 - Invalid license key
{
  "detail": "License key not found"
}

// 400 - Already activated on another machine
{
  "detail": "License already activated on a different machine"
}

// 400 - License expired
{
  "detail": "License has expired"
}

// 500 - Server error
{
  "detail": "Activation failed: <error message>"
}
```

---

### License-Protected Endpoints

All other `/api/*` endpoints require a valid license. If no license is active, they return:

```json
// 403 Forbidden
{
  "detail": "No valid license. Please activate a license first.",
  "license_required": true
}
```

**Quota Exhausted Error:**

When an operation quota is exhausted (e.g., max audits reached):

```json
// 403 Forbidden
{
  "detail": "Audit quota exhausted (500/500). Upgrade your plan to continue."
}
```

**Asset Limit Reached:**

When trying to create an asset beyond the limit:

```json
// 403 Forbidden
{
  "detail": "Asset limit reached (50/50). Upgrade your plan or delete unused assets."
}
```

---

## Application Startup Flow

### Recommended Flow

```
App Start
    ↓
Check License Status (GET /api/license/status)
    ↓
    ├─→ valid: false
    │       ↓
    │   Show Activation Screen
    │       ↓
    │   User enters license key
    │       ↓
    │   POST /api/license/activate
    │       ↓
    │       ├─→ Success: Proceed to Login
    │       └─→ Error: Show error message
    │
    └─→ valid: true
            ↓
        Proceed to Login Screen
```

### Implementation Example

```typescript
// App.tsx or main entry point
import { useEffect, useState } from 'react';
import { checkLicenseStatus } from './api/license';

function App() {
  const [licenseStatus, setLicenseStatus] = useState<'loading' | 'valid' | 'invalid'>('loading');
  const [licenseData, setLicenseData] = useState(null);

  useEffect(() => {
    async function initApp() {
      try {
        const status = await checkLicenseStatus();
        setLicenseData(status);
        
        if (status.valid) {
          setLicenseStatus('valid');
        } else {
          setLicenseStatus('invalid');
        }
      } catch (error) {
        console.error('Failed to check license:', error);
        setLicenseStatus('invalid');
      }
    }
    
    initApp();
  }, []);

  if (licenseStatus === 'loading') {
    return <LoadingScreen />;
  }

  if (licenseStatus === 'invalid') {
    return <LicenseActivationScreen onActivated={() => setLicenseStatus('valid')} />;
  }

  return <MainApp licenseData={licenseData} />;
}
```

---

## License Activation Screen

### UI Requirements

1. **Input field** for license key (format: `XXXX-XXXX-XXXX-XXXX`)
2. **Activate button**
3. **Error message display**
4. **Loading state** during activation
5. **Help text** explaining where to get a license key

### Component Example

```tsx
import { useState } from 'react';
import { activateLicense } from './api/license';

interface Props {
  onActivated: () => void;
}

export function LicenseActivationScreen({ onActivated }: Props) {
  const [licenseKey, setLicenseKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleActivate = async () => {
    if (!licenseKey.trim()) {
      setError('Please enter a license key');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = await activateLicense(licenseKey);
      
      if (result.valid) {
        // Success! Store license data if needed
        localStorage.setItem('license_data', JSON.stringify(result));
        onActivated();
      } else {
        setError(result.message || 'Activation failed');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Activation failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="activation-screen">
      <div className="activation-card">
        <h1>Activate Your License</h1>
        <p>Enter the license key provided by your administrator</p>
        
        <input
          type="text"
          placeholder="XXXX-XXXX-XXXX-XXXX"
          value={licenseKey}
          onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
          disabled={loading}
          maxLength={19}
        />
        
        {error && (
          <div className="error-message">{error}</div>
        )}
        
        <button onClick={handleActivate} disabled={loading}>
          {loading ? 'Activating...' : 'Activate License'}
        </button>
        
        <div className="help-text">
          <p>Don't have a license key?</p>
          <p>Contact your system administrator to obtain one.</p>
        </div>
      </div>
    </div>
  );
}
```

---

## Global Error Handling

### Axios Interceptor (Recommended)

Set up a global interceptor to catch license-related errors:

```typescript
// api/axios.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor for global error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 403) {
      const data = error.response.data;
      
      // License required error
      if (data.license_required) {
        // Redirect to activation screen
        window.location.href = '/activate-license';
        return Promise.reject(new Error('License activation required'));
      }
      
      // Quota exhausted error
      if (data.detail?.includes('quota') || data.detail?.includes('limit')) {
        // Show upgrade modal or notification
        showQuotaExhaustedModal(data.detail);
        return Promise.reject(new Error(data.detail));
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;
```

### React Context for License State

```typescript
// context/LicenseContext.tsx
import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { checkLicenseStatus, LicenseStatus } from '../api/license';

interface LicenseContextType {
  license: LicenseStatus | null;
  loading: boolean;
  refreshLicense: () => Promise<void>;
}

const LicenseContext = createContext<LicenseContextType | undefined>(undefined);

export function LicenseProvider({ children }: { children: ReactNode }) {
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshLicense = async () => {
    try {
      const status = await checkLicenseStatus();
      setLicense(status);
    } catch (error) {
      console.error('Failed to refresh license:', error);
    }
  };

  useEffect(() => {
    async function init() {
      await refreshLicense();
      setLoading(false);
    }
    init();
  }, []);

  return (
    <LicenseContext.Provider value={{ license, loading, refreshLicense }}>
      {children}
    </LicenseContext.Provider>
  );
}

export function useLicense() {
  const context = useContext(LicenseContext);
  if (!context) {
    throw new Error('useLicense must be used within LicenseProvider');
  }
  return context;
}
```


---

## License Status Display

### Plan Badge Component

```tsx
interface PlanBadgeProps {
  planType: string | null;
  isPilotMode: boolean;
}

export function PlanBadge({ planType, isPilotMode }: PlanBadgeProps) {
  if (!planType) return null;

  const planNames = {
    pilot: 'Pilot (Trial)',
    basic1: 'Basic 15',
    basic2: 'Basic 50',
    basic3: 'Basic 150',
    enterprise: 'Enterprise',
  };

  const planColors = {
    pilot: 'bg-yellow-500',
    basic1: 'bg-blue-500',
    basic2: 'bg-green-500',
    basic3: 'bg-purple-500',
    enterprise: 'bg-gradient-to-r from-purple-600 to-pink-600',
  };

  return (
    <span className={`px-3 py-1 rounded-full text-white text-sm ${planColors[planType]}`}>
      {planNames[planType] || planType}
      {isPilotMode && ' 🚀'}
    </span>
  );
}
```

### Quota Display Component

```tsx
interface QuotaBarProps {
  label: string;
  used: number;
  max: number | null;
}

export function QuotaBar({ label, used, max }: QuotaBarProps) {
  if (max === null) {
    return (
      <div className="quota-item">
        <div className="quota-label">{label}</div>
        <div className="quota-unlimited">Unlimited ∞</div>
      </div>
    );
  }

  const percentage = (used / max) * 100;
  const isWarning = percentage >= 80;
  const isDanger = percentage >= 95;

  return (
    <div className="quota-item">
      <div className="quota-header">
        <span className="quota-label">{label}</span>
        <span className={`quota-count ${isDanger ? 'text-red-600' : isWarning ? 'text-yellow-600' : ''}`}>
          {used} / {max}
        </span>
      </div>
      <div className="quota-bar-container">
        <div
          className={`quota-bar ${isDanger ? 'bg-red-500' : isWarning ? 'bg-yellow-500' : 'bg-green-500'}`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  );
}
```

### License Dashboard Component

```tsx
import { useLicense } from '../context/LicenseContext';
import { PlanBadge } from './PlanBadge';
import { QuotaBar } from './QuotaBar';

export function LicenseDashboard() {
  const { license, loading, refreshLicense } = useLicense();

  if (loading) return <div>Loading license info...</div>;
  if (!license || !license.valid) return <div>No valid license</div>;

  const { plan_type, is_pilot_mode, limits, usage } = license;

  return (
    <div className="license-dashboard">
      <div className="license-header">
        <h2>License Information</h2>
        <PlanBadge planType={plan_type} isPilotMode={is_pilot_mode} />
        <button onClick={refreshLicense}>Refresh</button>
      </div>

      <div className="quota-section">
        <h3>Usage & Limits</h3>
        
        <QuotaBar
          label="Assets"
          used={usage?.used_assets || 0}
          max={limits?.max_assets || null}
        />
        
        <QuotaBar
          label="Discoveries"
          used={usage?.used_discoveries || 0}
          max={limits?.max_discoveries || null}
        />
        
        <QuotaBar
          label="Audits"
          used={usage?.used_audits || 0}
          max={limits?.max_audits || null}
        />
        
        <QuotaBar
          label="Hardens"
          used={usage?.used_hardens || 0}
          max={limits?.max_hardens || null}
        />
        
        <QuotaBar
          label="Monitors"
          used={usage?.used_monitors || 0}
          max={limits?.max_monitors || null}
        />
      </div>

      {is_pilot_mode && (
        <div className="pilot-notice">
          <p>🚀 You're on a trial plan. Upgrade for more features!</p>
        </div>
      )}
    </div>
  );
}
```

---

## TypeScript Interfaces

```typescript
// types/license.ts

export interface LicenseStatus {
  valid: boolean;
  plan_type: 'pilot' | 'basic1' | 'basic2' | 'basic3' | 'enterprise' | null;
  is_pilot_mode: boolean;
  message: string;
  limits: LicenseLimits | null;
  usage: LicenseUsage | null;
}

export interface LicenseLimits {
  max_assets: number | null;       // null = unlimited (Enterprise)
  max_discoveries: number | null;
  max_audits: number | null;
  max_hardens: number | null;
  max_monitors: number | null;
}

export interface LicenseUsage {
  used_assets: number;
  used_discoveries: number;
  used_audits: number;
  used_hardens: number;
  used_monitors: number;
}

export interface LicenseActivateRequest {
  license_key: string;
}

export interface LicenseError {
  detail: string;
  license_required?: boolean;
}
```

---

## React Component Examples

### API Service

```typescript
// api/license.ts
import api from './axios';
import { LicenseStatus, LicenseActivateRequest } from '../types/license';

export async function checkLicenseStatus(): Promise<LicenseStatus> {
  const response = await api.get<LicenseStatus>('/api/license/status');
  return response.data;
}

export async function activateLicense(licenseKey: string): Promise<LicenseStatus> {
  const response = await api.post<LicenseStatus>('/api/license/activate', {
    license_key: licenseKey,
  });
  return response.data;
}
```

### Protected Route Component

```tsx
// components/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useLicense } from '../context/LicenseContext';

interface Props {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: Props) {
  const { license, loading } = useLicense();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!license || !license.valid) {
    return <Navigate to="/activate-license" replace />;
  }

  return <>{children}</>;
}
```

### Usage in Router

```tsx
// App.tsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { LicenseProvider } from './context/LicenseContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LicenseActivationScreen } from './pages/LicenseActivation';
import { Dashboard } from './pages/Dashboard';

function App() {
  return (
    <BrowserRouter>
      <LicenseProvider>
        <Routes>
          <Route path="/activate-license" element={<LicenseActivationScreen />} />
          
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          
          {/* Other protected routes */}
        </Routes>
      </LicenseProvider>
    </BrowserRouter>
  );
}
```

---

## Quota Management

### Pre-Operation Quota Check

Before performing operations that consume quota, check if quota is available:

```typescript
// hooks/useQuotaCheck.ts
import { useLicense } from '../context/LicenseContext';

export function useQuotaCheck() {
  const { license } = useLicense();

  const canPerformOperation = (operationType: keyof LicenseUsage): boolean => {
    if (!license || !license.valid) return false;
    if (!license.limits || !license.usage) return false;

    // Enterprise has unlimited quota
    const limitKey = `max_${operationType.replace('used_', '')}s` as keyof LicenseLimits;
    const limit = license.limits[limitKey];
    
    if (limit === null) return true; // Unlimited

    const used = license.usage[operationType];
    return used < limit;
  };

  const getRemainingQuota = (operationType: keyof LicenseUsage): number | null => {
    if (!license || !license.valid) return 0;
    if (!license.limits || !license.usage) return 0;

    const limitKey = `max_${operationType.replace('used_', '')}s` as keyof LicenseLimits;
    const limit = license.limits[limitKey];
    
    if (limit === null) return null; // Unlimited

    const used = license.usage[operationType];
    return Math.max(0, limit - used);
  };

  return { canPerformOperation, getRemainingQuota };
}
```

### Usage Example

```tsx
// components/AuditButton.tsx
import { useQuotaCheck } from '../hooks/useQuotaCheck';

export function AuditButton() {
  const { canPerformOperation, getRemainingQuota } = useQuotaCheck();
  const remaining = getRemainingQuota('used_audits');

  const handleAudit = async () => {
    if (!canPerformOperation('used_audits')) {
      alert('Audit quota exhausted. Please upgrade your plan.');
      return;
    }

    try {
      await performAudit();
      // Backend will consume quota automatically
    } catch (error) {
      // Handle error
    }
  };

  return (
    <div>
      <button onClick={handleAudit} disabled={!canPerformOperation('used_audits')}>
        Run Audit
      </button>
      {remaining !== null && (
        <span className="quota-hint">
          {remaining} audits remaining
        </span>
      )}
    </div>
  );
}
```

### Handling Quota Exhausted Errors

```tsx
// components/QuotaExhaustedModal.tsx
interface Props {
  message: string;
  onClose: () => void;
  onUpgrade: () => void;
}

export function QuotaExhaustedModal({ message, onClose, onUpgrade }: Props) {
  return (
    <div className="modal-overlay">
      <div className="modal">
        <h2>Quota Limit Reached</h2>
        <p>{message}</p>
        
        <div className="modal-actions">
          <button onClick={onUpgrade} className="btn-primary">
            Upgrade Plan
          </button>
          <button onClick={onClose} className="btn-secondary">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
```


---

## What Frontend Does NOT Need

### 1. Fingerprint Generation

**Backend handles this automatically.**

- The fingerprint is generated by the license server
- Main app fetches it when activating
- Frontend never sees or needs the fingerprint value

### 2. Heartbeat Calls

**Backend runs heartbeat automatically every hour.**

- No need to call `/api/licenses/heartbeat` from frontend
- Backend handles this in a background thread
- Heartbeat validates license and checks for expiration

### 3. Organization Token

**This is a secret value, never exposed to frontend.**

- Returned by license server during activation
- Stored encrypted in `~/.license` on the server
- Used for HMAC signature verification
- Frontend never needs to know or use this value

### 4. Manual Quota Consumption

**Backend consumes quota automatically when operations are performed.**

- When you call `POST /api/discovery/scan`, backend calls `consume("discovery")`
- When you call `POST /api/audit/cisco/execute`, backend calls `consume("audit")`
- Frontend just makes normal API calls; quota is handled server-side

### 5. License Validation Calls

**Backend validates automatically on startup and via heartbeat.**

- No need to call `/api/licenses/validate` from frontend
- Use `GET /api/license/status` instead (reads from in-memory cache)
- Backend keeps license state up-to-date automatically

### 6. Signature Generation

**All HMAC signatures are generated server-side.**

- Frontend doesn't need to sign requests
- Backend handles all cryptographic operations
- Frontend just sends normal HTTP requests

---

## Plan Types & Limits Reference

| Plan | Assets | Discoveries | Audits | Hardens | Monitors | Duration |
|------|--------|-------------|--------|---------|----------|----------|
| **Pilot** | 5 | 10 | 20 | 10 | 5 | 30 days |
| **Basic1** | 15 | 50 | 100 | 50 | 15 | 365 days |
| **Basic2** | 50 | 200 | 500 | 200 | 50 | 365 days |
| **Basic3** | 150 | 600 | 1500 | 600 | 150 | 365 days |
| **Enterprise** | ∞ | ∞ | ∞ | ∞ | ∞ | 365 days |

---

## Error Handling Checklist

### ✅ Handle These Errors

1. **License not activated** (403 with `license_required: true`)
   - Redirect to activation screen
   - Show "Please activate your license" message

2. **Quota exhausted** (403 with quota message)
   - Show upgrade modal
   - Display remaining quota
   - Disable operation buttons when quota is 0

3. **Asset limit reached** (403 with asset limit message)
   - Show "Delete assets or upgrade" message
   - Display current asset count
   - Disable "Add Asset" button when at limit

4. **Activation failed** (400 from `/api/license/activate`)
   - Show error message from server
   - Allow user to retry with different key
   - Provide help text

5. **License expired** (detected via `valid: false` in status)
   - Show "License expired" message
   - Prompt for new license key
   - Block all operations

---

## Testing Checklist

### ✅ Test These Scenarios

1. **First-time user (no license)**
   - App should show activation screen
   - Cannot access any features until activated

2. **Valid license activation**
   - Enter valid license key
   - Should redirect to main app
   - License status should show correct plan

3. **Invalid license key**
   - Enter invalid key
   - Should show error message
   - Should allow retry

4. **Quota exhaustion**
   - Perform operations until quota is exhausted
   - Should show quota exhausted error
   - Should disable operation buttons

5. **Asset limit reached**
   - Create assets until limit is reached
   - Should show asset limit error
   - Should disable "Add Asset" button

6. **License expiration**
   - Wait for license to expire (or test with expired license)
   - Should block all operations
   - Should prompt for new license

7. **Page refresh**
   - Refresh page after activation
   - License status should persist
   - Should not require re-activation

---

## Complete Example: Full Integration

```typescript
// main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { LicenseProvider } from './context/LicenseContext';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <LicenseProvider>
        <App />
      </LicenseProvider>
    </BrowserRouter>
  </React.StrictMode>
);
```

```typescript
// App.tsx
import { Routes, Route, Navigate } from 'react-router-dom';
import { useLicense } from './context/LicenseContext';
import { LicenseActivationScreen } from './pages/LicenseActivation';
import { Dashboard } from './pages/Dashboard';
import { Assets } from './pages/Assets';
import { Discovery } from './pages/Discovery';
import { Audit } from './pages/Audit';

function App() {
  const { license, loading } = useLicense();

  if (loading) {
    return <div className="loading-screen">Loading...</div>;
  }

  return (
    <Routes>
      <Route
        path="/activate"
        element={
          license?.valid ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <LicenseActivationScreen />
          )
        }
      />
      
      <Route
        path="/dashboard"
        element={
          license?.valid ? (
            <Dashboard />
          ) : (
            <Navigate to="/activate" replace />
          )
        }
      />
      
      <Route
        path="/assets"
        element={
          license?.valid ? (
            <Assets />
          ) : (
            <Navigate to="/activate" replace />
          )
        }
      />
      
      {/* More routes... */}
      
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

export default App;
```

---

## Summary

### What Frontend Needs to Do

1. ✅ Check license status on app startup
2. ✅ Show activation screen if no valid license
3. ✅ Handle activation API call
4. ✅ Display license status and quota in UI
5. ✅ Handle 403 errors globally (license required, quota exhausted)
6. ✅ Disable operation buttons when quota is exhausted
7. ✅ Show upgrade prompts when limits are reached

### What Frontend Does NOT Need to Do

1. ❌ Generate or manage fingerprints
2. ❌ Call heartbeat endpoint
3. ❌ Store or use organization_token
4. ❌ Manually consume quota
5. ❌ Call validate endpoint
6. ❌ Generate HMAC signatures

---

## Support & Questions

If you encounter issues or have questions:

1. Check `LICENSE_SYSTEM_COMPLETE_GUIDE.md` for backend details
2. Check `VALIDATE_RESPONSE_FORMAT.md` for exact API response formats
3. Check `API_RESPONSE_EXAMPLES.md` for more examples
4. Contact backend team for license server issues

---

**Last Updated:** April 28, 2025  
**Backend API Version:** 1.0  
**License Server Port:** 8001  
**Main App Port:** 8000
