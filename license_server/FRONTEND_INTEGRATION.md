# Frontend Integration Guide

Complete guide for integrating the License Server into your frontend application.

## Table of Contents

1. [Overview](#overview)
2. [API Endpoints](#api-endpoints)
3. [VM Fingerprint Generation](#vm-fingerprint-generation)
4. [Request Signing](#request-signing)
5. [Integration Steps](#integration-steps)
6. [Code Examples](#code-examples)
7. [Error Handling](#error-handling)
8. [Testing](#testing)

---

## Overview

### Architecture

```
┌─────────────────┐
│  Your Frontend  │
│   Application   │
└────────┬────────┘
         │
         │ HTTP/HTTPS
         │
┌────────▼────────┐
│ License Server  │
│   (FastAPI)     │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───▼──┐  ┌──▼───┐
│ DB   │  │Redis │
└──────┘  └──────┘
```

### Key Concepts

- **License Key**: Format `XXXX-XXXX-XXXX-XXXX` - provided to customer
- **Organization Token**: Secret token returned after activation
- **VM Fingerprint**: Unique hardware identifier for license binding
- **Request Signing**: HMAC-SHA256 signature for secure operations

---

## API Endpoints

### Base URL

```
Production: https://license.yourdomain.com
Development: http://localhost:8000
```

### 1. Get VM Fingerprint

**NEW ENDPOINT** - Generate VM fingerprint on server side.

```http
GET /api/fingerprint
```

**Response:**
```json
{
  "fingerprint": "a1b2c3d4e5f6789..."
}
```

**Example:**
```bash
curl http://localhost:8000/api/fingerprint
```

### 2. Activate License

First-time activation - binds license to this machine.

```http
POST /api/licenses/activate
Content-Type: application/json
```

**Request Body:**
```json
{
  "license_key": "A3F2-9K7L-M4N8-P2Q5",
  "vm_fingerprint": "a1b2c3d4e5f6789..."
}
```

**Response (Success):**
```json
{
  "valid": true,
  "message": "لایسنس با موفقیت فعال شد",
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "organization_token": "org_token_here_keep_secret",
  "limits": {
    "max_assets": 50,
    "max_discoveries": 50,
    "max_audits": 50,
    "max_hardens": 50,
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

**Response (Error):**
```json
{
  "detail": "کلید لایسنس یافت نشد"
}
```

### 3. Validate License

Check license validity and get current usage. **Requires signature.**

```http
POST /api/licenses/validate
Content-Type: application/json
X-Signature: hmac_signature_here
X-Timestamp: 2025-04-23T10:30:00Z
```

**Request Body:**
```json
{
  "license_key": "A3F2-9K7L-M4N8-P2Q5",
  "organization_token": "org_token_here",
  "vm_fingerprint": "a1b2c3d4e5f6789..."
}
```

**Response:**
```json
{
  "valid": true,
  "message": "لایسنس معتبر است",
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "limits": { ... },
  "usage": { ... }
}
```

### 4. Consume Operation

Consume operation quota. **Requires signature.**

```http
POST /api/licenses/consume
Content-Type: application/json
X-Signature: hmac_signature_here
X-Timestamp: 2025-04-23T10:30:00Z
```

**Request Body:**
```json
{
  "license_key": "A3F2-9K7L-M4N8-P2Q5",
  "organization_token": "org_token_here",
  "vm_fingerprint": "a1b2c3d4e5f6789...",
  "operation_type": "discovery",
  "count": 1
}
```

**Operation Types:**
- `asset` - Add network asset
- `discovery` - Network discovery scan
- `audit` - Security audit
- `harden` - Security hardening
- `monitor` - NOC/SOC monitoring

**Response:**
```json
{
  "valid": true,
  "message": "عملیات با موفقیت ثبت شد",
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "limits": { ... },
  "usage": {
    "used_discoveries": 1,
    ...
  }
}
```

### 5. Heartbeat

Keep license alive. **No signature required.**

```http
POST /api/licenses/heartbeat
Content-Type: application/json
```

**Request Body:**
```json
{
  "license_key": "A3F2-9K7L-M4N8-P2Q5",
  "organization_token": "org_token_here",
  "vm_fingerprint": "a1b2c3d4e5f6789..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Heartbeat successful",
  "should_downgrade": false
}
```

---

## VM Fingerprint Generation

### Option 1: Use Server Endpoint (Recommended)

Call the `/api/fingerprint` endpoint to get the fingerprint generated server-side.

```javascript
async function getVMFingerprint() {
  const response = await fetch('http://localhost:8000/api/fingerprint');
  const data = await response.json();
  return data.fingerprint;
}
```

### Option 2: Generate Client-Side

If you need to generate it client-side (for offline scenarios):

```javascript
async function generateFingerprint() {
  const components = [];
  
  // MAC Address (if available)
  // Note: Browser APIs don't expose MAC address for privacy
  
  // Screen resolution
  components.push(`screen:${screen.width}x${screen.height}`);
  
  // Timezone
  components.push(`tz:${Intl.DateTimeFormat().resolvedOptions().timeZone}`);
  
  // Platform
  components.push(`platform:${navigator.platform}`);
  
  // Hardware concurrency
  components.push(`cpu:${navigator.hardwareConcurrency}`);
  
  // User agent
  components.push(`ua:${navigator.userAgent}`);
  
  // Combine and hash
  const combined = components.join('|');
  const encoder = new TextEncoder();
  const data = encoder.encode(combined);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return hashHex;
}
```

**Important:** For desktop applications (Electron, etc.), use system APIs to get real hardware identifiers.

---

## Request Signing

### Why Signing?

Prevents tampering and replay attacks on sensitive operations (`/validate` and `/consume`).

### How to Sign Requests

```javascript
async function signRequest(data, organizationToken) {
  // 1. Create timestamp
  const timestamp = new Date().toISOString();
  
  // 2. Serialize data (sorted keys)
  const payload = JSON.stringify(data, Object.keys(data).sort());
  
  // 3. Create message
  const message = `${payload}:${timestamp}`;
  
  // 4. Generate HMAC-SHA256 signature
  const encoder = new TextEncoder();
  const keyData = encoder.encode(organizationToken);
  const messageData = encoder.encode(message);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    messageData
  );
  
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const signature = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return { signature, timestamp };
}
```

### Using Signed Requests

```javascript
async function validateLicense(licenseKey, orgToken, fingerprint) {
  const data = {
    license_key: licenseKey,
    organization_token: orgToken,
    vm_fingerprint: fingerprint
  };
  
  const { signature, timestamp } = await signRequest(data, orgToken);
  
  const response = await fetch('http://localhost:8000/api/licenses/validate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature': signature,
      'X-Timestamp': timestamp
    },
    body: JSON.stringify(data)
  });
  
  return await response.json();
}
```

---

## Integration Steps

### Step 1: First Launch - Activation

```javascript
class LicenseManager {
  constructor(serverUrl) {
    this.serverUrl = serverUrl;
    this.licenseData = null;
  }
  
  async activate(licenseKey) {
    // Get VM fingerprint
    const fingerprint = await this.getFingerprint();
    
    // Activate license
    const response = await fetch(`${this.serverUrl}/api/licenses/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        license_key: licenseKey,
        vm_fingerprint: fingerprint
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Activation failed');
    }
    
    const data = await response.json();
    
    // Store license data securely
    this.licenseData = {
      license_key: licenseKey,
      organization_token: data.organization_token,
      vm_fingerprint: fingerprint,
      plan_type: data.plan_type
    };
    
    // Save to local storage (encrypted in production!)
    localStorage.setItem('license', JSON.stringify(this.licenseData));
    
    return data;
  }
  
  async getFingerprint() {
    const response = await fetch(`${this.serverUrl}/api/fingerprint`);
    const data = await response.json();
    return data.fingerprint;
  }
}
```

### Step 2: Application Startup - Validation

```javascript
async function startApplication() {
  const manager = new LicenseManager('http://localhost:8000');
  
  // Load stored license
  const stored = localStorage.getItem('license');
  
  if (!stored) {
    // Show activation screen
    showActivationScreen();
    return;
  }
  
  manager.licenseData = JSON.parse(stored);
  
  // Validate license
  try {
    const status = await manager.validate();
    
    if (!status.valid) {
      showError(status.message);
      showActivationScreen();
      return;
    }
    
    // Start application
    showMainScreen(status);
    
    // Start heartbeat
    startHeartbeat(manager);
    
  } catch (error) {
    showError('License validation failed: ' + error.message);
  }
}
```

### Step 3: Validate Method

```javascript
async validate() {
  const data = {
    license_key: this.licenseData.license_key,
    organization_token: this.licenseData.organization_token,
    vm_fingerprint: this.licenseData.vm_fingerprint
  };
  
  const { signature, timestamp } = await signRequest(
    data,
    this.licenseData.organization_token
  );
  
  const response = await fetch(`${this.serverUrl}/api/licenses/validate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature': signature,
      'X-Timestamp': timestamp
    },
    body: JSON.stringify(data)
  });
  
  return await response.json();
}
```

### Step 4: Consume Operations

```javascript
async consumeOperation(operationType, count = 1) {
  const data = {
    license_key: this.licenseData.license_key,
    organization_token: this.licenseData.organization_token,
    vm_fingerprint: this.licenseData.vm_fingerprint,
    operation_type: operationType,
    count: count
  };
  
  const { signature, timestamp } = await signRequest(
    data,
    this.licenseData.organization_token
  );
  
  const response = await fetch(`${this.serverUrl}/api/licenses/consume`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature': signature,
      'X-Timestamp': timestamp
    },
    body: JSON.stringify(data)
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Operation failed');
  }
  
  return await response.json();
}
```

### Step 5: Background Heartbeat

```javascript
function startHeartbeat(manager) {
  // Send heartbeat every hour
  setInterval(async () => {
    try {
      const response = await fetch(`${manager.serverUrl}/api/licenses/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          license_key: manager.licenseData.license_key,
          organization_token: manager.licenseData.organization_token,
          vm_fingerprint: manager.licenseData.vm_fingerprint
        })
      });
      
      const data = await response.json();
      
      if (data.should_downgrade) {
        showWarning('License downgraded to Pilot mode due to connectivity issues');
      }
      
    } catch (error) {
      console.error('Heartbeat failed:', error);
    }
  }, 3600000); // 1 hour
}
```

---

## Code Examples

### Complete React Example

```jsx
import React, { useState, useEffect } from 'react';

function App() {
  const [licenseStatus, setLicenseStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const manager = new LicenseManager('http://localhost:8000');
  
  useEffect(() => {
    initializeLicense();
  }, []);
  
  async function initializeLicense() {
    try {
      const stored = localStorage.getItem('license');
      
      if (!stored) {
        setLoading(false);
        return;
      }
      
      manager.licenseData = JSON.parse(stored);
      const status = await manager.validate();
      
      if (status.valid) {
        setLicenseStatus(status);
        startHeartbeat(manager);
      } else {
        setError(status.message);
      }
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }
  
  async function handleActivation(licenseKey) {
    try {
      setLoading(true);
      const result = await manager.activate(licenseKey);
      setLicenseStatus(result);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }
  
  async function handleOperation(operationType) {
    try {
      const result = await manager.consumeOperation(operationType, 1);
      setLicenseStatus(result);
    } catch (err) {
      setError(err.message);
    }
  }
  
  if (loading) {
    return <div>Loading...</div>;
  }
  
  if (!licenseStatus) {
    return <ActivationScreen onActivate={handleActivation} error={error} />;
  }
  
  return (
    <div>
      <LicenseStatusWidget status={licenseStatus} />
      <MainApplication onOperation={handleOperation} />
    </div>
  );
}

function ActivationScreen({ onActivate, error }) {
  const [licenseKey, setLicenseKey] = useState('');
  
  return (
    <div className="activation-screen">
      <h2>Activate License</h2>
      <input
        type="text"
        placeholder="XXXX-XXXX-XXXX-XXXX"
        value={licenseKey}
        onChange={(e) => setLicenseKey(e.value)}
      />
      <button onClick={() => onActivate(licenseKey)}>
        Activate
      </button>
      {error && <div className="error">{error}</div>}
    </div>
  );
}

function LicenseStatusWidget({ status }) {
  return (
    <div className="license-status">
      <h3>License Status</h3>
      <p>Plan: {status.plan_type}</p>
      <p>Status: {status.valid ? 'Active' : 'Invalid'}</p>
      
      <h4>Usage:</h4>
      <ul>
        <li>Assets: {status.usage.used_assets} / {status.limits.max_assets || '∞'}</li>
        <li>Discoveries: {status.usage.used_discoveries} / {status.limits.max_discoveries || '∞'}</li>
        <li>Audits: {status.usage.used_audits} / {status.limits.max_audits || '∞'}</li>
        <li>Hardens: {status.usage.used_hardens} / {status.limits.max_hardens || '∞'}</li>
        <li>Monitors: {status.usage.used_monitors} / {status.limits.max_monitors || '∞'}</li>
      </ul>
    </div>
  );
}
```

---

## Error Handling

### Common Errors

```javascript
function handleLicenseError(error) {
  const errorMap = {
    'کلید لایسنس یافت نشد': {
      title: 'License Not Found',
      message: 'The license key you entered is invalid.',
      action: 'retry'
    },
    'لایسنس منقضی شده است': {
      title: 'License Expired',
      message: 'Your license has expired. Please renew.',
      action: 'contact_support'
    },
    'محدودیت به پایان رسیده است': {
      title: 'Quota Exceeded',
      message: 'You have reached your operation limit.',
      action: 'upgrade'
    },
    'VM fingerprint مطابقت ندارد': {
      title: 'License Locked',
      message: 'This license is locked to another machine.',
      action: 'contact_support'
    },
    'Invalid signature': {
      title: 'Security Error',
      message: 'Request signature validation failed.',
      action: 'retry'
    },
    'Rate limit exceeded': {
      title: 'Too Many Requests',
      message: 'Please wait a moment and try again.',
      action: 'wait'
    }
  };
  
  for (const [key, info] of Object.entries(errorMap)) {
    if (error.message.includes(key)) {
      return info;
    }
  }
  
  return {
    title: 'Error',
    message: error.message,
    action: 'retry'
  };
}
```

---

## Testing

### Test Checklist

- [ ] Activation with valid license key
- [ ] Activation with invalid license key
- [ ] Validation after activation
- [ ] Consume operations (all types)
- [ ] Quota exceeded handling
- [ ] Heartbeat functionality
- [ ] Offline behavior
- [ ] Network error handling
- [ ] Signature generation
- [ ] VM fingerprint consistency

### Test Script

```javascript
async function runTests() {
  const manager = new LicenseManager('http://localhost:8000');
  
  console.log('Test 1: Get VM Fingerprint');
  const fingerprint = await manager.getFingerprint();
  console.log('✓ Fingerprint:', fingerprint);
  
  console.log('\nTest 2: Activate License');
  try {
    const result = await manager.activate('YOUR-TEST-LICENSE-KEY');
    console.log('✓ Activated:', result.plan_type);
  } catch (error) {
    console.log('✗ Failed:', error.message);
  }
  
  console.log('\nTest 3: Validate License');
  try {
    const result = await manager.validate();
    console.log('✓ Valid:', result.valid);
  } catch (error) {
    console.log('✗ Failed:', error.message);
  }
  
  console.log('\nTest 4: Consume Operation');
  try {
    const result = await manager.consumeOperation('discovery', 1);
    console.log('✓ Consumed:', result.usage.used_discoveries);
  } catch (error) {
    console.log('✗ Failed:', error.message);
  }
  
  console.log('\nAll tests completed!');
}
```

---

## Security Best Practices

1. **Store Credentials Securely**
   - Never store `organization_token` in plain text
   - Use encrypted storage (e.g., electron-store with encryption)
   - Clear sensitive data on logout

2. **HTTPS Only in Production**
   - Always use HTTPS for API calls
   - Validate SSL certificates

3. **Handle Tokens Carefully**
   - Don't log tokens
   - Don't send tokens to analytics
   - Rotate tokens if compromised

4. **Validate Responses**
   - Check response status codes
   - Validate JSON structure
   - Handle unexpected responses

5. **Rate Limiting**
   - Implement client-side rate limiting
   - Cache validation results (5-10 minutes)
   - Don't spam the server

---

## Support

For integration issues:

1. Check server logs
2. Verify API endpoint URLs
3. Test with curl first
4. Check network connectivity
5. Validate request signatures

**Contact:** support@yourdomain.com

---

## Appendix: Complete LicenseManager Class

```javascript
class LicenseManager {
  constructor(serverUrl) {
    this.serverUrl = serverUrl;
    this.licenseData = null;
  }
  
  async getFingerprint() {
    const response = await fetch(`${this.serverUrl}/api/fingerprint`);
    const data = await response.json();
    return data.fingerprint;
  }
  
  async activate(licenseKey) {
    const fingerprint = await this.getFingerprint();
    
    const response = await fetch(`${this.serverUrl}/api/licenses/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        license_key: licenseKey,
        vm_fingerprint: fingerprint
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Activation failed');
    }
    
    const data = await response.json();
    
    this.licenseData = {
      license_key: licenseKey,
      organization_token: data.organization_token,
      vm_fingerprint: fingerprint,
      plan_type: data.plan_type
    };
    
    localStorage.setItem('license', JSON.stringify(this.licenseData));
    
    return data;
  }
  
  async validate() {
    const data = {
      license_key: this.licenseData.license_key,
      organization_token: this.licenseData.organization_token,
      vm_fingerprint: this.licenseData.vm_fingerprint
    };
    
    const { signature, timestamp } = await this.signRequest(data);
    
    const response = await fetch(`${this.serverUrl}/api/licenses/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': timestamp
      },
      body: JSON.stringify(data)
    });
    
    return await response.json();
  }
  
  async consumeOperation(operationType, count = 1) {
    const data = {
      license_key: this.licenseData.license_key,
      organization_token: this.licenseData.organization_token,
      vm_fingerprint: this.licenseData.vm_fingerprint,
      operation_type: operationType,
      count: count
    };
    
    const { signature, timestamp } = await this.signRequest(data);
    
    const response = await fetch(`${this.serverUrl}/api/licenses/consume`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Timestamp': timestamp
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Operation failed');
    }
    
    return await response.json();
  }
  
  async signRequest(data) {
    const timestamp = new Date().toISOString();
    const payload = JSON.stringify(data, Object.keys(data).sort());
    const message = `${payload}:${timestamp}`;
    
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.licenseData.organization_token);
    const messageData = encoder.encode(message);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signatureBuffer = await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      messageData
    );
    
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    const signature = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return { signature, timestamp };
  }
}
```
