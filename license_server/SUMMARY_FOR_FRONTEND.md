# License Server - Frontend Integration Summary

## Quick Overview

Your license server is ready with all necessary endpoints. Here's what the frontend team needs to know:

---

## 🔗 API Endpoints

### Base URL
```
Development: http://localhost:8000
Production: https://your-domain.com
```

### Available Endpoints

| Endpoint | Method | Auth Required | Signature Required | Purpose |
|----------|--------|---------------|-------------------|---------|
| `/api/fingerprint` | GET | No | No | Get VM fingerprint |
| `/api/licenses/activate` | POST | No | No | Activate license |
| `/api/licenses/validate` | POST | No | Yes | Validate license |
| `/api/licenses/consume` | POST | No | Yes | Consume operation |
| `/api/licenses/heartbeat` | POST | No | No | Keep license alive |

---

## 📋 Integration Flow

### 1. First Time Setup (Activation)

```javascript
// Step 1: Get VM fingerprint
GET /api/fingerprint
Response: { "fingerprint": "abc123..." }

// Step 2: Activate with license key
POST /api/licenses/activate
Body: {
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "vm_fingerprint": "abc123..."
}
Response: {
  "valid": true,
  "organization_token": "secret_token_here",  // SAVE THIS!
  "plan_type": "basic2",
  "limits": { ... },
  "usage": { ... }
}
```

**Important:** Save `organization_token` securely - you'll need it for all future requests!

### 2. Application Startup (Validation)

```javascript
// Validate license with signature
POST /api/licenses/validate
Headers:
  X-Signature: hmac_signature
  X-Timestamp: 2025-04-23T10:30:00Z
Body: {
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "organization_token": "secret_token",
  "vm_fingerprint": "abc123..."
}
```

### 3. Before Each Operation (Consume)

```javascript
// Consume operation quota
POST /api/licenses/consume
Headers:
  X-Signature: hmac_signature
  X-Timestamp: 2025-04-23T10:30:00Z
Body: {
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "organization_token": "secret_token",
  "vm_fingerprint": "abc123...",
  "operation_type": "discovery",  // or "asset", "audit", "harden", "monitor"
  "count": 1
}
```

### 4. Background Task (Heartbeat)

```javascript
// Send every hour
POST /api/licenses/heartbeat
Body: {
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "organization_token": "secret_token",
  "vm_fingerprint": "abc123..."
}
```

---

## 🔐 Request Signing (HMAC-SHA256)

**Required for:** `/validate` and `/consume` endpoints

### How to Sign

```javascript
async function signRequest(data, organizationToken) {
  // 1. Create timestamp
  const timestamp = new Date().toISOString();
  
  // 2. Serialize data with sorted keys
  const payload = JSON.stringify(data, Object.keys(data).sort());
  
  // 3. Create message
  const message = `${payload}:${timestamp}`;
  
  // 4. Generate HMAC-SHA256
  const encoder = new TextEncoder();
  const keyData = encoder.encode(organizationToken);
  const messageData = encoder.encode(message);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC', cryptoKey, messageData
  );
  
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const signature = signatureArray
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return { signature, timestamp };
}

// Usage
const { signature, timestamp } = await signRequest(data, orgToken);

fetch('/api/licenses/validate', {
  headers: {
    'X-Signature': signature,
    'X-Timestamp': timestamp
  },
  body: JSON.stringify(data)
});
```

---

## 📦 Ready-to-Use Code

### Complete LicenseManager Class

```javascript
class LicenseManager {
  constructor(serverUrl) {
    this.serverUrl = serverUrl;
    this.licenseData = null;
  }
  
  // Get VM fingerprint from server
  async getFingerprint() {
    const response = await fetch(`${this.serverUrl}/api/fingerprint`);
    const data = await response.json();
    return data.fingerprint;
  }
  
  // Activate license (first time only)
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
      throw new Error(error.detail);
    }
    
    const data = await response.json();
    
    // Save license data
    this.licenseData = {
      license_key: licenseKey,
      organization_token: data.organization_token,
      vm_fingerprint: fingerprint
    };
    
    localStorage.setItem('license', JSON.stringify(this.licenseData));
    return data;
  }
  
  // Validate license
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
  
  // Consume operation
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
      throw new Error(error.detail);
    }
    
    return await response.json();
  }
  
  // Sign request helper
  async signRequest(data) {
    const timestamp = new Date().toISOString();
    const payload = JSON.stringify(data, Object.keys(data).sort());
    const message = `${payload}:${timestamp}`;
    
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.licenseData.organization_token);
    const messageData = encoder.encode(message);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );
    
    const signatureBuffer = await crypto.subtle.sign(
      'HMAC', cryptoKey, messageData
    );
    
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    const signature = signatureArray
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    return { signature, timestamp };
  }
}

// Usage Example
const manager = new LicenseManager('http://localhost:8000');

// First time
await manager.activate('XXXX-XXXX-XXXX-XXXX');

// Every startup
const status = await manager.validate();

// Before operations
await manager.consumeOperation('discovery', 1);
```

---

## 🎯 Operation Types

| Type | Description |
|------|-------------|
| `asset` | Add network asset |
| `discovery` | Network discovery scan |
| `audit` | Security audit |
| `harden` | Security hardening |
| `monitor` | NOC/SOC monitoring |

---

## 📊 Plan Types

| Plan | Duration | Max Assets | Max Operations |
|------|----------|------------|----------------|
| `pilot` | 30 days | 5 | 2 each |
| `basic1` | 365 days | 15 | 15 each |
| `basic2` | 365 days | 50 | 50 each |
| `basic3` | 365 days | 150 | 150 each |
| `enterprise` | 365 days | Unlimited | Unlimited |

---

## ⚠️ Error Handling

### Common Error Messages

| Error | Meaning | Action |
|-------|---------|--------|
| `کلید لایسنس یافت نشد` | License key not found | Check key format |
| `لایسنس منقضی شده است` | License expired | Contact support |
| `محدودیت به پایان رسیده است` | Quota exceeded | Upgrade plan |
| `VM fingerprint مطابقت ندارد` | Wrong machine | Contact support |
| `Invalid signature` | Signature error | Check signing code |
| `Rate limit exceeded` | Too many requests | Wait and retry |

---

## 🧪 Testing

### Test with curl

```bash
# 1. Get fingerprint
curl http://localhost:8000/api/fingerprint

# 2. Activate
curl -X POST http://localhost:8000/api/licenses/activate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "YOUR-KEY-HERE",
    "vm_fingerprint": "fingerprint-from-step-1"
  }'

# 3. Heartbeat (no signature needed)
curl -X POST http://localhost:8000/api/licenses/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "YOUR-KEY",
    "organization_token": "YOUR-TOKEN",
    "vm_fingerprint": "YOUR-FINGERPRINT"
  }'
```

---

## 📚 Full Documentation

For complete details, see:
- **FRONTEND_INTEGRATION.md** - Complete integration guide with React examples
- **DEVELOPER_GUIDE.md** - Backend license generation guide
- **README.md** - General overview

---

## 🚀 Quick Start Checklist

- [ ] Copy `LicenseManager` class to your project
- [ ] Update `serverUrl` to your license server
- [ ] Implement activation screen
- [ ] Add license validation on startup
- [ ] Add operation consumption before actions
- [ ] Implement background heartbeat (every hour)
- [ ] Add error handling
- [ ] Test all flows

---

## 💡 Key Points

1. **VM Fingerprint**: Get from `/api/fingerprint` endpoint
2. **Organization Token**: Save securely after activation
3. **Request Signing**: Required for validate and consume
4. **Heartbeat**: Send every hour to keep license active
5. **Error Handling**: Handle all error cases gracefully

---

## 📞 Support

If you have questions:
1. Check `FRONTEND_INTEGRATION.md` for detailed examples
2. Test endpoints with curl first
3. Verify request signatures are correct
4. Check server logs for errors

**Server Status:** `GET /health` should return `{"status": "healthy"}`

---

**Ready to integrate!** 🎉

The license server is fully functional with all endpoints ready. The frontend team can start integration immediately using the provided `LicenseManager` class.
