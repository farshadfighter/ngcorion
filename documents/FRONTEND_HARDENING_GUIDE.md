# Frontend Implementation Guide: Network Device Hardening

**Version**: 1.0
**Last Updated**: 2026-02-07
**Target Audience**: Frontend Developers

> ### ⚠️ Outdated: the per-family "Harden All" endpoints were removed
>
> The three-mode Harden All flow described below no longer exists. These
> endpoints were removed from **all seven** device families (cisco, fortinet,
> linux, apache, mongodb, mssql, windows):
>
> - `GET  /api/hardening/{family}/session/{id}/parameters`
> - `GET  /api/hardening/{family}/session/{id}/auto-preview`
> - `POST /api/hardening/{family}/auto-harden-defaults`
> - `POST /api/hardening/{family}/batch-execute`
>
> They are replaced by two device-agnostic endpoints:
>
> - `GET  /api/hardening/harden-all/session/{id}/plan` — returns the fixable
>   checks, the unfixable ones with reasons, the parameters to collect, the
>   credential fields to render, and the supported options (`backup`, `dry_run`).
> - `POST /api/hardening/harden-all/execute` — body:
>   `{ session_id, credentials{}, parameters{}, result_ids[]?, create_backup?, dry_run? }`;
>   returns `{ successful, failed, skipped, results[{result_id, check_number, vdom, status, detail, commands[]}] }`.
>
> The response shape is identical for every device family, so clients must not
> branch on device type. Single-check remediation (`/preview`, `/execute`,
> `/execute-single`) is unchanged. Sections below that describe the old flow are
> retained only as history.

---


## Table of Contents

1. [Overview](#overview)
2. [Three Hardening Modes](#three-hardening-modes)
3. [API Endpoints](#api-endpoints)
4. [SSH Error Handling](#ssh-error-handling)
5. [Parameter System](#parameter-system)
6. [Component Architecture](#component-architecture)
7. [State Management (Redux)](#state-management-redux)
8. [Implementation Steps](#implementation-steps)
9. [Error Handling & User Feedback](#error-handling--user-feedback)
10. [Testing Scenarios](#testing-scenarios)

---

## Overview

The hardening system allows users to automatically fix security compliance failures on Cisco IOS and FortiGate devices. The frontend provides three distinct workflows for applying fixes, each with different levels of automation and user control.

### Supported Devices
- **Cisco IOS/IOS-XE** - Routers and switches
- **FortiGate** - Firewalls (with VDOM support)

### Key Features
- ✅ Preview commands before execution
- ✅ Dynamic parameter forms based on check requirements
- ✅ Batch execution of multiple fixes
- ✅ Automatic hardening with CIS defaults
- ✅ Real-time verification of fixes
- ✅ Detailed error messages with actionable suggestions
- ✅ Configuration backup before changes

---

## Three Hardening Modes

### Mode 1: Fix Single Check

**Use Case**: User wants to fix one specific failed check with full control.

**Workflow**:
```
1. User clicks "Fix" button on a failed check row
2. System fetches command preview → POST /api/hardening/preview
3. Display commands and required parameters
4. User fills in parameter form (if needed)
5. User provides SSH credentials
6. Execute fix → POST /api/hardening/execute
7. Display results with verification status
```

**When to Use**:
- Testing individual fixes
- Organization-specific parameters needed
- Learning what commands will be executed

---

### Mode 2: Fix All / Batch Execution

**Use Case**: User selects multiple checks and provides all parameters at once.

**Workflow**:
```
1. User selects checkboxes for multiple failed checks
2. User clicks "Fix Selected" button
3. System aggregates all parameters → GET /session/{id}/parameters
4. Display unified parameter form with all required fields
5. User fills in all parameters
6. User provides SSH credentials
7. Execute batch → POST /api/hardening/batch-execute
8. Display results for each check
```

**When to Use**:
- Fixing multiple checks efficiently
- User knows all required parameter values
- Comprehensive hardening session

---

### Mode 3: Automatic Hardening

**Use Case**: Apply all fixes that don't require user input (use CIS defaults).

**Workflow**:
```
1. User clicks "Automatic Hardening" button
2. System shows preview of defaults → GET /session/{id}/auto-preview
3. Display which checks will be fixed and which will be skipped
4. User reviews and confirms
5. User provides SSH credentials only
6. Execute auto-hardening → POST /api/hardening/auto-harden-defaults
7. Display results summary
```

**When to Use**:
- Quick hardening with industry standards
- User wants sensible defaults applied
- No organization-specific requirements

**What Gets Skipped**:
- Checks requiring passwords/secrets
- Checks requiring IP addresses (NTP, Syslog servers)
- Checks requiring organization-specific text (banners, hostnames)
- Checks requiring ACL names or other custom identifiers

---

## API Endpoints

### Cisco Endpoints

Base URL: `/api/hardening`

#### Preview Single Check
```http
POST /api/hardening/preview
Content-Type: application/json

{
  "audit_result_id": 1523,
  "parameters": {
    "TIMEOUT_MIN": "10"  // Optional: pre-fill parameters
  }
}
```

**Response** (200 OK):
```json
{
  "action_id": 4567,
  "check_number": "IOS-L1-001",
  "check_title": "Use 'enable secret' only",
  "commands": [
    "configure terminal",
    "no enable password",
    "enable secret <STRONG_SECRET>",
    "end",
    "write memory"
  ],
  "requires_config_mode": true,
  "required_parameters": ["STRONG_SECRET"],
  "optional_parameters": [],
  "warnings": ["This will remove the existing enable password"]
}
```

---

#### Execute Single Check
```http
POST /api/hardening/execute
Content-Type: application/json

{
  "action_id": 4567,
  "ssh_username": "admin",
  "ssh_password": "cisco123",
  "ssh_secret": "cisco123",  // Enable secret (optional)
  "parameters": {
    "STRONG_SECRET": "MyNewSecret123!"
  },
  "skip_backup": false
}
```

**Response** (200 OK):
```json
{
  "action_id": 4567,
  "status": "success",
  "verification_passed": true,
  "verification_evidence": "enable secret <REDACTED>",
  "backup_created": true,
  "commands_executed": [
    "configure terminal",
    "no enable password",
    "enable secret <REDACTED>",
    "end",
    "write memory"
  ],
  "error_message": null
}
```

---

#### Get Session Parameters (for Batch Mode)
```http
GET /api/hardening/session/{session_id}/parameters?check_ids=101,102,103
```

**Query Parameters**:
- `check_ids` (optional): Comma-separated list of audit result IDs. If omitted, includes all failed checks.

**Response** (200 OK):
```json
{
  "session_id": 123,
  "total_failed": 8,
  "selected_count": 3,
  "fixable_count": 2,
  "unfixable_count": 1,
  "required_parameters": {
    "STRONG_SECRET": {
      "type": "password",
      "label": "Enable Secret",
      "description": "New enable secret password",
      "required": true,
      "default": null,
      "placeholder": "MySecureSecret123!",
      "validation": "min_length:8",
      "checks": ["IOS-L1-001"]
    },
    "TIMEOUT_MIN": {
      "type": "number",
      "label": "Exec Timeout (minutes)",
      "description": "Idle timeout in minutes",
      "required": false,
      "default": "5",
      "min_value": 1,
      "max_value": 60,
      "checks": ["IOS-L1-002"]
    },
    "BANNER_TEXT": {
      "type": "textarea",
      "label": "Banner Message",
      "description": "Warning/legal banner text",
      "required": true,
      "default": null,
      "placeholder": "Authorized users only...",
      "checks": ["IOS-L1-005", "IOS-L1-006"]
    }
  },
  "auto_fixable_checks": [
    {
      "check_number": "IOS-L1-002",
      "check_title": "Set exec timeout",
      "result_id": 101
    }
  ],
  "needs_params_checks": [
    {
      "check_number": "IOS-L1-001",
      "check_title": "Use enable secret",
      "result_id": 102,
      "missing_params": ["STRONG_SECRET"]
    }
  ]
}
```

---

#### Get Auto-Harden Preview
```http
GET /api/hardening/session/{session_id}/auto-preview
```

**Response** (200 OK):
```json
{
  "session_id": 123,
  "auto_fixable_count": 5,
  "skipped_count": 3,
  "checks_with_defaults": [
    {
      "check_number": "IOS-L1-002",
      "check_title": "Set exec timeout",
      "result_id": 101,
      "defaults": {
        "TIMEOUT_MIN": "5",
        "TIMEOUT_SEC": "0"
      }
    },
    {
      "check_number": "IOS-L1-007",
      "check_title": "SSH version 2 enabled",
      "result_id": 103,
      "defaults": {}
    }
  ],
  "skipped_checks": [
    {
      "check_number": "IOS-L1-001",
      "check_title": "Use enable secret",
      "result_id": 102,
      "reason": "Requires STRONG_SECRET parameter"
    },
    {
      "check_number": "IOS-L1-005",
      "check_title": "Login banner configured",
      "result_id": 104,
      "reason": "Requires BANNER_TEXT parameter"
    }
  ]
}
```

---

#### Execute Auto-Hardening
```http
POST /api/hardening/auto-harden-defaults
Content-Type: application/json

{
  "audit_session_id": 123,
  "ssh_username": "admin",
  "ssh_password": "cisco123",
  "ssh_secret": "cisco123",
  "confirmed": true,  // MUST be true
  "skip_backup": false
}
```

**Response** (200 OK):
```json
{
  "audit_session_id": 123,
  "fixed_count": 5,
  "skipped_count": 3,
  "failed_count": 0,
  "actions": [101, 102, 103, 104, 105],
  "fixed_checks": [
    {
      "check_number": "IOS-L1-002",
      "check_title": "Set exec timeout",
      "action_id": 101,
      "defaults_applied": {
        "TIMEOUT_MIN": "5",
        "TIMEOUT_SEC": "0"
      },
      "verification_passed": true
    }
  ],
  "skipped_checks": [
    {
      "check_number": "IOS-L1-001",
      "check_title": "Use enable secret",
      "reason": "Requires user input"
    }
  ]
}
```

---

#### Execute Batch
```http
POST /api/hardening/batch-execute
Content-Type: application/json

{
  "audit_session_id": 123,
  "check_ids": [101, 102, 103],
  "parameters": {
    "STRONG_SECRET": "MyNewSecret123!",
    "BANNER_TEXT": "Authorized access only. All activity is monitored.",
    "TIMEOUT_MIN": "10"
  },
  "ssh_username": "admin",
  "ssh_password": "cisco123",
  "ssh_secret": "cisco123",
  "skip_backup": false
}
```

**Response** (200 OK):
```json
{
  "audit_session_id": 123,
  "total_selected": 3,
  "fixed_count": 2,
  "failed_count": 1,
  "skipped_count": 0,
  "actions": [201, 202],
  "results": [
    {
      "check_number": "IOS-L1-001",
      "check_title": "Use enable secret",
      "status": "success",
      "action_id": 201,
      "verification_passed": true
    },
    {
      "check_number": "IOS-L1-002",
      "check_title": "Set exec timeout",
      "status": "success",
      "action_id": 202,
      "verification_passed": true
    },
    {
      "check_number": "IOS-L1-003",
      "check_title": "VTY ACL configured",
      "status": "failed",
      "error_message": "ACL 'VTY_ACCESS' does not exist on device"
    }
  ]
}
```

---

### FortiGate Endpoints

Base URL: `/api/hardening/fortinet`

All FortiGate endpoints follow the same structure as Cisco, with these additions:

#### Additional Request Fields
```json
{
  "vdom": "root",  // Optional VDOM context (default: global)
  // ... other fields same as Cisco
}
```

#### Endpoints
- `POST /api/hardening/fortinet/preview`
- `POST /api/hardening/fortinet/execute`
- `GET /api/hardening/fortinet/session/{id}/parameters`
- `GET /api/hardening/fortinet/session/{id}/auto-preview`
- `POST /api/hardening/fortinet/auto-harden-defaults`
- `POST /api/hardening/fortinet/batch-execute`
- `GET /api/hardening/fortinet/actions` (history)
- `GET /api/hardening/fortinet/actions/{id}` (details)

---

## SSH Error Handling

### New Structured Error Responses

All SSH-related errors now return structured JSON with actionable suggestions instead of generic "Execution failed" messages.

### Error Types and HTTP Status Codes

| Error Type | HTTP Status | Meaning | User Action |
|------------|-------------|---------|-------------|
| `authentication_error` | 401 | Wrong username/password | Verify credentials |
| `timeout_error` | 504 | Connection timed out | Check device is online |
| `connection_error` | 503 | Device unreachable | Check IP/network |
| `algorithm_mismatch` | 502 | Outdated SSH version | Upgrade device SSH |
| `host_key_error` | 502 | Host key changed | Clear old host key |
| `ssh_error` | 502 | Generic SSH error | Check logs |

---

### Error Response Format

All SSH errors follow this structure:

```json
{
  "detail": {
    "error_type": "authentication_error",
    "message": "Authentication failed for 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": [
      "Verify the username and password are correct",
      "Check if the account is locked or disabled on the device",
      "Ensure SSH authentication is enabled on the device",
      "Verify the user has appropriate privileges for SSH access"
    ],
    "original_error": "Authentication to device failed."
  }
}
```

---

### Frontend Error Handling Implementation

#### React Component Example

```jsx
const handleExecute = async () => {
  try {
    const response = await fetch('/api/hardening/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(executionData)
    });

    if (!response.ok) {
      const errorData = await response.json();

      // Check if it's a structured SSH error
      if (errorData.detail && errorData.detail.error_type) {
        handleSSHError(errorData.detail);
      } else {
        // Handle other errors
        showError(errorData.detail || 'Execution failed');
      }
      return;
    }

    const result = await response.json();
    showSuccess(result);

  } catch (error) {
    showError('Network error: ' + error.message);
  }
};

const handleSSHError = (errorDetail) => {
  const { error_type, message, suggestions, device_ip } = errorDetail;

  // Map error types to user-friendly titles
  const errorTitles = {
    'authentication_error': 'Authentication Failed',
    'timeout_error': 'Connection Timeout',
    'connection_error': 'Cannot Connect to Device',
    'algorithm_mismatch': 'SSH Protocol Mismatch',
    'host_key_error': 'Host Key Verification Failed',
    'ssh_error': 'SSH Connection Error'
  };

  // Map error types to icons/colors
  const errorStyles = {
    'authentication_error': { icon: '🔐', color: 'warning' },
    'timeout_error': { icon: '⏱️', color: 'warning' },
    'connection_error': { icon: '🔌', color: 'error' },
    'algorithm_mismatch': { icon: '⚠️', color: 'warning' },
    'host_key_error': { icon: '🔑', color: 'warning' },
    'ssh_error': { icon: '❌', color: 'error' }
  };

  const style = errorStyles[error_type] || { icon: '❌', color: 'error' };

  // Display structured error modal
  setErrorModal({
    open: true,
    title: errorTitles[error_type] || 'SSH Error',
    icon: style.icon,
    color: style.color,
    message: message,
    deviceIP: device_ip,
    suggestions: suggestions,
    errorType: error_type
  });
};
```

---

#### Error Display Component

```jsx
const SSHErrorModal = ({ error, onClose, onRetry }) => {
  if (!error) return null;

  return (
    <div className="modal-overlay">
      <div className={`error-modal error-${error.color}`}>
        <div className="error-header">
          <span className="error-icon">{error.icon}</span>
          <h2>{error.title}</h2>
        </div>

        <div className="error-body">
          <p className="error-message">{error.message}</p>
          <p className="device-info">Device: <code>{error.deviceIP}</code></p>

          {error.suggestions && error.suggestions.length > 0 && (
            <div className="suggestions-section">
              <h3>Suggestions:</h3>
              <ul>
                {error.suggestions.map((suggestion, idx) => (
                  <li key={idx}>{suggestion}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Context-specific help */}
          {error.errorType === 'authentication_error' && (
            <div className="help-box">
              <strong>💡 Tip:</strong> Make sure you're using the correct
              credentials for SSH access (not web UI credentials).
            </div>
          )}

          {error.errorType === 'algorithm_mismatch' && (
            <div className="help-box">
              <strong>💡 Note:</strong> This device may be running an older
              SSH version. Contact your network administrator if you need
              assistance upgrading the device firmware.
            </div>
          )}
        </div>

        <div className="error-actions">
          {error.errorType === 'authentication_error' && (
            <button onClick={onRetry} className="btn-retry">
              Try Different Credentials
            </button>
          )}
          <button onClick={onClose} className="btn-close">
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
```

---

#### Redux Action Example

```javascript
export const executeSingleCheck = createAsyncThunk(
  'hardening/executeSingle',
  async (payload, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/hardening/execute', payload);
      return response.data;
    } catch (error) {
      if (error.response?.data?.detail) {
        const detail = error.response.data.detail;

        // Check if it's a structured SSH error
        if (typeof detail === 'object' && detail.error_type) {
          return rejectWithValue({
            type: 'ssh_error',
            ...detail
          });
        }

        // String error
        return rejectWithValue({
          type: 'generic_error',
          message: detail
        });
      }

      return rejectWithValue({
        type: 'network_error',
        message: error.message
      });
    }
  }
);
```

---

### Error Categorization for UI

#### Critical Errors (Require User Action)
- `authentication_error` - User must fix credentials
- `connection_error` - User must check device/network
- `algorithm_mismatch` - May require admin intervention

**UI Treatment**:
- Display prominent modal with suggestions
- Block retry until user addresses issue
- Provide "Update Credentials" button for auth errors

#### Transient Errors (May Self-Resolve)
- `timeout_error` - Device may be slow

**UI Treatment**:
- Offer automatic retry with backoff
- Show progress indicator
- Allow manual retry

#### Informational Errors
- `host_key_error` - Security warning but resolvable

**UI Treatment**:
- Explain the security implications
- Provide option to clear old key (admin only)
- Link to documentation

---

### Error Message Customization by Context

```javascript
const getContextualMessage = (errorType, context) => {
  if (context === 'auto-audit') {
    if (errorType === 'authentication_error') {
      return 'Unable to audit device: incorrect SSH credentials. ' +
             'Please verify the username and password.';
    }
  }

  if (context === 'batch-execute') {
    if (errorType === 'connection_error') {
      return 'Cannot connect to device to apply hardening fixes. ' +
             'All selected fixes have been cancelled.';
    }
  }

  // Default to error message from backend
  return null;
};
```

---

## Parameter System

### Parameter Types

The backend defines metadata for each parameter. Frontend should render appropriate input controls:

| Type | HTML Input | Validation | Example |
|------|-----------|------------|---------|
| `password` | `<input type="password">` | min_length:8 | Enable secret |
| `text` | `<input type="text">` | Pattern matching | ACL name, hostname |
| `textarea` | `<textarea>` | min_length | Banner text |
| `number` | `<input type="number">` | min/max values | Timeout minutes |
| `ip` | `<input type="text">` | IP regex | NTP server IP |
| `select` | `<select>` | One of options | AAA method type |

---

### Parameter Metadata Structure

```typescript
interface ParameterMetadata {
  name: string;
  type: 'password' | 'text' | 'textarea' | 'number' | 'ip' | 'select';
  label: string;
  description: string;
  required: boolean;
  default: string | null;
  placeholder: string | null;
  validation: string | null;
  options: string[] | null;
  min_value: number | null;
  max_value: number | null;
  checks: string[];  // Which checks use this parameter
}
```

---

### Dynamic Form Rendering

```jsx
const ParameterInput = ({ param, value, onChange, disabled }) => {
  const { name, type, label, description, required, placeholder,
          min_value, max_value, options } = param;

  const renderInput = () => {
    switch (type) {
      case 'password':
        return (
          <div className="password-field">
            <input
              type={showPassword ? 'text' : 'password'}
              value={value || ''}
              onChange={(e) => onChange(name, e.target.value)}
              placeholder={placeholder}
              required={required}
              disabled={disabled}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="toggle-password"
            >
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
          </div>
        );

      case 'textarea':
        return (
          <textarea
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            placeholder={placeholder}
            required={required}
            disabled={disabled}
            rows={4}
          />
        );

      case 'number':
        return (
          <input
            type="number"
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            placeholder={placeholder || param.default}
            required={required}
            disabled={disabled}
            min={min_value}
            max={max_value}
          />
        );

      case 'ip':
        return (
          <input
            type="text"
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            placeholder={placeholder || '192.168.1.1'}
            required={required}
            disabled={disabled}
            pattern="^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            title="Enter a valid IP address"
          />
        );

      case 'select':
        return (
          <select
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            required={required}
            disabled={disabled}
          >
            <option value="">Select {label}...</option>
            {options.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        );

      default:
        return (
          <input
            type="text"
            value={value || ''}
            onChange={(e) => onChange(name, e.target.value)}
            placeholder={placeholder}
            required={required}
            disabled={disabled}
          />
        );
    }
  };

  return (
    <div className="parameter-field">
      <label htmlFor={`param-${name}`}>
        {label}
        {required && <span className="required">*</span>}
      </label>
      {renderInput()}
      {description && (
        <small className="field-description">{description}</small>
      )}
      {param.checks && param.checks.length > 0 && (
        <small className="used-by">
          Used by: {param.checks.join(', ')}
        </small>
      )}
    </div>
  );
};
```

---

### Pre-filling Default Values

```jsx
useEffect(() => {
  if (sessionParameters?.required_parameters) {
    const defaults = {};

    Object.entries(sessionParameters.required_parameters).forEach(([name, meta]) => {
      if (meta.default) {
        defaults[name] = meta.default;
      }
    });

    // Pre-fill form with defaults
    setUserParams(prev => ({ ...defaults, ...prev }));
  }
}, [sessionParameters]);
```

---

## Component Architecture

### Component Hierarchy

```
<Hardening>
  ├── <AuditResultsTable>
  │     ├── Displays failed checks with selection
  │     ├── "Fix" button per row → opens FixSingleModal
  │     └── Checkbox selection for batch mode
  │
  ├── <FixSingleModal>
  │     ├── Step 1: Preview commands
  │     ├── Step 2: Parameter form (if needed)
  │     ├── Step 3: SSH credentials form
  │     ├── Step 4: Execution progress
  │     └── Step 5: Results display
  │
  ├── <FixAllModal>
  │     ├── Step 1: Summary of selected checks
  │     ├── Step 2: Aggregated parameter form
  │     ├── Step 3: SSH credentials form
  │     ├── Step 4: Execution progress
  │     └── Step 5: Batch results display
  │
  ├── <AutoHardenModal>
  │     ├── Step 1: Preview defaults & skipped checks
  │     ├── Step 2: SSH credentials form
  │     ├── Step 3: Execution progress
  │     └── Step 4: Results display
  │
  ├── <ConfigurationForm>
  │     └── Dynamic parameter input fields
  │
  ├── <SSHCredentialsForm>
  │     ├── Username input
  │     ├── Password input
  │     ├── Enable secret input (optional)
  │     └── VDOM input (FortiGate only)
  │
  ├── <HardeningHistory>
  │     └── Display past hardening actions
  │
  └── <SSHErrorModal>
        └── Structured SSH error display
```

---

### Component Props

#### FixSingleModal

```typescript
interface FixSingleModalProps {
  check: {
    id: number;
    check_number: string;
    check_title: string;
    status: 'failed';
    severity: string;
  };
  deviceType: 'cisco' | 'fortinet';
  onClose: () => void;
}
```

#### FixAllModal

```typescript
interface FixAllModalProps {
  deviceType: 'cisco' | 'fortinet';
  onClose: () => void;
}
```

#### AutoHardenModal

```typescript
interface AutoHardenModalProps {
  deviceType: 'cisco' | 'fortinet';
  onClose: () => void;
}
```

#### ConfigurationForm

```typescript
interface ConfigurationFormProps {
  parameters: {
    [paramName: string]: ParameterMetadata;
  };
  values: {
    [paramName: string]: string;
  };
  onChange: (paramName: string, value: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
  loading: boolean;
}
```

#### SSHCredentialsForm

```typescript
interface SSHCredentialsFormProps {
  values: {
    username: string;
    password: string;
    secret?: string;
    vdom?: string;  // FortiGate only
  };
  onChange: (field: string, value: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
  loading: boolean;
  deviceType: 'cisco' | 'fortinet';
}
```

---

## State Management (Redux)

### State Slice Structure

```javascript
const hardeningSlice = createSlice({
  name: 'hardening',
  initialState: {
    // Session & Audit Results
    selectedSession: null,
    failedChecks: [],
    selectedCheckIds: [],

    // Fix Single Mode
    singlePreview: null,
    singleExecutionResult: null,

    // Fix All Mode
    sessionParameters: null,
    userParameters: {},
    batchResult: null,

    // Auto-Harden Mode
    autoHardenPreview: null,

    // UI State
    loading: false,
    error: null,
    sshError: null,  // Structured SSH error
    activeModal: null  // 'fix-single' | 'fix-all' | 'auto-harden'
  },
  reducers: {
    // ... reducers
  },
  extraReducers: (builder) => {
    // Handle async thunks
  }
});
```

---

### Redux Actions (Async Thunks)

```javascript
// Fix Single
export const previewSingleCheck = createAsyncThunk(...);
export const executeSingleCheck = createAsyncThunk(...);

// Fix All / Batch
export const fetchSessionParameters = createAsyncThunk(...);
export const batchExecuteChecks = createAsyncThunk(...);

// Auto-Harden
export const fetchAutoHardenPreview = createAsyncThunk(...);
export const executeAutoHarden = createAsyncThunk(...);

// Common
export const setSelectedCheckIds = createAction(...);
export const clearUserParameters = createAction(...);
export const clearExecutionResult = createAction(...);
```

---

### Example: executeSingleCheck Thunk

```javascript
export const executeSingleCheck = createAsyncThunk(
  'hardening/executeSingle',
  async (payload, { rejectWithValue }) => {
    try {
      const { deviceType, ...executionData } = payload;
      const endpoint = deviceType === 'fortinet'
        ? '/api/hardening/fortinet/execute'
        : '/api/hardening/execute';

      const response = await api.post(endpoint, executionData);
      return response.data;

    } catch (error) {
      if (error.response?.data?.detail) {
        const detail = error.response.data.detail;

        // Structured SSH error
        if (typeof detail === 'object' && detail.error_type) {
          return rejectWithValue({
            type: 'ssh_error',
            sshError: detail
          });
        }

        // String error
        return rejectWithValue({
          type: 'api_error',
          message: detail
        });
      }

      return rejectWithValue({
        type: 'network_error',
        message: error.message
      });
    }
  }
);
```

---

### Reducer Handling

```javascript
extraReducers: (builder) => {
  builder
    // Preview Single
    .addCase(previewSingleCheck.pending, (state) => {
      state.loading = true;
      state.error = null;
    })
    .addCase(previewSingleCheck.fulfilled, (state, action) => {
      state.loading = false;
      state.singlePreview = action.payload;
    })
    .addCase(previewSingleCheck.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload || action.error.message;
    })

    // Execute Single
    .addCase(executeSingleCheck.pending, (state) => {
      state.loading = true;
      state.error = null;
      state.sshError = null;
    })
    .addCase(executeSingleCheck.fulfilled, (state, action) => {
      state.loading = false;
      state.singleExecutionResult = action.payload;
    })
    .addCase(executeSingleCheck.rejected, (state, action) => {
      state.loading = false;

      // Handle structured SSH errors
      if (action.payload?.type === 'ssh_error') {
        state.sshError = action.payload.sshError;
      } else {
        state.error = action.payload?.message || action.error.message;
      }
    });
}
```

---

## Implementation Steps

### Step 1: Set Up Redux Store

1. Create `hardeningSlice.js` with state structure
2. Define async thunks for all API operations
3. Add reducers for loading/error states
4. Register slice in store

### Step 2: Create Base Components

1. **ConfigurationForm.jsx**
   - Dynamic parameter rendering
   - Form validation
   - Default value population

2. **SSHCredentialsForm.jsx**
   - Username/password inputs
   - Enable secret (Cisco) / VDOM (FortiGate)
   - Form validation

3. **SSHErrorModal.jsx**
   - Structured error display
   - Suggestions list
   - Context-specific help

### Step 3: Implement Modal Components

1. **FixSingleModal.jsx**
   - Multi-step workflow
   - Preview → Parameters → Credentials → Execute → Results
   - Progress indicators

2. **FixAllModal.jsx**
   - Batch selection summary
   - Aggregated parameter form
   - Batch results display

3. **AutoHardenModal.jsx**
   - Preview defaults and skipped checks
   - Confirmation checkbox
   - Results summary

### Step 4: Wire Up Components

1. Connect modals to Redux store
2. Implement step navigation logic
3. Handle form submissions
4. Display results and errors

### Step 5: Add Error Handling

1. Implement SSH error detection
2. Display structured errors
3. Add retry mechanisms
4. Context-specific error messages

### Step 6: Testing

1. Test all three modes with valid data
2. Test error scenarios (auth, timeout, network)
3. Test parameter validation
4. Test FortiGate VDOM support

---

## Error Handling & User Feedback

### Loading States

```jsx
// During execution
<div className="execution-progress">
  <Spinner />
  <p>Applying hardening fix...</p>
  <small>This may take up to 60 seconds</small>
</div>
```

### Success States

```jsx
// After successful execution
<div className="success-result">
  <div className="success-icon">✅</div>
  <h3>Hardening Applied Successfully</h3>

  {result.verification_passed ? (
    <p className="verification-success">
      ✓ Verification passed - Check is now compliant
    </p>
  ) : (
    <p className="verification-warning">
      ⚠️ Commands executed but verification failed
    </p>
  )}

  <div className="execution-details">
    <strong>Commands Executed:</strong>
    <pre>{result.commands_executed.join('\n')}</pre>
  </div>

  {result.backup_created && (
    <p className="backup-notice">
      💾 Configuration backup created before changes
    </p>
  )}
</div>
```

### Error States

#### Generic Errors

```jsx
<div className="error-result">
  <div className="error-icon">❌</div>
  <h3>Hardening Failed</h3>
  <p className="error-message">{error.message}</p>
</div>
```

#### SSH Errors (Use SSHErrorModal)

See [SSH Error Handling](#ssh-error-handling) section above.

### Validation Errors

```jsx
// Missing required parameters
<div className="validation-error">
  <span className="error-icon">⚠️</span>
  <span>Please fill in all required fields</span>
</div>

// Invalid IP address
<div className="field-error">
  <small className="error-text">
    Invalid IP address format. Example: 192.168.1.1
  </small>
</div>
```

---

## Testing Scenarios

### Fix Single Mode

#### Test Case 1: Check with Required Parameters
```
1. Click "Fix" on check "IOS-L1-001" (Enable Secret)
2. Verify preview shows commands with <STRONG_SECRET> placeholder
3. Verify parameter form shows password input for STRONG_SECRET
4. Fill in password (min 8 chars)
5. Provide SSH credentials
6. Execute
7. Verify success result shows verification passed
```

#### Test Case 2: Check with Default Parameters
```
1. Click "Fix" on check "IOS-L1-002" (Exec Timeout)
2. Verify preview shows commands with default values
3. Verify parameter form pre-fills TIMEOUT_MIN=5, TIMEOUT_SEC=0
4. User can modify or keep defaults
5. Provide SSH credentials
6. Execute
7. Verify success
```

#### Test Case 3: Authentication Error
```
1. Click "Fix" on any check
2. Provide wrong SSH credentials
3. Execute
4. Verify SSH error modal shows:
   - Title: "Authentication Failed"
   - Icon: 🔐
   - Message includes device IP
   - Suggestions list displays
   - "Try Different Credentials" button visible
```

#### Test Case 4: Connection Timeout
```
1. Click "Fix" on any check
2. Provide unreachable IP or slow device
3. Execute
4. Verify timeout error modal shows:
   - Title: "Connection Timeout"
   - Icon: ⏱️
   - Suggestions to check device status
```

---

### Fix All Mode

#### Test Case 5: Batch Execution with Mixed Parameters
```
1. Select checks: IOS-L1-001, IOS-L1-002, IOS-L1-005
2. Click "Fix Selected"
3. Verify aggregated parameters show:
   - STRONG_SECRET (required)
   - TIMEOUT_MIN (default: 5)
   - TIMEOUT_SEC (default: 0)
   - BANNER_TEXT (required)
4. Fill required fields
5. Provide SSH credentials
6. Execute batch
7. Verify results show individual status for each check
```

#### Test Case 6: Missing Required Parameter
```
1. Select check requiring STRONG_SECRET
2. Don't fill in STRONG_SECRET field
3. Try to submit
4. Verify frontend validation blocks submission
5. Verify error message highlights missing field
```

#### Test Case 7: Batch Partial Success
```
1. Select 3 checks
2. Provide valid parameters
3. Execute (simulate one check fails on device)
4. Verify results show:
   - 2 successful checks with ✓
   - 1 failed check with error message
   - Overall status indicates partial success
```

---

### Auto-Harden Mode

#### Test Case 8: Auto-Harden Preview
```
1. Click "Automatic Hardening"
2. Verify preview shows two lists:
   - Checks with defaults (will be fixed)
   - Checks requiring params (will be skipped)
3. Verify default values are displayed for each check
4. User can review before confirming
```

#### Test Case 9: Auto-Harden Execution
```
1. Review preview
2. Check "I confirm" checkbox
3. Provide SSH credentials only (no parameters needed)
4. Execute
5. Verify results show:
   - Count of fixed checks
   - Count of skipped checks
   - List of what was applied
   - Verification status for each
```

#### Test Case 10: Auto-Harden Without Confirmation
```
1. Click "Automatic Hardening"
2. Don't check confirmation checkbox
3. Try to execute
4. Verify error: "You must confirm by checking the box"
```

---

### FortiGate-Specific Tests

#### Test Case 11: FortiGate VDOM Support
```
1. Switch to FortiGate device
2. Open any modal
3. Verify VDOM input field appears in credentials form
4. Test with:
   - VDOM: "root"
   - VDOM: "custom-vdom"
   - VDOM: empty (should use global)
```

#### Test Case 12: FortiGate Command Preview
```
1. Preview a FortiGate check
2. Verify commands show FortiGate syntax:
   - "config system global"
   - "set admin-https enable"
   - "end"
3. Not Cisco syntax
```

---

### Error Handling Tests

#### Test Case 13: All SSH Error Types

| Error Type | Trigger | Expected UI |
|------------|---------|-------------|
| Authentication | Wrong password | 401 modal, retry button |
| Timeout | Unreachable IP | 504 modal, suggestions |
| Connection | Invalid IP | 503 modal, check network |
| Algorithm Mismatch | Old device | 502 modal, upgrade note |
| Host Key | Key changed | 502 modal, security warning |

#### Test Case 14: Network Error
```
1. Disconnect from internet
2. Try to execute any hardening
3. Verify error: "Network error: Failed to fetch"
4. Verify no structured SSH error (just network error)
```

#### Test Case 15: Session Expired
```
1. Start hardening process
2. Let session expire
3. Try to execute
4. Verify redirect to login or session expired message
```

---

### Edge Cases

#### Test Case 16: Empty Parameter Default
```
1. Parameter has default="" (empty string)
2. Verify form shows empty input
3. Verify user can fill in value
4. Verify backend accepts empty string if valid
```

#### Test Case 17: Very Long Banner Text
```
1. Fill BANNER_TEXT with 500+ characters
2. Verify textarea expands
3. Execute
4. Verify backend accepts long text
```

#### Test Case 18: Special Characters in Password
```
1. Use password with special chars: P@$$w0rd!#%
2. Verify form accepts it
3. Execute
4. Verify backend handles special characters
```

#### Test Case 19: Concurrent Executions
```
1. Open two browser tabs
2. Execute hardening in both simultaneously
3. Verify both handle properly (no race conditions)
```

#### Test Case 20: Verification Failure
```
1. Execute a fix
2. Backend reports verification_passed: false
3. Verify UI shows warning:
   "Commands executed but check still failing"
4. Display verification evidence
5. Suggest manual review
```

---

## API Response Examples

### Successful Execution

```json
{
  "action_id": 4567,
  "status": "success",
  "verification_passed": true,
  "verification_evidence": "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
  "backup_created": true,
  "commands_executed": [
    "configure terminal",
    "no enable password",
    "enable secret <REDACTED>",
    "end",
    "write memory"
  ],
  "error_message": null
}
```

### Failed Execution (Command Error)

```json
{
  "action_id": 4568,
  "status": "failed",
  "verification_passed": false,
  "verification_evidence": "",
  "backup_created": true,
  "commands_executed": [
    "configure terminal",
    "ip access-class VTY_ACCESS in"
  ],
  "error_message": "% Error: ACL 'VTY_ACCESS' does not exist"
}
```

### SSH Authentication Error (401)

```json
{
  "detail": {
    "error_type": "authentication_error",
    "message": "Authentication failed for 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": [
      "Verify the username and password are correct",
      "Check if the account is locked or disabled on the device",
      "Ensure SSH authentication is enabled on the device",
      "Verify the user has appropriate privileges for SSH access"
    ],
    "original_error": "Authentication to device failed."
  }
}
```

### SSH Connection Timeout (504)

```json
{
  "detail": {
    "error_type": "timeout_error",
    "message": "Connection timed out to 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": [
      "Verify the device is powered on and responsive",
      "Check network connectivity to the device",
      "Increase the connection timeout if the device is slow",
      "Check if a firewall is blocking or rate-limiting SSH connections"
    ],
    "original_error": "NetMikoTimeoutException: Connection timed out"
  }
}
```

### SSH Network Error (503)

```json
{
  "detail": {
    "error_type": "connection_error",
    "message": "Cannot connect to 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": [
      "Verify the IP address is correct",
      "Check if the device is powered on and reachable (try ping)",
      "Ensure SSH service is running on the device",
      "Check if a firewall is blocking port 22",
      "Verify network routing to the device"
    ],
    "original_error": "OSError: [Errno 113] No route to host"
  }
}
```

### SSH Algorithm Mismatch (502)

```json
{
  "detail": {
    "error_type": "algorithm_mismatch",
    "message": "SSH algorithm negotiation failed with 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": [
      "The device may be running an outdated SSH version",
      "Check if the device supports modern SSH algorithms",
      "Consider upgrading the device's SSH implementation",
      "Enable legacy SSH algorithms on the management server if needed"
    ],
    "original_error": "IncompatiblePeer: Incompatible ssh peer"
  }
}
```

---

## Best Practices

### 1. Always Show Loading States
```jsx
{loading && <Spinner text="Executing hardening..." />}
```

### 2. Provide Clear Error Messages
```jsx
// ❌ Bad
<p>Error occurred</p>

// ✅ Good
<p>Failed to execute hardening: {error.message}</p>
<p>Device: {error.device_ip}</p>
<ul>
  {error.suggestions.map(s => <li>{s}</li>)}
</ul>
```

### 3. Validate Before Submission
```javascript
const validateForm = () => {
  const errors = {};

  Object.entries(requiredParams).forEach(([name, meta]) => {
    if (meta.required && !userParams[name]) {
      errors[name] = `${meta.label} is required`;
    }
  });

  return errors;
};
```

### 4. Handle Edge Cases
- Empty parameter lists
- Network failures
- Session expiration
- Concurrent operations

### 5. Provide Feedback
- Success messages with verification status
- Error messages with suggestions
- Progress indicators during execution
- Configuration backup confirmation

### 6. Security Considerations
- Never log SSH passwords
- Mask sensitive data in UI (show/hide toggles)
- Clear sensitive data from state after use
- Use HTTPS for all API calls

### 7. Accessibility
- Proper ARIA labels
- Keyboard navigation
- Screen reader support
- Color contrast for errors

---

## Appendix: Complete Flow Diagrams

### Fix Single Flow

```
User Action → Frontend → API → Backend → Device → Response
─────────────────────────────────────────────────────────

1. Click "Fix"
   ├─→ Open FixSingleModal
   ├─→ POST /api/hardening/preview
   │   └─→ Return: commands, required_parameters
   │
2. Review Preview
   └─→ User confirms
       │
3. Fill Parameters (if needed)
   └─→ User fills form
       │
4. Provide SSH Credentials
   └─→ User submits credentials
       │
5. Execute
   ├─→ POST /api/hardening/execute
   │   ├─→ Backend connects via SSH
   │   ├─→ Backup config
   │   ├─→ Execute commands
   │   ├─→ Verify fix
   │   └─→ Return: status, verification
   │
6. Display Results
   ├─→ Success: Show ✓ with verification
   └─→ Error: Show SSH error modal with suggestions
```

### Fix All / Batch Flow

```
1. Select Checks (checkboxes)
2. Click "Fix Selected"
3. GET /session/{id}/parameters
   └─→ Aggregate all unique parameters
4. Display unified form
5. User fills all parameters
6. User provides SSH credentials
7. POST /api/hardening/batch-execute
   └─→ Execute all checks sequentially
8. Display batch results
   ├─→ Individual status for each check
   ├─→ Overall summary (fixed/failed/skipped)
   └─→ Action IDs for audit trail
```

### Auto-Harden Flow

```
1. Click "Automatic Hardening"
2. GET /session/{id}/auto-preview
   └─→ Return: checks_with_defaults, skipped_checks
3. Display preview
   ├─→ Show what will be applied
   └─→ Show what will be skipped
4. User confirms checkbox
5. User provides SSH credentials only
6. POST /api/hardening/auto-harden-defaults
   └─→ Apply only auto-fixable checks
7. Display results
   ├─→ Fixed count with verification
   └─→ Skipped count with reasons
```

---

## Questions?

Contact the backend team if you need:
- Additional parameter types
- New validation rules
- Different error categorization
- API endpoint modifications
- FortiGate-specific features

---

**End of Guide**
