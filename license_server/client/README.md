# License Client SDK

Python client library for interacting with the License Server API.

## Features

- **Encrypted Storage**: License data stored locally with Fernet encryption
- **Automatic Signing**: HMAC-SHA256 request signing for secure communication
- **VM Fingerprinting**: Hardware-based license binding
- **Background Heartbeat**: Automatic periodic heartbeat service
- **Cross-Platform**: Works on Windows and Linux

## Installation

The client SDK uses the same dependencies as the server:

```bash
pip install cryptography requests
```

## Quick Start

### 1. Activate License

```python
from client import LicenseClient

client = LicenseClient(server_url="http://localhost:8000")

# Activate with license key
result = client.activate("XXXX-XXXX-XXXX-XXXX")
print(f"License activated: {result['message']}")
print(f"Plan: {result['plan_type']}")
```

### 2. Validate License

```python
# Validate license (signed request)
result = client.validate()

if result['valid']:
    print(f"License valid - Plan: {result['plan_type']}")
    print(f"Limits: {result['limits']}")
    print(f"Usage: {result['usage']}")
else:
    print(f"License invalid: {result['message']}")
```

### 3. Consume Operations

```python
# Consume operation quota
result = client.consume(operation_type="discovery", count=1)

if result['valid']:
    print(f"Operation consumed successfully")
    print(f"Remaining: {result['usage']}")
else:
    print(f"Failed: {result['message']}")
```

### 4. Start Heartbeat Service

```python
from client import HeartbeatService

# Start automatic heartbeat (every hour)
heartbeat = HeartbeatService(client, interval_seconds=3600)
heartbeat.start()

# Your application runs...

# Stop when done
heartbeat.stop()
```

## Complete Example

```python
from client import LicenseClient, HeartbeatService
import time

def main():
    # Initialize client
    client = LicenseClient(server_url="http://localhost:8000")
    
    # Activate license (first time only)
    try:
        result = client.activate("XXXX-XXXX-XXXX-XXXX")
        print(f"✓ License activated: {result['plan_type']}")
    except Exception as e:
        print(f"Activation failed: {e}")
        return
    
    # Start heartbeat service
    heartbeat = HeartbeatService(client, interval_seconds=3600)
    heartbeat.start()
    
    try:
        # Validate license
        result = client.validate()
        if not result['valid']:
            print(f"✗ License invalid: {result['message']}")
            return
        
        print(f"✓ License valid")
        print(f"  Plan: {result['plan_type']}")
        print(f"  Limits: {result['limits']}")
        print(f"  Usage: {result['usage']}")
        
        # Perform operations
        operations = ["discovery", "audit", "harden"]
        
        for op in operations:
            result = client.consume(operation_type=op, count=1)
            if result['valid']:
                print(f"✓ {op.capitalize()} operation consumed")
            else:
                print(f"✗ {op.capitalize()} failed: {result['message']}")
        
        # Keep running
        print("\nApplication running... Press Ctrl+C to stop")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        heartbeat.stop()

if __name__ == "__main__":
    main()
```

## API Reference

### LicenseClient

#### `__init__(server_url: str, storage_dir: str = "~/.license")`

Initialize the client.

- `server_url`: License server URL
- `storage_dir`: Directory for encrypted license storage

#### `activate(license_key: str) -> dict`

Activate a license with the server. Generates VM fingerprint and stores encrypted license data locally.

Returns: Activation response with organization token and plan details

#### `validate() -> dict`

Validate the license with the server. Uses stored license data and generates signed request.

Returns: Validation response with limits and usage

#### `heartbeat() -> dict`

Send heartbeat to server. Should be called periodically (recommended: hourly).

Returns: Heartbeat response

#### `consume(operation_type: str, count: int = 1) -> dict`

Consume operation quota. Uses signed request.

- `operation_type`: One of "asset", "discovery", "audit", "harden", "monitor"
- `count`: Number of operations to consume

Returns: Consumption response with updated usage

#### `deactivate()`

Remove local license data (does not deactivate on server).

### HeartbeatService

#### `__init__(client: LicenseClient, interval_seconds: int = 3600)`

Initialize heartbeat service.

- `client`: LicenseClient instance
- `interval_seconds`: Heartbeat interval (default: 1 hour)

#### `start()`

Start the background heartbeat thread.

#### `stop()`

Stop the heartbeat service gracefully.

## Security

- License data encrypted with Fernet (AES-128)
- Encryption key stored with 0600 permissions
- HMAC-SHA256 request signing with timestamp validation
- VM fingerprint prevents license sharing
- Signature prevents request tampering

## Storage Location

Default: `~/.license/`

Files:
- `.license.dat`: Encrypted license data
- `.license.key`: Encryption key (keep secure!)

## Error Handling

```python
try:
    result = client.validate()
except requests.HTTPError as e:
    if e.response.status_code == 401:
        print("Authentication failed - invalid signature")
    elif e.response.status_code == 429:
        print("Rate limit exceeded")
    else:
        print(f"HTTP error: {e}")
except Exception as e:
    print(f"Error: {e}")
```
