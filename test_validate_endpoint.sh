#!/bin/bash

echo "=== Testing /api/licenses/validate Endpoint ==="
echo ""

# Check if license server is running
if ! netstat -tlnp 2>/dev/null | grep -q ":8001 "; then
    echo "ERROR: License server is NOT running on port 8001"
    echo ""
    echo "Start it with:"
    echo "  cd /home/sina/netease/license_server"
    echo "  source .venv/bin/activate"
    echo "  uvicorn app.main:app --host 0.0.0.0 --port 8001"
    exit 1
fi

echo "License server is running on port 8001"
echo ""

# Get fingerprint
echo "Step 1: Getting VM fingerprint..."
FINGERPRINT=$(curl -s http://localhost:8001/api/fingerprint | jq -r '.fingerprint')
if [ -z "$FINGERPRINT" ] || [ "$FINGERPRINT" == "null" ]; then
    echo "ERROR: Failed to get fingerprint"
    exit 1
fi
echo "Fingerprint: $FINGERPRINT"
echo ""

# Test with invalid data
echo "Step 2: Testing with invalid license key..."
RESPONSE=$(curl -s -X POST http://localhost:8001/api/licenses/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"license_key\": \"INVALID-KEY-12345\",
    \"organization_token\": \"invalid-token\",
    \"vm_fingerprint\": \"$FINGERPRINT\"
  }")

echo "Response: $RESPONSE"
VALID=$(echo "$RESPONSE" | jq -r '.valid')

if [ "$VALID" == "false" ]; then
    echo "PASS: Invalid license correctly returned valid: false"
else
    echo "FAIL: Expected valid: false for invalid license"
fi
echo ""

echo "=== To test with a real license ==="
echo ""
echo "1. Activate a license first"
echo "2. Save the organization_token"
echo "3. Call validate with real credentials"
echo ""
echo "Check OpenAPI docs at: http://172.16.200.90:8001/docs"
echo ""

echo "Test completed!"
