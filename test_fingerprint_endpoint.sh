#!/bin/bash

echo "=== Testing Fingerprint Endpoint ==="
echo ""

# Check if license server is running
if ! netstat -tlnp 2>/dev/null | grep -q ":8001 "; then
    echo "License server is NOT running on port 8001"
    echo ""
    echo "Start it with:"
    echo "  cd /home/sina/netease/license_server"
    echo "  source .venv/bin/activate"
    echo "  uvicorn app.main:app --host 0.0.0.0 --port 8001"
    exit 1
fi

echo "License server is running on port 8001"
echo ""

# Test the endpoint
echo "Testing GET /api/fingerprint..."
RESPONSE=$(curl -s http://localhost:8001/api/fingerprint)
echo "Response: $RESPONSE"
echo ""

# Check if response contains fingerprint field
if echo "$RESPONSE" | grep -q '"fingerprint"'; then
    echo "Response contains fingerprint field"
    
    # Extract fingerprint value
    FINGERPRINT=$(echo "$RESPONSE" | grep -o '"fingerprint":"[^"]*"' | cut -d'"' -f4)
    echo "Fingerprint value: $FINGERPRINT"
else
    echo "Response does NOT contain fingerprint field"
    exit 1
fi

echo ""
echo "=== OpenAPI Documentation ==="
echo "Check the endpoint documentation at:"
echo "  http://172.16.200.90:8001/docs"
echo ""
echo "Look for GET /api/fingerprint and verify:"
echo "  - Response schema shows: { fingerprint: string }"
echo "  - Documentation is clear and descriptive"
echo ""

echo "All tests passed!"
