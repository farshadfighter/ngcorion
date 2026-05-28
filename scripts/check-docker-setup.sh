#!/bin/bash

echo "=== Docker Database Setup Verification ==="
echo ""

# Check if docker-compose.yml exists
if [ -f "docker-compose.yml" ]; then
    echo "✓ docker-compose.yml exists"
else
    echo "✗ docker-compose.yml NOT found"
    exit 1
fi

# Check if init scripts exist
if [ -f "docker/postgres-main/init.sql" ]; then
    echo "✓ Main DB init script exists"
else
    echo "✗ Main DB init script NOT found"
fi

if [ -f "docker/postgres-license/init.sql" ]; then
    echo "✓ License DB init script exists"
else
    echo "✗ License DB init script NOT found"
fi

if [ -f "docker/redis/redis.conf" ]; then
    echo "✓ Redis config exists"
else
    echo "✗ Redis config NOT found"
fi

echo ""
echo "=== Docker Installation Check ==="

# Check if Docker is installed
if command -v docker &> /dev/null; then
    echo "✓ Docker is installed"
    docker --version
else
    echo "✗ Docker is NOT installed"
    echo "  Install with: curl -fsSL https://get.docker.com | sh"
fi

# Check if Docker Compose is installed
if command -v docker-compose &> /dev/null; then
    echo "✓ Docker Compose is installed"
    docker-compose --version
else
    echo "✗ Docker Compose is NOT installed"
    echo "  Install with: sudo apt-get install docker-compose"
fi

echo ""
echo "=== Ready to Start ==="
echo ""
echo "To start databases, run:"
echo "  docker-compose up -d"
echo ""
echo "To check status, run:"
echo "  docker-compose ps"
echo ""
echo "To view logs, run:"
echo "  docker-compose logs -f"
