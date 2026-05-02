#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Netease Services Startup Script ===${NC}\n"

# Check if running on the correct server
CURRENT_IP=$(hostname -I | awk '{print $1}')
echo -e "Current IP: ${YELLOW}$CURRENT_IP${NC}"
echo -e "Expected IP: ${YELLOW}172.16.200.90${NC}\n"

# Function to check if port is in use
check_port() {
    local port=$1
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        echo -e "${RED}Port $port is already in use${NC}"
        netstat -tlnp 2>/dev/null | grep ":$port "
        return 1
    else
        echo -e "${GREEN}Port $port is available${NC}"
        return 0
    fi
}

# Check all required ports
echo -e "${YELLOW}Checking ports...${NC}"
check_port 8000
check_port 8001
check_port 5173
echo ""

# Check if virtual environments exist
echo -e "${YELLOW}Checking virtual environments...${NC}"
if [ -d "/home/sina/netease/.venv" ]; then
    echo -e "${GREEN}Main app venv found${NC}"
else
    echo -e "${RED}Main app venv NOT found at /home/sina/netease/.venv${NC}"
fi

if [ -d "/home/sina/netease/license_server/venv" ]; then
    echo -e "${GREEN}License server venv found${NC}"
else
    echo -e "${RED}License server venv NOT found at /home/sina/netease/license_server/venv${NC}"
fi
echo ""

# Check if node_modules exists
echo -e "${YELLOW}Checking frontend dependencies...${NC}"
if [ -d "/home/sina/netease/front/node_modules" ]; then
    echo -e "${GREEN}Frontend node_modules found${NC}"
else
    echo -e "${RED}Frontend node_modules NOT found. Run: cd /home/sina/netease/front && npm install${NC}"
fi
echo ""

echo -e "${GREEN}=== Instructions to Start Services ===${NC}\n"

echo -e "${YELLOW}Terminal 1 - License Server (Port 8001):${NC}"
echo "cd /home/sina/netease/license_server"
echo "source venv/bin/activate"
echo "uvicorn app.main:app --host 0.0.0.0 --port 8001"
echo ""

echo -e "${YELLOW}Terminal 2 - Main App Backend (Port 8000):${NC}"
echo "cd /home/sina/netease"
echo "source .venv/bin/activate"
echo "uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""

echo -e "${YELLOW}Terminal 3 - Frontend (Port 5173):${NC}"
echo "cd /home/sina/netease/front"
echo "npm run dev"
echo ""

echo -e "${GREEN}=== Access URLs ===${NC}"
echo -e "Frontend: ${YELLOW}http://172.16.200.90:5173${NC}"
echo -e "Backend API: ${YELLOW}http://172.16.200.90:8000/docs${NC}"
echo -e "License Server: ${YELLOW}http://172.16.200.90:8001/docs${NC}"
echo ""

echo -e "${GREEN}=== Troubleshooting ===${NC}"
echo "1. If you can't access from browser, check firewall:"
echo "   sudo ufw status"
echo "   sudo ufw allow 5173/tcp"
echo "   sudo ufw allow 8000/tcp"
echo "   sudo ufw allow 8001/tcp"
echo ""
echo "2. Verify services are listening on 0.0.0.0:"
echo "   netstat -tlnp | grep -E ':(8000|8001|5173)'"
echo ""
echo "3. Test from the server itself:"
echo "   curl http://localhost:5173"
echo "   curl http://localhost:8000/docs"
echo "   curl http://localhost:8001/docs"
echo ""

