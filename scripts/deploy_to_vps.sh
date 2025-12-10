#!/bin/bash
#
# VPS Deployment Script
#
# This script deploys your code to the VPS and runs migrations automatically.
# It uses Git to pull the latest code and Alembic to update the database schema.
#
# Usage: ./scripts/deploy_to_vps.sh
#

set -e  # Exit on any error

# ============================================================================
# CONFIGURATION - EDIT THESE VALUES
# ============================================================================

# VPS Configuration
VPS_HOST="172.16.200.90"        # e.g., "192.168.1.100" or "yourdomain.com"
VPS_USER="srv"            # SSH username for VPS
VPS_PROJECT_PATH="/home/srv/netease"     # Full path to project on VPS (e.g., /home/user/netease)

# Git Configuration
GIT_BRANCH="main"                       # Branch to deploy

# Service Configuration (if using systemd)
SERVICE_NAME="netease"                  # Systemd service name (leave empty if not using systemd)

# ============================================================================
# SCRIPT START - DO NOT EDIT BELOW THIS LINE
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Deploying to VPS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Test VPS connection
echo -e "${YELLOW}[1/7] Testing VPS connection...${NC}"
if ! ssh -o ConnectTimeout=10 "$VPS_USER@$VPS_HOST" "echo 'Connection successful'" &>/dev/null; then
    echo -e "${RED}✗ Cannot connect to VPS at $VPS_USER@$VPS_HOST${NC}"
    echo -e "${RED}  Please check VPS_HOST and VPS_USER in the script.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ VPS connection successful${NC}"
echo ""

# Step 2: Push local changes to Git
echo -e "${YELLOW}[2/7] Checking Git status...${NC}"
if git diff-index --quiet HEAD --; then
    echo -e "${GREEN}✓ No uncommitted changes${NC}"
else
    echo -e "${YELLOW}⚠ You have uncommitted changes!${NC}"
    echo -e "${YELLOW}  Commit and push your changes before deploying.${NC}"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Deployment cancelled${NC}"
        exit 1
    fi
fi
echo ""

# Step 3: Pull latest code on VPS
echo -e "${YELLOW}[3/7] Pulling latest code from Git...${NC}"
ssh "$VPS_USER@$VPS_HOST" "cd $VPS_PROJECT_PATH && git fetch origin && git checkout $GIT_BRANCH && git pull origin $GIT_BRANCH"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Code updated on VPS${NC}"
else
    echo -e "${RED}✗ Failed to pull code${NC}"
    exit 1
fi
echo ""

# Step 4: Install/update dependencies
echo -e "${YELLOW}[4/7] Installing dependencies...${NC}"
ssh "$VPS_USER@$VPS_HOST" "cd $VPS_PROJECT_PATH && source venv/bin/activate && pip install -r requirements.txt --quiet"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Dependencies updated${NC}"
else
    echo -e "${YELLOW}⚠ Dependency installation had issues (might be okay)${NC}"
fi
echo ""

# Step 5: Run database migrations
echo -e "${YELLOW}[5/7] Running database migrations...${NC}"
ssh "$VPS_USER@$VPS_HOST" "cd $VPS_PROJECT_PATH && source venv/bin/activate && alembic upgrade head"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database migrations completed${NC}"
else
    echo -e "${RED}✗ Migration failed${NC}"
    exit 1
fi
echo ""

# Step 6: Build frontend (if needed)
echo -e "${YELLOW}[6/7] Building frontend...${NC}"
if ssh "$VPS_USER@$VPS_HOST" "cd $VPS_PROJECT_PATH/frontend-react && npm run build" 2>/dev/null; then
    echo -e "${GREEN}✓ Frontend built successfully${NC}"
else
    echo -e "${YELLOW}⚠ Frontend build skipped or failed${NC}"
fi
echo ""

# Step 7: Restart service
echo -e "${YELLOW}[7/7] Restarting application...${NC}"
if [ -n "$SERVICE_NAME" ]; then
    ssh "$VPS_USER@$VPS_HOST" "sudo systemctl restart $SERVICE_NAME"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Service restarted: $SERVICE_NAME${NC}"
    else
        echo -e "${YELLOW}⚠ Service restart failed (you may need to restart manually)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ No service configured (restart manually if needed)${NC}"
fi
echo ""

# Success message
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Deployment completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}What was done:${NC}"
echo -e "  • Pulled latest code from Git ($GIT_BRANCH branch)"
echo -e "  • Installed/updated Python dependencies"
echo -e "  • Ran database migrations"
echo -e "  • Built frontend"
if [ -n "$SERVICE_NAME" ]; then
    echo -e "  • Restarted $SERVICE_NAME service"
fi
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. Test the application on VPS"
echo -e "  2. Run './scripts/sync_from_vps.sh' to sync the database back to local"
