#!/bin/bash
#
# Database Sync Script: Local → VPS
#
# This script uploads your LOCAL database to the VPS.
# It creates a backup of the VPS database before syncing.
#
# Usage: ./scripts/sync_to_vps.sh
#

set -e  # Exit on any error

# ============================================================================
# CONFIGURATION - EDIT THESE VALUES
# ============================================================================

# VPS Configuration
VPS_HOST="172.16.200.90"                # e.g., "192.168.1.100" or "yourdomain.com"
VPS_USER="srv"                          # SSH username for VPS
VPS_DB_NAME="netease_db"                # Database name on VPS
VPS_DB_USER="netease"                   # PostgreSQL user on VPS
VPS_DB_PASSWORD="1234"                  # PostgreSQL password on VPS

# Local Configuration
LOCAL_DB_NAME="netease_db"              # Local database name
LOCAL_DB_USER="netease"                 # Local PostgreSQL user
LOCAL_DB_PASSWORD="1234"                # Local PostgreSQL password

# Backup Configuration
BACKUP_DIR="$HOME/db_backups"           # Where to store backups
KEEP_BACKUPS=7                          # Number of backups to keep

# ============================================================================
# SCRIPT START - DO NOT EDIT BELOW THIS LINE
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp for backup filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOCAL_DUMP_FILE="$BACKUP_DIR/local_dump_${TIMESTAMP}.sql"
VPS_BACKUP_FILE="vps_backup_${TIMESTAMP}.sql"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Database Sync: Local → VPS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Test VPS SSH connection
echo -e "${YELLOW}[1/6] Testing VPS connection...${NC}"
if ! ssh -o ConnectTimeout=10 "$VPS_USER@$VPS_HOST" "echo 'Connection successful'" &>/dev/null; then
    echo -e "${RED}✗ Cannot connect to VPS at $VPS_USER@$VPS_HOST${NC}"
    echo -e "${RED}  Please check VPS_HOST and VPS_USER in the script.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ VPS connection successful${NC}"
echo ""

# Step 2: Backup VPS database
echo -e "${YELLOW}[2/6] Backing up VPS database...${NC}"
ssh "$VPS_USER@$VPS_HOST" "mkdir -p ~/db_backups && PGPASSWORD='$VPS_DB_PASSWORD' pg_dump -h localhost -U $VPS_DB_USER $VPS_DB_NAME > ~/db_backups/$VPS_BACKUP_FILE" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ VPS backup saved: ~/db_backups/$VPS_BACKUP_FILE${NC}"
else
    echo -e "${YELLOW}⚠ Failed to backup VPS database${NC}"
    echo -e "${YELLOW}  Continuing anyway...${NC}"
fi
echo ""

# Step 3: Dump local database
echo -e "${YELLOW}[3/6] Dumping local database...${NC}"
export PGPASSWORD="$LOCAL_DB_PASSWORD"
if pg_dump -h localhost -U "$LOCAL_DB_USER" "$LOCAL_DB_NAME" > "$LOCAL_DUMP_FILE" 2>/dev/null; then
    echo -e "${GREEN}✓ Local database dumped successfully${NC}"
    # Show dump file size
    DUMP_SIZE=$(du -h "$LOCAL_DUMP_FILE" | cut -f1)
    echo -e "${BLUE}  Dump size: $DUMP_SIZE${NC}"
else
    echo -e "${RED}✗ Failed to dump local database${NC}"
    exit 1
fi
echo ""

# Step 4: Upload dump to VPS
echo -e "${YELLOW}[4/6] Uploading database to VPS...${NC}"
if scp "$LOCAL_DUMP_FILE" "$VPS_USER@$VPS_HOST:/tmp/local_dump.sql" &>/dev/null; then
    echo -e "${GREEN}✓ Database uploaded to VPS${NC}"
else
    echo -e "${RED}✗ Failed to upload database${NC}"
    exit 1
fi
echo ""

# Step 5: Drop and recreate VPS database
echo -e "${YELLOW}[5/6] Recreating VPS database...${NC}"
ssh "$VPS_USER@$VPS_HOST" "
    export PGPASSWORD='$VPS_DB_PASSWORD'
    # Drop database (ignore errors if it doesn't exist)
    dropdb -h localhost -U $VPS_DB_USER $VPS_DB_NAME 2>/dev/null || true
    # Create fresh database
    createdb -h localhost -U $VPS_DB_USER $VPS_DB_NAME
" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ VPS database recreated${NC}"
else
    echo -e "${RED}✗ Failed to recreate VPS database${NC}"
    exit 1
fi
echo ""

# Step 6: Restore local dump to VPS
echo -e "${YELLOW}[6/6] Restoring local data to VPS database...${NC}"
ssh "$VPS_USER@$VPS_HOST" "
    export PGPASSWORD='$VPS_DB_PASSWORD'
    psql -h localhost -U $VPS_DB_USER $VPS_DB_NAME < /tmp/local_dump.sql
    rm /tmp/local_dump.sql
" &>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database restored successfully on VPS${NC}"
else
    echo -e "${RED}✗ Failed to restore database on VPS${NC}"
    echo -e "${YELLOW}  VPS backup is available at: ~/db_backups/$VPS_BACKUP_FILE${NC}"
    exit 1
fi
echo ""

# Cleanup old backups
echo -e "${YELLOW}Cleaning up old backups...${NC}"
cd "$BACKUP_DIR"
ls -t local_dump_*.sql 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs rm -f 2>/dev/null || true
BACKUP_COUNT=$(ls -1 local_dump_*.sql 2>/dev/null | wc -l)
echo -e "${GREEN}✓ Keeping $BACKUP_COUNT local dump(s)${NC}"

# Cleanup old VPS backups
ssh "$VPS_USER@$VPS_HOST" "
    cd ~/db_backups 2>/dev/null || exit 0
    ls -t vps_backup_*.sql 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs rm -f 2>/dev/null || true
" 2>/dev/null

echo ""

# Success message
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Database sync completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Summary:${NC}"
echo -e "  • Local dump: $LOCAL_DUMP_FILE"
echo -e "  • VPS backup: ~/db_backups/$VPS_BACKUP_FILE"
echo -e "  • Database: $VPS_DB_NAME"
echo ""
echo -e "${YELLOW}Note: Your VPS database now matches your LOCAL database.${NC}"
