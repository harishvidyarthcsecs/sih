#!/bin/bash
# Linux Hardening Tool - Installation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "=========================================================================="
echo "Linux Hardening Tool - Installation"
echo "=========================================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root!"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "hardening_controller.py" ]; then
    log_error "hardening_controller.py not found!"
    log_error "Please run this script from the directory containing all tool files"
    exit 1
fi

log_info "Checking prerequisites..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    log_warn "Python 3 not found. Installing..."
    apt-get update
    apt-get install -y python3
fi

# Check SQLite
if ! python3 -c "import sqlite3" 2>/dev/null; then
    log_warn "Python SQLite3 not found. Installing..."
    apt-get install -y python3-sqlite3
fi

log_info "Creating directory structure..."

# Create directories
mkdir -p hardening_scripts
mkdir -p output
mkdir -p backups/{filesystem,package_management,services,network,firewall,access_control,user_accounts,logging_auditing,system_maintenance}

# Define the script files that should exist in current directory
SCRIPTS=(
    "filesystem.sh"
    "package_mgmt.sh"
    "services.sh"
    "network.sh"
    "firewall.sh"
    "access_control.sh"
    "user_accounts.sh"
    "logging_auditing.sh"
    "system_maintenance.sh"
)

log_info "Copying hardening scripts to hardening_scripts/ directory..."

MISSING_SCRIPTS=0
COPIED_SCRIPTS=0

for script in "${SCRIPTS[@]}"; do
    # Check if script exists in current directory
    if [ -f "$script" ]; then
        # Copy to hardening_scripts directory
        cp "$script" "hardening_scripts/"
        log_info "Copied: $script -> hardening_scripts/"
        ((COPIED_SCRIPTS++))
    elif [ -f "hardening_scripts/$script" ]; then
        # Already in the correct location
        log_info "Already exists: hardening_scripts/$script"
        ((COPIED_SCRIPTS++))
    else
        log_warn "Missing: $script (not found in current directory or hardening_scripts/)"
        ((MISSING_SCRIPTS++))
    fi
done

log_info "Setting permissions..."

# Make controller executable
chmod +x hardening_controller.py

# Make all scripts in hardening_scripts executable
if [ -d "hardening_scripts" ]; then
    chmod +x hardening_scripts/*.sh 2>/dev/null || true
    log_info "Set executable permissions for scripts in hardening_scripts/"
fi

echo ""
log_info "Script copy summary:"
echo "  Copied/Found: $COPIED_SCRIPTS scripts"
echo "  Missing: $MISSING_SCRIPTS scripts"
echo ""

if [ $MISSING_SCRIPTS -gt 0 ]; then
    log_warn "$MISSING_SCRIPTS script(s) are missing!"
    log_warn "Please ensure all 9 hardening scripts are in the current directory"
    log_warn "or in the hardening_scripts/ directory before running the tool"
    echo ""
fi

# Create a sample configuration file
cat > config.txt << 'EOF'
# Linux Hardening Tool Configuration
# This file is for reference only

# Database location
DB_PATH=./hardening.db

# Output directory
OUTPUT_DIR=./output

# Backup directory
BACKUP_DIR=./backups

# Log level (INFO, WARN, ERROR)
LOG_LEVEL=INFO
EOF

log_info "Configuration file created: config.txt"

# Initialize the database
log_info "Initializing database..."
python3 << 'PYEOF'
import sqlite3
import os

db_path = "hardening.db"

# Remove old database if exists
if os.path.exists(db_path):
    print(f"[INFO] Removing old database: {db_path}")
    os.remove(db_path)

# Create new database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Configurations table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS configurations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        topic TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        original_value TEXT,
        current_value TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'original',
        UNIQUE(topic, rule_id)
    )
''')

# Audit log table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        topic TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        action TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        success INTEGER DEFAULT 1
    )
''')

conn.commit()
conn.close()

print("[INFO] Database initialized successfully")
PYEOF

# Create a quick start guide
cat > QUICKSTART.md << 'EOF'
# Quick Start Guide

## First Time Setup

1. **Initial Scan (Recommended)**
   ```bash
   sudo ./hardening_controller.py
   > scan
   > 1
   ```
   This scans the Filesystem topic and shows current status.

2. **Review Output**
   ```bash
   cat output/Filesystem_scan_*.txt
   ```
   Check what failed and what passed.

3. **Apply Fixes**
   ```bash
   sudo ./hardening_controller.py
   > fix
   > 1
   ```
   This fixes the issues found in step 1.

4. **Verify**
   ```bash
   sudo ./hardening_controller.py
   > scan
   > 1
   ```
   Confirm fixes were applied (should show more PASS).

5. **Scan All Topics**
   ```bash
   sudo ./hardening_controller.py
   > all
   ```
   Scan all 9 security topics at once.

## Common Tasks

### Generate Full Report
```bash
sudo ./hardening_controller.py
> report
```

### Check Status
```bash
sudo ./hardening_controller.py
> status
```

### Rollback Topic
```bash
sudo ./hardening_controller.py
> rollback
> 1
> yes
```

### Command Line Mode
```bash
# Scan all topics
sudo ./hardening_controller.py scan-all

# Generate report
sudo ./hardening_controller.py report
```

## Topic Numbers

1. Filesystem
2. Package Management
3. Services
4. Network
5. Host Based Firewall
6. Access Control
7. User Accounts
8. Logging and Auditing
9. System Maintenance

## Important Notes

- Always run as root (sudo)
- Test in staging before production
- Some changes require reboot
- Keep database backups
- Review output files regularly
EOF

log_info "Quick start guide created: QUICKSTART.md"

# Test the installation
log_info "Testing installation..."

if python3 hardening_controller.py --help 2>/dev/null | grep -q "scan-all"; then
    log_info "Controller test: OK"
else
    log_warn "Controller test: Could not verify"
fi

# Create wrapper script for easy access
cat > hardening << 'EOF'
#!/bin/bash
# Wrapper script for Linux Hardening Tool

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This tool must be run as root!"
    exit 1
fi

cd "$SCRIPT_DIR"
exec python3 hardening_controller.py "$@"
EOF

chmod +x hardening

log_info "Wrapper script created: ./hardening"

echo ""
echo "=========================================================================="
log_info "Installation complete!"
echo "=========================================================================="
echo ""
echo "File Structure:"
echo "  ${BLUE}./hardening_controller.py${NC}  - Main controller"
echo "  ${BLUE}./hardening${NC}                - Wrapper script"
echo "  ${BLUE}./hardening_scripts/${NC}       - All hardening scripts"
echo "  ${BLUE}./output/${NC}                  - Scan/fix output files"
echo "  ${BLUE}./backups/${NC}                 - Backup files"
echo "  ${BLUE}./hardening.db${NC}             - SQLite database"
echo ""
echo "Next steps:"
echo ""
echo "  1. Verify all scripts are present:"
echo "     ${BLUE}ls -lh hardening_scripts/${NC}"
echo ""
echo "  2. Run your first scan:"
echo "     ${GREEN}sudo ./hardening_controller.py${NC}"
echo "     or"
echo "     ${GREEN}sudo ./hardening${NC}"
echo ""

if [ $MISSING_SCRIPTS -gt 0 ]; then
    echo "=========================================================================="
    log_warn "WARNING: $MISSING_SCRIPTS script(s) are missing!"
    log_warn "Please add all 9 hardening scripts to the current directory"
    log_warn "then run this install script again to copy them."
    echo "=========================================================================="
    echo ""
fi

log_info "Happy hardening! 🔒"
