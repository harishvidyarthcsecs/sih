#!/bin/bash
# Enhanced Access Control Hardening Script
# Covers: SSH Server, Privilege Escalation, PAM
# Version: 2.0 - Enhanced with better error handling and privilege checks

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/access_control"
TOPIC="Access Control"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_REQUIRED=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_manual() { echo -e "${BLUE}[MANUAL]${NC} $1"; }

# ============================================================================
# Privilege Check
# ============================================================================

check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo ""
        log_error "This script must be run as root or with sudo privileges"
        log_info "Please run: sudo $0 $MODE"
        echo ""
        exit 1
    fi
}

# ============================================================================
# Database Functions
# ============================================================================

save_config() {
    python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configurations (
            topic TEXT,
            rule_id TEXT,
            rule_name TEXT,
            original_value TEXT,
            current_value TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (topic, rule_id)
        )
    ''')
    cursor.execute('''
        INSERT OR REPLACE INTO configurations 
        (topic, rule_id, rule_name, original_value, current_value, status)
        VALUES (?, ?, ?, ?, ?, 'stored')
    ''', ('$TOPIC', '$1', '''$2''', '''$3''', '''${4:-$3}'''))
    conn.commit()
    conn.close()
except Exception as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

get_original_config() {
    python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$1'))
    result = cursor.fetchone()
    conn.close()
    print(result[0] if result else '')
except:
    print('')
" 2>/dev/null
}

# ============================================================================
# SSH Configuration Checks
# ============================================================================

check_ssh_config() {
    local rule_id="SSH-CONFIG-PERMS"
    local rule_name="Ensure permissions on /etc/ssh/sshd_config are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/ssh/sshd_config ]; then
            local perms=$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)
            local owner=$(stat -c %U /etc/ssh/sshd_config 2>/dev/null)
            local group=$(stat -c %G /etc/ssh/sshd_config 2>/dev/null)
            
            if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                log_pass "SSH config permissions correct: 600 root:root"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "SSH config permissions incorrect: $perms $owner:$group (expected: 600 root:root)"
                ((FAILED_CHECKS++))
                return 1
            fi
        else
            log_error "SSH config file not found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/ssh/sshd_config ]; then
            local current=$(stat -c "%a %U:%G" /etc/ssh/sshd_config 2>/dev/null)
            save_config "$rule_id" "$rule_name" "$current"
            
            chown root:root /etc/ssh/sshd_config
            chmod 600 /etc/ssh/sshd_config
            log_info "Set SSH config permissions to 600 root:root"
            ((FIXED_CHECKS++))
        else
            log_error "Cannot fix: SSH config file not found"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ] && [ -f /etc/ssh/sshd_config ]; then
            local orig_perms=$(echo "$original" | awk '{print $1}')
            local orig_owner=$(echo "$original" | awk '{print $2}' | cut -d: -f1)
            local orig_group=$(echo "$original" | awk '{print $2}' | cut -d: -f2)
            
            chmod "$orig_perms" /etc/ssh/sshd_config 2>/dev/null
            chown "$orig_owner:$orig_group" /etc/ssh/sshd_config 2>/dev/null
            log_info "Restored SSH config permissions to $orig_perms $orig_owner:$orig_group"
        fi
    fi
}

check_sshd_parameter() {
    local param="$1"
    local expected_value="$2"
    local rule_id="SSH-PARAM-$(echo $param | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure sshd $param is $expected_value"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Check if sshd is installed
        if ! command -v sshd >/dev/null 2>&1; then
            log_warn "SSH server (sshd) is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Get current value using sshd -T
        local current=$(sshd -T 2>/dev/null | grep -i "^$param " | awk '{print $2}')
        
        # If sshd -T fails, try to read from config file directly
        if [ -z "$current" ]; then
            current=$(grep -i "^$param " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        fi
        
        if [ -z "$current" ]; then
            log_error "SSH $param is not set (expected: $expected_value)"
            ((FAILED_CHECKS++))
            return 1
        elif [ "$current" = "$expected_value" ]; then
            log_pass "SSH $param = $expected_value"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "SSH $param = $current (expected: $expected_value)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ ! -f /etc/ssh/sshd_config ]; then
            log_error "Cannot fix: SSH config file not found"
            return 1
        fi
        
        # Get current value
        local current=$(sshd -T 2>/dev/null | grep -i "^$param " | awk '{print $2}')
        if [ -z "$current" ]; then
            current=$(grep -i "^$param " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        fi
        
        if [ -z "$current" ]; then
            current="not_set"
        fi
        
        save_config "$rule_id" "$rule_name" "$current" "$expected_value"
        
        # Backup sshd_config
        cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)"
        
        # Update or add parameter (case-insensitive)
        if grep -iq "^$param " /etc/ssh/sshd_config; then
            sed -i "s/^${param} .*/${param} ${expected_value}/I" /etc/ssh/sshd_config
        elif grep -iq "^#${param} " /etc/ssh/sshd_config; then
            sed -i "s/^#${param} .*/${param} ${expected_value}/I" /etc/ssh/sshd_config
        else
            echo "${param} ${expected_value}" >> /etc/ssh/sshd_config
        fi
        
        log_info "Set SSH $param = $expected_value"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/sshd_config.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/ssh/sshd_config
            log_info "Restored SSH configuration from backup"
        else
            log_warn "No backup found for SSH configuration"
        fi
    fi
}

check_all_ssh_parameters() {
    log_info "=== SSH Server Configuration ==="
    
    check_ssh_config
    check_sshd_parameter "PermitRootLogin" "no"
    check_sshd_parameter "PermitEmptyPasswords" "no"
    check_sshd_parameter "PermitUserEnvironment" "no"
    check_sshd_parameter "HostbasedAuthentication" "no"
    check_sshd_parameter "IgnoreRhosts" "yes"
    check_sshd_parameter "X11Forwarding" "no"
    check_sshd_parameter "MaxAuthTries" "4"
    check_sshd_parameter "MaxSessions" "10"
    check_sshd_parameter "LoginGraceTime" "60"
    check_sshd_parameter "ClientAliveInterval" "300"
    check_sshd_parameter "ClientAliveCountMax" "3"
    check_sshd_parameter "LogLevel" "INFO"
    check_sshd_parameter "UsePAM" "yes"
    check_sshd_parameter "GSSAPIAuthentication" "no"
}

# ============================================================================
# Privilege Escalation - Sudo
# ============================================================================

check_sudo_installed() {
    local rule_id="SUDO-INSTALLED"
    local rule_name="Ensure sudo is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if command -v sudo >/dev/null 2>&1; then
            log_pass "sudo is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "sudo is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            save_config "$rule_id" "$rule_name" "not_installed"
            
            log_info "Installing sudo..."
            if apt-get update && apt-get install -y sudo; then
                log_info "Successfully installed sudo"
                ((FIXED_CHECKS++))
            else
                log_error "Failed to install sudo"
            fi
        else
            log_info "sudo is already installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            log_warn "Removing sudo (as it was not installed originally)"
            apt-get remove -y sudo
            log_info "Removed sudo"
        fi
    fi
}

check_sudo_pty() {
    local rule_id="SUDO-USE-PTY"
    local rule_name="Ensure sudo commands use pty"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -rq "^Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
            log_pass "sudo use_pty is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "sudo use_pty is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured" "configured"
        
        # Backup sudoers
        cp /etc/sudoers "$BACKUP_DIR/sudoers.$(date +%Y%m%d_%H%M%S)"
        
        # Create hardening file if it doesn't exist
        if [ ! -f /etc/sudoers.d/hardening ]; then
            touch /etc/sudoers.d/hardening
            chmod 440 /etc/sudoers.d/hardening
        fi
        
        if ! grep -q "^Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
            echo "Defaults use_pty" >> /etc/sudoers.d/hardening
            log_info "Configured sudo use_pty"
            ((FIXED_CHECKS++))
        else
            log_info "sudo use_pty is already configured"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        if [ -f /etc/sudoers.d/hardening ]; then
            sed -i '/use_pty/d' /etc/sudoers.d/hardening 2>/dev/null
            log_info "Removed sudo use_pty configuration"
        fi
        
        local backup=$(ls -t "$BACKUP_DIR"/sudoers.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/sudoers
            log_info "Restored sudoers from backup"
        fi
    fi
}

check_sudo_logfile() {
    local rule_id="SUDO-LOGFILE"
    local rule_name="Ensure sudo log file exists"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -rq "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
            log_pass "sudo logfile is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "sudo logfile is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured" "configured"
        
        # Create hardening file if it doesn't exist
        if [ ! -f /etc/sudoers.d/hardening ]; then
            touch /etc/sudoers.d/hardening
            chmod 440 /etc/sudoers.d/hardening
        fi
        
        if ! grep -rq "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
            echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers.d/hardening
            log_info "Configured sudo logfile at /var/log/sudo.log"
            ((FIXED_CHECKS++))
        else
            log_info "sudo logfile is already configured"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        if [ -f /etc/sudoers.d/hardening ]; then
            sed -i '/logfile=/d' /etc/sudoers.d/hardening 2>/dev/null
            log_info "Removed sudo logfile configuration"
        fi
    fi
}

check_su_restricted() {
    local rule_id="SU-RESTRICTED"
    local rule_name="Ensure access to the su command is restricted"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
            log_pass "su command is restricted to wheel group"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "su command is not restricted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/pam.d/su "$BACKUP_DIR/su.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        save_config "$rule_id" "$rule_name" "not_restricted" "restricted"
        
        if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
            echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
            log_info "Restricted su command to wheel group"
            ((FIXED_CHECKS++))
        else
            log_info "su command is already restricted"
        fi
        
        # Create wheel group if it doesn't exist
        if ! getent group wheel >/dev/null; then
            groupadd wheel
            log_info "Created wheel group"
        fi
        
        echo ""
        log_manual "╔════════════════════════════════════════════════════════════╗"
        log_manual "║ MANUAL ACTION REQUIRED: Add authorized users to wheel     ║"
        log_manual "║ group to allow them to use 'su' command:                  ║"
        log_manual "║                                                            ║"
        log_manual "║   sudo usermod -aG wheel <username>                        ║"
        log_manual "║                                                            ║"
        log_manual "║ Users not in the wheel group will NOT be able to use su   ║"
        log_manual "╚════════════════════════════════════════════════════════════╝"
        echo ""
        ((MANUAL_REQUIRED++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/su.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/pam.d/su
            log_info "Restored su configuration from backup"
        else
            sed -i '/pam_wheel.so/d' /etc/pam.d/su 2>/dev/null
            log_info "Removed su restrictions"
        fi
    fi
}

# ============================================================================
# PAM Configuration
# ============================================================================

check_pam_package() {
    local package="$1"
    local rule_id="PAM-PKG-$(echo $package | tr '-' '_' | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $package is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package"; then
            log_pass "$package is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "$package is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! dpkg -l 2>/dev/null | grep -q "^ii.*$package"; then
            save_config "$rule_id" "$rule_name" "not_installed"
            
            log_info "Installing $package..."
            if apt-get update && apt-get install -y "$package"; then
                log_info "Successfully installed $package"
                ((FIXED_CHECKS++))
            else
                log_error "Failed to install $package"
            fi
        else
            log_info "$package is already installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            log_warn "Removing $package (as it was not installed originally)"
            apt-get remove -y "$package"
            log_info "Removed $package"
        fi
    fi
}

check_pam_pwquality() {
    local rule_id="PAM-PWQUALITY"
    local rule_name="Ensure password quality requirements are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ ! -f /etc/security/pwquality.conf ]; then
            log_error "pwquality.conf not found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        local minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
        
        if [ -z "$minlen" ]; then
            minlen=0
        fi
        
        if [ "${minlen}" -ge 14 ]; then
            log_pass "Password quality is configured (minlen = $minlen)"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Password quality not properly configured (minlen = $minlen, expected >= 14)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ ! -f /etc/security/pwquality.conf ]; then
            log_error "Cannot fix: pwquality.conf not found. Install libpam-pwquality first."
            return 1
        fi
        
        cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
        save_config "$rule_id" "$rule_name" "not_configured" "configured"
        
        # Configure password quality requirements
        if grep -q "^minlen" /etc/security/pwquality.conf; then
            sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf
        else
            sed -i 's/^# minlen.*/minlen = 14/' /etc/security/pwquality.conf
        fi
        
        if grep -q "^minclass" /etc/security/pwquality.conf; then
            sed -i 's/^minclass.*/minclass = 4/' /etc/security/pwquality.conf
        else
            sed -i 's/^# minclass.*/minclass = 4/' /etc/security/pwquality.conf
        fi
        
        # Set credit requirements
        for credit in dcredit ucredit lcredit ocredit; do
            if grep -q "^$credit" /etc/security/pwquality.conf; then
                sed -i "s/^$credit.*/$credit = -1/" /etc/security/pwquality.conf
            else
                sed -i "s/^# $credit.*/$credit = -1/" /etc/security/pwquality.conf
            fi
        done
        
        log_info "Configured password quality requirements:"
        log_info "  - Minimum length: 14 characters"
        log_info "  - Minimum character classes: 4"
        log_info "  - Require: digit, uppercase, lowercase, special character"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/pwquality.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/security/pwquality.conf
            log_info "Restored pwquality configuration from backup"
        fi
    fi
}

check_pam_faillock() {
    local rule_id="PAM-FAILLOCK"
    local rule_name="Ensure password failed attempts lockout is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
            log_pass "Account lockout (pam_faillock) is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Account lockout (pam_faillock) is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/pam.d/common-auth "$BACKUP_DIR/common-auth.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        cp /etc/pam.d/common-account "$BACKUP_DIR/common-account.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        save_config "$rule_id" "$rule_name" "not_configured" "requires_manual_config"
        
        echo ""
        log_manual "╔════════════════════════════════════════════════════════════╗"
        log_manual "║ MANUAL ACTION REQUIRED: Configure pam_faillock            ║"
        log_manual "╚════════════════════════════════════════════════════════════╝"
        log_manual ""
        log_manual "Account lockout requires manual PAM configuration."
        log_manual "Run the following commands to configure:"
        log_manual ""
        log_manual "1. Edit /etc/pam.d/common-auth and add BEFORE pam_unix.so:"
        log_manual "   auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
        log_manual ""
        log_manual "2. Edit /etc/pam.d/common-auth and add AFTER pam_unix.so:"
        log_manual "   auth required pam_faillock.so authfail audit deny=5 unlock_time=900"
        log_manual ""
        log_manual "3. Edit /etc/pam.d/common-account and add:"
        log_manual "   account required pam_faillock.so"
        log_manual ""
        log_manual "This will lock accounts after 5 failed attempts for 15 minutes."
        log_manual ""
        log_manual "Automatic configuration script:"
        echo ""
        cat << 'EOF'
# Copy and run this as root:
cat > /tmp/configure_faillock.sh << 'SCRIPT'
#!/bin/bash
# Backup files
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup
cp /etc/pam.d/common-account /etc/pam.d/common-account.backup

# Configure common-auth
if ! grep -q "pam_faillock.so preauth" /etc/pam.d/common-auth; then
    sed -i '/pam_unix.so/i auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' /etc/pam.d/common-auth
fi

if ! grep -q "pam_faillock.so authfail" /etc/pam.d/common-auth; then
    sed -i '/pam_unix.so/a auth required pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/common-auth
fi

# Configure common-account
if ! grep -q "pam_faillock.so" /etc/pam.d/common-account; then
    echo "account required pam_faillock.so" >> /etc/pam.d/common-account
fi

echo "pam_faillock configured successfully"
SCRIPT

chmod +x /tmp/configure_faillock.sh
sudo /tmp/configure_faillock.sh
EOF
        echo ""
        ((MANUAL_REQUIRED++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup_auth=$(ls -t "$BACKUP_DIR"/common-auth.* 2>/dev/null | head -1)
        local backup_account=$(ls -t "$BACKUP_DIR"/common-account.* 2>/dev/null | head -1)
        
        if [ -n "$backup_auth" ]; then
            cp "$backup_auth" /etc/pam.d/common-auth
            log_info "Restored common-auth from backup"
        fi
        
        if [ -n "$backup_account" ]; then
            cp "$backup_account" /etc/pam.d/common-account
            log_info "Restored common-account from backup"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

print_summary() {
    echo ""
    echo "========================================================================"
    echo "Summary"
    echo "========================================================================"
    echo "Total Checks: $TOTAL_CHECKS"
    
    if [ "$MODE" = "scan" ]; then
        echo "Passed: $PASSED_CHECKS"
        echo "Failed: $FAILED_CHECKS"
        echo ""
        
        if [ $FAILED_CHECKS -eq 0 ]; then
            log_pass "✓ All access control checks passed!"
        else
            log_warn "✗ $FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            echo ""
            log_info "Run: sudo $0 fix"
        fi
        
    elif [ "$MODE" = "fix" ]; then
        echo "Fixed: $FIXED_CHECKS"
        if [ $MANUAL_REQUIRED -gt 0 ]; then
            echo "Manual Actions Required: $MANUAL_REQUIRED"
        fi
        echo ""
        
        if [ $FIXED_CHECKS -gt 0 ]; then
            log_info "✓ Fixes applied successfully"
            echo ""
            log_warn "═══════════════════════════════════════════════════════════"
            log_warn "  IMPORTANT: Services need to be restarted"
            log_warn "═══════════════════════════════════════════════════════════"
            log_warn "Run the following commands to apply changes:"
            log_warn ""
            log_warn "  sudo systemctl restart sshd    # or 'ssh' on some systems"
            log_warn ""
            log_warn "After restarting services, run scan to verify:"
            log_warn "  sudo $0 scan"
            echo ""
        fi
        
        if [ $MANUAL_REQUIRED -gt 0 ]; then
            echo ""
            log_manual "═══════════════════════════════════════════════════════════"
            log_manual "  $MANUAL_REQUIRED manual configuration(s) required"
            log_manual "  Review the warnings above for details"
            log_manual "═══════════════════════════════════════════════════════════"
            echo ""
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "✓ Rollback completed"
        log_warn "Restart services for changes to take effect:"
        log_warn "  sudo systemctl restart sshd"
    fi
}

main() {
    echo "========================================================================"
    echo "Enhanced Access Control Hardening Script v2.0"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    # Check for root privileges
    check_root_privileges
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        # SSH Server Configuration
        check_all_ssh_parameters
        
        # Privilege Escalation
        echo ""
        log_info "=== Privilege Escalation ==="
        check_sudo_installed
        check_sudo_pty
        check_sudo_logfile
        check_su_restricted
        
        # PAM Configuration
        echo ""
        log_info "=== PAM Configuration ==="
        check_pam_package "libpam-pwquality"
        check_pam_pwquality
        check_pam_faillock
        
        # Print summary
        print_summary
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back access control configurations..."
        echo ""
        
        # Rollback SSH
        check_all_ssh_parameters
        
        # Rollback Sudo
        check_sudo_installed
        check_sudo_pty
        check_sudo_logfile
        check_su_restricted
        
        # Rollback PAM
        check_pam_package "libpam-pwquality"
        check_pam_pwquality
        check_pam_faillock
        
        print_summary
        
    else
        echo ""
        log_error "Invalid mode: $MODE"
        echo ""
        echo "Usage: $0 {scan|fix|rollback}"
        echo ""
        echo "Modes:"
        echo "  scan     - Check system against access control hardening rules"
        echo "  fix      - Apply hardening fixes automatically where possible"
        echo "  rollback - Restore original configurations from backups"
        echo ""
        echo "Examples:"
        echo "  sudo $0 scan       # Check current configuration"
        echo "  sudo $0 fix        # Apply hardening"
        echo "  sudo $0 rollback   # Undo changes"
        echo ""
        exit 1
    fi
}

# Run main function
main
