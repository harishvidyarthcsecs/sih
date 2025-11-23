#!/bin/bash
# Package Management Hardening Script
# Covers: Bootloader, Process Hardening, Warning Banners

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Package Management"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

initialize_db() {
    if [ ! -f "$DB_PATH" ]; then
        sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS configurations (
            topic TEXT,
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT,
            original_value TEXT,
            current_value TEXT,
            status TEXT
        );"
    fi
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"
    
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('''
    INSERT OR REPLACE INTO configurations 
    (topic, rule_id, rule_name, original_value, current_value, status)
    VALUES (?, ?, ?, ?, ?, 'stored')
''', ('$TOPIC', '$rule_id', '$rule_name', '$original_value', '$current_value'))
conn.commit()
conn.close()
"
}

get_original_config() {
    local rule_id="$1"
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
"
}

# ============================================================================
# 2.1 Configure Bootloader
# ============================================================================
get_grub_cfg() {
    local grub_paths=(
        "/boot/grub/grub.cfg"
        "/boot/grub2/grub.cfg"
        "/boot/efi/EFI/kali/grub.cfg"
        "/boot/efi/EFI/ubuntu/grub.cfg"
        "/boot/efi/EFI/fedora/grub.cfg"
    )

    for path in "${grub_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    # If no GRUB configuration is found, attempt to regenerate it
    log_warn "No GRUB configuration file found. Attempting to regenerate GRUB config..."
    create_grub_config || return 1

    # Try to find the GRUB config again after regeneration
    for path in "${grub_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    log_error "Failed to find or regenerate GRUB configuration file."
    return 1
}


create_grub_config() {
    log_warn "No GRUB configuration file found. Attempting to regenerate GRUB config..."

    # Check for presence of update-grub or grub-mkconfig tools
    if command -v update-grub &>/dev/null; then
        update-grub || return 1
    elif command -v grub-mkconfig &>/dev/null; then
        grub-mkconfig -o /boot/grub/grub.cfg || return 1
    else
        log_error "Neither update-grub nor grub-mkconfig found. Attempting to install missing GRUB tools."
        
        # Try installing GRUB tools based on package manager
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y grub2-common || return 1
        elif command -v yum &>/dev/null; then
            sudo yum install -y grub2 || return 1
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y grub2 || return 1
        else
            log_error "Unable to install GRUB tools automatically. Please install GRUB manually."
            return 1
        fi
        
        # Reattempt to regenerate the GRUB config
        if command -v update-grub &>/dev/null; then
            update-grub || return 1
        elif command -v grub-mkconfig &>/dev/null; then
            grub-mkconfig -o /boot/grub/grub.cfg || return 1
        else
            log_error "Failed to regenerate GRUB config. Please check your GRUB installation."
            return 1
        fi
    fi
    
    log_info "GRUB configuration regenerated successfully."
    return 0
}

log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1"
}

regenerate_grub_config() {
    log_info "Checking for GRUB configuration file..."
    if ! grub-mkconfig -o /boot/grub/grub.cfg && ! update-grub; then
        log_error "Failed to regenerate GRUB configuration. Ensure GRUB is properly installed."
        return 1
    fi
    log_info "GRUB configuration regenerated successfully."
    return 0
}

generate_grub_password_hash() {
    log_info "Generating GRUB password hash..."
    local password="mysecurepassword"  # Replace this with a secure password generation method
    password_hash=$(echo -n "$password" | grub-mkpasswd-pbkdf2 2>/dev/null | grep 'grub.pbkdf2.sha512' | awk '{print $NF}')
    if [ -z "$password_hash" ]; then
        log_error "Failed to generate GRUB password hash."
        return 1
    fi
    log_info "Generated GRUB password hash successfully."
    return 0
}

apply_permissions_to_grub() {
    log_info "Setting permissions for GRUB configuration files..."
    local grub_cfg="/boot/grub/grub.cfg"
    if [ ! -f "$grub_cfg" ]; then
        log_error "GRUB configuration file $grub_cfg not found."
        return 1
    fi
    chown root:root "$grub_cfg"
    chmod 400 "$grub_cfg"
    log_info "Permissions set for GRUB configuration file."
    return 0
}

fix_grub_security() {
    log_info "Starting GRUB security hardening..."

    regenerate_grub_config || return 1
    generate_grub_password_hash || return 1
    apply_permissions_to_grub || return 1

    log_info "GRUB security hardening completed successfully."
    return 0
}

set_grub_password() {
    log_info "Attempting to set GRUB password using grub2-setpassword..."

    # Check if grub2-setpassword is available
    if ! command -v grub2-setpassword >/dev/null 2>&1; then
        log_error "grub2-setpassword is not available. Falling back to manual password hash generation."
        return 1
    fi

    # Run grub2-setpassword to set the password
    echo "Enter GRUB password:"
    grub2-setpassword
    if [ $? -eq 0 ]; then
        log_info "GRUB password set successfully using grub2-setpassword."
    else
        log_error "Failed to set GRUB password using grub2-setpassword."
        return 1
    fi

    # Update GRUB
    log_info "Running update-grub to apply changes..."
    update-grub || return 1

    log_info "GRUB password has been set and changes applied."
    return 0
}


check_bootloader_password() {
    local rule_id="PKG-BOOT-PASSWORD"
    local rule_name="Ensure bootloader password is set"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    
    if [ "$MODE" = "scan" ]; then
        if [ -n "$grub_cfg" ]; then
            if grep -q "^password_pbkdf2" "$grub_cfg" 2>/dev/null; then
                log_pass "Bootloader password is configured in $grub_cfg"
                ((PASSED_CHECKS++))
            else
                log_error "Bootloader password is not set in $grub_cfg"
                ((FAILED_CHECKS++))
            fi
        else
            log_warn "No GRUB configuration found on this system"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if [ -z "$grub_cfg" ]; then
            create_grub_config || return 1
            grub_cfg=$(get_grub_cfg)
        fi

        set_grub_password || return 1
    fi
}

check_bootloader_config_permissions() {
    local rule_id="PKG-BOOT-PERMS"
    local rule_name="Ensure access to bootloader config is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    
    if [ "$MODE" = "scan" ]; then
        if [ -n "$grub_cfg" ]; then
            local perms owner group
            perms=$(stat -c %a "$grub_cfg")
            owner=$(stat -c %U "$grub_cfg")
            group=$(stat -c %G "$grub_cfg")
            
            if [ "$perms" = "400" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                log_pass "Bootloader config permissions are correct (400 root:root)"
                ((PASSED_CHECKS++))
            else
                log_error "Bootloader config permissions incorrect: $perms $owner:$group"
                ((FAILED_CHECKS++))
            fi
        else
            log_warn "No GRUB configuration found on this system"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if [ -n "$grub_cfg" ]; then
            chown root:root "$grub_cfg"
            chmod 400 "$grub_cfg"
            log_info "Set bootloader config permissions to 400 root:root"
            ((FIXED_CHECKS++))
        fi
    fi
}

# ============================================================================
# 2.2 Additional Process Hardening
# ============================================================================
check_aslr() {
    local rule_id="PKG-PROC-ASLR"
    local rule_name="Ensure address space layout randomization is enabled"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local aslr_value=$(sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}')
        
        if [ "$aslr_value" = "2" ]; then
            log_pass "ASLR is enabled (kernel.randomize_va_space = 2)"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "ASLR is not properly configured: $aslr_value"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
        save_config "$rule_id" "$rule_name" "$current"
        
        # Set runtime
        sysctl -w kernel.randomize_va_space=2
        
        # Set persistent
        cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        
        if ! grep -q "kernel.randomize_va_space" /etc/sysctl.conf; then
            echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
        else
            sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
        fi
        
        log_info "ASLR enabled"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sysctl -w kernel.randomize_va_space="$original"
            sed -i "s/^kernel.randomize_va_space.*/kernel.randomize_va_space = $original/" /etc/sysctl.conf
            log_info "Restored ASLR setting"
        fi
    fi
}

check_ptrace_scope() {
    local rule_id="PKG-PROC-PTRACE"
    local rule_name="Ensure ptrace_scope is restricted"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local ptrace_value=$(sysctl kernel.yama.ptrace_scope 2>/dev/null | awk '{print $3}')
        
        if [ "$ptrace_value" = "1" ] || [ "$ptrace_value" = "2" ]; then
            log_pass "ptrace_scope is restricted: $ptrace_value"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "ptrace_scope is not restricted: $ptrace_value"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
    	        local current=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
        save_config "$rule_id" "$rule_name" "$current"
        
        sysctl -w kernel.yama.ptrace_scope=1
        
        if ! grep -q "kernel.yama.ptrace_scope" /etc/sysctl.conf; then
            echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
        else
            sed -i 's/^kernel.yama.ptrace_scope.*/kernel.yama.ptrace_scope = 1/' /etc/sysctl.conf
        fi
        
        log_info "ptrace_scope restricted"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sysctl -w kernel.yama.ptrace_scope="$original"
            log_info "Restored ptrace_scope setting"
        fi
    fi
}

check_core_dumps() {
    local rule_id="PKG-PROC-COREDUMP"
    local rule_name="Ensure core dumps are restricted"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local hard_limit=$(grep "hard.*core" /etc/security/limits.conf 2>/dev/null | grep -v "^#")
        local suid_dumpable=$(sysctl fs.suid_dumpable 2>/dev/null | awk '{print $3}')
        
        if [ -n "$hard_limit" ] && [ "$suid_dumpable" = "0" ]; then
            log_pass "Core dumps are properly restricted"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Core dumps are not properly restricted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/security/limits.conf "$BACKUP_DIR/limits.conf.$(date +%Y%m%d_%H%M%S)"
        save_config "$rule_id" "$rule_name" "not_restricted"
        
        # Add limits
        if ! grep -q "* hard core" /etc/security/limits.conf; then
            echo "* hard core 0" >> /etc/security/limits.conf
        fi
        
        # Set sysctl
        sysctl -w fs.suid_dumpable=0
        if ! grep -q "fs.suid_dumpable" /etc/sysctl.conf; then
            echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
        fi
        
        log_info "Core dumps restricted"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/limits.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/security/limits.conf
            log_info "Restored limits configuration"
        fi
    fi
}

check_prelink() {
    local rule_id="PKG-PROC-PRELINK"
    local rule_name="Ensure prelink is not installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*prelink"; then
            log_error "prelink is installed"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "prelink is not installed"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii.*prelink"; then
            save_config "$rule_id" "$rule_name" "installed"
            apt-get remove -y prelink 2>/dev/null
            log_info "Removed prelink"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "installed" ]; then
            apt-get install -y prelink 2>/dev/null
            log_info "Reinstalled prelink"
        fi
    fi
}

check_apport() {
    local rule_id="PKG-PROC-APPORT"
    local rule_name="Ensure Automatic Error Reporting is not enabled"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled apport 2>/dev/null | grep -q "enabled"; then
            log_error "Apport (automatic error reporting) is enabled"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "Automatic error reporting is disabled"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if systemctl is-enabled apport 2>/dev/null | grep -q "enabled"; then
            save_config "$rule_id" "$rule_name" "enabled"
            systemctl disable apport
            systemctl stop apport
            log_info "Disabled apport"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "enabled" ]; then
            systemctl enable apport
            systemctl start apport
            log_info "Re-enabled apport"
        fi
    fi
}

# ============================================================================
# 2.3 Command Line Warning Banners
# ============================================================================
check_issue_banner() {
    local rule_id="PKG-BANNER-ISSUE"
    local rule_name="Ensure local login warning banner is configured properly"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/issue ] && [ -s /etc/issue ]; then
            if grep -E -i "\\\\v|\\\\r|\\\\m|\\\\s" /etc/issue >/dev/null; then
                log_error "/etc/issue contains OS information"
                ((FAILED_CHECKS++))
                return 1
            else
                log_pass "Login warning banner is configured"
                ((PASSED_CHECKS++))
                return 0
            fi
        else
            log_error "/etc/issue is empty or missing"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/issue "$BACKUP_DIR/issue.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        save_config "$rule_id" "$rule_name" "$(cat /etc/issue 2>/dev/null)"
        
        cat > /etc/issue << 'EOF'
***************************************************************************
                            NOTICE TO USERS
                            
This computer system is for authorized use only. Users have no explicit
or implicit expectation of privacy. Any or all uses of this system and
all files on this system may be intercepted, monitored, recorded, copied,
audited, inspected, and disclosed to authorized site, government, and law
enforcement personnel, as well as authorized officials of other agencies.
By using this system, the user consents to such interception, monitoring,
recording, copying, auditing, inspection, and disclosure at the discretion
of authorized site or government personnel.
***************************************************************************
EOF
        
        log_info "Configured /etc/issue banner"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/issue.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/issue
            log_info "Restored /etc/issue"
        fi
    fi
}

check_issue_net_banner() {
    local rule_id="PKG-BANNER-ISSUE-NET"
    local rule_name="Ensure remote login warning banner is configured properly"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/issue.net ] && [ -s /etc/issue.net ]; then
            if grep -E -i "\\\\v|\\\\r|\\\\m|\\\\s" /etc/issue.net >/dev/null; then
                log_error "/etc/issue.net contains OS information"
                ((FAILED_CHECKS++))
                return 1
            else
                log_pass "Remote login warning banner is configured"
                ((PASSED_CHECKS++))
                return 0
            fi
        else
            log_error "/etc/issue.net is empty or missing"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
                cp /etc/issue.net "$BACKUP_DIR/issue.net.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        save_config "$rule_id" "$rule_name" "$(cat /etc/issue.net 2>/dev/null)"
        
        cat > /etc/issue.net << 'EOF'
***************************************************************************
                            NOTICE TO REMOTE USERS
                            
This system is for authorized use only. Unauthorized access will be
prosecuted to the fullest extent of the law. All activities on this system
are monitored and recorded.
***************************************************************************
EOF
        
        log_info "Configured /etc/issue.net banner"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/issue.net.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/issue.net
            log_info "Restored /etc/issue.net"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================
initialize_db

fix_grub_security
check_bootloader_password
check_bootloader_config_permissions
check_aslr
check_ptrace_scope
check_core_dumps
check_prelink
check_apport
check_issue_banner
check_issue_net_banner

# Summary
echo ""
echo "========================================================================"
echo "Summary"
echo "========================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "========================================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some checks failed. See above for details.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}"
fi

