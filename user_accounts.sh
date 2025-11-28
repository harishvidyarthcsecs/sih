#!/bin/bash
# Comprehensive User Accounts and Environment Hardening Script
# Covers: Shadow Password Suite, Root Account, System Accounts, User Environment

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/user_accounts"
TOPIC="User Accounts"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

save_config() {
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('''
    INSERT OR REPLACE INTO configurations 
    (topic, rule_id, rule_name, original_value, current_value, status)
    VALUES (?, ?, ?, ?, ?, 'stored')
''', ('$TOPIC', '$1', '''$2''', '''$3''', '''${4:-$3}'''))
conn.commit()
conn.close()
"
}

get_original_config() {
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$1'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
"
}

# ============================================================================
# Shadow Password Suite Parameters
# ============================================================================

check_login_defs_param() {
    local param="$1"
    local expected_value="$2"
    local rule_id="USR-LOGINDEFS-$(echo $param | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $param is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/login.defs ]; then
            local current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
            
            if [ "$current" = "$expected_value" ] || [ "$current" -le "$expected_value" ] 2>/dev/null; then
                log_pass "$param is configured correctly: $current"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "$param = $current (expected: $expected_value)"
                ((FAILED_CHECKS++))
                return 1
            fi
        else
            log_error "/etc/login.defs not found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/login.defs ]; then
            local current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
            save_config "$rule_id" "$rule_name" "$current"
            
            cp /etc/login.defs "$BACKUP_DIR/login.defs.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^$param" /etc/login.defs; then
                sed -i "s/^$param.*/$param\t$expected_value/" /etc/login.defs
            else
                echo "$param\t$expected_value" >> /etc/login.defs
            fi
            
            log_info "Set $param = $expected_value"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/login.defs.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/login.defs
            log_info "Restored login.defs from backup"
        fi
    fi
}

check_password_hashing() {
    local rule_id="USR-PASS-HASH"
    local rule_name="Ensure strong password hashing algorithm is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        
        if [ "$encrypt_method" = "SHA512" ] || [ "$encrypt_method" = "yescrypt" ]; then
            log_pass "Strong password hashing configured: $encrypt_method"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Weak password hashing: $encrypt_method"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        save_config "$rule_id" "$rule_name" "$current"
        
        cp /etc/login.defs "$BACKUP_DIR/login.defs.hash.$(date +%Y%m%d_%H%M%S)"
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        log_info "Set password hashing to SHA512"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD $original/" /etc/login.defs
            log_info "Restored password hashing algorithm to: $original"
        fi
    fi
}

check_inactive_password_lock() {
    local rule_id="USR-INACTIVE-LOCK"
    local rule_name="Ensure inactive password lock is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local inactive=$(useradd -D | grep INACTIVE | cut -d= -f2)
        
        if [ "$inactive" -le 30 ] && [ "$inactive" -gt 0 ] 2>/dev/null; then
            log_pass "Inactive password lock configured: $inactive days"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Inactive password lock not configured properly: $inactive"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(useradd -D | grep INACTIVE | cut -d= -f2)
        save_config "$rule_id" "$rule_name" "$current"
        
        useradd -D -f 30
        log_info "Set inactive password lock to 30 days"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            useradd -D -f "$original"
            log_info "Restored inactive password lock to: $original days"
        fi
    fi
}

check_password_change_dates() {
    local rule_id="USR-PASS-LASTCHANGE"
    local rule_name="Ensure all users last password change date is in the past"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local invalid_dates=""
        local current_date=$(date +%s)
        
        while IFS=: read -r username password lastchange rest; do
            if [[ "$username" != "#"* ]] && [ -n "$lastchange" ] && [ "$lastchange" != "0" ]; then
                # Convert days since epoch to seconds
                local change_date=$((lastchange * 86400))
                if [ "$change_date" -gt "$current_date" ]; then
                    invalid_dates="${invalid_dates}${username} "
                fi
            fi
        done < /etc/shadow
        
        if [ -z "$invalid_dates" ]; then
            log_pass "All password change dates are valid"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Users with future password change dates: $invalid_dates"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local users_fixed=""
        local current_days=$(($(date +%s) / 86400))
        
        while IFS=: read -r username password lastchange rest; do
            if [[ "$username" != "#"* ]] && [ -n "$lastchange" ] && [ "$lastchange" != "0" ]; then
                if [ "$lastchange" -gt "$current_days" ]; then
                    chage -d 0 "$username"
                    users_fixed="${users_fixed}${username} "
                fi
            fi
        done < /etc/shadow
        
        if [ -n "$users_fixed" ]; then
            save_config "$rule_id" "$rule_name" "$users_fixed"
            log_info "Reset password change dates for: $users_fixed"
            ((FIXED_CHECKS++))
        fi
    fi
}

# ============================================================================
# Root and System Accounts
# ============================================================================

check_root_uid_zero() {
    local rule_id="USR-ROOT-UID-ZERO"
    local rule_name="Ensure root is the only UID 0 account"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local uid_zero_accounts=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
        
        if [ "$uid_zero_accounts" = "root" ]; then
            log_pass "Only root has UID 0"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Multiple UID 0 accounts found: $uid_zero_accounts"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local other_uid_zero=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -n "$other_uid_zero" ]; then
            save_config "$rule_id" "$rule_name" "$other_uid_zero"
            log_warn "Found non-root UID 0 accounts: $other_uid_zero"
            log_warn "MANUAL INTERVENTION REQUIRED - Review and modify these accounts"
            log_warn "Consider using: usermod -u <new_uid> <username>"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual review required for UID 0 accounts"
    fi
}

check_root_gid_zero() {
    local rule_id="USR-ROOT-GID-ZERO"
    local rule_name="Ensure root is the only GID 0 account"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local gid_zero_accounts=$(awk -F: '($4 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -z "$gid_zero_accounts" ]; then
            log_pass "Only root has GID 0"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Non-root accounts with GID 0: $gid_zero_accounts"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local gid_zero=$(awk -F: '($4 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -n "$gid_zero" ]; then
            save_config "$rule_id" "$rule_name" "$gid_zero"
            log_warn "MANUAL INTERVENTION REQUIRED for accounts with GID 0: $gid_zero"
            log_warn "Consider using: usermod -g <new_gid> <username>"
        fi
    fi
}

check_group_root_gid_zero() {
    local rule_id="USR-GROUP-ROOT-GID-ZERO"
    local rule_name="Ensure group root is the only GID 0 group"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local gid_zero_groups=$(awk -F: '($3 == 0) { print $1 }' /etc/group)
        
        if [ "$gid_zero_groups" = "root" ]; then
            log_pass "Only root group has GID 0"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Multiple GID 0 groups found: $gid_zero_groups"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local other_gid_zero=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/group)
        
        if [ -n "$other_gid_zero" ]; then
            save_config "$rule_id" "$rule_name" "$other_gid_zero"
            log_warn "Found non-root GID 0 groups: $other_gid_zero"
            log_warn "MANUAL INTERVENTION REQUIRED - Review and modify these groups"
        fi
    fi
}

check_root_access_controlled() {
    local rule_id="USR-ROOT-ACCESS"
    local rule_name="Ensure root account access is controlled"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local issues=0
        
        # Check if root can login via SSH
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
            log_error "Root SSH login is enabled"
            ((issues++))
        fi
        
        # Check if root has a password set
        if grep "^root:" /etc/shadow | cut -d: -f2 | grep -q "^!"; then
            log_info "Root password is locked (good)"
        else
            log_warn "Root password is set (consider locking and using sudo)"
            ((issues++))
        fi
        
        if [ $issues -eq 0 ]; then
            log_pass "Root access is properly controlled"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Root access control issues found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "configured"
        
        # Disable root SSH login
        if [ -f /etc/ssh/sshd_config ]; then
            cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)"
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            log_info "Disabled root SSH login"
        fi
        
        log_warn "Consider locking root password with: passwd -l root"
        log_warn "Ensure you have sudo access before locking root!"
        ((FIXED_CHECKS++))
    fi
}

check_root_path() {
    local rule_id="USR-ROOT-PATH"
    local rule_name="Ensure root path integrity"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local path_issues=0
        
        # Check for empty directories in PATH
        if echo "$PATH" | grep -q "::"; then
            log_error "Empty directory in root PATH"
            ((path_issues++))
        fi
        
        # Check for trailing :
        if echo "$PATH" | grep -q ":$"; then
            log_error "Trailing : in root PATH"
            ((path_issues++))
        fi
        
        # Check for . in PATH
        if echo "$PATH" | grep -q "\."; then
            log_error "Current directory (.) in root PATH"
            ((path_issues++))
        fi
        
        # Check PATH directories for proper permissions
        IFS=':' read -ra PATHS <<< "$PATH"
        for dir in "${PATHS[@]}"; do
            if [ -d "$dir" ]; then
                local perms=$(stat -c %a "$dir" 2>/dev/null)
                local owner=$(stat -c %U "$dir" 2>/dev/null)
                
                if [ "$owner" != "root" ]; then
                    log_error "PATH directory $dir not owned by root (owner: $owner)"
                    ((path_issues++))
                fi
                
                # Check if group or others have write permission
                if [ "${perms:1:1}" -gt 5 ] || [ "${perms:2:1}" -gt 5 ]; then
                    log_error "PATH directory $dir has excessive permissions: $perms"
                    ((path_issues++))
                fi
            fi
        done
        
        if [ $path_issues -eq 0 ]; then
            log_pass "Root PATH integrity maintained"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Root PATH integrity issues found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "$PATH"
        log_warn "MANUAL REVIEW of root PATH required"
        log_info "Edit /root/.bashrc and /root/.profile to fix PATH"
        log_info "Remove: empty directories (::), trailing colons, and current directory (.)"
        log_info "Ensure all PATH directories are owned by root with secure permissions"
    fi
}

check_root_umask() {
    local rule_id="USR-ROOT-UMASK"
    local rule_name="Ensure root user umask is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local root_umask_files="/root/.bashrc /root/.bash_profile /root/.profile"
        local proper_umask=0
        
        for file in $root_umask_files; do
            if [ -f "$file" ]; then
                if grep -q "^umask 0[02]7" "$file"; then
                    proper_umask=1
                    break
                fi
            fi
        done
        
        if [ $proper_umask -eq 1 ]; then
            log_pass "Root umask is properly configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Root umask not properly configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        for file in /root/.bashrc /root/.bash_profile; do
            if [ -f "$file" ]; then
                cp "$file" "$BACKUP_DIR/$(basename $file).$(date +%Y%m%d_%H%M%S)"
                
                if grep -q "^umask" "$file"; then
                    sed -i 's/^umask.*/umask 027/' "$file"
                else
                    echo "umask 027" >> "$file"
                fi
            fi
        done
        
        log_info "Set root umask to 027"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        for file in .bashrc .bash_profile; do
            local backup=$(ls -t "$BACKUP_DIR"/$file.* 2>/dev/null | head -1)
            if [ -n "$backup" ]; then
                cp "$backup" "/root/$file"
                log_info "Restored /root/$file"
            fi
        done
    fi
}

check_system_accounts_nologin() {
    local rule_id="USR-SYSTEM-NOLOGIN"
    local rule_name="Ensure system accounts do not have a valid login shell"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local system_with_shell=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1":"$7}' /etc/passwd)
        
        if [ -z "$system_with_shell" ]; then
            log_pass "System accounts have no valid login shell"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "System accounts with login shell found:"
            echo "$system_with_shell"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local system_accounts=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1}' /etc/passwd)
        
        if [ -n "$system_accounts" ]; then
            cp /etc/passwd "$BACKUP_DIR/passwd.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "$system_accounts"
            
            for account in $system_accounts; do
                usermod -s /usr/sbin/nologin "$account" 2>/dev/null || \
                usermod -s /sbin/nologin "$account" 2>/dev/null
                log_info "Set $account shell to nologin"
            done
            
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/passwd.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/passwd
            log_info "Restored /etc/passwd from backup"
        fi
    fi
}

check_accounts_nologin_locked() {
    local rule_id="USR-NOLOGIN-LOCKED"
    local rule_name="Ensure accounts without a valid login shell are locked"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local unlocked_nologin=""
        
        while IFS=: read -r username password uid gid comment home shell; do
            if [[ "$shell" =~ (nologin|false)$ ]]; then
                # Check if password is locked (starts with ! or *)
                local shadow_pass=$(grep "^${username}:" /etc/shadow | cut -d: -f2)
                if [[ ! "$shadow_pass" =~ ^[!*] ]] && [ -n "$shadow_pass" ]; then
                    unlocked_nologin="${unlocked_nologin}${username} "
                fi
            fi
        done < /etc/passwd
        
        if [ -z "$unlocked_nologin" ]; then
            log_pass "All nologin accounts are properly locked"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Unlocked accounts with nologin shell: $unlocked_nologin"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local accounts_locked=""
        
        while IFS=: read -r username password uid gid comment home shell; do
            if [[ "$shell" =~ (nologin|false)$ ]]; then
                local shadow_pass=$(grep "^${username}:" /etc/shadow | cut -d: -f2)
                if [[ ! "$shadow_pass" =~ ^[!*] ]] && [ -n "$shadow_pass" ]; then
                    passwd -l "$username" 2>/dev/null
                    accounts_locked="${accounts_locked}${username} "
                fi
            fi
        done < /etc/passwd
        
        if [ -n "$accounts_locked" ]; then
            save_config "$rule_id" "$rule_name" "$accounts_locked"
            log_info "Locked accounts: $accounts_locked"
            ((FIXED_CHECKS++))
        fi
    fi
}

# ============================================================================
# User Default Environment
# ============================================================================

check_nologin_not_in_shells() {
    local rule_id="USR-NOLOGIN-SHELLS"
    local rule_name="Ensure nologin is not listed in /etc/shells"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "nologin" /etc/shells 2>/dev/null; then
            log_error "nologin is listed in /etc/shells"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "nologin is not in /etc/shells"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if grep -q "nologin" /etc/shells; then
            cp /etc/shells "$BACKUP_DIR/shells.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "present"
            
            sed -i '/nologin/d' /etc/shells
            log_info "Removed nologin from /etc/shells"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/shells.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/shells
            log_info "Restored /etc/shells from backup"
        fi
    fi
}

check_shell_timeout() {
    local rule_id="USR-SHELL-TIMEOUT"
    local rule_name="Ensure default user shell timeout is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local timeout_set=0
        
        for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
            if [ -f "$file" ]; then
                if grep -q "^TMOUT=" "$file" 2>/dev/null || grep -q "^readonly TMOUT" "$file" 2>/dev/null; then
                    timeout_set=1
                    break
                fi
            fi
        done
        
        if [ $timeout_set -eq 1 ]; then
            log_pass "Shell timeout is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Shell timeout is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        cat > /etc/profile.d/tmout.sh << 'EOF'
# Set shell timeout to 15 minutes (900 seconds)
TMOUT=900
readonly TMOUT
export TMOUT
EOF
        
        chmod 644 /etc/profile.d/tmout.sh
        log_info "Configured shell timeout to 900 seconds (15 minutes)"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        if [ -f /etc/profile.d/tmout.sh ]; then
            rm -f /etc/profile.d/tmout.sh
            log_info "Removed shell timeout configuration"
        fi
    fi
}

check_default_user_umask() {
    local rule_id="USR-DEFAULT-UMASK"
    local rule_name="Ensure default user umask is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local umask_found=0
        local correct_umask=0
        
        for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
            if [ -f "$file" ]; then
                if grep -q "^umask" "$file" 2>/dev/null; then
                    umask_found=1
                    local umask_val=$(grep "^umask" "$file" | awk '{print $2}' | head -1)
                    
                    # Check if umask is 027 or 077 (both are acceptable)
                    if [ "$umask_val" = "027" ] || [ "$umask_val" = "077" ]; then
                        correct_umask=1
                        break
                    fi
                fi
            fi
        done
        
        if [ $correct_umask -eq 1 ]; then
            log_pass "Default user umask is properly configured"
            ((PASSED_CHECKS++))
            return 0
        elif [ $umask_found -eq 1 ]; then
            log_error "Default user umask is set but not secure"
            ((FAILED_CHECKS++))
            return 1
        else
            log_error "Default user umask is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        # Create umask configuration file
        cat > /etc/profile.d/umask.sh << 'EOF'
# Set default umask for users
umask 027
EOF
        
        chmod 644 /etc/profile.d/umask.sh
        
        # Also update /etc/login.defs if present
        if [ -f /etc/login.defs ]; then
            cp /etc/login.defs "$BACKUP_DIR/login.defs.umask.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^UMASK" /etc/login.defs; then
                sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
            else
                echo "UMASK		027" >> /etc/login.defs
            fi
        fi
        
        # Update /etc/bash.bashrc if it exists
        if [ -f /etc/bash.bashrc ]; then
            cp /etc/bash.bashrc "$BACKUP_DIR/bash.bashrc.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^umask" /etc/bash.bashrc; then
                sed -i 's/^umask.*/umask 027/' /etc/bash.bashrc
            else
                echo "umask 027" >> /etc/bash.bashrc
            fi
        fi
        
        # Update /etc/profile
        if [ -f /etc/profile ]; then
            cp /etc/profile "$BACKUP_DIR/profile.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^umask" /etc/profile; then
                sed -i 's/^umask.*/umask 027/' /etc/profile
            else
                echo "umask 027" >> /etc/profile
            fi
        fi
        
        log_info "Configured default user umask to 027"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        # Remove umask configuration file
        if [ -f /etc/profile.d/umask.sh ]; then
            rm -f /etc/profile.d/umask.sh
            log_info "Removed umask configuration file"
        fi
        
        # Restore backups
        for file in login.defs.umask bash.bashrc profile; do
            local backup=$(ls -t "$BACKUP_DIR"/${file}.* 2>/dev/null | head -1)
            if [ -n "$backup" ]; then
                local target_file=$(echo $file | sed 's/\.umask//')
                case $target_file in
                    login.defs)
                        cp "$backup" /etc/login.defs
                        ;;
                    bash.bashrc)
                        cp "$backup" /etc/bash.bashrc
                        ;;
                    profile)
                        cp "$backup" /etc/profile
                        ;;
                esac
                log_info "Restored $target_file from backup"
            fi
        done
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "=========================================="
    echo "User Accounts and Environment Hardening"
    echo "Mode: $MODE"
    echo "=========================================="
    echo ""
    
    # Shadow Password Suite Parameters
    echo "=== Shadow Password Suite Parameters ==="
    check_login_defs_param "PASS_MAX_DAYS" "365"
    check_login_defs_param "PASS_MIN_DAYS" "1"
    check_login_defs_param "PASS_WARN_AGE" "7"
    check_password_hashing
    check_inactive_password_lock
    check_password_change_dates
    
    # Root and System Accounts
    echo ""
    echo "=== Root and System Accounts ==="
    check_root_uid_zero
    check_root_gid_zero
    check_group_root_gid_zero
    check_root_access_controlled
    check_root_path
    check_root_umask
    check_system_accounts_nologin
    check_accounts_nologin_locked
    
    # User Default Environment
    echo ""
    echo "=== User Default Environment ==="
    check_nologin_not_in_shells
    check_shell_timeout
    check_default_user_umask
    
    # Summary
    echo ""
    echo "=========================================="
    echo "Summary"
    echo "=========================================="
    echo "Total Checks: $TOTAL_CHECKS"
    
    if [ "$MODE" = "scan" ]; then
        echo "Passed: $PASSED_CHECKS"
        echo "Failed: $FAILED_CHECKS"
        
        if [ $FAILED_CHECKS -eq 0 ]; then
            echo ""
            log_pass "All user account hardening checks passed!"
        else
            echo ""
            log_warn "Some checks failed. Run with 'fix' mode to remediate."
            log_warn "Usage: $0 fix"
        fi
    elif [ "$MODE" = "fix" ]; then
        echo "Fixed: $FIXED_CHECKS"
        log_info "Remediation complete. Run scan mode to verify."
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rollback complete."
    fi
    
    echo "=========================================="
}

# Run main function
main

exit 0
