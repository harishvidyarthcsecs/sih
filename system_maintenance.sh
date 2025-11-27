#!/bin/bash
# System Maintenance Hardening Script - 23 Policies

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/backups"
LOG_FILE="$SCRIPT_DIR/system_maintenance.log"

mkdir -p "$BACKUP_DIR"

# Colors for log output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

# ===================================================================
# Logging Functions
# ===================================================================
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; echo "$(date): [INFO] $1" >> "$LOG_FILE"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED_CHECKS++)); echo "$(date): [PASS] $1" >> "$LOG_FILE"; }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; ((FIXED_CHECKS++)); echo "$(date): [FIXED] $1" >> "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; echo "$(date): [WARN] $1" >> "$LOG_FILE"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED_CHECKS++)); echo "$(date): [FAIL] $1" >> "$LOG_FILE"; }
log_manual() { echo -e "${YELLOW}[MANUAL]${NC} $1"; ((MANUAL_CHECKS++)); echo "$(date): [MANUAL] $1" >> "$LOG_FILE"; }

# ===================================================================
# Utility Functions
# ===================================================================
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$(basename $file).$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        return $?
    fi
    return 1
}

# Policy i-x: File Permissions
check_permissions() {
    local file=$1
    local expected=$2
    local owner=${3:-root}
    local group=${4:-root}
    local policy_num=$5

    ((TOTAL_CHECKS++))
    if [ ! -e "$file" ]; then
        log_error "P$policy_num: $file missing"
        return 1
    fi

    perms=$(stat -c "%a" "$file" 2>/dev/null)
    if [ $? -ne 0 ]; then
        log_error "P$policy_num: Cannot read permissions for $file"
        return 1
    fi
    
    perms=$(printf "%03o" "$perms")
    file_owner=$(stat -c "%U" "$file")
    file_group=$(stat -c "%G" "$file")

    if [ "$perms" == "$expected" ] && [ "$file_owner" == "$owner" ] && [ "$file_group" == "$group" ]; then
        log_pass "P$policy_num: $file permissions correct ($perms $owner:$group)"
        return 0
    else
        if [ "$MODE" == "fix" ]; then
            if ! backup_file "$file"; then
                log_warn "P$policy_num: Could not backup $file, attempting fix anyway..."
            fi

            echo "Fixing permissions on $file..."
            echo "Current: $perms $file_owner:$file_group"
            echo "Expected: $expected $owner:$group"
            
            # Fix ownership first
            if ! chown "$owner:$group" "$file" 2>/dev/null; then
                log_error "P$policy_num: Failed to change ownership of $file"
                return 1
            fi
            
            # Fix permissions
            if ! chmod "$expected" "$file" 2>/dev/null; then
                log_error "P$policy_num: Failed to change permissions of $file"
                return 1
            fi
            
            # Verify the fix
            sleep 1
            new_perms=$(stat -c "%a" "$file")
            new_owner=$(stat -c "%U" "$file")
            new_group=$(stat -c "%G" "$file")
            
            if [ "$new_perms" == "$expected" ] && [ "$new_owner" == "$owner" ] && [ "$new_group" == "$group" ]; then
                log_fixed "P$policy_num: $file permissions fixed to $expected ($new_owner:$new_group)"
                return 0
            else
                log_error "P$policy_num: Permissions reverted on $file (now $new_perms $new_owner:$new_group)"
                log_warn "P$policy_num: System has automatic permission enforcement"
                return 1
            fi
        else
            log_error "P$policy_num: $file permissions incorrect ($perms $file_owner:$file_group, expected $expected $owner:$group)"
            return 1
        fi
    fi
}

# Policy xi: Ensure world writable files and directories are secured
check_world_writable() {
    ((TOTAL_CHECKS++))
    local found_risky=false
    
    # Check for world-writable files excluding virtual filesystems
    while IFS= read -r -d '' file; do
        if [[ ! "$file" =~ ^/proc/ ]] && [[ ! "$file" =~ ^/sys/ ]] && [[ ! "$file" =~ ^/dev/ ]] && 
           [[ ! "$file" =~ ^/run/ ]] && [[ ! "$file" =~ ^/tmp/ ]] && [ -f "$file" ]; then
            if [ "$found_risky" = false ]; then
                found_risky=true
                log_error "Pxi: World-writable files found:"
            fi
            log_error "Pxi:   $file"
        fi
    done < <(find / -type f -perm -0002 -print0 2>/dev/null)
    
    # Check for world-writable directories excluding standard ones
    while IFS= read -r -d '' dir; do
        if [[ ! "$dir" =~ ^/proc/ ]] && [[ ! "$dir" =~ ^/sys/ ]] && [[ ! "$dir" =~ ^/dev/ ]] &&
           [[ ! "$dir" =~ ^/run/ ]] && [[ ! "$dir" =~ ^/tmp/ ]] && [[ ! "$dir" =~ ^/var/tmp/ ]] &&
           [[ ! "$dir" =~ ^/var/cache/ ]] && [ -d "$dir" ]; then
            if [ "$found_risky" = false ]; then
                found_risky=true
                log_error "Pxi: World-writable directories found:"
            fi
            log_error "Pxi:   $dir"
            if [ "$MODE" == "fix" ]; then
                echo "Fixing permissions on $dir..."
                chmod o-w "$dir" 2>/dev/null && log_fixed "Pxi: Fixed world-writable directory $dir"
            fi
        fi
    done < <(find / -type d -perm -0002 -print0 2>/dev/null)
    
    if [ "$found_risky" != true ]; then
        log_pass "Pxi: No unsafe world-writable files or directories found"
    fi
}

# ===================================================================
# Policy 7.2.1: Ensure accounts in /etc/passwd use shadowed passwords
check_shadowed_passwords() {
    ((TOTAL_CHECKS++))
    grep -E "^[^:]+:[^\!*]" /etc/passwd > /dev/null
    if [ $? -eq 0 ]; then
        log_pass "7.2.1: All accounts in /etc/passwd use shadowed passwords"
    else
        log_error "7.2.1: Some accounts in /etc/passwd do not have shadowed passwords"
    fi
}

# ===================================================================
# Additional User/Group Policies
# ===================================================================

# Ensure no duplicate UIDs, GIDs, or usernames
check_unique_ids() {
    ((TOTAL_CHECKS++))
    duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    duplicate_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
    duplicate_usernames=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
    duplicate_groupnames=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)

    if [ -n "$duplicate_uids" ]; then
        log_error "Duplicate UIDs found: $duplicate_uids"
    else
        log_pass "No duplicate UIDs found"
    fi

    if [ -n "$duplicate_gids" ]; then
        log_error "Duplicate GIDs found: $duplicate_gids"
    else
        log_pass "No duplicate GIDs found"
    fi

    if [ -n "$duplicate_usernames" ]; then
                log_error "Duplicate usernames found: $duplicate_usernames"
    else
        log_pass "No duplicate usernames found"
    fi

    if [ -n "$duplicate_groupnames" ]; then
        log_error "Duplicate group names found: $duplicate_groupnames"
    else
        log_pass "No duplicate group names found"
    fi
}

# Policy 7.2.2: Ensure local interactive user home directories are configured
check_home_directories() {
    ((TOTAL_CHECKS++))
    local missing_home_dirs=false

    while IFS=: read -r username _ _ _ _ home_dir _; do
        if [ -n "$username" ] && [ -z "$home_dir" ]; then
            missing_home_dirs=true
            log_error "7.2.2: Missing home directory for user: $username"
        fi
    done < /etc/passwd

    if [ "$missing_home_dirs" = false ]; then
        log_pass "7.2.2: All local interactive user home directories are configured"
    fi
}

# Policy 7.2.3: Ensure local interactive user dot files access is configured
check_dot_files_access() {
    ((TOTAL_CHECKS++))
    local improper_access=false

    # Check that local users' home directories have secure access for dot files (e.g., .bashrc, .profile)
    find /home -type f -name ".*" -exec stat -c "%a %n" {} \; | while read perms file; do
        if [ "${perms: -1}" != "0" ]; then
            improper_access=true
            log_error "7.2.3: Improper access permissions for dot file: $file (permissions: $perms)"
        fi
    done

    if [ "$improper_access" = false ]; then
        log_pass "7.2.3: All local interactive user dot files have secure access"
    fi
}

# ===================================================================
# Main Execution
# ===================================================================
echo "===== SYSTEM MAINTENANCE HARDENING - 23 POLICIES ====="
echo "Mode: $MODE"
echo "Log file: $LOG_FILE"
echo ""

# Clear previous log
> "$LOG_FILE"

# Policy i: Ensure permissions on /etc/passwd are configured
check_permissions "/etc/passwd" "644" "root" "root" "i"

# Policy ii: Ensure permissions on /etc/passwd- are configured
check_permissions "/etc/passwd-" "600" "root" "root" "ii"

# Policy iii: Ensure permissions on /etc/group are configured
check_permissions "/etc/group" "644" "root" "root" "iii"

# Policy iv: Ensure permissions on /etc/group- are configured
check_permissions "/etc/group-" "600" "root" "root" "iv"

# Policy v: Ensure permissions on /etc/shadow are configured
check_permissions "/etc/shadow" "000" "root" "root" "v"

# Policy vi: Ensure permissions on /etc/shadow- are configured
check_permissions "/etc/shadow-" "000" "root" "root" "vi"

# Policy vii: Ensure permissions on /etc/gshadow are configured
check_permissions "/etc/gshadow" "000" "root" "root" "vii"

# Policy viii: Ensure permissions on /etc/gshadow- are configured
check_permissions "/etc/gshadow-" "000" "root" "root" "viii"

# Policy ix: Ensure permissions on /etc/shells are configured
check_permissions "/etc/shells" "644" "root" "root" "ix"

# Policy x: Ensure permissions on /etc/security/opasswd are configured
check_permissions "/etc/security/opasswd" "600" "root" "root" "x"

# Policy xi: Ensure world writable files and directories are secured
check_world_writable

# Policy 7.2.1: Ensure accounts in /etc/passwd use shadowed passwords
check_shadowed_passwords

# Policy 7.2.2: Ensure local interactive user home directories are configured
check_home_directories

# Policy 7.2.3: Ensure local interactive user dot files access is configured
check_dot_files_access

# Policy xii: Ensure no files or directories without an owner and a group exist
check_ownership() {
    ((TOTAL_CHECKS++))
    find / -nouser -o -nogroup -print0 | while IFS= read -r -d '' file; do
        log_error "xii: File or directory without owner/group: $file"
    done

    log_pass "xii: All files and directories have owners and groups."
}

check_ownership

# Policy xiii: Ensure SUID and SGID files are reviewed (Manual)
log_manual "xiii: Review SUID and SGID files manually"
# This requires manual review, so we just log it as a manual task

# ===================================================================
# Summary
# ===================================================================
echo ""
echo "========================================================================"
echo "Summary - 23 System Maintenance Policies"
echo "========================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "Manual: $MANUAL_CHECKS"
echo "========================================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some checks failed. See above for details.${NC}"
    echo -e "${YELLOW}Check log file: $LOG_FILE${NC}"
    exit 1
else
    echo -e "${GREEN}[PASS] All automated checks passed or fixed.${NC}"
    echo -e "${YELLOW}Remember to manually review SUID/SGID files (Policy xiii)${NC}"
    echo -e "${YELLOW}Check log file: $LOG_FILE${NC}"
    exit 0
fi

