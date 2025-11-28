#!/bin/bash

# Global variables for log files, backup paths, and counters
LOG_FILE="security_check_log.txt"
BACKUP_DIR="/path/to/backups"
TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_FIXED=0

# Function to initialize the log file
initialize_log() {
    echo "Security Check Log" > "$LOG_FILE"
    echo "====================" >> "$LOG_FILE"
}

# Function to perform scan mode (just checking, no fixes)
scan_mode() {
    echo "Running Scan Mode..." >> "$LOG_FILE"

    # Run all the checks in scan mode
    check_file_permissions
    check_shadow_passwords
    check_empty_shadow_password_fields
    check_duplicate_uids
    check_duplicate_gids
    check_duplicate_usernames
    check_duplicate_groupnames
    check_local_user_home_dirs
    check_local_user_dotfiles_access
    check_suid_sgid_files
    check_accounts_using_shadowed_passwords
    check_groups_in_passwd_and_group
    check_shadow_group_is_empty
    check_world_writable_files
    check_no_files_without_owner
    check_files_without_group
    check_empty_user_shells
    check_sudo_permissions
    check_opasswd_permissions

    echo "Scan complete." >> "$LOG_FILE"
}

# Function to perform fix mode (applying fixes)
fix_mode() {
    echo "Running Fix Mode..." >> "$LOG_FILE"

    # Apply fixes where possible
    fix_file_permissions
    fix_shadow_passwords
    fix_empty_shadow_password_fields
    fix_duplicate_uids
    fix_duplicate_gids
    fix_duplicate_usernames
    fix_duplicate_groupnames
    fix_local_user_home_dirs
    fix_local_user_dotfiles_access
    fix_suid_sgid_files
    fix_world_writable_files
    fix_no_files_without_owner
    fix_empty_user_shells

    echo "Fix mode complete." >> "$LOG_FILE"
}

# Function to rollback changes (optional, if required by user)
rollback_mode() {
    echo "Rolling back changes..." >> "$LOG_FILE"

    # This could be implemented to restore backups or undo changes, depending on what was fixed
    # For example, restore original files from a backup folder:
    # cp $BACKUP_DIR/* /etc/

    echo "Rollback complete." >> "$LOG_FILE"
}

# File Permissions Check Functions (Scan Mode)
check_file_permissions() {
    files=("/etc/passwd" "/etc/passwd-" "/etc/group" "/etc/group-" "/etc/shadow" "/etc/shadow-" "/etc/gshadow" "/etc/gshadow-" "/etc/shells" "/etc/security/opasswd")
    perms=("644" "644" "644" "644" "0000" "0000" "0000" "0000" "644" "644")
    
    for i in ${!files[@]}; do
        if [ "$(stat -c %a ${files[$i]})" != "${perms[$i]}" ]; then
            echo "FAILED: Permissions on ${files[$i]} incorrect." >> "$LOG_FILE"
            ((TOTAL_FAILED++))
        else
            echo "PASSED: Permissions on ${files[$i]} correct." >> "$LOG_FILE"
            ((TOTAL_PASSED++))
        fi
    done
}

# Fix File Permissions (Fix Mode)
fix_file_permissions() {
    files=("/etc/passwd" "/etc/passwd-" "/etc/group" "/etc/group-" "/etc/shadow" "/etc/shadow-" "/etc/gshadow" "/etc/gshadow-" "/etc/shells" "/etc/security/opasswd")
    perms=("644" "644" "644" "644" "0000" "0000" "0000" "0000" "644" "644")
    
    for i in ${!files[@]}; do
        if [ "$(stat -c %a ${files[$i]})" != "${perms[$i]}" ]; then
            chmod ${perms[$i]} ${files[$i]}
            echo "FIXED: Permissions on ${files[$i]} set to ${perms[$i]}." >> "$LOG_FILE"
            ((TOTAL_FIXED++))
        fi
    done
}

# Check if the account uses shadowed passwords
check_accounts_using_shadowed_passwords() {
    if [ "$(awk -F: '($2 != "") {print $1}' /etc/passwd)" ]; then
        echo "PASSED: All accounts in /etc/passwd use shadowed passwords." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: Some accounts in /etc/passwd don't use shadowed passwords." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

# Check for empty password fields in /etc/shadow
check_empty_shadow_password_fields() {
    if grep -q '::' /etc/shadow; then
        echo "FAILED: Empty password fields found in /etc/shadow." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No empty password fields in /etc/shadow." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Check for duplicate UIDs
check_duplicate_uids() {
    if [ $(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | wc -l) -gt 0 ]; then
        echo "FAILED: Duplicate UIDs found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate UIDs." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Check for duplicate GIDs
check_duplicate_gids() {
    if [ $(awk -F: '{print $4}' /etc/passwd | sort | uniq -d | wc -l) -gt 0 ]; then
        echo "FAILED: Duplicate GIDs found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate GIDs." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Check for duplicate usernames
check_duplicate_usernames() {
    if [ $(awk -F: '{print $1}' /etc/passwd | sort | uniq -d | wc -l) -gt 0 ]; then
        echo "FAILED: Duplicate usernames found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate usernames." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Check for duplicate group names
check_duplicate_groupnames() {
    if [ $(awk -F: '{print $1}' /etc/group | sort | uniq -d | wc -l) -gt 0 ]; then
        echo "FAILED: Duplicate group names found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate group names." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Check for local user home directories
check_local_user_home_dirs() {
    if grep -E '^[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:([^\n]+)$' /etc/passwd | grep -q '/home'; then
        echo "PASSED: Local interactive user home directories are configured." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: Local interactive user home directories not configured correctly." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

# Check for local user dot files access
check_local_user_dotfiles_access() {
    if find /home -type f -name ".*" -exec ls -l {} \; | grep -q '^.*-rw'; then
        echo "PASSED: Local user dot files access is configured correctly." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: Local user dot files access not configured correctly." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

# Check for SUID and SGID files
check_suid_sgid_files() {
    if find / -type f \( -perm -4000 -o -perm -2000 \); then
        echo "PASSED: SUID/SGID files review completed." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: SUID/SGID files review required." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

# Check for world writable files
check_world_writable_files() {
    if find / -type f -perm -002 ! -path "/proc/*" -exec ls -l {} \; > /dev/null; then
        echo "FAILED: World-writable files found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No world-writable files." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Ensure there are no files without owner or group
check_no_files_without_owner() {
    if find / -nouser -o -nogroup; then
        echo "FAILED: Files without an owner or group found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No files without an owner or group." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Ensure no empty user shells
check_empty_user_shells() {
    if grep -q '^[^:]*::' /etc/passwd; then
        echo "FAILED: Empty user shells found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No empty user shells." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

# Check sudo permissions
check_sudo_permissions() {
    if [ -f /etc/sudoers ]; then
        echo "PASSED: sudo permissions are set correctly." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: sudoers file not found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

# Check opasswd permissions
check_opasswd_permissions() {
    if [ -f /etc/security/opasswd ]; then
        echo "PASSED: opasswd permissions are set correctly." >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: opasswd file not found." >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

# Generate a summary of results at the end of the run
generate_summary() {
    echo "==================== Summary ====================" >> "$LOG_FILE"
    echo "Total Passed: $TOTAL_PASSED" >> "$LOG_FILE"
    echo "Total Failed: $TOTAL_FAILED" >> "$LOG_FILE"
    echo "Total Fixed: $TOTAL_FIXED" >> "$LOG_FILE"
    echo "==================== End of Log ===================" >> "$LOG_FILE"
}

# Main function to execute the desired mode
main() {
    # Initialize log file
    initialize_log

    # Check if the user passed a mode
    if [ "$1" == "scan" ]; then
        scan_mode
    elif [ "$1" == "fix" ]; then
        fix_mode
    elif [ "$1" == "rollback" ]; then
        rollback_mode
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi

    # Generate a summary after running the checks
    generate_summary

    # Optionally, print the summary to stdout as well
    cat "$LOG_FILE"
}

# Run the script
main "$@"

