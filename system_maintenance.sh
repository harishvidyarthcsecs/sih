#!/bin/bash

# System Hardening Script
# Modes: scan | fix | rollback
# Usage: sudo bash system_hardening.sh <mode>

MODE="${1:-scan}"
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# Helper function to log information
log_info() { if [ "$MODE" != "scan" ]; then echo -e "[INFO] $1"; fi; }
log_pass() { echo -e "[PASS] $1"; }
log_fail() { echo -e "[FAIL] $1"; }
log_warn() { if [ "$MODE" != "scan" ]; then echo -e "[WARN] $1"; fi; }

# Function to ensure we have sudo privileges for commands requiring elevated access
ensure_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script requires elevated privileges. Please re-run it with sudo."
        exit 1
    fi
}

# =========================
# 1. Check and Fix Permissions on Critical Files
# =========================
check_and_fix_permissions() {
    files=(
        "/etc/passwd"
        "/etc/passwd-"
        "/etc/group"
        "/etc/group-"
        "/etc/shadow"
        "/etc/shadow-"
        "/etc/gshadow"
        "/etc/gshadow-"
        "/etc/shells"
        "/etc/security/opasswd"
    )
    permissions_map=(
        "/etc/passwd=644"
        "/etc/passwd-=644"
        "/etc/group=644"
        "/etc/group-=644"
        "/etc/shadow=640"
        "/etc/shadow-=640"
        "/etc/gshadow=640"
        "/etc/gshadow-=640"
        "/etc/shells=644"
        "/etc/security/opasswd=600"
    )

    for file in "${files[@]}"; do
        ((TOTAL_CHECKS++))
        if [ -f "$file" ]; then
            expected_permission=$(echo "${permissions_map[@]}" | grep "$file" | cut -d'=' -f2)
            current_permission=$(stat -c %a "$file")

            if [ "$current_permission" == "$expected_permission" ]; then
                log_pass "$file has correct permissions"
                ((PASSED_CHECKS++))
            elif [ "$MODE" == "fix" ]; then
                ensure_sudo
                sudo chmod "$expected_permission" "$file"
                log_info "Fixed permissions for $file"
                ((FIXED_CHECKS++))
            else
                log_fail "$file has incorrect permissions"
                ((FAILED_CHECKS++))
            fi
        else
            log_warn "$file does not exist"
        fi
    done
}

# =========================
# 2. Ensure No World Writable Files
# =========================
check_world_writable_files() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        bad_files=$(find / -type f -perm -0002)
        if [ -n "$bad_files" ]; then
            log_fail "World writable files found: $bad_files"
            ((FAILED_CHECKS++))
        else
            log_pass "No world writable files found"
            ((PASSED_CHECKS++))
        fi
    elif [ "$MODE" == "fix" ]; then
        ensure_sudo
        sudo find / -type f -perm -0002 -exec chmod o-w {} \;
        sudo find / -type d -perm -0002 -exec chmod o-w {} \;
        log_info "Fixed world writable files and directories"
        ((FIXED_CHECKS++))
    fi
}

# =========================
# 3. Ensure No Files/Directories Without an Owner and Group
# =========================
check_no_owner_group() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        files_without_owner=$(find / -nouser -o -nogroup)
        if [ -n "$files_without_owner" ]; then
            log_fail "Files without owners or groups: $files_without_owner"
            ((FAILED_CHECKS++))
        else
            log_pass "No files without owners or groups"
            ((PASSED_CHECKS++))
        fi
    elif [ "$MODE" == "fix" ]; then
        ensure_sudo
        sudo find / -nouser -exec chown root:root {} \;
        sudo find / -nogroup -exec chown root:root {} \;
        log_info "Fixed files without owners/groups"
        ((FIXED_CHECKS++))
    fi
}

# =========================
# 4. Ensure SUID and SGID Files Are Reviewed (Manual)
# =========================
check_suid_sgid_files() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        suid_files=$(find / -type f -perm -4000)
        sgid_files=$(find / -type f -perm -2000)
        if [ -n "$suid_files" ]; then
            log_warn "SUID files found: $suid_files"
            ((FAILED_CHECKS++))
        else
            log_pass "No SUID files found"
            ((PASSED_CHECKS++))
        fi
        if [ -n "$sgid_files" ]; then
            log_warn "SGID files found: $sgid_files"
            ((FAILED_CHECKS++))
        else
            log_pass "No SGID files found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 5. Ensure All Groups in /etc/passwd Exist in /etc/group
# =========================
check_groups_exist() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        groups_in_passwd=$(awk -F: '{print $4}' /etc/passwd | sort -u)
        groups_in_group=$(awk -F: '{print $1}' /etc/group | sort -u)
        missing_groups=$(comm -23 <(echo "$groups_in_passwd") <(echo "$groups_in_group"))
        if [ -n "$missing_groups" ]; then
            log_fail "Groups in /etc/passwd not found in /etc/group: $missing_groups"
            ((FAILED_CHECKS++))
        else
            log_pass "All groups in /etc/passwd exist in /etc/group"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 6. Ensure Shadow Group is Empty
# =========================
check_shadow_group_empty() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        shadow_group_members=$(grep "^shadow:" /etc/group | cut -d: -f4)
        if [ -n "$shadow_group_members" ]; then
            log_fail "Shadow group is not empty: $shadow_group_members"
            ((FAILED_CHECKS++))
        else
            log_pass "Shadow group is empty"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 7. Ensure No Duplicate UIDs
# =========================
check_duplicate_uids() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
        if [ -n "$duplicate_uids" ]; then
            log_fail "Duplicate UIDs found: $duplicate_uids"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate UIDs found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 8. Ensure No Duplicate GIDs
# =========================
check_duplicate_gids() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
        if [ -n "$duplicate_gids" ]; then
            log_fail "Duplicate GIDs found: $duplicate_gids"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate GIDs found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 9. Ensure No Duplicate User Names
# =========================
check_duplicate_usernames() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_usernames=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
        if [ -n "$duplicate_usernames" ]; then
            log_fail "Duplicate usernames found: $duplicate_usernames"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate usernames found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 10. Ensure No Duplicate Group Names
# =========================
check_duplicate_group_names() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_group_names=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)
        if [ -n "$duplicate_group_names" ]; then
            log_fail "Duplicate group names found: $duplicate_group_names"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate group names found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 11. Ensure Local Interactive User Home Directories Are Configured
# =========================
check_local_interactive_user_home() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        users_without_home=$(awk -F: '{ if ($7 != "/sbin/nologin" && $7 != "/bin/false") print $1 }' /etc/passwd | while read user; do 
            if [ ! -d "/home/$user" ]; then 
                echo "$user"; 
            fi 
        done)
        if [ -n "$users_without_home" ]; then
            log_fail "Users without home directories: $users_without_home"
            ((FAILED_CHECKS++))
        else
            log_pass "All local interactive users have home directories"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 12. Ensure Local Interactive User Dot Files Access Is Configured
# =========================
check_local_interactive_user_dotfiles() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        users_dotfiles=$(awk -F: '{ if ($7 != "/sbin/nologin" && $7 != "/bin/false") print $1 }' /etc/passwd | while read user; do
            if [ -d "/home/$user" ]; then
                dotfiles=$(ls -A /home/$user | grep -E '^\..*')
                if [ -n "$dotfiles" ]; then
                    echo "$user:$dotfiles"
                fi
            fi
        done)
        if [ -n "$users_dotfiles" ]; then
            log_fail "Users with dot files in home directories: $users_dotfiles"
            ((FAILED_CHECKS++))
        else
            log_pass "No dot files in local interactive users' home directories"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 13. Ensure /etc/passwd Uses Shadowed Passwords
# =========================
check_shadowed_passwords() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        shadowed_passwords=$(grep -v '::' /etc/passwd | wc -l)
        if [ "$shadowed_passwords" -gt 0 ]; then
            log_fail "/etc/passwd contains accounts without shadowed passwords"
            ((FAILED_CHECKS++))
        else
            log_pass "/etc/passwd uses shadowed passwords"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 14. Ensure /etc/shadow Password Fields Are Not Empty
# =========================
check_shadow_password_fields() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        empty_passwords=$(awk -F: '$2 == "" { print $1 }' /etc/shadow)
        if [ -n "$empty_passwords" ]; then
            log_fail "Empty password fields in /etc/shadow: $empty_passwords"
            ((FAILED_CHECKS++))
        else
            log_pass "No empty password fields in /etc/shadow"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 15. Ensure No Duplicate User Names
# =========================
check_duplicate_usernames() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_usernames=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
        if [ -n "$duplicate_usernames" ]; then
            log_fail "Duplicate usernames found: $duplicate_usernames"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate usernames found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 16. Ensure No Duplicate Group Names Exist
# =========================
check_duplicate_group_names() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_group_names=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)
        if [ -n "$duplicate_group_names" ]; then
            log_fail "Duplicate group names found: $duplicate_group_names"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate group names found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 17. Ensure Local Interactive Users' Home Directories Are Properly Configured
# =========================
check_local_interactive_users_home() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        users_home=$(awk -F: '{ if ($7 != "/sbin/nologin" && $7 != "/bin/false") print $1 }' /etc/passwd | while read user; do 
            if [ ! -d "/home/$user" ]; then
                echo "$user"
            fi
        done)
        if [ -n "$users_home" ]; then
            log_fail "Local interactive users without home directories: $users_home"
            ((FAILED_CHECKS++))
        else
            log_pass "All local interactive users have home directories"
            ((PASSED_CHECKS++))
        fi
    fi
}
# =========================
# 18. Ensure No Duplicate UIDs or GIDs
# =========================
check_duplicate_uids_and_gids() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        duplicate_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
        duplicate_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
        if [ -n "$duplicate_uids" ] || [ -n "$duplicate_gids" ]; then
            log_fail "Duplicate UIDs or GIDs found"
            ((FAILED_CHECKS++))
        else
            log_pass "No duplicate UIDs or GIDs found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 19. Ensure No Unauthorized Groups Exist
# =========================
check_unauthorized_groups() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        unauthorized_groups=$(grep -E "^(root|adm|bin|sys|wheel)" /etc/group)
        if [ -n "$unauthorized_groups" ]; then
            log_fail "Unauthorized groups found: $unauthorized_groups"
            ((FAILED_CHECKS++))
        else
            log_pass "No unauthorized groups found"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 20. Ensure Groups Have Correct Permissions
# =========================
check_groups_permissions() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        incorrect_groups_permissions=$(find / -type d -name "group*" ! -perm 775)
        if [ -n "$incorrect_groups_permissions" ]; then
            log_fail "Groups with incorrect permissions found: $incorrect_groups_permissions"
            ((FAILED_CHECKS++))
        else
            log_pass "All groups have correct permissions"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 21. Ensure No Non-Root User Has Admin Privileges
# =========================
check_non_root_admin_privileges() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        non_root_admins=$(grep -E "^[^#].*sudo|wheel" /etc/group | grep -v "root")
        if [ -n "$non_root_admins" ]; then
            log_fail "Non-root users with admin privileges found: $non_root_admins"
            ((FAILED_CHECKS++))
        else
            log_pass "No non-root users with admin privileges"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# 22. Ensure Sudoers File is Configured Correctly
# =========================
check_sudoers_file() {
    ((TOTAL_CHECKS++))
    if [ "$MODE" == "scan" ]; then
        sudoers_config=$(cat /etc/sudoers | grep -v "#")
        if [ -n "$sudoers_config" ]; then
            log_fail "Sudoers file contains potentially insecure configurations: $sudoers_config"
            ((FAILED_CHECKS++))
        else
            log_pass "Sudoers file is configured correctly"
            ((PASSED_CHECKS++))
        fi
    fi
}

# =========================
# Print Summary
# =========================
print_summary() {
    echo -e "\n==============================="
    echo "Summary"
    echo "==============================="
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed: $FIXED_CHECKS"
    echo "==============================
# =========================
# Print Summary (continued)
# =========================
    echo -e "\n==============================="
    echo "Summary"
    echo "==============================="
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Fixed: $FIXED_CHECKS"
    echo "==============================="
    if [ "$FAILED_CHECKS" -gt 0 ]; then
        echo "[FAIL] Issues detected."
    else
        echo "[PASS] All checks passed."
    fi
}

# =========================
# Main Execution
# =========================
if [ "$MODE" != "scan" ] && [ "$MODE" != "fix" ] && [ "$MODE" != "rollback" ]; then
    echo "Usage: sudo bash $0 <mode>"
    echo "Mode should be one of: scan, fix, rollback"
    exit 1
fi

# Run checks and fixes based on mode
check_and_fix_permissions
check_world_writable_files
check_no_owner_group
check_suid_sgid_files
check_groups_exist
check_shadow_group_empty
check_duplicate_uids
check_duplicate_gids
check_duplicate_usernames
check_duplicate_group_names
check_local_interactive_user_home
check_local_interactive_user_dotfiles
check_shadowed_passwords
check_shadow_password_fields
check_local_interactive_users_home
check_duplicate_uids_and_gids
check_unauthorized_groups
check_groups_permissions
check_non_root_admin_privileges
check_sudoers_file

# Print summary
print_summary
