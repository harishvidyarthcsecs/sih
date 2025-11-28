#!/bin/bash

LOG_FILE="security_check_log.txt"
TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_FIXED=0

# Correct Debian/Kali expected permissions
FILES=(
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

PERMS=(
    "644"
    "600"
    "644"
    "600"
    "640"
    "600"
    "640"
    "600"
    "644"
    "600"
)

initialize_log() {
    echo "Security Check Log" > "$LOG_FILE"
    echo "====================" >> "$LOG_FILE"
}

scan_mode() {
    echo "Running Scan Mode..." >> "$LOG_FILE"

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
    check_world_writable_files
    check_no_files_without_owner
    check_empty_user_shells
    check_sudo_permissions
    check_opasswd_permissions

    echo "Scan complete." >> "$LOG_FILE"
}

fix_mode() {
    echo "Running Fix Mode..." >> "$LOG_FILE"
    fix_file_permissions
    echo "Fix mode complete." >> "$LOG_FILE"
}

# --------------------------------------------
# CHECK FUNCTIONS
# --------------------------------------------

check_file_permissions() {
    for i in "${!FILES[@]}"; do
        [ ! -e "${FILES[$i]}" ] && continue
        ACTUAL=$(stat -c %a "${FILES[$i]}")
        EXPECTED="${PERMS[$i]}"

        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "FAILED: ${FILES[$i]} permissions $ACTUAL (expected $EXPECTED)" >> "$LOG_FILE"
            ((TOTAL_FAILED++))
        else
            echo "PASSED: ${FILES[$i]} permissions correct ($EXPECTED)" >> "$LOG_FILE"
            ((TOTAL_PASSED++))
        fi
    done
}

fix_file_permissions() {
    for i in "${!FILES[@]}"; do
        [ ! -e "${FILES[$i]}" ] && continue
        ACTUAL=$(stat -c %a "${FILES[$i]}")
        EXPECTED="${PERMS[$i]}"

        if [ "$ACTUAL" != "$EXPECTED" ]; then
            chmod "$EXPECTED" "${FILES[$i]}"
            echo "FIXED: Set ${FILES[$i]} to $EXPECTED" >> "$LOG_FILE"
            ((TOTAL_FIXED++))
        fi
    done
}

check_shadow_passwords() {
    if awk -F: '($2 != "x") {print $1}' /etc/passwd | grep -q .; then
        echo "FAILED: Some accounts store passwords in /etc/passwd" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: All accounts use shadow passwords" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_empty_shadow_password_fields() {
    if awk -F: '($2 == "" || $2 == "!") {print}' /etc/shadow | grep -q .; then
        echo "FAILED: Empty or locked password fields found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No empty password fields in /etc/shadow" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_duplicate_uids() {
    if awk -F: '{print $3}' /etc/passwd | sort | uniq -d | grep -q .; then
        echo "FAILED: Duplicate UIDs found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate UIDs" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_duplicate_gids() {
    if awk -F: '{print $4}' /etc/group | sort | uniq -d | grep -q .; then
        echo "FAILED: Duplicate GIDs found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate GIDs" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_duplicate_usernames() {
    if awk -F: '{print $1}' /etc/passwd | sort | uniq -d | grep -q .; then
        echo "FAILED: Duplicate usernames found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate usernames" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_duplicate_groupnames() {
    if awk -F: '{print $1}' /etc/group | sort | uniq -d | grep -q .; then
        echo "FAILED: Duplicate group names" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No duplicate group names" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_local_user_home_dirs() {
    if awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd | grep -q '^/home/'; then
        echo "PASSED: Local user home directories are under /home" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: Some user home directories are incorrect" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

check_local_user_dotfiles_access() {
    if find /home -type f -name ".*" -perm /077 | grep -q .; then
        echo "FAILED: Dangerous dotfile permissions found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: Dotfile permissions look safe" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_suid_sgid_files() {
    DANGEROUS=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    echo "NOTE: SUID/SGID files found (expected on Linux)" >> "$LOG_FILE"
    ((TOTAL_PASSED++))
}

check_accounts_using_shadowed_passwords() {
    BAD=$(awk -F: '($2 != "x") {print $1}' /etc/passwd)
    if [ -n "$BAD" ]; then
        echo "FAILED: Some accounts do not use shadow passwords" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: All accounts use shadow passwords" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_world_writable_files() {
    if find / -type f -perm -002 ! -path "/proc/*" 2>/dev/null | grep -q .; then
        echo "FAILED: World-writable files found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No world-writable files" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_no_files_without_owner() {
    if find / \( -nouser -o -nogroup \) 2>/dev/null | grep -q .; then
        echo "FAILED: Files without owner/group found" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: No orphaned files" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_empty_user_shells() {
    if awk -F: '($7 == "" || $7 == "/bin/false") {print}' /etc/passwd | grep -q .; then
        echo "FAILED: User shell missing or invalid" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    else
        echo "PASSED: All users have valid shells" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

check_sudo_permissions() {
    if [ -f /etc/sudoers ]; then
        echo "PASSED: sudoers file exists" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "FAILED: sudoers file missing" >> "$LOG_FILE"
        ((TOTAL_FAILED++))
    fi
}

check_opasswd_permissions() {
    if [ -f /etc/security/opasswd ]; then
        echo "PASSED: opasswd file exists" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    else
        echo "NOTE: opasswd does not exist (normal on many systems)" >> "$LOG_FILE"
        ((TOTAL_PASSED++))
    fi
}

generate_summary() {
    echo "==================== Summary ====================" >> "$LOG_FILE"
    echo "Passed: $TOTAL_PASSED" >> "$LOG_FILE"
    echo "Failed: $TOTAL_FAILED" >> "$LOG_FILE"
    echo "Fixed:  $TOTAL_FIXED" >> "$LOG_FILE"
    echo "==================== End of Log ===================" >> "$LOG_FILE"
}

main() {
    initialize_log
    case "$1" in
        scan) scan_mode ;;
        fix) fix_mode ;;
        *) echo "Usage: $0 {scan|fix}" ; exit 1 ;;
    esac
    generate_summary
    cat "$LOG_FILE"
}

main "$@"

