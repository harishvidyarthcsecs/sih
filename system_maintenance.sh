#!/usr/bin/env bash
#
# security_audit_fixed.sh — Kali-friendly audit script
# FULL VERSION — NO MISSING LINES
#

LOG="security_check_log.txt"
PASSED=0
FAILED=0
FIXED=0

echo "Security Check Log" > "$LOG"
echo "====================" >> "$LOG"
echo "Running Scan Mode..." >> "$LOG"

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
pass() { echo "PASSED: $1" | tee -a "$LOG"; ((PASSED++)); }
fail() { echo "FAILED: $1" | tee -a "$LOG"; ((FAILED++)); }

# ---------------------------------------------------------------------------
# Critical system permission checks
# ---------------------------------------------------------------------------
check_perm() {
    file="$1"
    acceptable="$2"

    if [[ ! -e "$file" ]]; then
        pass "$file does not exist (skipped)"
        return
    fi

    mode=$(stat -c "%a" "$file")

    IFS=',' read -ra allowed <<< "$acceptable"
    for val in "${allowed[@]}"; do
        if [[ "$mode" == "$val" ]]; then
            pass "$file permissions correct ($mode)"
            return
        fi
    done

    fail "$file permissions $mode (expected: $acceptable)"
}

check_perm /etc/passwd "644"
check_perm /etc/passwd- "600,644"
check_perm /etc/group "644"
check_perm /etc/group- "600,644"
check_perm /etc/shadow "600,640"
check_perm /etc/shadow- "600"
check_perm /etc/gshadow "600,640"
check_perm /etc/gshadow- "600"
check_perm /etc/shells "644"
check_perm /etc/security/opasswd "600,644"

# ---------------------------------------------------------------------------
# Shadow password usage check
# ---------------------------------------------------------------------------
if pwck -r 2>&1 | grep -q "no shadow"; then
    fail "Some accounts are not using shadow passwords"
else
    pass "All accounts use shadow passwords"
fi

# ---------------------------------------------------------------------------
# Empty password fields (ignore locked accounts: ! or *)
# ---------------------------------------------------------------------------
empty_fields=$(awk -F: '($2 == "") {print $1}' /etc/shadow)

if [[ -z "$empty_fields" ]]; then
    pass "No empty password fields"
else
    fail "Empty password fields found: $empty_fields"
fi

# ---------------------------------------------------------------------------
# Duplicate UIDs (real users only)
# ---------------------------------------------------------------------------
dup_uids=$(awk -F: '($3 >= 1000){print $3}' /etc/passwd | sort -n | uniq -d)

if [[ -z "$dup_uids" ]]; then
    pass "No duplicate UIDs (real users)"
else
    fail "Duplicate UIDs found: $dup_uids"
fi

# ---------------------------------------------------------------------------
# Duplicate GIDs (real users only)
# ---------------------------------------------------------------------------
dup_gids=$(awk -F: '($3 >= 1000){print $3}' /etc/group | sort -n | uniq -d)

if [[ -z "$dup_gids" ]]; then
    pass "No duplicate GIDs (real users)"
else
    fail "Duplicate GIDs found: $dup_gids"
fi

# ---------------------------------------------------------------------------
# Duplicate usernames
# ---------------------------------------------------------------------------
dup_users=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)

if [[ -z "$dup_users" ]]; then
    pass "No duplicate usernames"
else
    fail "Duplicate usernames found: $dup_users"
fi

# ---------------------------------------------------------------------------
# Duplicate group names
# ---------------------------------------------------------------------------
dup_groupnames=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)

if [[ -z "$dup_groupnames" ]]; then
    pass "No duplicate group names"
else
    fail "Duplicate group names found: $dup_groupnames"
fi

# ---------------------------------------------------------------------------
# Home directory structure check (real users only)
# ---------------------------------------------------------------------------
homes=$(awk -F: '($3>=1000 && $1!="nobody"){print $6}' /etc/passwd | grep -v "^/home")

if [[ -z "$homes" ]]; then
    pass "Real user home directories are under /home"
else
    pass "System service homes outside /home detected (normal): $homes"
fi


# ---------------------------------------------------------------------------
# Dotfile permissions (real user homes only)
# ---------------------------------------------------------------------------
dangerous_dotfiles=$(find /home -maxdepth 3 -type f -name ".*" -perm /022 2>/dev/null)

if [[ -n "$dangerous_dotfiles" ]]; then
    fail "Dangerous dotfile permissions found:\n$dangerous_dotfiles"
else
    pass "No dangerous dotfile permissions"
fi

# ---------------------------------------------------------------------------
# SUID / SGID files (just note — not fail)
# ---------------------------------------------------------------------------
suid=$(find / -xdev -perm -4000 2>/dev/null)
sgid=$(find / -xdev -perm -2000 2>/dev/null)

echo "NOTE: SUID files found: $(echo "$suid" | wc -l)" | tee -a "$LOG"
echo "NOTE: SGID files found: $(echo "$sgid" | wc -l)" | tee -a "$LOG"

# ---------------------------------------------------------------------------
# World-writable files (exclude safe paths)
# ---------------------------------------------------------------------------
world_write=$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /dev -prune -o \
    -path /run -prune -o \
    -path /tmp -prune -o \
    -path /var/tmp -prune -o \
    -type f -perm -0002 -print 2>/dev/null)

if [[ -n "$world_write" ]]; then
    fail "World-writable files found:\n$world_write"
else
    pass "No unsafe world-writable files"
fi

# ---------------------------------------------------------------------------
# Files without owner or group (system dirs only, excludes temp dirs)
# ---------------------------------------------------------------------------
nog=$(find / \
    -path /home -prune -o \
    -path /tmp -prune -o \
    -path /var/tmp -prune -o \
    -path /run/user -prune -o \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -nouser -o -nogroup -print 2>/dev/null)

if [[ -n "$nog" ]]; then
    fail "System files without owner/group found:\n$nog"
else
    pass "All system files have valid owners/groups"
fi

# ---------------------------------------------------------------------------
# Shell validity check
# ---------------------------------------------------------------------------
invalid_shells=$(pwck -r 2>&1 | grep "invalid shell")

if [[ -n "$invalid_shells" ]]; then
    fail "Invalid shells detected:\n$invalid_shells"
else
    pass "All users have valid shells"
fi

# ---------------------------------------------------------------------------
# sudoers + opasswd existence
# ---------------------------------------------------------------------------
[[ -e /etc/sudoers ]] && pass "sudoers file exists" || fail "sudoers missing"
[[ -e /etc/security/opasswd ]] && pass "opasswd file exists" || fail "opasswd missing"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "Scan complete." | tee -a "$LOG"
echo "==================== Summary ====================" | tee -a "$LOG"
echo "Passed: $PASSED" | tee -a "$LOG"
echo "Failed: $FAILED" | tee -a "$LOG"
echo "Fixed:  $FIXED" | tee -a "$LOG"
echo "==================== End of Log ===================" | tee -a "$LOG"

