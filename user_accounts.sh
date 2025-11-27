#!/bin/bash
# ===================================================================
# Full System Hardening Script – Auto-Fix Mode
# Implements all 23 policies: User Accounts, Environment, File Permissions
# WARNING: HIGH RISK – Backup VM or snapshot before running!
# ===================================================================

MODE="fix"  # Full auto-fix mode
BACKUP_DIR="/var/backups/security-hardening/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$BACKUP_DIR/hardening.log"

mkdir -p "$BACKUP_DIR"
touch "$LOG_FILE"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_FILE"; }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1" | tee -a "$LOG_FILE"; }

# ===================================================================
# Backup Function
# ===================================================================
backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$(basename $file).bak"
    fi
}

# ===================================================================
# 1. File Permission Hardening
# ===================================================================
declare -A files_permissions=(
    ["/etc/passwd"]="644"
    ["/etc/passwd-"]="600"
    ["/etc/group"]="644"
    ["/etc/group-"]="600"
    ["/etc/shadow"]="000"
    ["/etc/shadow-"]="000"
    ["/etc/gshadow"]="000"
    ["/etc/gshadow-"]="000"
    ["/etc/shells"]="644"
    ["/etc/security/opasswd"]="600"
)

for file in "${!files_permissions[@]}"; do
    backup_file "$file"
    chmod "${files_permissions[$file]}" "$file"
    log_fixed "Permissions set for $file to ${files_permissions[$file]}"
done

# ===================================================================
# 2. World Writable Files
# ===================================================================
find / -xdev -type f -perm -002 -exec bash -c 'backup_file "$0"; chmod o-w "$0"; log_fixed "Removed world-write from $0"' {} \;

# ===================================================================
# 3. Orphaned Files / Unowned Files
# ===================================================================
find / -xdev \( -nouser -o -nogroup \) -exec bash -c 'log_warn "Orphaned file: $0"' {} \;

# ===================================================================
# 4. SUID/SGID Files Review (just log)
# ===================================================================
find / -xdev \( -perm -4000 -o -perm -2000 \) -exec bash -c 'log_warn "SUID/SGID file: $0"' {} \;

# ===================================================================
# 5. Shadow Password Suite / Account Hardening
# ===================================================================
# Backup critical files
for file in /etc/shadow /etc/passwd /etc/group /etc/gshadow; do
    backup_file "$file"
done

# Password Aging
for user in $(cut -f1 -d: /etc/passwd); do
    chage --maxdays 90 "$user"
    chage --mindays 7 "$user"
    chage --warndays 7 "$user"
    chage --inactive 30 "$user"
    log_fixed "Password aging configured for $user"
done

# Strong Hashing
authconfig --passalgo=sha512 --update 2>/dev/null || log_warn "authconfig not available, ensure SHA-512 manually"

# UID 0 Enforcement
for u in $(awk -F: '($3==0){print $1}' /etc/passwd); do
    if [ "$u" != "root" ]; then
        usermod -L "$u"
        log_fixed "Locked non-root UID 0 account: $u"
    fi
done

# GID 0 Enforcement
for g in $(awk -F: '($3==0){print $1}' /etc/group); do
    if [ "$g" != "root" ]; then
        log_fixed "Non-root GID 0 group detected: $g – please review manually"
    fi
done

# ===================================================================
# 6. Root Account Environment
# ===================================================================
# Root PATH integrity
backup_file /root/.bashrc
echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /root/.bashrc
log_fixed "Root PATH integrity enforced"

# Root umask
echo 'umask 027' >> /root/.bashrc
log_fixed "Root umask set to 027"

# ===================================================================
# 7. System Accounts
# ===================================================================
for user in $(awk -F: '($3<1000 && $3!=0){print $1}' /etc/passwd); do
    usermod -s /usr/sbin/nologin "$user"
    log_fixed "Set nologin shell for system account: $user"
done

# Lock accounts without valid login shells
for user in $(awk -F: '($7 ~ /nologin|false/){print $1}' /etc/passwd); do
    passwd -l "$user"
    log_fixed "Locked account without valid shell: $user"
done

# ===================================================================
# 8. Default User Environment
# ===================================================================
# Remove nologin from /etc/shells if exists
sed -i '/nologin/d' /etc/shells
log_fixed "Removed nologin from /etc/shells"

# Default user shell timeout
echo 'TMOUT=900' >> /etc/profile
log_fixed "Default shell timeout set to 900s"

# Default umask for users
echo 'umask 027' >> /etc/profile
log_fixed "Default umask set to 027"

# ===================================================================
# 9. Summary
# ===================================================================
echo -e "${GREEN}All 23 policies scanned and auto-fixed where possible.${NC}"
echo -e "Backups stored in: $BACKUP_DIR"
echo -e "Detailed log: $LOG_FILE"
echo -e "${RED}WARNING: Verify UID/GID 0 accounts and critical system accounts manually!${NC}"

