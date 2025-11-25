#!/bin/bash
# Services and Job Schedulers Hardening Script
# Covers: Server Services, Client Services, Time Synchronization, Cron
# Mode: scan | fix | rollback
# Automatically installs missing utilities if required

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/services_hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Services"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# =========================
# DB Functions
# =========================
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

save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"
    
    python3 - <<EOF
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
EOF
}

get_original_config() {
    local rule_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
EOF
}

# =========================
# Logging
# =========================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

# =========================
# Utilities Installer
# =========================
install_if_missing() {
    local cmd="$1"
    local pkg="$2"
    if ! command -v "$cmd" &>/dev/null; then
        log_warn "$cmd not found. Installing $pkg..."
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    fi
}

# =========================
# 1. Server Services
# =========================
check_service_disabled() {
    local rule_id="$1"
    local rule_name="$2"
    local service="$3"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled "$service" 2>/dev/null | grep -q "disabled"; then
            log_pass "$service is disabled"
            ((PASSED_CHECKS++))
        else
            log_error "$service is enabled"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "$(systemctl is-enabled $service 2>/dev/null)"
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
        systemctl mask "$service" 2>/dev/null
        log_info "$service stopped, disabled, and masked"
        ((FIXED_CHECKS++))
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "enabled" ]; then
            systemctl unmask "$service"
            systemctl enable "$service"
            systemctl start "$service"
        fi
    fi
}

SERVER_SERVICES=(autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd dovecot nfs-kernel-server nis cups rpcbind rsync smbd snmpd tftpd-hpa squid apache2 xinetd gdm postfix)
SERVER_RULES=( \
"Ensure autofs services are not in use" \
"Ensure avahi daemon services are not in use" \
"Ensure dhcp server services are not in use" \
"Ensure dns server services are not in use" \
"Ensure dnsmasq services are not in use" \
"Ensure ftp server services are not in use" \
"Ensure ldap server services are not in use" \
"Ensure message access server services are not in use" \
"Ensure network file system services are not in use" \
"Ensure nis server services are not in use" \
"Ensure print server services are not in use" \
"Ensure rpcbind services are not in use" \
"Ensure rsync services are not in use" \
"Ensure samba file server services are not in use" \
"Ensure snmp services are not in use" \
"Ensure tftp server services are not in use" \
"Ensure web proxy server services are not in use" \
"Ensure web server services are not in use" \
"Ensure xinetd services are not in use" \
"Ensure X window server services are not in use" \
"Ensure mail transfer agent is configured for local-only mode" \
)

# =========================
# 2. Client Services
# =========================
CLIENT_PACKAGES=(nis rsh-client talk telnet ldap-utils ftp)
CLIENT_RULES=( \
"Ensure NIS Client is not installed" \
"Ensure rsh client is not installed" \
"Ensure talk client is not installed" \
"Ensure telnet client is not installed" \
"Ensure ldap client is not installed" \
"Ensure ftp client is not installed" \
)

check_package_removed() {
    local rule_id="$1"
    local rule_name="$2"
    local pkg="$3"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*$pkg"; then
            log_error "$pkg is installed"
            ((FAILED_CHECKS++))
        else
            log_pass "$pkg is not installed"
            ((PASSED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii.*$pkg"; then
            save_config "$rule_id" "$rule_name" "installed"
            apt-get remove -y "$pkg"
            log_info "$pkg removed"
            ((FIXED_CHECKS++))
        fi
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "installed" ]; then
            apt-get install -y "$pkg"
            log_info "$pkg reinstalled"
        fi
    fi
}

# =========================
# 3. Time Synchronization
# =========================
check_timesyncd() {
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: systemd-timesyncd"

    install_if_missing timedatectl systemd-timesyncd

    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled systemd-timesyncd &>/dev/null && systemctl is-active systemd-timesyncd &>/dev/null; then
            log_pass "systemd-timesyncd is enabled and running"
            ((PASSED_CHECKS++))
        else
            log_error "systemd-timesyncd not properly configured"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "TIMESYNCD" "systemd-timesyncd" "$(systemctl is-enabled systemd-timesyncd 2>/dev/null)"
        systemctl enable systemd-timesyncd
        systemctl start systemd-timesyncd
        log_info "systemd-timesyncd enabled and started"
        ((FIXED_CHECKS++))
    fi
}

check_chrony() {
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: chrony"

    install_if_missing chronyd chrony

    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled chrony &>/dev/null && systemctl is-active chrony &>/dev/null; then
            log_pass "chrony is enabled and running"
            ((PASSED_CHECKS++))
        else
            log_error "chrony not properly configured"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "CHRONY" "chrony" "$(systemctl is-enabled chrony 2>/dev/null)"
        systemctl enable chrony
        systemctl start chrony
        log_info "chrony enabled and started"
        ((FIXED_CHECKS++))
    fi
}

check_single_timesyncd() {
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: Only one time synchronization daemon is running"
    local active_count=0
    systemctl is-active chrony &>/dev/null && ((active_count++))
    systemctl is-active systemd-timesyncd &>/dev/null && ((active_count++))
    if [ $active_count -eq 1 ]; then
        log_pass "Single time synchronization daemon is running"
        ((PASSED_CHECKS++))
    else
        log_error "Multiple or no time sync daemons active"
        ((FAILED_CHECKS++))
    fi
}

# =========================
# 4. Cron / Job Schedulers
# =========================
check_cron_daemon() {
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: cron daemon"
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled cron &>/dev/null && systemctl is-active cron &>/dev/null; then
            log_pass "cron daemon enabled and active"
            ((PASSED_CHECKS++))
        else
            log_error "cron daemon not enabled/active"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "CRON-DAEMON" "cron daemon" "$(systemctl is-enabled cron 2>/dev/null)"
        systemctl enable cron
        systemctl start cron
        log_info "cron daemon enabled and started"
        ((FIXED_CHECKS++))
    fi
}

check_cron_permissions() {
    local path="$1"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking permissions on $path"
    
    if [ "$MODE" = "scan" ]; then
        perms=$(stat -c %a "$path")
        if [ "$perms" = "600" ] || [ "$perms" = "700" ]; then
            log_pass "$path permissions OK"
            ((PASSED_CHECKS++))
        else
            log_error "$path permissions NOT OK: $perms"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "CRON-$path" "Cron permissions $path" "$(stat -c %a "$path")"
        chmod 600 "$path" 2>/dev/null || chmod 700 "$path" 2>/dev/null
        log_info "$path permissions fixed"
        ((FIXED_CHECKS++))
    fi
}

check_crontab_restriction() {
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: crontab access restriction"
    if [ -f /etc/cron.allow ]; then
        log_pass "/etc/cron.allow exists; access restricted"
        ((PASSED_CHECKS++))
    else
        if [ "$MODE" = "fix" ]; then
            touch /etc/cron.allow
            chmod 600 /etc/cron.allow
            log_info "/etc/cron.allow created"
            ((FIXED_CHECKS++))
        else
            log_error "/etc/cron.allow missing; check cron access"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_approved_services() {
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: Only approved services are listening on network interfaces"
    local allowed_ports="22 53 80 443"
    local listening=$(ss -tuln | awk 'NR>1 {print $5}' | cut -d: -f2)
    local unauthorized=""
    for port in $listening; do
        if ! grep -qw "$port" <<< "$allowed_ports"; then
            if [ "$MODE" = "fix" ]; then
                pid=$(lsof -i :$port -t)
                [ -n "$pid" ] && kill -9 $pid
                log_info "Unauthorized process on port $port killed"
            fi
            unauthorized="$unauthorized $port"
        fi
    done
    if [ -z "$unauthorized" ]; then
        log_pass "No unauthorized services are listening"
        ((PASSED_CHECKS++))
    else
        log_error "Unauthorized services listening on ports:$unauthorized"
        ((FAILED_CHECKS++))
    fi
}

# =========================
# Main Execution
# =========================
initialize_db

# Server services
for i in "${!SERVER_SERVICES[@]}"; do
    check_service_disabled "SRV-$i" "${SERVER_RULES[$i]}" "${SERVER_SERVICES[$i]}"
done

# Client packages
for i in "${!CLIENT_PACKAGES[@]}"; do
    check_package_removed "CLT-$i" "${CLIENT_RULES[$i]}" "${CLIENT_PACKAGES[$i]}"
done

# Time sync
check_timesyncd
check_chrony
check_single_timesyncd

# Cron
check_cron_daemon

CRON_PATHS=("/etc/crontab" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
for path in "${CRON_PATHS[@]}"; do
    [ -e "$path" ] && check_cron_permissions "$path"
done
check_crontab_restriction

# Only approved services
check_approved_services

# =========================
# Summary
# =========================
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

