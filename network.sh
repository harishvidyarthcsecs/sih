#!/bin/bash
# Network Hardening Script
# Covers: Network Devices, Kernel Modules, Kernel Parameters

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Network"

mkdir -p "$BACKUP_DIR"

# Colors ----------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# DB Init ---------------------------------------------------------------------
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

# Logging ---------------------------------------------------------------------
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

# DB Helpers ------------------------------------------------------------------
save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("""
INSERT OR REPLACE INTO configurations 
(topic, rule_id, rule_name, original_value, current_value, status)
VALUES (?, ?, ?, ?, ?, 'stored')
""", ("$TOPIC", "$rule_id", "$rule_name", "$original_value", "$current_value"))
conn.commit()
conn.close()
EOF
}

get_original_config() {
    local rule_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("SELECT original_value FROM configurations WHERE topic=? AND rule_id=?", 
               ("$TOPIC", "$rule_id"))
result = cursor.fetchone()
conn.close()
print(result[0] if result else "")
EOF
}

# -----------------------------------------------------------------------------
# Section 4.a — Network Devices
# -----------------------------------------------------------------------------

# 4.a.i Ensure IPv6 status is identified --------------------------------------
check_ipv6_status() {
    local rule_id="NET-DEVC-IPv6"
    local rule_name="Ensure IPv6 status is identified"
    ((TOTAL_CHECKS++))

    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"

    if [ "$MODE" = "scan" ]; then
        if sysctl net.ipv6.conf.all.disable_ipv6 &>/dev/null; then
            local state=$(sysctl -n net.ipv6.conf.all.disable_ipv6)
            log_pass "IPv6 status: disable_ipv6=$state"
            ((PASSED_CHECKS++))
        else
            log_error "Unable to determine IPv6 status."
            ((FAILED_CHECKS++))
        fi
    fi
}

# 4.a.ii Ensure wireless interfaces are disabled ------------------------------
check_disable_wireless() {
    local rule_id="NET-DEVC-WIFI"
    local rule_name="Ensure wireless interfaces are disabled"
    ((TOTAL_CHECKS++))

    echo ""
    echo "Checking: $rule_name"

    local wifi_iface
    wifi_iface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

    if [ "$MODE" = "scan" ]; then
        if [ -z "$wifi_iface" ]; then
            log_pass "No wireless interfaces detected."
            ((PASSED_CHECKS++))
        else
            if ip link show "$wifi_iface" | grep -q "state DOWN"; then
                log_pass "Wireless interface $wifi_iface is disabled"
                ((PASSED_CHECKS++))
            else
                log_error "Wireless interface $wifi_iface is ENABLED"
                ((FAILED_CHECKS++))
            fi
        fi

    elif [ "$MODE" = "fix" ]; then
        if [ -n "$wifi_iface" ]; then
            ip link set "$wifi_iface" down
            log_info "Disabled wireless interface $wifi_iface"
            ((FIXED_CHECKS++))
        fi
    fi
}

# 4.a.iii Ensure Bluetooth services are not in use ----------------------------
check_bluetooth() {
    local rule_id="NET-DEVC-BLUETOOTH"
    local rule_name="Ensure Bluetooth service is not in use"
    ((TOTAL_CHECKS++))

    echo ""
    echo "Checking: $rule_name"

    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled bluetooth 2>/dev/null | grep -q "enabled"; then
            log_error "Bluetooth service is enabled"
            ((FAILED_CHECKS++))
        else
            log_pass "Bluetooth service is disabled"
            ((PASSED_CHECKS++))
        fi

    elif [ "$MODE" = "fix" ]; then
        systemctl disable bluetooth 2>/dev/null
        systemctl stop bluetooth 2>/dev/null
        log_info "Bluetooth service disabled"
        ((FIXED_CHECKS++))
    fi
}

# -----------------------------------------------------------------------------
# Section 4.b — Kernel Modules
# -----------------------------------------------------------------------------

disable_module_rule() {
    local module="$1"
    local rule_id="$2"
    local rule_name="$3"

    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if [ "$MODE" = "scan" ]; then
        if lsmod | grep -q "^$module"; then
            log_error "Module $module is loaded"
            ((FAILED_CHECKS++))
        elif grep -q "^install $module /bin/true" /etc/modprobe.d/* 2>/dev/null; then
            log_pass "Module $module is blacklisted"
            ((PASSED_CHECKS++))
        else
            log_warn "Module $module not loaded but not blacklisted"
            ((FAILED_CHECKS++))
        fi

    elif [ "$MODE" = "fix" ]; then
        echo "install $module /bin/true" > /etc/modprobe.d/"$module".conf
        modprobe -r "$module" 2>/dev/null
        log_info "Module $module disabled and blacklisted"
        ((FIXED_CHECKS++))
    fi
}

check_dccp() { disable_module_rule "dccp" "NET-MOD-DCCP" "Ensure dccp kernel module is not available"; }
check_tipc() { disable_module_rule "tipc" "NET-MOD-TIPC" "Ensure tipc kernel module is not available"; }
check_rds()  { disable_module_rule "rds"  "NET-MOD-RDS"  "Ensure rds kernel module is not available"; }
check_sctp() { disable_module_rule "sctp" "NET-MOD-SCTP" "Ensure sctp kernel module is not available"; }

# -----------------------------------------------------------------------------
# Section 4.c — Kernel Parameters (sysctl)
# -----------------------------------------------------------------------------

sysctl_rule() {
    local rule_id="$1"
    local rule_name="$2"
    local key="$3"
    local good_val="$4"

    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    local current
    current=$(sysctl -n "$key" 2>/dev/null)

    if [ "$MODE" = "scan" ]; then
        if [ "$current" = "$good_val" ]; then
            log_pass "$key is correctly set to $good_val"
            ((PASSED_CHECKS++))
        else
            log_error "$key is $current (expected $good_val)"
            ((FAILED_CHECKS++))
        fi

    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "$current"

        sysctl -w "$key=$good_val" >/dev/null

        if ! grep -q "^$key" /etc/sysctl.conf; then
            echo "$key = $good_val" >> /etc/sysctl.conf
        else
            sed -i "s|^$key.*|$key = $good_val|" /etc/sysctl.conf
        fi

        log_info "$key set to $good_val"
        ((FIXED_CHECKS++))
    fi
}

# 4.c rules -------------------------------------------------------------
check_ip_forwarding()            { sysctl_rule "NET-PAR-FWD"      "Ensure IP forwarding is disabled"             "net.ipv4.ip_forward" "0"; }
check_redirect_sending()         { sysctl_rule "NET-PAR-REDIR"    "Ensure packet redirect sending is disabled"   "net.ipv4.conf.all.send_redirects" "0"; }
check_bogus_icmp()               { sysctl_rule "NET-PAR-BOGUS"    "Ensure bogus ICMP responses are ignored"      "net.ipv4.icmp_ignore_bogus_error_responses" "1"; }
check_broadcast_icmp()           { sysctl_rule "NET-PAR-BCAST"    "Ensure broadcast ICMP requests are ignored"   "net.ipv4.icmp_echo_ignore_broadcasts" "1"; }
check_icmp_redirects()           { sysctl_rule "NET-PAR-ICMPRED"  "Ensure ICMP redirects are not accepted"        "net.ipv4.conf.all.accept_redirects" "0"; }
check_secure_redirects()         { sysctl_rule "NET-PAR-SREDIR"   "Ensure secure ICMP redirects are not accepted" "net.ipv4.conf.all.secure_redirects" "0"; }
check_reverse_path_filter()      { sysctl_rule "NET-PAR-RPF"      "Ensure reverse path filtering is enabled"      "net.ipv4.conf.all.rp_filter" "1"; }
check_source_routing()           { sysctl_rule "NET-PAR-SROUTE"   "Ensure source routed packets are not accepted" "net.ipv4.conf.all.accept_source_route" "0"; }
check_log_martians()             { sysctl_rule "NET-PAR-MART"     "Ensure suspicious packets are logged"          "net.ipv4.conf.all.log_martians" "1"; }
check_syn_cookies()              { sysctl_rule "NET-PAR-SYNC"     "Ensure TCP SYN cookies are enabled"           "net.ipv4.tcp_syncookies" "1"; }
check_ipv6_ra()                  { sysctl_rule "NET-PAR-RA"       "Ensure IPv6 router advertisements are not accepted" "net.ipv6.conf.all.accept_ra" "0"; }

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
initialize_db

# Device checks
check_ipv6_status
check_disable_wireless
check_bluetooth

# Kernel module checks
check_dccp
check_tipc
check_rds
check_sctp

# Kernel parameter checks
check_ip_forwarding
check_redirect_sending
check_bogus_icmp
check_broadcast_icmp
check_icmp_redirects
check_secure_redirects
check_reverse_path_filter
check_source_routing
check_log_martians
check_syn_cookies
check_ipv6_ra

# Summary ---------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "Network Hardening Summary"
echo "========================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed:  $FIXED_CHECKS"
echo "========================================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some checks failed.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}"
fi

