#!/bin/bash

# ============================================================================
# Firewall Automation Script
# ============================================================================
# Modes: scan | fix | rollback
MODE=${1:-scan}

# Initialize counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# Logging functions
log_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
log_error() { echo -e "\033[0;31m[FAIL]\033[0m $1"; }
log_pass() { echo -e "\033[0;32m[PASS]\033[0m $1"; }

# ============================================================================
# Helper functions to save/rollback original config (dummy for now)
# ============================================================================
save_config() { :; }
get_original_config() { echo ""; }

# ============================================================================
# Firewall Checks
# ============================================================================

check_ufw_installed() {
    local rule_id="FW-UFW-INST"
    local rule_name="Ensure ufw is installed"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if [ "$MODE" = "scan" ]; then
        if command -v ufw >/dev/null 2>&1; then
            log_pass "ufw is installed"
            ((PASSED_CHECKS++))
        else
            log_error "ufw is NOT installed"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        apt-get update -y >/dev/null
        apt-get install -y ufw >/dev/null
        log_info "Installed ufw"
        ((FIXED_CHECKS++))
    fi
}

check_no_iptables_persistent() {
    local rule_id="FW-UFW-IPTPERS"
    local rule_name="Ensure iptables-persistent is not installed with ufw"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    local installed="no"
    dpkg -l | grep -q "^ii  iptables-persistent" && installed="yes"

    if [ "$MODE" = "scan" ]; then
        if [ "$installed" = "yes" ]; then
            log_error "iptables-persistent is installed (conflict)"
            ((FAILED_CHECKS++))
        else
            log_pass "iptables-persistent is not installed"
            ((PASSED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if [ "$installed" = "yes" ]; then
            apt-get purge -y iptables-persistent >/dev/null
            log_info "Removed iptables-persistent"
            ((FIXED_CHECKS++))
        fi
    fi
}

check_ufw_enabled() {
    local rule_id="FW-UFW-SVC"
    local rule_name="Ensure ufw service is enabled"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if [ "$MODE" = "scan" ]; then
        systemctl is-enabled ufw >/dev/null 2>&1 && { log_pass "ufw service is enabled"; ((PASSED_CHECKS++)); } || { log_error "ufw service is NOT enabled"; ((FAILED_CHECKS++)); }
    elif [ "$MODE" = "fix" ]; then
        systemctl enable ufw >/dev/null
        sudo ufw --force enable >/dev/null
        log_info "ufw service enabled"
        ((FIXED_CHECKS++))
    fi
}

check_ufw_loopback() {
    local rule_id="FW-UFW-LOOP"
    local rule_name="Ensure ufw loopback traffic is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)

    if [[ "$MODE" == "scan" ]]; then
        if echo "$snapshot" | grep -qE "ALLOW IN.*(lo|127\.0\.0\.1)" && \
           echo "$snapshot" | grep -qE "ALLOW OUT.*(lo|127\.0\.0\.1)"; then
            log_pass "Loopback firewall rules exist"
            ((PASSED_CHECKS++))
        else
            log_error "Missing UFW loopback rules"
            ((FAILED_CHECKS++))
        fi

    elif [[ "$MODE" == "fix" ]]; then
        save_config "$rule_id" "$rule_name" "$snapshot"
        ufw allow in on lo >/dev/null
        ufw allow out on lo >/dev/null
        ufw allow in from 127.0.0.1 >/dev/null
        ufw allow out to 127.0.0.1 >/dev/null
        log_info "Applied loopback UFW rules"
        ((FIXED_CHECKS++))

    elif [[ "$MODE" == "rollback" ]]; then
        ufw --force reset >/dev/null
        echo "$snapshot" >/tmp/ufw_snapshot.txt
        log_info "Loopback rules rolled back"
    fi
}


check_ufw_outbound() {
    local rule_id="FW-UFW-OUT"
    local rule_name="Ensure UFW outbound connections are allowed"

    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)

    if [[ "$MODE" == "scan" ]]; then
        # Pass if default outgoing policy is allow
        if echo "$snapshot" | grep -q "Default: deny (incoming), allow (outgoing)"; then
            log_pass "Default outbound policy is allow"
            ((PASSED_CHECKS++))
        else
            log_warn "Outbound connections must be manually reviewed"
        fi

    elif [[ "$MODE" == "fix" ]]; then
        ufw default allow outgoing >/dev/null
        log_info "Set default outbound policy to allow"
        ((FIXED_CHECKS++))
    fi
}


check_ufw_rules_for_open_ports() {
    local rule_id="FW-UFW-PORTS"
    local rule_name="Ensure UFW firewall rules exist for all open ports"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)
    local ports
    ports=$(ss -tuln | awk 'NR>1 {gsub(/.*:/,"",$5); print $5}' | sort -u)

    local missing=0
    for p in $ports; do
        if ! echo "$snapshot" | grep -q "$p"; then
            log_warn "Adding missing UFW rule for port: $p"
            ufw allow "$p" >/dev/null
            missing=1
        fi
    done

    ufw reload >/dev/null

    if [ "$MODE" = "scan" ]; then
        if [ $missing -eq 0 ]; then
            log_pass "All open ports have UFW rules"
            ((PASSED_CHECKS++))
        else
            log_error "Some open ports were missing UFW rules"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        log_info "UFW rules for all open ports applied"
        ((FIXED_CHECKS++))
    fi
}

check_ufw_default_deny() {
    local rule_id="FW-UFW-DENY"
    local rule_name="Ensure UFW default deny firewall policy"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if [ "$MODE" = "scan" ]; then
        local default_in
        default_in=$(ufw status verbose | awk '/Default:/ {print $2}')
        if [[ "$default_in" == "deny" ]]; then
            log_pass "Default deny incoming policy active"
            ((PASSED_CHECKS++))
        else
            log_error "Default deny incoming policy NOT active"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw reload >/dev/null
        log_info "Default deny incoming and allow outgoing applied"
        ((FIXED_CHECKS++))
    fi
}

check_ufw_no_iptables_conflict() {
    local rule_id="FW-UFW-CONFLICT"
    local rule_name="Ensure UFW is not in use with raw iptables"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if iptables -L | grep -q "ACCEPT" && ! ufw status | grep -q "active"; then
        log_error "iptables rules active without UFW — conflict detected"
        ((FAILED_CHECKS++))
    else
        log_pass "No UFW/iptables conflict detected"
        ((PASSED_CHECKS++))
    fi
}

# ============================================================================
# Main Execution
# ============================================================================
check_ufw_installed
check_no_iptables_persistent
check_ufw_enabled
check_ufw_loopback
check_ufw_outbound
check_ufw_rules_for_open_ports
check_ufw_default_deny
check_ufw_no_iptables_conflict

# ============================================================================
# Summary
# ============================================================================
echo -e "\n===== Firewall Check Summary ====="
echo "Total checks : $TOTAL_CHECKS"
echo "Passed       : $PASSED_CHECKS"
echo "Failed       : $FAILED_CHECKS"
echo "Fixed        : $FIXED_CHECKS"

