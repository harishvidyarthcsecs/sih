#!/bin/bash
# CIS-Style Logging and Auditing Hardening Script
# Modes: scan | fix | rollback

# Default mode is "scan" if no mode is provided
MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPIC="Logging and Auditing"

# Initialize counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# Logging functions for output
log_info() { echo -e "[INFO] $1"; }
log_pass() { echo -e "[PASS] $1"; }
log_fail() { echo -e "[FAIL] $1"; }
log_warn() { echo -e "[WARN] $1"; }

# =========================
# Function Definitions for Policy Checks
# =========================

## 8a. System Logging
### i. Configure systemd-journald service
check_journald_service() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: systemd-journald service"
    if [ "$MODE" = "scan" ]; then
        if systemctl is-active --quiet systemd-journald && systemctl is-enabled --quiet systemd-journald; then
            log_pass "systemd-journald is enabled and active"
            ((PASSED_CHECKS++))
        else
            log_fail "systemd-journald is not enabled or active"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_journald_file_access() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: journald log file access"
    if [ "$MODE" = "scan" ]; then
        if [ -r /var/log/journal ] && [ -w /var/log/journal ]; then
            log_pass "Journald log file has appropriate access"
            ((PASSED_CHECKS++))
        else
            log_fail "Journald log file access is misconfigured"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_journald_rotation() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: journald log file rotation"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^SystemMaxUse=" /etc/systemd/journald.conf; then
            log_pass "Journald log rotation is configured"
            ((PASSED_CHECKS++))
        else
            log_fail "Journald log rotation is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_only_one_logging_system() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Only one logging system is in use"
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/rsyslog.conf ]; then
            log_fail "Both journald and rsyslog are being used"
            ((FAILED_CHECKS++))
        else
            log_pass "Only systemd-journald is in use"
            ((PASSED_CHECKS++))
        fi
    fi
}

### ii. Configure rsyslog
check_rsyslog_installed() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: rsyslog installation"
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii  rsyslog"; then
            log_pass "rsyslog is installed"
            ((PASSED_CHECKS++))
        else
            log_fail "rsyslog is not installed"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        apt install -y rsyslog
        log_info "rsyslog installed"
        ((FIXED_CHECKS++))
    fi
}

check_rsyslog_enabled() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: rsyslog service"
    if [ "$MODE" = "scan" ]; then
        if systemctl is-active --quiet rsyslog && systemctl is-enabled --quiet rsyslog; then
            log_pass "rsyslog is enabled and active"
            ((PASSED_CHECKS++))
        else
            log_fail "rsyslog is not enabled or active"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        systemctl enable rsyslog
        systemctl start rsyslog
        log_info "rsyslog enabled and started"
        ((FIXED_CHECKS++))
    fi
}

check_journald_to_rsyslog() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: journald sends logs to rsyslog"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^ForwardToSyslog=" /etc/systemd/journald.conf && grep -q "^ForwardToSyslog=yes" /etc/systemd/journald.conf; then
            log_pass "journald configured to forward logs to rsyslog"
            ((PASSED_CHECKS++))
        else
            log_fail "journald not forwarding logs to rsyslog"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_rsyslog_file_creation_mode() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: rsyslog log file creation mode"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^CreateDirMode" /etc/rsyslog.conf; then
            log_pass "rsyslog log file creation mode is configured"
            ((PASSED_CHECKS++))
        else
            log_fail "rsyslog log file creation mode is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_rsyslog_remote_logging() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: rsyslog configured to send logs to a remote host"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^*.* @@<remote_log_host>" /etc/rsyslog.conf; then
            log_pass "rsyslog configured to send logs to remote log host"
            ((PASSED_CHECKS++))
        else
            log_fail "rsyslog not configured to send logs to remote log host"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_rsyslog_no_receive_from_remote() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: rsyslog not configured to receive logs from remote clients"
    if [ "$MODE" = "scan" ]; then
        if ! grep -q "^$ModLoad imtcp.so" /etc/rsyslog.conf && ! grep -q "^$InputTCPServerRun" /etc/rsyslog.conf; then
            log_pass "rsyslog not configured to receive logs from remote clients"
            ((PASSED_CHECKS++))
        else
            log_fail "rsyslog configured to receive logs from remote clients"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_logrotate_configured() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: logrotate configured"
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii  logrotate"; then
            log_pass "logrotate is installed and configured"
            ((PASSED_CHECKS++))
        else
            log_fail "logrotate is not installed or configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

### iii. Configure Logfiles
check_logfile_access() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: access to all logfiles"
    if [ "$MODE" = "scan" ]; then
        if find /var/log -type f -exec stat {} \; | grep -E "Access: .* rw" > /dev/null; then
            log_pass "Access to logfiles is configured"
            ((PASSED_CHECKS++))
        else
            log_fail "Logfiles access is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

## 8b. System Auditing
check_auditd_installed() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: auditd installation"
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii  auditd"; then
            log_pass "auditd is installed"
            ((PASSED_CHECKS++))
        else
            log_fail "auditd is not installed"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        apt install -y auditd
        log_info "auditd installed"
        ((FIXED_CHECKS++))
    fi
}

check_auditd_service() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: auditd service"
    if [ "$MODE" = "scan" ]; then
        if systemctl is-active --quiet auditd && systemctl is-enabled --quiet auditd; then
            log_pass "auditd is enabled and active"
            ((PASSED_CHECKS++))
        else
            log_fail "auditd is not enabled or active"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        systemctl enable auditd
        systemctl start auditd
        log_info "auditd enabled and started"
        ((FIXED_CHECKS++))
    fi
}

check_auditd_processes() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Auditing for processes that start prior to auditd"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^AUDIT_BACKLOG_LIMIT=" /etc/audit/auditd.conf; then
            log_pass "Auditing for processes before auditd is enabled"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit backlog limit is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_auditd_backlog_limit() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: auditd backlog limit"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^audit_backlog_limit" /etc/audit/auditd.conf; then
            log_pass "Audit backlog limit is configured"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit backlog limit is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

## 8c. Configure Data Retention
check_audit_log_storage_size() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Audit log storage size configuration"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^max_log_file" /etc/audit/auditd.conf; then
            log_pass "Audit log storage size is configured"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit log storage size is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_audit_log_auto_deletion() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Audit logs auto-deletion configuration"
    if [ "$MODE" = "scan" ]; then
        if ! grep -q "^delete_logs" /etc/audit/auditd.conf; then
            log_pass "Audit logs are not configured to delete automatically"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit logs are configured to delete automatically"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_audit_log_full() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: System disabled when audit logs are full"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^max_log_file_action=ignore" /etc/audit/auditd.conf; then
            log_pass "System is disabled when audit logs are full"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit log full action is not configured correctly"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_audit_log_warning() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: System warns when audit logs are low on space"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^space_left_action=syslog" /etc/audit/auditd.conf; then
            log_pass "System warns when audit logs are low on space"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit log low space warning is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

## 8d. Configure auditd Rules
check_auditd_rules() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: auditd rules configuration"
    if [ "$MODE" = "scan" ]; then
        for rule in $(cat /etc/audit/rules.d/*.rules); do
            if [[ "$rule" =~ "sudoers" ]] || [[ "$rule" =~ "date" ]] || [[ "$rule" =~ "usermod" ]] || [[ "$rule" =~ "setfacl" ]]; then
                log_pass "Audit rule: $rule"
                ((PASSED_CHECKS++))
            else
                log_fail "Missing audit rule: $rule"
                ((FAILED_CHECKS++))
            fi
        done
    fi
}

## 8e. Configure auditd File Access
check_audit_log_files_permissions() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: audit log file permissions"
    if [ "$MODE" = "scan" ]; then
        if find /var/log/audit -type f -exec stat {} \; | grep -E "Access: .* rw" > /dev/null; then
            log_pass "Audit log file permissions are correct"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit log file permissions are incorrect"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_audit_config_permissions() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: audit configuration file permissions"
    if [ "$MODE" = "scan" ]; then
        if find /etc/audit -type f -exec stat {} \; | grep -E "Access: .* rw" > /dev/null; then
            log_pass "Audit configuration file permissions are correct"
            ((PASSED_CHECKS++))
        else
            log_fail "Audit configuration file permissions are incorrect"
            ((FAILED_CHECKS++))
        fi
    fi
}

## 8f. Configure Integrity Checking (AIDE)
check_aide_installed() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: AIDE installation"
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii  aide"; then
            log_pass "AIDE is installed"
            ((PASSED_CHECKS++))
        else
            log_fail "AIDE is not installed"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        apt install -y aide
        log_info "AIDE installed"
        ((FIXED_CHECKS++))
    fi
}

check_aide_integrity_check() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: AIDE integrity checks"
    if [ "$MODE" = "scan" ]; then
        if grep -q "^/usr/sbin/aide --check" /etc/cron.daily/aide; then
            log_pass "AIDE integrity check is configured"
            ((PASSED_CHECKS++))
        else
            log_fail "AIDE integrity check is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

check_aide_protection() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: AIDE protection"
    if [ "$MODE" = "scan" ]; then
        if grep -q "cryptographic" /etc/aide/aide.conf; then
            log_pass "Cryptographic mechanisms are used to protect AIDE"
            ((PASSED_CHECKS++))
        else
            log_fail "AIDE protection with cryptographic mechanisms is not configured"
            ((FAILED_CHECKS++))
        fi
    fi
}

# =========================
# Main Execution
# =========================
for check in $(declare -F | awk '{print $3}'); do
    $check
done

# =========================
# Summary
# =========================
echo -e "\n========================================================"
echo "Summary"
echo "========================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "========================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo "[FAIL] Issues detected."
else
    echo "[PASS] All checks passed."
fi

