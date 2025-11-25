#!/bin/bash
# kali_harden.sh
# Aggressive Kali hardening to maximize services.sh scan pass count

echo "=== Removing Kali meta-packages that reinstall services ==="
sudo apt purge -y kali-linux-default kali-linux-headless legion
sudo apt autoremove -y

echo "=== Stopping, disabling, and masking risky services ==="
services=(
    autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd dovecot
    nfs-kernel-server nis cups rpcbind rsync smbd snmpd tftpd-hpa squid
    apache2 xinetd gdm postfix
)
for svc in "${services[@]}"; do
    echo "Processing $svc..."
    sudo systemctl stop "$svc" 2>/dev/null
    sudo systemctl disable "$svc" 2>/dev/null
    sudo systemctl mask "$svc" 2>/dev/null
done

echo "=== Removing unwanted clients ==="
clients=(telnet ftp nis ldap-utils rsh-client talk)
sudo apt purge -y "${clients[@]}"
sudo apt autoremove -y

echo "=== Time synchronization: disable systemd-timesyncd, enable chrony ==="
sudo systemctl stop systemd-timesyncd 2>/dev/null
sudo systemctl disable systemd-timesyncd 2>/dev/null
sudo systemctl mask systemd-timesyncd 2>/dev/null

sudo systemctl enable chrony
sudo systemctl restart chrony

echo "=== Ensuring only one NTP daemon runs ==="
sudo systemctl stop ntp 2>/dev/null
sudo systemctl disable ntp 2>/dev/null

echo "=== Killing unauthorized processes on high-risk ports ==="
ports=(323 38695 39360 52693)
for port in "${ports[@]}"; do
    pid=$(sudo lsof -t -i:"$port")
    if [ ! -z "$pid" ]; then
        echo "Killing process $pid on port $port..."
        sudo kill -9 "$pid"
    fi
done

echo "=== Cron permissions and access ==="
sudo chmod 600 /etc/crontab
sudo chmod 700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
[ -f /etc/cron.allow ] || sudo touch /etc/cron.allow

echo "=== Hardening complete! Run 'sudo bash services.sh scan' to check ==="

