#!/bin/bash

echo "=== Lesson 8: Bash Security Automation ==="

# -----------------------------
# 0. Перевірка root
# -----------------------------
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (use sudo)"
  exit 1
fi

# -----------------------------
# 1. Password policy (minlen >= 8)
# -----------------------------
echo "[*] Checking password policy (minlen >= 8)"

PASS_MINLEN=$(grep pam_unix.so /etc/pam.d/common-password | grep -o 'minlen=[0-9]*' | head -n 1 | cut -d= -f2)

if [ -z "$PASS_MINLEN" ]; then
  echo "[!] minlen not set. Applying minlen=8"
  sed -i '/pam_unix.so/ s/$/ minlen=8/' /etc/pam.d/common-password
elif [ "$PASS_MINLEN" -lt 8 ]; then
  echo "[!] minlen=$PASS_MINLEN is weak. Updating to minlen=8"
  sed -i 's/minlen=[0-9]*/minlen=8/' /etc/pam.d/common-password
else
  echo "[+] Password policy OK (minlen=$PASS_MINLEN)"
fi

# -----------------------------
# 2. Firewall (UFW)
# -----------------------------
echo "[*] Checking firewall (UFW)"

if ! command -v ufw >/dev/null 2>&1; then
  echo "[*] Installing UFW"
  apt update && apt install ufw -y
fi

if ufw status | grep -qi inactive; then
  echo "[!] UFW inactive. Enabling..."
  ufw --force enable
else
  echo "[+] UFW already active"
fi

# -----------------------------
# 3. Disable root login via SSH
# -----------------------------
echo "[*] Disabling root login via SSH"

SSHD_CONFIG="/etc/ssh/sshd_config"

if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
else
  echo "PermitRootLogin no" >> "$SSHD_CONFIG"
fi

systemctl restart ssh
echo "[+] Root SSH login disabled"

# -----------------------------
# 4. Automatic updates
# -----------------------------
echo "[*] Enabling automatic updates"

apt install unattended-upgrades -y
systemctl enable unattended-upgrades
systemctl start unattended-upgrades

echo "[+] Automatic updates enabled"

# -----------------------------
# 5. Account lockout (fail after 5 attempts)
# -----------------------------
echo "[*] Configuring account lockout policy"

PAM_FILE="/etc/pam.d/common-auth"

if ! grep -q pam_faillock.so "$PAM_FILE"; then
  sed -i '1i auth required pam_faillock.so preauth deny=5 unlock_time=900' "$PAM_FILE"
  sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900' "$PAM_FILE"
fi

echo "[+] Account lockout configured (5 attempts)"

echo "=== CIS hardening completed successfully ==="
