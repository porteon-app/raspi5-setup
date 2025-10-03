#!/usr/bin/env bash
set -euo pipefail

# =========================
# ADS-B Edge One-Shot Setup
# =========================

log(){ printf "\e[1;36m>>> %s\e[0m\n" "$*"; }
warn(){ printf "\e[1;33m⚠ %s\e[0m\n" "$*"; }
ok(){ printf "\e[1;32m✔ %s\e[0m\n" "$*"; }

ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# --- pre-load env (optional fleet config) ---
# Prefer /etc/default/adsb-edge, else try boot partition variants
for _env in /etc/default/adsb-edge /boot/adsb-edge.env /boot/firmware/adsb-edge.env; do
  if [ -f "${_env}" ]; then
    set +u
    . "${_env}"
    set -u
    ENV_FILE="${_env}"
    break
  fi
done
: "${ENV_FILE:=/etc/default/adsb-edge}"

export DEBIAN_FRONTEND=noninteractive
# --- network + apt helpers (with retries, safe under set -e) ---
probe_net() {
  # Distinguish DNS vs raw IP reachability
  curl -sS --ipv4 --max-time 5 https://deb.debian.org/ >/dev/null 2>&1 || \
  ping -c1 -W2 1.1.1.1 >/dev/null 2>&1
}

apt_dns_repair() {
  # Prefer systemd-resolved if present and startable; otherwise write static resolv.conf
  if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^systemd-resolved.service'; then
    sudo systemctl enable --now systemd-resolved || true
    sleep 1
    if systemctl is-active --quiet systemd-resolved; then
      sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true
    else
      warn "systemd-resolved failed to start; falling back to static /etc/resolv.conf"
      sudo rm -f /etc/resolv.conf
      printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
    fi
  else
    sudo rm -f /etc/resolv.conf
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
  fi
}

apt_update_safe() {
  set +e; sudo apt-get -o Acquire::ForceIPv4=true update; local rc=$?; set -e; return $rc
}

apt_install_safe() {
  set +e; sudo apt-get -o Acquire::ForceIPv4=true \
               -o Acquire::Retries=3 \
               -o Acquire::http::Timeout=30 \
               install -y "$@"; local rc=$?; set -e; return $rc
}

apt_retry_install() {
  # usage: apt_retry_install pkg1 pkg2 ...
  local tries=7 i
  for i in $(seq 1 ${tries}); do
    apt_dns_repair
    apt_update_safe || true
    if apt_install_safe "$@"; then
      return 0
    fi
    warn "apt install failed (attempt ${i}/${tries}); repairing DNS + nudging LTE, then retrying..."
    # Only bring LTE up if not already active (avoid flapping)
    nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || sudo nmcli con up lte >/dev/null 2>&1 || true
    sleep $((4*i))
  done
  return 1
}

# Auto-repair sources.list if 'trixie' present but OS is not 'trixie'
detect_sources_mismatch() {
  local os_codename=""
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    os_codename="${VERSION_CODENAME:-}"
  fi
  [ -n "$os_codename" ] || return 0

  # If any sources reference 'trixie' but OS isn't 'trixie', rewrite to the OS codename (with backups)
  if grep -RqsE '(^|[[:space:]/])trixie([[:space:]/]|$)' /etc/apt/sources.list*; then
    if [ "${os_codename}" != "trixie" ]; then
      warn "APT sources mention 'trixie' but OS is '${os_codename}' — rewriting sources (backups kept)."
      for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
        [ -e "$f" ] || continue
        sudo cp -a "$f" "$f.bak.$(date +%s)" || true
        sudo sed -i -E "s@(^|[[:space:]/])trixie([[:space:]/]|$)@\1${os_codename}\2@g" "$f" || true
      done
      ok "APT sources now point to '${os_codename}'."
    fi
  fi
}

# ---- defaults / env ----
PI_USER="${SUDO_USER:-$USER}"
PI_HOME="$(getent passwd "$PI_USER" | cut -d: -f6)"
HOSTNAME_DEF="$(hostname)"
TZ_DEF="Europe/Zurich"
WIFI_SSID=""
WIFI_PSK=""
AWS_REGION_DEF="us-east-2"
S3_PREFIX_DEF="s3://adsbcsvdata/adsb_hex_data/Europe/switzerland/lsgs/"
SIXFAB_APN_DEFAULT="super"  # Sixfab SIM APN
DUMP1090_REF_DEF="master"
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
SSH_PUBKEY=""

# ---- prompts ----
echo "=== ADS-B Edge Device One-Shot Installer (LTE failover ready) ==="
read -rp "Hostname for this Pi [${HOSTNAME_DEF}]: " HOSTNAME_SET
HOSTNAME_SET="${HOSTNAME_SET:-$HOSTNAME_DEF}"

read -rp "Timezone (e.g. Europe/Zurich) [${TZ_DEF}]: " TZ_SET
TZ_SET="${TZ_SET:-$TZ_DEF}"

echo "---- Wi-Fi (primary) ----"
read -rp "Wi-Fi SSID [${WIFI_SSID}]: " WIFI_SSID
WIFI_SSID="${WIFI_SSID:-$WIFI_SSID}"
read -rsp "Wi-Fi password [${WIFI_PSK}]: " WIFI_PSK
WIFI_PSK="${WIFI_PSK:-$WIFI_PSK}"

echo "---- LTE (fallback via Sixfab SIM) ----"
read -rp "Sixfab APN [${SIXFAB_APN_DEFAULT}]: " SIXFAB_APN
SIXFAB_APN="${SIXFAB_APN:-$SIXFAB_APN_DEFAULT}"
read -rp "SIM PIN (leave empty if none): " SIXFAB_PIN

echo "---- AWS (S3 upload target) ----"
read -rp "AWS Region [${AWS_REGION_DEF}]: " AWS_REGION
AWS_REGION="${AWS_REGION:-$AWS_REGION_DEF}"
read -rp "AWS Access Key ID [${AWS_ACCESS_KEY_ID}]: " _AKI
AWS_ACCESS_KEY_ID="${_AKI:-$AWS_ACCESS_KEY_ID}"
read -rsp "AWS Secret Access Key [${AWS_SECRET_ACCESS_KEY}]: " _ASK; echo
AWS_SECRET_ACCESS_KEY="${_ASK:-$AWS_SECRET_ACCESS_KEY}"
read -rp "S3 prefix (s3://bucket/prefix/) [${S3_PREFIX_DEF}]: " S3_PREFIX
S3_PREFIX="${S3_PREFIX:-$S3_PREFIX_DEF}"
# normalize S3 prefix to end with a single '/'
case "$S3_PREFIX" in
  */) : ;;
  *) S3_PREFIX="${S3_PREFIX}/" ;;
esac

echo "---- remote.it (optional) ----"
read -rp "remote.it R3 Registration Code (leave empty to skip): " REMOTEIT_R3

echo "---- dump1090 build ----"
read -rp "dump1090 git ref (branch/tag/SHA) [${DUMP1090_REF_DEF}]: " DUMP1090_REF
DUMP1090_REF="${DUMP1090_REF:-$DUMP1090_REF_DEF}"


# --- SSH public key (env-aware; persisted) ---
: "${ENV_FILE:=/etc/default/adsb-edge}"

# Helper: sanitize the key (strip quotes, trim, squash spaces)
_normalize_pubkey() {
  # remove CRs, trim, collapse internal whitespace to single spaces
  tr -d '\r' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g'
}

# Ensure SSH_PUBKEY present (prompt only if missing)
if [ -z "${SSH_PUBKEY:-}" ]; then
  echo "---- SSH public key for ${PI_USER} (for SSH/remote.it) ----"
  read -rp "SSH PUBLIC key (ssh-ed25519/ssh-rsa). Leave empty to skip: " SSH_PUBKEY || true
  SSH_PUBKEY="$(printf '%s' "${SSH_PUBKEY:-}" | _normalize_pubkey)"
  if [ -n "${SSH_PUBKEY}" ]; then
    # Persist to env (quote safely)
    if grep -q '^SSH_PUBKEY=' "${ENV_FILE}" 2>/dev/null; then
      sudo sed -i -E "s|^SSH_PUBKEY=.*|SSH_PUBKEY='${SSH_PUBKEY//\'/\'\\\'\'}'|" "${ENV_FILE}"
    else
      echo "SSH_PUBKEY='${SSH_PUBKEY//\'/\'\\\'\'}'" | sudo tee -a "${ENV_FILE}" >/dev/null
    fi
    sudo chmod 600 "${ENV_FILE}"
  fi
else
  # Sanitize the env-provided key
  SSH_PUBKEY="$(printf '%s' "${SSH_PUBKEY}" | _normalize_pubkey)"
  echo "---- SSH public key: (from env) ----"
fi

# Validate + install
if [ -n "${SSH_PUBKEY:-}" ]; then
  # Accept common formats; do not over-validate the comment field
  if printf '%s' "${SSH_PUBKEY}" | grep -qE '^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+'; then
    SSH_DIR="${PI_HOME}/.ssh"
    AUTH_KEYS="${SSH_DIR}/authorized_keys"
    mkdir -p "${SSH_DIR}"
    touch "${AUTH_KEYS}"

    if ! grep -qxF "${SSH_PUBKEY}" "${AUTH_KEYS}" 2>/dev/null; then
      printf '%s\n' "${SSH_PUBKEY}" >> "${AUTH_KEYS}"
      echo "Added key to ${AUTH_KEYS}"
    else
      echo "Key already present in ${AUTH_KEYS}"
    fi

    chown -R "${PI_USER}:${PI_USER}" "${SSH_DIR}"
    chmod 700 "${SSH_DIR}"
    chmod 600 "${AUTH_KEYS}"

    sudo mkdir -p /etc/ssh/sshd_config.d
    sudo tee /etc/ssh/sshd_config.d/10-adsb-ssh.conf >/dev/null <<'EOF'
PubkeyAuthentication yes
# Keep password auth as fallback; set to "no" later if you want key-only.
PasswordAuthentication yes
# Make sure standard locations are honored
AuthorizedKeysFile .ssh/authorized_keys
EOF
    sudo systemctl reload ssh || sudo systemctl restart ssh || true
  else
    warn "SSH_PUBKEY present but format looks invalid; expected 'ssh-ed25519 <base64> [comment]' or 'ssh-rsa <base64> [comment]'."
  fi
else
  echo "No SSH public key provided; skipping."
fi

# ---- layout ----
BASE_DIR="$PI_HOME/Documents/adsb"
APP_DIR="$BASE_DIR/app"
PROC_DIR="$BASE_DIR/files/processing"
SEND_DIR="$BASE_DIR/files/sending"
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$APP_DIR" "$PROC_DIR" "$SEND_DIR" "$LOG_DIR"
chown -R "$PI_USER":"$PI_USER" "$BASE_DIR"

# --- Create Python apps early (idempotent) ---
cd "$APP_DIR"
if [ ! -f collector.py ]; then
cat > collector.py <<'PY'
#!/usr/bin/env python3
import os, socket, time, gzip, pathlib, signal, sys
from datetime import datetime, timezone
BASE=os.path.expanduser("~/Documents/adsb")
PROC=os.path.join(BASE,"files","processing")
SEND=os.path.join(BASE,"files","sending")
LOG=os.path.join(BASE,"logs","collector.log")
HOST="127.0.0.1"; PORT=30002
MAX_LINES=5000; MAX_SECS=3.0
pathlib.Path(PROC).mkdir(parents=True, exist_ok=True)
pathlib.Path(SEND).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.dirname(LOG)).mkdir(parents=True, exist_ok=True)

def tsu(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def rotate(buf, hostname):
    if not buf: return
    epoch_ms=int(time.time()*1000)
    fname=f"hex_{hostname}_{time.strftime('%Y%m%d', time.gmtime())}_{epoch_ms}.hex"
    fpath=os.path.join(PROC,fname)
    with open(fpath,"w") as f: f.write("\n".join(buf)+"\n")
    gz=fpath+".gz"
    with open(fpath,"rb") as src, gzip.open(gz,"wb") as dst: dst.writelines(src)
    os.remove(fpath); os.replace(gz, os.path.join(SEND, os.path.basename(gz)))

hostname=os.uname().nodename
running=True

def handle_term(signum, frame):
    global running
    running=False

signal.signal(signal.SIGTERM, handle_term)
signal.signal(signal.SIGINT, handle_term)

with open(LOG,"a") as lg:
    lg.write(f"{tsu()} collector started\n"); lg.flush()
    while running:
        try:
            with socket.create_connection((HOST,PORT),timeout=5) as s:
                s.settimeout(0.2)
                buf=[]; start=time.monotonic()
                while running:
                    try:
                        line=s.recv(65536)
                        if not line:
                            time.sleep(0.01); continue
                        for raw in line.splitlines():
                            if not raw: continue
                            txt=raw.decode('ascii','ignore')
                            if not txt or txt[0]!="*": continue
                            hexv=txt[1:].split(';',1)[0].strip().upper()
                            buf.append(f"{hexv} {tsu()}")
                    except socket.timeout:
                        pass
                    now=time.monotonic()
                    if len(buf)>=MAX_LINES or (now-start)>=MAX_SECS:
                        rotate(buf,hostname); buf=[]; start=now
        except Exception as e:
            with open(LOG,"a") as lg2: lg2.write(f"{tsu()} retry: {e}\n"); lg2.flush()
            time.sleep(2)
PY
chmod +x collector.py; chown "$PI_USER":"$PI_USER" collector.py
fi

if [ ! -f uploader.py ]; then
cat > uploader.py <<'PY'
#!/usr/bin/env python3
import os, time, subprocess, pathlib
from datetime import datetime, timezone
BASE=os.path.expanduser("~/Documents/adsb")
SEND=os.path.join(BASE,"files","sending")
LOG=os.path.join(BASE,"logs","uploader.log")
pathlib.Path(SEND).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.dirname(LOG)).mkdir(parents=True, exist_ok=True)

def tsu(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

S3_PREFIX=os.environ.get("S3_PREFIX","s3://adsbcsvdata/adsb_hex_data/Europe/switzerland/lsgs/")
REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))

with open(LOG,"a") as lg: lg.write(f"{tsu()} uploader started\n"); lg.flush()
while True:
    try:
        files=sorted([f for f in os.listdir(SEND) if f.endswith(".hex.gz")])
    except FileNotFoundError:
        time.sleep(1); continue
    for name in files:
        path=os.path.join(SEND,name)
        cmd=["aws","s3","cp",path,S3_PREFIX+name,"--region",REGION,"--only-show-errors"]
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.remove(path)
            with open(LOG,"a") as lg: lg.write(f"{tsu()} UPLOAD_OK {name}\n"); lg.flush()
        except subprocess.CalledProcessError:
            with open(LOG,"a") as lg: lg.write(f"{tsu()} UPLOAD_FAIL {name}\n"); lg.flush()
            time.sleep(3)
    time.sleep(1)
PY
chmod +x uploader.py; chown "$PI_USER":"$PI_USER" uploader.py
fi

# DNS safety net (works even if /etc/resolv.conf is a broken symlink)
if ! systemctl is-active --quiet systemd-resolved; then
  warn "systemd-resolved not active; using temporary resolv.conf"
  sudo rm -f /etc/resolv.conf
  printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
fi

# 1) Base packages, hostname, timezone, DNS cache, NM, ModemManager
log "Pre-flight packages + hostname/timezone + DNS cache + NM/MM"
detect_sources_mismatch
apt_retry_install \
  curl unzip jq ca-certificates gnupg lsb-release \
  python3 python3-pip python3-venv awscli picocom \
  net-tools dnsutils network-manager systemd-resolved \
  modemmanager mobile-broadband-provider-info iproute2

# hostname/time
[ "$(hostname)" = "$HOSTNAME_SET" ] || { echo "$HOSTNAME_SET" | sudo tee /etc/hostname >/dev/null; sudo hostnamectl set-hostname "$HOSTNAME_SET"; }
# Ensure /etc/hosts maps 127.0.1.1 to the hostname (Debian/Raspbian convention)
if ! grep -qE "^[[:space:]]*127\.0\.1\.1[[:space:]]+${HOSTNAME_SET}\b" /etc/hosts; then
  if grep -qE "^[[:space:]]*127\.0\.1\.1[[:space:]]+" /etc/hosts; then
    sudo sed -i "s/^127\.0\.1\.1.*/127.0.1.1 ${HOSTNAME_SET}/" /etc/hosts
  else
    echo "127.0.1.1 ${HOSTNAME_SET}" | sudo tee -a /etc/hosts >/dev/null
  fi
fi
sudo timedatectl set-timezone "$TZ_SET"
sudo timedatectl set-ntp true

# DNS cache
sudo systemctl enable --now systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true

# Network services
sudo systemctl enable --now NetworkManager
sudo systemctl enable --now ModemManager

# --- Create LTE profile early so apt retries can use it ---
if ! nmcli -t -f NAME,TYPE con show | grep -q '^lte:gsm$'; then
  sudo nmcli con add type gsm ifname "*" con-name lte apn "${SIXFAB_APN}"
fi
sudo nmcli con modify lte connection.autoconnect yes ipv4.method auto ipv6.method ignore
sudo nmcli con modify lte gsm.apn "${SIXFAB_APN}"
[ -n "${SIXFAB_PIN:-}" ] && sudo nmcli con modify lte gsm.pin "${SIXFAB_PIN}" || true
# Try to bring LTE ready in background; if Wi-Fi is good, it will just sit idle
nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || sudo nmcli con up lte >/dev/null 2>&1 || true

# Wi-Fi connect (primary)
if [ -n "${WIFI_SSID:-}" ]; then
  nmcli radio wifi on || true
  WIFI_CON_NAME="wifi-${WIFI_SSID}"
  if ! nmcli -t -f NAME con show | grep -Fxq "$WIFI_CON_NAME"; then
    sudo nmcli con add type wifi ifname "*" con-name "$WIFI_CON_NAME" ssid "$WIFI_SSID" || true
  fi
  if [ -n "${WIFI_PSK:-}" ]; then
    # Secured network (WPA-PSK)
    sudo nmcli con modify "$WIFI_CON_NAME" wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$WIFI_PSK" || true
  else
    # Open network (no key management)
    sudo nmcli con modify "$WIFI_CON_NAME" --delete wifi-sec.psk || true
    sudo nmcli con modify "$WIFI_CON_NAME" wifi-sec.key-mgmt none || true
  fi
  sudo nmcli con modify "$WIFI_CON_NAME" connection.autoconnect yes ipv4.method auto ipv6.method ignore || true
  sudo nmcli con up "$WIFI_CON_NAME" || true
fi

# 3) AWS CLI config
log "Configuring AWS CLI"
AWS_CFG_DIR="$PI_HOME/.aws"; mkdir -p "$AWS_CFG_DIR"; chmod 700 "$AWS_CFG_DIR"
cat >"$AWS_CFG_DIR/credentials" <<EOF
[default]
aws_access_key_id = ${AWS_ACCESS_KEY_ID}
aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}
EOF
cat >"$AWS_CFG_DIR/config" <<EOF
[default]
region = ${AWS_REGION}
output = json
EOF
chown -R "$PI_USER":"$PI_USER" "$AWS_CFG_DIR"
chmod 600 "$AWS_CFG_DIR/credentials" "$AWS_CFG_DIR/config" || true

# 4) Build & install dump1090-fa (with deps)
log "Installing build deps & compiling dump1090-fa"
log "Checking internet reachability before build deps"
detect_sources_mismatch
if ! probe_net; then
  warn "No internet yet; attempting to bring up LTE profile"
  nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || sudo nmcli con up lte >/dev/null 2>&1 || true
  sleep 6
fi
apt_retry_install build-essential pkg-config libncurses-dev librtlsdr-dev libusb-1.0-0-dev git
mkdir -p "$APP_DIR"; cd "$APP_DIR"

[ -d dump1090-fa ] || git clone https://github.com/flightaware/dump1090.git dump1090-fa
cd dump1090-fa
git fetch --tags --prune || true
git checkout --detach "$DUMP1090_REF" || true
COMMIT_SHA="$(git rev-parse --short=12 HEAD || echo unknown)"
echo "Building dump1090 at $COMMIT_SHA"
make clean || true
make -j"$(nproc)"
sudo install -m0755 ./dump1090 /usr/local/bin/dump1090-fa
echo "$COMMIT_SHA" | sudo tee /usr/local/share/dump1090-fa.commit >/dev/null

# 4.5) Ensure kernel DVB drivers don't grab RTL-SDR
log "Blacklisting DVB RTL-SDR kernel modules (so dump1090 can access the dongle)"
sudo tee /etc/modprobe.d/rtl-sdr-blacklist.conf >/dev/null <<'EOF'
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF
sudo rmmod dvb_usb_rtl28xxu rtl2832 rtl2830 2>/dev/null || true

# 6) Systemd units (dump1090-fa, collector, uploader)
log "Wiring systemd services"
sudo tee /etc/systemd/system/dump1090-fa.service >/dev/null <<'EOF'
[Unit]
Description=dump1090 ADS-B receiver (custom)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
RuntimeDirectory=dump1090-fa
ExecStartPre=/bin/sh -c 'for m in dvb_usb_rtl28xxu rtl2832 rtl2830; do /sbin/rmmod "$m" 2>/dev/null || true; done'
ExecStart=/usr/local/bin/dump1090-fa --device-index 0 --gain -10 --ppm 0 \
  --net --net-ro-port 30002 --net-sbs-port 30003 --net-bo-port 30005 \
  --write-json /run/dump1090-fa --json-location-accuracy 1
Restart=always
RestartSec=2
# Minimal hardening
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/adsb-collector.service >/dev/null <<EOF
[Unit]
Description=ADS-B collector (.hex -> processing, gzip -> sending)
After=dump1090-fa.service network-online.target
Wants=network-online.target
Requires=dump1090-fa.service

[Service]
Type=simple
User=${PI_USER}
WorkingDirectory=${APP_DIR}
# Wait (up to 30s) for dump1090 to expose port 30002 before starting
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 30); do /usr/bin/ss -lnt | grep -q ":30002" && exit 0; sleep 1; done; exit 0'
# Ensure the script exists and is executable
ExecStartPre=/bin/sh -c '[ -x "${APP_DIR}/collector.py" ]'
ExecStart=/usr/bin/python3 ${APP_DIR}/collector.py
Restart=always
RestartSec=2

# Minimal hardening (portable)
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/adsb-uploader.service >/dev/null <<EOF
[Unit]
Description=ADS-B uploader (to S3)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${PI_USER}
EnvironmentFile=-/etc/default/adsb-edge
WorkingDirectory=${APP_DIR}
ExecStartPre=/bin/sh -c '[ -x "${APP_DIR}/uploader.py" ]'
ExecStart=/usr/bin/python3 ${APP_DIR}/uploader.py
Restart=always
RestartSec=5
StartLimitIntervalSec=0

# Minimal hardening (portable)
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

# 7) Health timer (dump1090 + backlog + DNS self-heal)
log "Installing ADS-B health timer"
sudo tee /usr/local/sbin/adsb-health.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/adsb-health.log"
_ts(){ printf "%s" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; }

# Choose the correct adsb base dir: prefer PI_HOME if provided; otherwise infer from adsb-uploader.service user
_get_base(){
  if [ -n "${PI_HOME:-}" ]; then
    printf "%s" "${PI_HOME}/Documents/adsb"; return
  fi
  local u h
  u="$(systemctl show -p User --value adsb-uploader.service 2>/dev/null || echo root)"
  h="$(getent passwd "$u" | cut -d: -f6)"
  printf "%s" "${h:-$HOME}/Documents/adsb"
}
BASE="$(_get_base)"
SEND="${BASE}/files/sending"

# DNS self-heal
if ! systemctl is-active --quiet systemd-resolved; then
  sudo rm -f /etc/resolv.conf
  printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
fi

# dump1090 up?
if ! ss -lnt | grep -q ':30002'; then
  systemctl restart dump1090-fa || true
fi

# uploader nudge if backlog (avoid 'ls' with pipefail)
shopt -s nullglob
files=("${SEND}"/*.gz)
S=${#files[@]}
if [ "${S:-0}" -gt 0 ] && ! systemctl is-active --quiet adsb-uploader; then
  systemctl restart adsb-uploader || true
fi

printf "%s BACKLOG=%s BASE=%s\n" "$(_ts)" "${S:-0}" "$BASE" >> "$LOG"
EOF
sudo chmod +x /usr/local/sbin/adsb-health.sh
sudo tee /etc/systemd/system/adsb-health.timer >/dev/null <<'EOF'
[Unit]
Description=ADS-B health periodic checks
[Timer]
OnBootSec=30
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
EOF
sudo tee /etc/systemd/system/adsb-health.service >/dev/null <<'EOF'
[Unit]
Description=ADS-B health run
[Service]
Type=oneshot
EnvironmentFile=-/etc/default/adsb-edge
ExecStart=/usr/local/sbin/adsb-health.sh
# Minimal hardening
NoNewPrivileges=yes
PrivateTmp=yes
EOF

# 8) Udev rule for Telit (symlink optional) + AT helper
log "Telit udev + AT auto-detect helper"
sudo tee /etc/udev/rules.d/99-modem-at.rules >/dev/null <<'EOF'
SUBSYSTEM=="tty", ATTRS{idVendor}=="1bc7", ATTRS{idProduct}=="1206", SYMLINK+="Telit"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo tee /usr/local/bin/find-modem-at-port.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail; shopt -s nullglob
CANDS=( /dev/ttyUSB* /dev/ttyACM* /dev/Telit )
for DEV in "${CANDS[@]}"; do
  [ -e "$DEV" ] || continue
  stty -F "$DEV" 115200 cs8 -cstopb -parenb -echo raw 2>/dev/null || true
  ( echo -e "ATI\r"; sleep 0.3 ) > "$DEV"
  REPLY="$(timeout 1.2 tr -d '\r' < "$DEV" 2>/dev/null | head -n 8 || true)"
  if echo "$REPLY" | grep -qiE 'OK|Telit|SIMCOM|HUAWEI|FIBOCOM'; then
    echo "$DEV"; exit 0
  fi
done; exit 1
EOF
sudo chmod +x /usr/local/bin/find-modem-at-port.sh

# 9) remote.it watchdog + optional R3 registration
log "remote.it watchdog"
sudo tee /usr/local/sbin/remoteit-health.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
systemctl start remoteit-refresh.service || true
ACTIVE=$(systemctl list-units 'remoteit@*.service' --no-legend | grep running | wc -l || echo 0)
[ "$ACTIVE" -ge 1 ] || systemctl restart remoteit-refresh.service || true
EOF
sudo chmod +x /usr/local/sbin/remoteit-health.sh
sudo tee /etc/systemd/system/remoteit-health.timer >/dev/null <<'EOF'
[Unit]
Description=remote.it health
[Timer]
OnBootSec=45
OnUnitActiveSec=120
[Install]
WantedBy=timers.target
EOF
sudo tee /etc/systemd/system/remoteit-health.service >/dev/null <<'EOF'
[Unit]
Description=remote.it health run
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/remoteit-health.sh
# Minimal hardening
NoNewPrivileges=yes
PrivateTmp=yes
EOF
if [ -n "${REMOTEIT_R3:-}" ] && ! command -v remoteit >/dev/null 2>&1; then
  R3_REGISTRATION_CODE="${REMOTEIT_R3}" sh -c "$(curl -L https://downloads.remote.it/remoteit/install_agent.sh)" || warn "remote.it install returned non-zero"
fi

# 10) **LTE FAILOVER CORE** — create/manage GSM profile & failover timer
log "Configuring LTE fallback with NetworkManager + ModemManager"
if ! nmcli -t -f NAME,TYPE con show | grep -q '^lte:gsm$'; then
  sudo nmcli con add type gsm ifname "*" con-name lte apn "${SIXFAB_APN}"
fi
sudo nmcli con modify lte connection.autoconnect yes ipv4.method auto ipv6.method ignore
sudo nmcli con modify lte gsm.apn "${SIXFAB_APN}"
[ -n "${SIXFAB_PIN:-}" ] && sudo nmcli con modify lte gsm.pin "${SIXFAB_PIN}" || true
while IFS= read -r WIFI_CON; do
  sudo nmcli con modify "$WIFI_CON" connection.autoconnect yes connection.autoconnect-priority 100 ipv4.route-metric 100 || true
done < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="wifi"{print $1}')
sudo nmcli con modify lte connection.autoconnect-priority 50 ipv4.route-metric 200
# Bring LTE up now (only if not already active)
nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || sudo nmcli con up lte >/dev/null 2>&1 || true

# Failover watchdog: if internet down, bring lte up
sudo tee /usr/local/sbin/net-failover.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
REGION="${AWS_REGION:-us-east-2}"
_probe(){ curl -sS --ipv4 --max-time 5 "https://s3.${REGION}.amazonaws.com/" >/dev/null; }
# Only bring LTE up if it's not already active
if ! _probe; then
  if ! nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte; then
    nmcli con up lte >/dev/null 2>&1 || true
    sleep 5
    _probe || nmcli con up lte >/dev/null 2>&1 || true
  fi
fi
EOF
sudo chmod +x /usr/local/sbin/net-failover.sh
sudo tee /etc/systemd/system/net-failover.service >/dev/null <<'EOF'
[Unit]
Description=Bring LTE up when internet is unreachable
[Service]
Type=oneshot
EnvironmentFile=-/etc/default/adsb-edge
ExecStart=/usr/local/sbin/net-failover.sh
# Minimal hardening
NoNewPrivileges=yes
PrivateTmp=yes
EOF
sudo tee /etc/systemd/system/net-failover.timer >/dev/null <<'EOF'
[Unit]
Description=Periodic net failover check
[Timer]
OnBootSec=20
OnUnitActiveSec=30
AccuracySec=5s
Unit=net-failover.service
[Install]
WantedBy=timers.target
EOF

# 11) Verify then enable everything
# Verify unit files before enabling (surface syntax issues)
set +e
sudo systemd-analyze verify \
  /etc/systemd/system/dump1090-fa.service \
  /etc/systemd/system/adsb-collector.service \
  /etc/systemd/system/adsb-uploader.service \
  /etc/systemd/system/adsb-health.service \
  /etc/systemd/system/adsb-health.timer \
  /etc/systemd/system/remoteit-health.service \
  /etc/systemd/system/remoteit-health.timer \
  /etc/systemd/system/net-failover.service \
  /etc/systemd/system/net-failover.timer
set -e

log "Enabling services & timers"
sudo systemctl daemon-reload
sudo systemctl enable --now dump1090-fa.service
sudo systemctl enable --now adsb-collector.service
sudo systemctl enable --now adsb-uploader.service
sudo systemctl enable --now adsb-health.timer
sudo systemctl enable --now remoteit-health.timer || true
sudo systemctl enable --now net-failover.timer

# 12) ADS-B online bootstrap (network + tunnels + services watchdog)
echo "[INFO] Installing ADS-B online bootstrap (network+services watchdog)..."

sudo tee /usr/local/sbin/adsb-online-bootstrap.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
_ts(){ printf "%s " "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; }
log(){ echo "$(_ts)$*"; }

# DNS guard
if ! systemctl is-active --quiet systemd-resolved; then
  log "[DNS] systemd-resolved down, writing temporary resolv.conf"
  sudo rm -f /etc/resolv.conf
  printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
fi

# Core services
systemctl start NetworkManager ModemManager || true

# Internet probe
REGION="${AWS_REGION:-us-east-2}"
_probe(){ curl -sS --ipv4 --max-time 5 "https://s3.${REGION}.amazonaws.com/" >/dev/null; }
if ! _probe; then
  log "[NET] Internet not reachable, attempting LTE bring-up"
  nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || nmcli con up lte >/dev/null 2>&1 || true
  sleep 8
fi

for i in $(seq 1 18); do
  if _probe; then
    log "[NET] Internet reachable"
    break
  fi
  sleep 5
  if (( i % 3 == 0 )); then nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || nmcli con up lte >/dev/null 2>&1 || true; fi
done

# remote.it
systemctl start remoteit-refresh.service || true
sleep 3
systemctl restart remoteit-refresh.service || true
log "[R3] refreshed"

# ADS-B
systemctl restart dump1090-fa.service || true
sleep 3
systemctl restart adsb-collector.service || true
systemctl restart adsb-uploader.service  || true
log "[ADSB] services restarted in order"

UPLOG="${PI_HOME:-$HOME}/Documents/adsb/logs/uploader.log"
mkdir -p "$(dirname "$UPLOG")"
echo "$(date -u +%FT%TZ) BOOTSTRAP tick" >> "$UPLOG"
EOF
sudo chmod +x /usr/local/sbin/adsb-online-bootstrap.sh

sudo tee /etc/systemd/system/adsb-online-bootstrap.service >/dev/null <<'EOF'
[Unit]
Description=ADS-B online bootstrap (ensure net + tunnels + services)
Wants=network-online.target
After=network-online.target NetworkManager.service ModemManager.service systemd-resolved.service

[Service]
Type=oneshot
EnvironmentFile=-/etc/default/adsb-edge
ExecStart=/usr/local/sbin/adsb-online-bootstrap.sh
# Minimal hardening
NoNewPrivileges=yes
PrivateTmp=yes
EOF

sudo tee /etc/systemd/system/adsb-online-bootstrap.timer >/dev/null <<'EOF'
[Unit]
Description=Run ADS-B online bootstrap at boot and hourly

[Timer]
OnBootSec=20
OnUnitActiveSec=1h
AccuracySec=30s
Unit=adsb-online-bootstrap.service

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now adsb-online-bootstrap.timer

# 14) Logrotate setup
log "Installing logrotate config for adsb-edge"
sudo tee /etc/logrotate.d/adsb-edge >/dev/null <<EOF
/var/log/adsb-health.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0644 root root
}

${PI_HOME}/Documents/adsb/logs/*.log {
    su ${PI_USER} ${PI_USER}
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 ${PI_USER} ${PI_USER}
}
EOF

# 13) Quick checks
log "Quick checks"
ss -lnt | grep -E -q ':30002|:30003|:30005' && ok "dump1090 ports up" || warn "dump1090 port 30002 not listening yet"
systemctl is-active --quiet adsb-collector && ok "collector: active" || warn "collector: not active"
systemctl is-active --quiet adsb-uploader  && ok "uploader: active"  || warn "uploader: not active"
nmcli device || true
ip route | head -n 5 || true

cat <<EOF

Install finished. Recommended: sudo reboot
After reboot:
  - Route should be via Wi-Fi when present, LTE otherwise (check: ip route | head -1)
  - Services: systemctl status dump1090-fa adsb-collector adsb-uploader --no-pager
  - Logs: tail -n 40 ${LOG_DIR}/collector.log ; tail -n 40 ${LOG_DIR}/uploader.log
  - S3: aws s3 ls "${S3_PREFIX}" --region "${AWS_REGION}" | tail
  - Modem AT (stop MM temporarily): sudo systemctl stop ModemManager && PORT=\$(/usr/local/bin/find-modem-at-port.sh) && sudo picocom -b 115200 "\$PORT"
EOF

# 10.5) Connectivity restore hooks (restart services on Wi-Fi/LTE back online)
log "Installing connectivity-restore hooks"
sudo mkdir -p /etc/NetworkManager/dispatcher.d
sudo tee /usr/local/sbin/adsb-restart-services.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
_ts(){ printf "%s" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; }
log(){ printf "%s [ADSBRST] %s\n" "$(_ts)" "$*"; }
SERVICES=(dump1090-fa adsb-collector adsb-uploader)
for s in "${SERVICES[@]}"; do
  systemctl restart "$s" || true
  log "restarted $s"
done
EOF
sudo chmod +x /usr/local/sbin/adsb-restart-services.sh

sudo tee /etc/NetworkManager/dispatcher.d/90-adsb-recover.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
# Called by NetworkManager: $1 = interface, $2 = event
set -euo pipefail
IFACE="${1:-}"; EVENT="${2:-}"
case "$EVENT" in
  up|connectivity-change|dhcp4-change|hostname|reapply)
    sleep 2
    STATUS="$(nmcli -t -f CONNECTIVITY general status 2>/dev/null || echo unknown)"
    if [ "$STATUS" = "full" ] || [ "$STATUS" = "limited" ]; then
      nmcli -t -f NAME con show --active 2>/dev/null | grep -qx lte || nmcli con up lte >/dev/null 2>&1 || true
      /usr/local/sbin/adsb-online-bootstrap.sh || true
      /usr/local/sbin/adsb-restart-services.sh || true
    fi
    ;;
  down|pre-down|vpn-down|disconnect)
    :
    ;;
esac
EOF
sudo chmod +x /etc/NetworkManager/dispatcher.d/90-adsb-recover.sh