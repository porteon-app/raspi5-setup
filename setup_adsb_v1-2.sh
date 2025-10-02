#!/usr/bin/env bash
set -euo pipefail

# =========================
# ADS-B Edge One-Shot Setup
# =========================

log(){ printf "\e[1;36m>>> %s\e[0m\n" "$*"; }
warn(){ printf "\e[1;33m⚠ %s\e[0m\n" "$*"; }
ok(){ printf "\e[1;32m✔ %s\e[0m\n" "$*"; }
ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# ---- defaults / env ----
PI_USER="${SUDO_USER:-$USER}"
PI_HOME="$(getent passwd "$PI_USER" | cut -d: -f6)"
HOSTNAME_DEF="$(hostname)"
TZ_DEF="Europe/Zurich"
AWS_REGION_DEF="us-east-2"
S3_PREFIX_DEF="s3://adsbcsvdata/adsb_hex_data/Europe/switzerland/lsgs/"
TAGS_DEF="tag:adsb,tag:edge"
SIXFAB_APN_DEFAULT="super"  # Sixfab SIM APN

# ---- prompts ----
echo "=== ADS-B Edge Device One-Shot Installer (LTE failover ready) ==="
read -rp "Hostname for this Pi [${HOSTNAME_DEF}]: " HOSTNAME_SET
HOSTNAME_SET="${HOSTNAME_SET:-$HOSTNAME_DEF}"

read -rp "Timezone (e.g. Europe/Zurich) [${TZ_DEF}]: " TZ_SET
TZ_SET="${TZ_SET:-$TZ_DEF}"

echo "---- Wi-Fi (primary) ----"
read -rp "Wi-Fi SSID: " WIFI_SSID
read -rsp "Wi-Fi password (leave empty if not needed): " WIFI_PSK; echo

echo "---- LTE (fallback via Sixfab SIM) ----"
read -rp "Sixfab APN [${SIXFAB_APN_DEFAULT}]: " SIXFAB_APN
SIXFAB_APN="${SIXFAB_APN:-$SIXFAB_APN_DEFAULT}"
read -rp "SIM PIN (leave empty if none): " SIXFAB_PIN

echo "---- AWS (S3 upload target) ----"
read -rp "AWS Region [${AWS_REGION_DEF}]: " AWS_REGION
AWS_REGION="${AWS_REGION:-$AWS_REGION_DEF}"
read -rp "AWS Access Key ID: " AWS_ACCESS_KEY_ID
read -rsp "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY; echo
read -rp "S3 prefix (s3://bucket/prefix/) [${S3_PREFIX_DEF}]: " S3_PREFIX
S3_PREFIX="${S3_PREFIX:-$S3_PREFIX_DEF}"

echo "---- remote.it (optional) ----"
read -rp "remote.it R3 Registration Code (leave empty to skip): " REMOTEIT_R3

echo "---- Tailscale (optional) ----"
read -rp "Tailscale ephemeral auth key (leave empty to skip): " TS_AUTHKEY
read -rp "Tailscale tags (comma-separated, e.g. tag:adsb,tag:edge) [${TAGS_DEF}]: " TS_TAGS
TS_TAGS="${TS_TAGS:-$TAGS_DEF}"

# --- SSH key installation (for user $PI_USER) ---
echo "---- SSH public key for ${PI_USER} (for SSH/Tailscale/remote.it) ----"
read -rp "Paste your SSH PUBLIC key (ssh-ed25519/ssh-rsa). Leave empty to skip: " SSH_PUBKEY || true

if [ -n "${SSH_PUBKEY:-}" ]; then
  # minimal validation (starts with ssh-ed25519 or ssh-rsa)
  if echo "$SSH_PUBKEY" | grep -qE '^(ssh-ed25519|ssh-rsa)\s'; then
    SSH_DIR="$PI_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    mkdir -p "$SSH_DIR"
    touch "$AUTH_KEYS"
    # append only if not already present
    if ! grep -qxF "$SSH_PUBKEY" "$AUTH_KEYS" 2>/dev/null; then
      echo "$SSH_PUBKEY" >> "$AUTH_KEYS"
      echo "Added key to $AUTH_KEYS"
    else
      echo "Key already present in $AUTH_KEYS"
    fi
    chown -R "$PI_USER":"$PI_USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_KEYS"

    # ensure sshd allows pubkey auth (drop-in, non-invasive)
    sudo mkdir -p /etc/ssh/sshd_config.d
    sudo tee /etc/ssh/sshd_config.d/10-adsb-ssh.conf >/dev/null <<'EOF'
PubkeyAuthentication yes
# Keep password auth as fallback; set to "no" later if you want key-only.
PasswordAuthentication yes
# Make sure standard locations are honored
AuthorizedKeysFile .ssh/authorized_keys
EOF
    sudo systemctl reload ssh || sudo systemctl restart ssh
  else
    echo "Public key format didn’t look right; skipping install."
  fi
else
  echo "No public key provided; skipping."
fi

# ---- layout ----
BASE_DIR="$PI_HOME/Documents/adsb"
APP_DIR="$BASE_DIR/app"
PROC_DIR="$BASE_DIR/files/processing"
SEND_DIR="$BASE_DIR/files/sending"
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$APP_DIR" "$PROC_DIR" "$SEND_DIR" "$LOG_DIR"

# DNS safety net if systemd-resolved not active yet
if ! systemctl is-active --quiet systemd-resolved; then
  warn "systemd-resolved not active; using temporary resolv.conf"
  sudo bash -c 'printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf'
fi

# 1) Base packages, hostname, timezone, DNS cache, NM, ModemManager
log "Pre-flight packages + hostname/timezone + DNS cache + NM/MM"
sudo apt-get update -y
sudo apt-get install -y \
  curl unzip jq ca-certificates gnupg lsb-release \
  python3 python3-pip python3-venv awscli picocom \
  net-tools dnsutils network-manager systemd-resolved \
  modemmanager mobile-broadband-provider-info

# hostname/time
[ "$(hostname)" = "$HOSTNAME_SET" ] || { echo "$HOSTNAME_SET" | sudo tee /etc/hostname >/dev/null; sudo hostnamectl set-hostname "$HOSTNAME_SET"; }
sudo timedatectl set-timezone "$TZ_SET"
sudo timedatectl set-ntp true

# DNS cache
sudo systemctl enable --now systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true

# Network services
sudo systemctl enable --now NetworkManager
sudo systemctl enable --now ModemManager

# Wi-Fi connect (primary)
if [ -n "${WIFI_SSID:-}" ]; then
  nmcli radio wifi on || true
  if [ -n "${WIFI_PSK:-}" ]; then
    nmcli dev wifi connect "$WIFI_SSID" password "$WIFI_PSK" || true
  else
    nmcli dev wifi connect "$WIFI_SSID" || true
  fi
fi

# 2) Tailscale install & bring up
log "Ensuring Tailscale is installed & up"
if ! dpkg -s tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi
sudo systemctl enable --now tailscaled || true
if [ -n "${TS_AUTHKEY:-}" ]; then
  if ! sudo tailscale up --authkey "${TS_AUTHKEY}" --ssh --accept-routes --accept-dns --advertise-tags="${TS_TAGS}"; then
    warn "Tailscale tags denied; retrying without tags"
    sudo tailscale up --reset || true
    sudo tailscale up --authkey "${TS_AUTHKEY}" --ssh --accept-routes --accept-dns || true
  fi
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

# 4) Build & install dump1090-fa (with deps)
log "Installing build deps & compiling dump1090-fa"
sudo apt-get install -y build-essential pkg-config libncurses-dev librtlsdr-dev libusb-1.0-0-dev git
mkdir -p "$APP_DIR"; cd "$APP_DIR"
[ -d dump1090-fa ] || git clone https://github.com/flightaware/dump1090.git dump1090-fa
cd dump1090-fa && make clean || true
make -j"$(nproc)"
sudo install -m0755 ./dump1090 /usr/local/bin/dump1090-fa

# 5) Python apps (create if missing to preserve local edits)
cd "$APP_DIR"
if [ ! -f collector.py ]; then
cat > collector.py <<'PY'
#!/usr/bin/env python3
import os, socket, time, gzip, pathlib
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
def rotate(buf, start_ns, hostname):
    if not buf: return
    epoch_ms=int(start_ns/1_000_000)
    fname=f"hex_{hostname}_{time.strftime('%Y%m%d', time.gmtime())}_{epoch_ms}.hex"
    fpath=os.path.join(PROC,fname)
    with open(fpath,"w") as f: f.write("\n".join(buf)+"\n")
    gz=fpath+".gz"
    with open(fpath,"rb") as src, gzip.open(gz,"wb") as dst: dst.writelines(src)
    os.remove(fpath); os.rename(gz, os.path.join(SEND, os.path.basename(gz)))
hostname=os.uname().nodename
with open(LOG,"a") as lg:
    lg.write(f"{tsu()} collector started\n"); lg.flush()
    while True:
        try:
            with socket.create_connection((HOST,PORT),timeout=5) as s:
                s.settimeout(0.2)
                buf=[]; start=time.monotonic_ns()
                while True:
                    try:
                        line=s.recv(65536)
                        if not line: time.sleep(0.01); continue
                        for raw in line.splitlines():
                            if not raw: continue
                            txt=raw.decode('ascii','ignore')
                            if not txt or txt[0]!="*": continue
                            hexv=txt[1:].split(';',1)[0].strip().upper()
                            buf.append(f"{hexv} {tsu()}")
                    except socket.timeout:
                        pass
                    now=time.monotonic_ns()
                    if len(buf)>=MAX_LINES or (now-start)/1e9>=MAX_SECS:
                        rotate(buf,start,hostname); buf=[]; start=now
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
REGION=os.environ.get("AWS_DEFAULT_REGION","us-east-2")
with open(LOG,"a") as lg: lg.write(f"{tsu()} uploader started\n"); lg.flush()
while True:
    files=sorted([f for f in os.listdir(SEND) if f.endswith(".hex.gz")])
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

# 6) Systemd units (dump1090-fa, collector, uploader)
log "Wiring systemd services"
sudo tee /etc/systemd/system/dump1090-fa.service >/dev/null <<'EOF'
[Unit]
Description=dump1090 ADS-B receiver (custom)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/dump1090-fa --device-index 0 --gain -10 --ppm 0 \
  --net --net-ro-port 30002 --net-sbs-port 30003 --net-bo-port 30005 \
  --write-json /run/dump1090-fa --json-location-accuracy 1
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/adsb-collector.service >/dev/null <<EOF
[Unit]
Description=ADS-B collector (.hex -> processing, gzip -> sending)
After=dump1090-fa.service
Requires=dump1090-fa.service
[Service]
User=${PI_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/collector.py
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/adsb-uploader.service >/dev/null <<EOF
[Unit]
Description=ADS-B uploader (to S3)
After=network-online.target
Wants=network-online.target
[Service]
User=${PI_USER}
Environment=S3_PREFIX=${S3_PREFIX}
Environment=AWS_DEFAULT_REGION=${AWS_REGION}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/uploader.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

# 7) Health timer (dump1090 + backlog + DNS self-heal)
log "Installing ADS-B health timer"
sudo tee /usr/local/sbin/adsb-health.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/adsb-health.log"
ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
# DNS self-heal
if ! systemctl is-active --quiet systemd-resolved; then
  printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
fi
# dump1090 up?
if ! ss -lnt | grep -q ':30002'; then
  systemctl restart dump1090-fa || true
fi
# uploader nudge if backlog
BASE="${HOME}/Documents/adsb"
SEND="${BASE}/files/sending"
S=$(ls -1 "${SEND}"/*.gz 2>/dev/null | wc -l || echo 0)
if [ "${S:-0}" -gt 0 ] && ! systemctl is-active --quiet adsb-uploader; then
  systemctl restart adsb-uploader || true
fi
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
ExecStart=/usr/local/sbin/adsb-health.sh
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
EOF
if [ -n "${REMOTEIT_R3:-}" ] && ! command -v remoteit >/dev/null 2>&1; then
  R3_REGISTRATION_CODE="${REMOTEIT_R3}" sh -c "$(curl -L https://downloads.remote.it/remoteit/install_agent.sh)" || warn "remote.it install returned non-zero"
fi

# 10) **LTE FAILOVER CORE** — create/manage GSM profile & failover timer
log "Configuring LTE fallback with NetworkManager + ModemManager"
# Create/patch LTE profile named 'lte'
if ! nmcli -t -f NAME,TYPE con show | grep -q '^lte:gsm$'; then
  sudo nmcli con add type gsm ifname "*" con-name lte apn "${SIXFAB_APN}"
fi
sudo nmcli con modify lte connection.autoconnect yes ipv4.method auto ipv6.method ignore
sudo nmcli con modify lte gsm.apn "${SIXFAB_APN}"
[ -n "${SIXFAB_PIN:-}" ] && sudo nmcli con modify lte gsm.pin "${SIXFAB_PIN}" || true
# Prefer Wi-Fi: raise priority of all wifi connections; LTE lower priority
while IFS= read -r WIFI_CON; do
  sudo nmcli con modify "$WIFI_CON" connection.autoconnect yes connection.autoconnect-priority 100 ipv4.route-metric 100 || true
done < <(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="wifi"{print $1}')
sudo nmcli con modify lte connection.autoconnect-priority 50 ipv4.route-metric 200
# Bring LTE up now (it will stay ready as fallback)
sudo nmcli con up lte || true

# Failover watchdog: if internet down, bring lte up
sudo tee /usr/local/sbin/net-failover.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
probe(){ curl -sS --ipv4 --max-time 5 https://s3.us-east-2.amazonaws.com/ >/dev/null; }
if ! probe; then
  nmcli con up lte >/dev/null 2>&1 || true
  sleep 5
  probe || nmcli con up lte >/dev/null 2>&1 || true
fi
EOF
sudo chmod +x /usr/local/sbin/net-failover.sh
sudo tee /etc/systemd/system/net-failover.service >/dev/null <<'EOF'
[Unit]
Description=Bring LTE up when internet is unreachable
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/net-failover.sh
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

# 11) Enable everything
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
ts(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; echo -n " "; }
log(){ echo "$(ts)$*"; }

# DNS guard
if ! systemctl is-active --quiet systemd-resolved; then
  log "[DNS] systemd-resolved down, writing temporary resolv.conf"
  printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf >/dev/null
fi

# Core services
systemctl start NetworkManager ModemManager || true

# Internet probe
probe(){ curl -sS --ipv4 --max-time 5 https://s3.us-east-2.amazonaws.com/ >/dev/null; }
if ! probe; then
  log "[NET] Internet not reachable, attempting LTE bring-up"
  nmcli con up lte >/dev/null 2>&1 || true
  sleep 8
fi

for i in $(seq 1 18); do
  if probe; then
    log "[NET] Internet reachable"
    break
  fi
  sleep 5
  if (( i % 3 == 0 )); then nmcli con up lte >/dev/null 2>&1 || true; fi
done

# Tailscale
if command -v tailscale >/dev/null 2>&1; then
  tailscale status >/dev/null 2>&1 || sudo tailscale up --ssh --accept-routes --accept-dns || true
  log "[TS] $(tailscale status | head -n 1 || echo 'status n/a')"
fi

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

UPLOG="$HOME/Documents/adsb/logs/uploader.log"
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
ExecStart=/usr/local/sbin/adsb-online-bootstrap.sh
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


# 13) Quick checks
log "Quick checks"
ss -lnt | egrep -q ':30002|:30003|:30005' && ok "dump1090 ports up" || warn "dump1090 port 30002 not listening yet"
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

#############################
# ADS-B Link Watchdog
# Restarts services if the sending queue backs up (>= THRESHOLD files)
# Idempotent; safe to re-run.
#############################
install_adsb_link_watchdog() {
  set -e

  # Choose a sensible default for the queue directory
  WATCH_DIR_DEFAULT="/opt/adsb/files/sending"
  if [ -d "/home/pi/adsb_monitor/files/sending" ]; then
    WATCH_DIR_DEFAULT="/home/pi/adsb_monitor/files/sending"
  elif [ -d "/opt/adsb_monitor/files/sending" ]; then
    WATCH_DIR_DEFAULT="/opt/adsb_monitor/files/sending"
  fi

  # 1) Config
  sudo tee /etc/default/adsb-link-watchdog >/dev/null <<'EOF_CFG'
# Folder where unsent files accumulate
WATCH_DIR="__WATCH_DIR__"

# Count threshold that indicates trouble
THRESHOLD=10

# Only count files older than this many seconds (ignore files still being written)
OLDER_THAN_SEC=15

# Don’t restart again until this many seconds have passed
COOLDOWN_SEC=300

# File pattern to count (leave "*" to count all files, or e.g. "*.hex")
FILE_PATTERN="*"

# Units to restart (only ones that exist/are active will actually restart)
SERVICES="dump1090-fa adsb-collector adsb-uploader remoteit connectd schannel"

# Optional: if you want to poke NetworkManager too (e.g., your LTE profile)
# NM_CONN="LTE-ECM"
EOF_CFG

  # Replace placeholder with detected default path
  sudo sed -i "s|__WATCH_DIR__|${WATCH_DIR_DEFAULT}|g" /etc/default/adsb-link-watchdog

  # 2) Watchdog script
  sudo install -d /usr/local/sbin
  sudo tee /usr/local/sbin/adsb_link_watchdog.sh >/dev/null <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -uo pipefail

# Load config if present
[ -f /etc/default/adsb-link-watchdog ] && . /etc/default/adsb-link-watchdog

: "${WATCH_DIR:=/opt/adsb/files/sending}"
: "${THRESHOLD:=10}"
: "${OLDER_THAN_SEC:=15}"
: "${COOLDOWN_SEC:=300}"
: "${FILE_PATTERN:=*}"
: "${SERVICES:=dump1090-fa adsb-collector adsb-uploader remoteit connectd schannel}"
: "${NM_CONN:=}"

LAST_FILE="/run/adsb-link-watchdog.last"
now_epoch=$(date +%s)
last_epoch=0
[ -f "$LAST_FILE" ] && last_epoch=$(date -r "$LAST_FILE" +%s 2>/dev/null || echo 0)

# If the directory is missing, nothing to do
if [ ! -d "$WATCH_DIR" ]; then
  logger -t adsb-link-watchdog "watch dir missing: $WATCH_DIR"
  exit 0
fi

# Count files older than OLDER_THAN_SEC
count=$(find "$WATCH_DIR" -maxdepth 1 -type f -name "$FILE_PATTERN" \
          -not -newermt "-${OLDER_THAN_SEC} seconds" 2>/dev/null | wc -l | tr -d ' ')

# Log a lightweight breadcrumb every run
logger -t adsb-link-watchdog "queue_count=$count threshold=$THRESHOLD cooldown_s=$COOLDOWN_SEC"

# Cooldown check
elapsed=$(( now_epoch - last_epoch ))
if [ "$count" -ge "$THRESHOLD" ] && [ "$elapsed" -ge "$COOLDOWN_SEC" ]; then
  logger -t adsb-link-watchdog "threshold exceeded (count=$count) – restarting services"
  for u in $SERVICES; do
    systemctl try-restart "$u" 2>/dev/null || systemctl restart "$u" 2>/dev/null || true
  done
  if [ -n "$NM_CONN" ]; then
    nmcli con up "$NM_CONN" 2>/dev/null || true
  fi
  touch "$LAST_FILE"
fi
EOF_SCRIPT
  sudo chmod +x /usr/local/sbin/adsb_link_watchdog.sh

  # 3) systemd unit + timer
  sudo tee /etc/systemd/system/adsb-link-watchdog.service >/dev/null <<'EOF_SVC'
[Unit]
Description=ADS-B link watchdog (restart services when queue backs up)
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/default/adsb-link-watchdog
ExecStart=/usr/local/sbin/adsb_link_watchdog.sh
Nice=10
EOF_SVC

  sudo tee /etc/systemd/system/adsb-link-watchdog.timer >/dev/null <<'EOF_TMR'
[Unit]
Description=Run ADS-B link watchdog periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=20s
AccuracySec=10s
Unit=adsb-link-watchdog.service
Persistent=true

[Install]
WantedBy=timers.target
EOF_TMR

  sudo systemctl daemon-reload
  sudo systemctl enable --now adsb-link-watchdog.timer

  echo "[setup] ADS-B link watchdog installed (watching: ${WATCH_DIR_DEFAULT})"
}

# Run it automatically when the setup script executes under systemd-capable OS
if command -v systemctl >/dev/null 2>&1; then
  install_adsb_link_watchdog || true
fi

