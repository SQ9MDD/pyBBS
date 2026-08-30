#!/bin/sh
set -eu

REPO_ARCHIVE_URL="${PYBBS_ARCHIVE_URL:-https://github.com/SQ9MDD/pyBBS/archive/refs/heads/main.tar.gz}"
INSTALL_DIR="/opt/pyBBS"
SERVICE_USER="pybbs"
SERVICE_GROUP="pybbs"
LOG_DIR="/var/log/pyBBS"
OPENRC_DIR="/etc/init.d"

say() {
    printf '%s\n' "pyBBS installer: $*"
}

die() {
    printf '%s\n' "pyBBS installer: ERROR: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || die "run this installer as root"
[ -f /etc/alpine-release ] || die "this installer supports Alpine Linux only"

say "installing system packages"
apk add --no-cache python3 curl ca-certificates openrc tar

if ! grep -q "^${SERVICE_GROUP}:" /etc/group; then
    addgroup -S "$SERVICE_GROUP"
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    adduser -S -D -H \
        -h "$INSTALL_DIR" \
        -s /sbin/nologin \
        -G "$SERVICE_GROUP" \
        "$SERVICE_USER"
fi

TMP_DIR="$(mktemp -d /tmp/pybbs-install.XXXXXX)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

say "downloading ${REPO_ARCHIVE_URL}"
curl -fL --retry 3 --connect-timeout 15 \
    "$REPO_ARCHIVE_URL" -o "$TMP_DIR/pybbs.tar.gz"
tar -xzf "$TMP_DIR/pybbs.tar.gz" -C "$TMP_DIR"

SOURCE_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[ -n "$SOURCE_DIR" ] || die "downloaded archive has no source directory"
[ -f "$SOURCE_DIR/bbs.py" ] || die "downloaded archive does not contain bbs.py"
[ -f "$SOURCE_DIR/pypacket_backend.py" ] || die "downloaded archive does not contain pypacket_backend.py"

install -d -m 0770 -o root -g "$SERVICE_GROUP" "$INSTALL_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$INSTALL_DIR/logs"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"

say "installing application in ${INSTALL_DIR}"
for file in bbs.py ax25_connector.py pypacket_backend.py; do
    install -m 0644 -o root -g root "$SOURCE_DIR/$file" "$INSTALL_DIR/$file"
done

for file in README.md LICENSE; do
    if [ -f "$SOURCE_DIR/$file" ]; then
        install -m 0644 -o root -g root "$SOURCE_DIR/$file" "$INSTALL_DIR/$file"
    fi
done

# Runtime configuration and editable BBS text survive repeat installations.
for file in pypacket_terminal_config.json info.txt motd.txt welcome.txt; do
    if [ ! -e "$INSTALL_DIR/$file" ] && [ -f "$SOURCE_DIR/$file" ]; then
        install -m 0640 -o "$SERVICE_USER" -g "$SERVICE_GROUP" \
            "$SOURCE_DIR/$file" "$INSTALL_DIR/$file"
    fi
done

for file in bbs_config.json pypacket_terminal_config.json info.txt motd.txt welcome.txt bbs.sqlite bbs.sqlite-wal bbs.sqlite-shm; do
    if [ -e "$INSTALL_DIR/$file" ]; then
        chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/$file"
    fi
done

cat > "$OPENRC_DIR/pybbs-backend" <<'OPENRC_BACKEND'
#!/sbin/openrc-run

name="pyBBS AX.25 backend"
description="KISS TCP and AX.25 connected-mode backend for pyBBS"
directory="/opt/pyBBS"
command="/usr/bin/python3"
command_args="/opt/pyBBS/pypacket_backend.py"
command_user="pybbs:pybbs"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
output_log="/var/log/pyBBS/backend.log"
error_log="/var/log/pyBBS/backend.log"
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

depend() {
    need net
}

start_pre() {
    checkpath --directory --mode 0750 --owner pybbs:pybbs /var/log/pyBBS
    checkpath --directory --mode 0750 --owner pybbs:pybbs /opt/pyBBS/logs
}
OPENRC_BACKEND

cat > "$OPENRC_DIR/pybbs" <<'OPENRC_BBS'
#!/sbin/openrc-run

name="pyBBS"
description="Telnet and AX.25 packet-radio BBS"
directory="/opt/pyBBS"
command="/usr/bin/python3"
command_args="/opt/pyBBS/bbs.py"
command_user="pybbs:pybbs"
supervisor="supervise-daemon"
respawn_delay=5
respawn_max=0
output_log="/var/log/pyBBS/pybbs.log"
error_log="/var/log/pyBBS/pybbs.log"
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

depend() {
    need net pybbs-backend
    after pybbs-backend
}

start_pre() {
    checkpath --directory --mode 0750 --owner pybbs:pybbs /var/log/pyBBS
    checkpath --directory --mode 0750 --owner pybbs:pybbs /opt/pyBBS/logs
}
OPENRC_BBS

chmod 0755 "$OPENRC_DIR/pybbs-backend" "$OPENRC_DIR/pybbs"
rc-update add pybbs-backend default >/dev/null
rc-update add pybbs default >/dev/null

if rc-service pybbs-backend status >/dev/null 2>&1; then
    rc-service pybbs-backend restart
else
    rc-service pybbs-backend start
fi

if rc-service pybbs status >/dev/null 2>&1; then
    rc-service pybbs restart
else
    rc-service pybbs start
fi

say "installation complete"
say "BBS config:     ${INSTALL_DIR}/bbs_config.json"
say "radio config:   ${INSTALL_DIR}/pypacket_terminal_config.json"
say "service status: rc-service pybbs-backend status; rc-service pybbs status"
say "logs:           ${LOG_DIR}/backend.log and ${LOG_DIR}/pybbs.log"
