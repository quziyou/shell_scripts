#!/usr/bin/env bash

set -Eeuo pipefail

APP_USER="${APP_USER:-developer}"
USER_ID="${USER_ID:-1000}"
GROUP_ID="${GROUP_ID:-1000}"

DISPLAY="${DISPLAY:-:1}"
VNC_PORT="${VNC_PORT:-5901}"
VNC_RESOLUTION="${VNC_RESOLUTION:-1920x1080}"
VNC_DEPTH="${VNC_DEPTH:-24}"
VNC_LOCALHOST="${VNC_LOCALHOST:-no}"

APP_HOME="/home/${APP_USER}"
VNC_DIR="${APP_HOME}/.vnc"
VNC_PASSWD_FILE="${VNC_DIR}/passwd"

X_DISPLAY_NUMBER="${DISPLAY#:}"
X_SOCKET="/tmp/.X11-unix/X${X_DISPLAY_NUMBER}"
X_LOCK="/tmp/.X${X_DISPLAY_NUMBER}-lock"

XDG_RUNTIME_DIR="/tmp/runtime-${APP_USER}"

XVNC_PID=""
XFCE_PID=""

log()
{
    printf '[entrypoint] %s\n' "$*"
}


fatal()
{
    printf '[entrypoint] ERROR: %s\n' "$*" >&2
    exit 1
}


is_positive_integer()
{
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]
}


cleanup()
{
    local exit_code=$?

    trap - SIGTERM SIGINT SIGQUIT EXIT

    log "Stopping XFCE and VNC processes..."

    if [ -n "${XFCE_PID}" ] && kill -0 "${XFCE_PID}" 2>/dev/null; then
        kill -TERM "${XFCE_PID}" 2>/dev/null || true
    fi

    if [ -n "${XVNC_PID}" ] && kill -0 "${XVNC_PID}" 2>/dev/null; then
        kill -TERM "${XVNC_PID}" 2>/dev/null || true
    fi

    if [ -n "${XFCE_PID}" ]; then
        wait "${XFCE_PID}" 2>/dev/null || true
    fi

    if [ -n "${XVNC_PID}" ]; then
        wait "${XVNC_PID}" 2>/dev/null || true
    fi

    rm -f "${X_LOCK}" "${X_SOCKET}"

    exit "${exit_code}"
}


trap cleanup SIGTERM SIGINT SIGQUIT EXIT


# -------------------------------------------------------------------
# Validate configuration
# -------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] \
    || fatal "The entrypoint must initially run as root."

id "${APP_USER}" >/dev/null 2>&1 \
    || fatal "User '${APP_USER}' does not exist."

is_positive_integer "${USER_ID}" \
    || fatal "USER_ID must be a positive integer: ${USER_ID}"

is_positive_integer "${GROUP_ID}" \
    || fatal "GROUP_ID must be a positive integer: ${GROUP_ID}"

[[ "${VNC_PORT}" =~ ^[0-9]+$ ]] \
    || fatal "VNC_PORT must be numeric: ${VNC_PORT}"

[[ "${VNC_DEPTH}" =~ ^[0-9]+$ ]] \
    || fatal "VNC_DEPTH must be numeric: ${VNC_DEPTH}"

[[ "${VNC_RESOLUTION}" =~ ^[0-9]+x[0-9]+$ ]] \
    || fatal "VNC_RESOLUTION must use WIDTHxHEIGHT, for example 1920x1080."

case "${VNC_LOCALHOST}" in
    yes|no)
        ;;
    *)
        fatal "VNC_LOCALHOST must be either 'yes' or 'no'."
        ;;
esac

: "${VNC_PW:?VNC_PW must be specified}"


# -------------------------------------------------------------------
# Dynamically configure the primary GID
# -------------------------------------------------------------------
CURRENT_UID="$(id -u "${APP_USER}")"
CURRENT_GID="$(id -g "${APP_USER}")"
CURRENT_GROUP="$(id -gn "${APP_USER}")"

log "Requested identity: UID=${USER_ID}, GID=${GROUP_ID}"
log "Current identity:   UID=${CURRENT_UID}, GID=${CURRENT_GID}"


if [ "${CURRENT_GID}" -ne "${GROUP_ID}" ]; then
    EXISTING_GROUP_ENTRY="$(getent group "${GROUP_ID}" || true)"

    if [ -n "${EXISTING_GROUP_ENTRY}" ]; then
        TARGET_GROUP="$(printf '%s' "${EXISTING_GROUP_ENTRY}" | cut -d: -f1)"

        log "GID ${GROUP_ID} is already owned by group '${TARGET_GROUP}'."
        log "Using '${TARGET_GROUP}' as the primary group for '${APP_USER}'."

        usermod \
            --gid "${TARGET_GROUP}" \
            "${APP_USER}"
    else
        log "Changing group '${CURRENT_GROUP}' GID to ${GROUP_ID}."

        groupmod \
            --gid "${GROUP_ID}" \
            "${CURRENT_GROUP}"
    fi
fi


# -------------------------------------------------------------------
# Dynamically configure UID
# -------------------------------------------------------------------
if [ "${CURRENT_UID}" -ne "${USER_ID}" ]; then
    EXISTING_USER="$(getent passwd "${USER_ID}" | cut -d: -f1 || true)"

    if [ -n "${EXISTING_USER}" ] && [ "${EXISTING_USER}" != "${APP_USER}" ]; then
        fatal "UID ${USER_ID} is already used by user '${EXISTING_USER}'."
    fi

    log "Changing user '${APP_USER}' UID to ${USER_ID}."

    usermod \
        --uid "${USER_ID}" \
        "${APP_USER}"
fi


# Refresh identity after usermod/groupmod
EFFECTIVE_UID="$(id -u "${APP_USER}")"
EFFECTIVE_GID="$(id -g "${APP_USER}")"
EFFECTIVE_GROUP="$(id -gn "${APP_USER}")"

log "Effective identity: UID=${EFFECTIVE_UID}, GID=${EFFECTIVE_GID}"
log "Effective group:    ${EFFECTIVE_GROUP}"


# -------------------------------------------------------------------
# Fix only the user's internal home directory.
#
# Do not recursively chown /workspace here. If /workspace is a bind
# mount, its ownership should match USER_ID/GROUP_ID supplied by the
# caller. Automatically chowning a large host directory would be slow
# and would modify host-side ownership unexpectedly.
# -------------------------------------------------------------------
mkdir -p \
    "${VNC_DIR}" \
    "${APP_HOME}/.config" \
    "${XDG_RUNTIME_DIR}" \
    /tmp/.X11-unix

chown -R \
    "${EFFECTIVE_UID}:${EFFECTIVE_GID}" \
    "${APP_HOME}"

chown \
    "${EFFECTIVE_UID}:${EFFECTIVE_GID}" \
    "${XDG_RUNTIME_DIR}"

chmod 0700 "${XDG_RUNTIME_DIR}"
chmod 1777 /tmp/.X11-unix


# -------------------------------------------------------------------
# Generate the VNC password at runtime.
#
# The password is not stored in the image.
# -------------------------------------------------------------------
log "Generating runtime VNC password file."

umask 077

printf '%s\n' "${VNC_PW}" \
    | runuser -u "${APP_USER}" -- vncpasswd -f \
    > "${VNC_PASSWD_FILE}"

chown \
    "${EFFECTIVE_UID}:${EFFECTIVE_GID}" \
    "${VNC_PASSWD_FILE}"

chmod 0600 "${VNC_PASSWD_FILE}"

# Remove the password from the exported environment before starting
# the desktop processes.
unset VNC_PW


# -------------------------------------------------------------------
# Remove files left behind by an unclean previous shutdown
# -------------------------------------------------------------------
rm -f \
    "${X_LOCK}" \
    "${X_SOCKET}" \
    "${VNC_DIR}"/*.pid \
    "${VNC_DIR}"/*.log


# -------------------------------------------------------------------
# Start Xvnc as the ordinary developer user
# -------------------------------------------------------------------
log "Starting Xvnc on display ${DISPLAY}, TCP port ${VNC_PORT}."

runuser -u "${APP_USER}" -- \
    env \
        HOME="${APP_HOME}" \
        USER="${APP_USER}" \
        LOGNAME="${APP_USER}" \
        DISPLAY="${DISPLAY}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
    Xvnc "${DISPLAY}" \
        -rfbport "${VNC_PORT}" \
        -rfbauth "${VNC_PASSWD_FILE}" \
        -geometry "${VNC_RESOLUTION}" \
        -depth "${VNC_DEPTH}" \
        -localhost "${VNC_LOCALHOST}" \
        -AlwaysShared \
        -SecurityTypes VncAuth \
        -nolisten tcp &

XVNC_PID=$!

log "Xvnc PID: ${XVNC_PID}"


# -------------------------------------------------------------------
# Wait until the X11 Unix socket exists
# -------------------------------------------------------------------
X_READY=0

for attempt in $(seq 1 50); do
    if ! kill -0 "${XVNC_PID}" 2>/dev/null; then
        wait "${XVNC_PID}" || true
        fatal "Xvnc exited before the X display became ready."
    fi

    if [ -S "${X_SOCKET}" ]; then
        X_READY=1
        break
    fi

    sleep 0.2
done

[ "${X_READY}" -eq 1 ] \
    || fatal "X display ${DISPLAY} did not become ready."


# -------------------------------------------------------------------
# Start minimal XFCE session as the ordinary developer user
# -------------------------------------------------------------------
log "Starting XFCE session as '${APP_USER}'."

runuser -u "${APP_USER}" -- \
    env \
        HOME="${APP_HOME}" \
        USER="${APP_USER}" \
        LOGNAME="${APP_USER}" \
        SHELL=/bin/bash \
        DISPLAY="${DISPLAY}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR}" \
        XDG_CONFIG_HOME="${APP_HOME}/.config" \
    dbus-launch \
        --exit-with-session \
        xfce4-session &

XFCE_PID=$!

log "XFCE PID: ${XFCE_PID}"
log "VNC desktop is ready."
log "User: ${APP_USER}"
log "UID:GID: ${EFFECTIVE_UID}:${EFFECTIVE_GID}"
log "Workspace: /workspace"


# -------------------------------------------------------------------
# Stop the whole container if either the VNC server or XFCE exits.
# -------------------------------------------------------------------
set +e

while true; do
    if ! kill -0 "${XVNC_PID}" 2>/dev/null; then
        wait "${XVNC_PID}"
        STATUS=$?
        log "Xvnc exited with status ${STATUS}."
        exit "${STATUS}"
    fi

    if ! kill -0 "${XFCE_PID}" 2>/dev/null; then
        wait "${XFCE_PID}"
        STATUS=$?
        log "XFCE exited with status ${STATUS}."
        exit "${STATUS}"
    fi

    sleep 1
done
