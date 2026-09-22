FROM rockylinux:9-minimal

ARG APP_USER=developer

ENV APP_USER="${APP_USER}" \
    USER_ID=1000 \
    GROUP_ID=1000 \
    DISPLAY=:1 \
    VNC_PORT=5901 \
    VNC_RESOLUTION=1920x1080 \
    VNC_DEPTH=24 \
    VNC_LOCALHOST=no \
    HOME="/home/${APP_USER}" \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# -------------------------------------------------------------------
# Install:
#   - EPEL for XFCE packages
#   - minimal TigerVNC server
#   - minimal XFCE components
#   - sudo for privilege escalation
#   - shadow-utils for usermod/groupmod
#   - util-linux for runuser
#
# We intentionally do not install:
#   - full Xfce package group
#   - xorg-x11-server-Xorg
#   - display manager
#   - firewalld
#   - complete systemd desktop environment
# -------------------------------------------------------------------

RUN microdnf install -y epel-release \
    && microdnf install -y \
        --enablerepo=crb \
        --setopt=install_weak_deps=0 \
        sudo \
        shadow-utils \
        util-linux \
        tigervnc-server-minimal \
        xfce4-session \
        xfwm4 \
        xfce4-panel \
        xfce4-settings \
        xfce4-terminal \
        dbus-x11 \
        dejavu-sans-fonts \
    && microdnf clean all \
    && rm -rf \
        /var/cache/dnf \
        /var/cache/yum \
        /tmp/* \
        /var/tmp/*

# -------------------------------------------------------------------
# Create the normal development user.
#
# The numeric UID/GID below are only image defaults. They will be
# adjusted by entrypoint.sh at container startup.
# -------------------------------------------------------------------

RUN groupadd \
        --gid 1000 \
        "${APP_USER}" \
    && useradd \
        --uid 1000 \
        --gid 1000 \
        --groups wheel \
        --create-home \
        --shell /bin/bash \
        "${APP_USER}" \
    && mkdir -p \
        "/home/${APP_USER}/.vnc" \
        "/home/${APP_USER}/.config" \
        /workspace \
    && chown -R \
        "${APP_USER}:${APP_USER}" \
        "/home/${APP_USER}" \
        /workspace

# -------------------------------------------------------------------
# Passwordless sudo.
#
# The VNC session is still run as an ordinary user. The developer can
# use:
#   sudo command
#   sudo -i
#   sudo su -
# -------------------------------------------------------------------

RUN printf '%s\n' \
        "${APP_USER} ALL=(ALL:ALL) NOPASSWD: ALL" \
        > "/etc/sudoers.d/${APP_USER}" \
    && chmod 0440 "/etc/sudoers.d/${APP_USER}" \
    && visudo -cf "/etc/sudoers.d/${APP_USER}"

COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh

WORKDIR /workspace

EXPOSE 5901

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

