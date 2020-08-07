#!/usr/bin/env bash

# ===================================================================================================================================
# Description:   This is a script that automatically checks the completion of Docker CIS Hardening.
# Based on:      CIS_Docker_1.13.0_Benchmark_v1.0.0
# Author:        Barry Qu
# Email:         quziyou@hotmail.com
# Creation Date: 2020-05-06
# Update Date:   2020-08-06
# ===================================================================================================================================


# Trap signal-list
# ===================================================================================================================================
trap _exit INT QUIT TERM


# Parameters
# ===================================================================================================================================
cur_dir="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
stty_width=$(stty size|awk '{print $2}')
container_name="arms_db"
[[ $stty_width -lt 95 ]] && space_with=$((($stty_width-15))) || space_with=$((($stty_width-35)))
service_file=$(systemctl show -p FragmentPath docker.service |cut -d "=" -f2)
socket_file=$(systemctl show -p FragmentPath docker.socket |cut -d "=" -f2)
valid_docker_group_users=(
"root"
"sa_arms"
)
sensitive_dirs=(
"/"
"/boot"
"/dev"
"/etc"
"/lib"
"/proc"
"/sys"
"/usr"
)

declare -A check_items=(
    ["Item_001"]="Create a separate partition for containers."
    ["Item_002"]="Only allow trusted users to control Docker daemon."
    ["Item_003"]="Audit docker daemon."
    ["Item_004"]="Audit Docker files and directories - /var/lib/docker."
    ["Item_005"]="Audit Docker files and directories - /etc/docker."
    ["Item_006"]="Audit Docker files and directories - docker.service."
    ["Item_007"]="Audit Docker files and directories - docker.socket."
    ["Item_008"]="Audit Docker files and directories - /etc/default/docker."
    ["Item_009"]="Audit Docker files and directories - /etc/docker/daemon.json"
    ["Item_010"]="Audit Docker files and directories - /usr/bin/docker-containerd."
    ["Item_011"]="Audit Docker files and directories - /usr/bin/docker-runc."
    ["Item_012"]="Restrict network traffic between containers."
    ["Item_013"]="Set the logging level."
    ["Item_014"]="Allow Docker to make changes to iptables."
    ["Item_015"]="Do not use insecure registries."
    ["Item_016"]="Do not use the aufs storage driver."
    ["Item_017"]="Set default ulimit as appropriate."
    ["Item_018"]="Enable user namespace support."
    ["Item_019"]="Confirm default cgroup usage."
    ["Item_020"]="Do not change base device size until needed."
    ["Item_021"]="Use authorization plugin."
    ["Item_022"]="Configure centralized and remote logging"
    ["Item_023"]="Disable operations on legacy registry (v1)."
    ["Item_024"]="Enable live restore."
    ["Item_025"]="Do not enable swarm mode, if not needed."
    ["Item_026"]="Disable Userland Proxy."
    ["Item_027"]="Apply a daemon-wide custom seccomp profile, if needed."
    ["Item_028"]="Avoid experimental features in production."
    ["Item_029"]="Verify that docker.service file ownership is set to root:root."
    ["Item_030"]="Verify that docker.service file permissions are set to 644 or more restrictive."
    ["Item_031"]="Verify that docker.socket file ownership is set to root:root."
    ["Item_032"]="Verify that docker.socket file permissions are set to 644 or more restrictive."
    ["Item_033"]="Verify that /etc/docker directory ownership is set to root:root."
    ["Item_034"]="Verify that /etc/docker directory permissions are set to 755 or more restrictive."
    ["Item_035"]="Verify that registry certificate file ownership is set to root:root."
    ["Item_036"]="Verify that registry certificate file permissions are set to 444 or more restrictive."
    ["Item_037"]="Verify that Docker socket file ownership is set to root:docker."
    ["Item_038"]="Verify that Docker socket file permissions are set to 660 or more restrictive."
    ["Item_039"]="Verify that daemon.json file ownership is set to root:root."
    ["Item_040"]="Verify that daemon.json file permissions are set to 644 or more restrictive."
    ["Item_041"]="Verify that /etc/default/docker file ownership is set to root:root."
    ["Item_042"]="Verify that /etc/default/docker file permissions are set to 644 or more restrictive."
    ["Item_043"]="Create a user for the container."
    ["Item_044"]="Enable Content trust for Docker."
    ["Item_045"]="Do not use privileged containers."
    ["Item_046"]="Do not mount sensitive host system directories on containers."
    ["Item_047"]="Do not map privileged ports within containers."
    ["Item_048"]="Do not share the host's network namespace."
    ["Item_049"]="Limit memory usage for container."
    ["Item_050"]="Set container CPU priority appropriately."
    ["Item_051"]="Bind incoming container traffic to a specific host interface."
    ["Item_052"]="Set the 'on-failure' container restart policy to 5."
    ["Item_053"]="Do not share the host's process namespace."
    ["Item_054"]="Do not share the host's IPC namespace."
    ["Item_055"]="Do not directly expose host devices to containers."
    ["Item_056"]="Do not share the host's UTS namespace."
    ["Item_057"]="Do not disable default seccomp profile."
    ["Item_058"]="Confirm cgroup usage."
    ["Item_059"]="Restrict container from acquiring additional privileges."
    ["Item_060"]="Check container health at runtime."
    ["Item_061"]="Use PIDs cgroup limit."
    ["Item_062"]="Do not share the host's user namespaces."
    ["Item_063"]="Do not mount the Docker socket inside any containers."
)


# Check the permissions of the current user
# ===================================================================================================================================
[ ${EUID} -ne 0 ] && printf '\033[1;31;31m%b\033[0m' "This script must be run as root.\n" && exit 1


# Ensure the Docker Deamon is running
# ===================================================================================================================================
[[ $(ps  aux |grep docker |grep -v "grep docker") == "" ]]  && \
printf '\033[1;31;31m%b\033[0m' "Docker daemon must be running when you run this script.\n"  && \
exit 1


# Ensure Container of MongoDB is running
# ===================================================================================================================================
[[ $(docker ps --format "{{.Names}}" |grep -w ${container_name}) == "" ]] && \
printf '\033[1;31;31m%b\033[0m' "MongoDB Container must be running when you run this script.\n" && \
exit 1


# If socket file is missing, create a new one.
# ===================================================================================================================================
if [[ ! -f ${socket_file} ]]; then
    socket_dir=$(dirname ${service_file})
    cp ./docker.socket ${socket_dir} 
    systemctl unmask docker.service && systemctl unmask docker.socket
    docker stop ${container_name} && systemctl restart docker && docker start ${container_name}
    socket_file=$(systemctl show -p FragmentPath docker.socket  |cut -d "=" -f2)
fi


# Basic utility functions
# ===================================================================================================================================

_red() {
    printf '\033[1;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[1;31;33m%b\033[0m' "$1"
}

_passed() {
    printf "%-${space_with}b" "$1"
    msg="[PASSED]"
    _green "$msg\n"
}

_failed() {
    printf "%-${space_with}b" "$1"
    msg="[FAILED]"
    _red "$msg\n"
}


_printargs() {
    printf -- "%s" "[$(date)] "
    printf -- "%s" "$1"
    printf "\n"
}

_info() {
    _printargs "$@"
}

_warn() {
    printf -- "%s" "[$(date)] "
    _yellow "$1"
    printf "\n"
}

_error() {
    printf -- "%s" "[$(date)] "
    _red "$1"
    printf "\n"
    exit 2
}

_exit() {
    printf "\n"
    _red "$0 has been terminated."
    printf "\n"
    exit 1
}

_exists() {
    local cmd="$1"
    if eval type type > /dev/null 2>&1; then
        eval type "$cmd" > /dev/null 2>&1
    elif command > /dev/null 2>&1; then
        command -v "$cmd" > /dev/null 2>&1
    else
        which "$cmd" > /dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

_error_detect() {
    local cmd="$1"
    _info "${cmd}"
    eval ${cmd} 1> /dev/null
    if [ $? -ne 0 ]; then
        _error "Execution command (${cmd}) failed, please check it and try again."
    fi
}


# Functions for checking
# ===================================================================================================================================

check_item_001() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    mountpoint -- "$(docker info -f '{{ .DockerRootDir }}')" > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_002() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    docker_group_users=$(getent group docker |cut -d":" -f4 |sed "s/,/\n/g")
    invalid_user=""
    for user in ${docker_group_users[@]}; do
        if [[ ${valid_docker_group_users[@]/${user}/} == ${valid_docker_group_users[@]} ]]; then
           invalid_user=$invalid_user$user
        fi
    done
    if [[ ${invalid_user} != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_003() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /usr/bin/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_004() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /var/lib/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_005() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /etc/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_006() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep docker.service > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_007() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep docker.sock > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_008() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /etc/default/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_009() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /etc/docker/daemon.json > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_010() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /usr/bin/docker-containerd > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_011() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    auditctl -l | grep /usr/bin/docker-runc > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_012() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    icc=$(docker network ls --quiet | xargs xargs docker network inspect -f \
    '{{ .Name }}: {{ .Options }}' | sed "s/ /\n/g"| grep "com.docker.network.bridge.enable_icc:" | \
    cut -d ":" -f 2)
    if [[ $icc == "true" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_013() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    log_leve=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'log-level' |cut -d '=' -f2)
    if [[ $log_leve != "info" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_014() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    is_allow=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'iptables=' |cut -d '=' -f2)
    if [[ $is_allow == "true" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_015() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    insecure_registry=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'insecure-registry=' |cut -d '=' -f2)
    if [[ $insecure_registry != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_016() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    storage_driver=$(docker info |grep "Storage Driver" |cut -d ':' -f2 |sed 's/ //')
    if [[ $storage_driver == "aufs" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_017() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    default_ulimit=$(ps -ef | grep dockerd |grep "default-ulimit ")
    if [[ $default_ulimit == "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_018() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    security_options=$(docker info -f '{{ .SecurityOptions }}')
    _passed "[$item] ${check_items[$item]}"
}


check_item_019() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    cgroup_parent=$(ps -ef | grep dockerd |grep "cgroup-parent")
    if [[ $cgroup_parent == "" ]]; then
        _passed "[$item] ${check_items[$item]}"
    else
        _failed "[$item] ${check_items[$item]}"
    fi
}


check_item_020() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    storage_opt=$(ps -ef | grep dockerd |grep "storage-opt")
    if [[ $storage_opt == "" ]]; then
        _passed "[$item] ${check_items[$item]}"
    else
        _failed "[$item] ${check_items[$item]}"
    fi
}


check_item_021() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    authorization_plugin=$(ps -ef | grep dockerd |grep "authorization-plugin")
    _passed "[$item] ${check_items[$item]}"
}


check_item_022() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    log_driver=$(docker info -f '{{ .LoggingDriver }}')
    _passed "[$item] ${check_items[$item]}"
}


check_item_023() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    disable_legacy_registry=$(ps -ef | grep dockerd | grep "disable-legacy-registry")
    if [[ $disable_legacy_registry == "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_024() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    live_restore=$(docker info -f '{{ .LiveRestoreEnabled }}')
    if [[ $live_restore != "true" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_025() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    swarm=$(docker info |grep "Swarm" |cut -d " " -f2)
    if [[ $swarm == "active" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_026() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    userland_proxy=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep  'userland-proxy=' |cut -d '=' -f2)
    if [[ $userland_proxy != "false" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_027() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    seccomp_profile=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep  'seccomp-profile=' |cut -d '=' -f2)
    if [[ $seccomp_profile == "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_028() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    experimental=$(docker version -f '{{ .Server.Experimental }}')
    if [[ $experimental != "false" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_029() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    ownership=$(stat -c %U:%G ${service_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_030() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    permissions=$(stat -c %a ${service_file})
    if [[ $permissions -ne 644 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_031() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    ownership=$(stat -c %U:%G ${socket_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_032() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    permissions=$(stat -c %a ${socket_file})
    if [[ $permissions -ne 644 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_033() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local docker_dir="/etc/docker"
    ownership=$(stat -c %U:%G ${docker_dir} | grep -v root:root)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_034() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local docker_dir="/etc/docker"
    permissions=$(stat -c %a ${docker_dir})
    if [[ $permissions -ne 755 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_035() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local certs_dir="/etc/docker/certs.d"
    ownership=$(stat -c %U:%G ${certs_dir}/* | grep -v root:root)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_036() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local certs_dir="/etc/docker/certs.d"
    local files=$(find /etc/docker/certs.d/ -mindepth 1 -type d |xargs -i find {} -type f)
    local check_num=0
    for file in ${files[@]}; do
        local permissions=$(stat -c %a ${file})
        if [[ ${permissions} -ne 444 ]]; then
            check_num=$((($check_num+1)))
        fi
    done
    if [[ $check_num -gt 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_037() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local sock_file="/var/run/docker.sock"
    ownership=$(stat -c %U:%G ${sock_file} | grep -v root:docker)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_038() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local sock_file="/var/run/docker.sock"
    permissions=$(stat -c %a ${sock_file})
    if [[ $permissions -ne 660 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_039() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local daemon_file="/etc/docker/daemon.json"
    ownership=$(stat -c %U:%G ${daemon_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_040() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local daemon_file="/etc/docker/daemon.json"
    permissions=$(stat -c %a ${daemon_file})
    if [[ $permissions -ne 644 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_041() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local default_file="/etc/default/docker"
    [[ ! -f ${default_file} ]] && touch ${default_file}
    ownership=$(stat -c %U:%G ${default_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_042() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local default_file="/etc/default/docker"
    permissions=$(stat -c %a ${default_file})
    if [[ $permissions -ne 644 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_043() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local container_user=$(docker inspect -f '{{ .Config.User }}' ${container_name})
    if [[ $container_user == "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_044() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local content_trust=$(echo $DOCKER_CONTENT_TRUST)
    if [[ $content_trust -ne 1 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_045() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local check_res=$(docker inspect -f '{{ .HostConfig.Privileged }}' ${container_name})
    if [[ $check_res != "false" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_046() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local pinds=$(docker inspect --format '{{range .HostConfig.Binds}}{{println .}}{{end}}' $container_name |cut -d ':' -f1)
    local check_num=0
    local invalid_dirs=""
    for dir in ${pinds[@]}; do
        for sen_dir in ${sensitive_dirs[@]}; do
            if [[ ${dir} == ${sen_dir} ]]; then
                invalid_dirs=$invalid_dirs$dir
                echo $dir
            fi
        done
    done
    if [[ $invalid_dirs != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_047() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local ports=$(docker inspect -f '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' ${container_name} |grep -Eo "HostPort:[0-9]{1,5}" |cut -d ':' -f2)
    check_num=0
    for port in ${ports[@]}; do
    	if [[ $port -lt 1024 ]]; then
    		check_num=$((($check_num +1 )))
    	fi
    done
    if [[ $check_num -ne 0 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_048() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local net=$(docker inspect -f '{{ .HostConfig.NetworkMode }}' ${container_name} |cut -d '=' -f2)
    if [[ $net == "host" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_049() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local mem=$(docker inspect -f '{{ .Id }}: Memory={{.HostConfig.Memory}}' ${container_name} |cut -d '=' -f2)
    if [[ $mem == "0" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_050() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local cpu_share=$(docker inspect -f '{{.HostConfig.CpuShares}}' ${container_name} |cut -d '=' -f2)
    if [[ $cpu_share == "0" || $cpu_share == "1024" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_051() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local host_ip=$(docker inspect -f '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' ${container_name} |grep -Eo "HostIp:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" |cut -d ':' -f2)
    if [[ $host_ip == "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_052() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local restart_policy_name=$(docker inspect -f '{{ .HostConfig.RestartPolicy.Name }}' ${container_name})
    local restart_max_count=$(docker inspect -f '{{ .HostConfig.RestartPolicy.MaximumRetryCount }}' ${container_name})
    if [[ $restart_policy_name != "on-failure" || $restart_max_count -ne 5 ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_053() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local pid_mod=$(docker inspect -f '{{ .HostConfig.PidMode }}' ${container_name})
    if [[ $pid_mod == "host" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_054() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local ipc_mod=$(docker inspect -f '{{ .HostConfig.IpcMode  }}' ${container_name})
    if [[ $ipc_mod == "host" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_055() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local devices=$(docker inspect -f '{{ .HostConfig.Devices }}' ${container_name})
    if [[ $devices != "[]" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_056() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local uts_mode=$(docker inspect -f '{{ .HostConfig.UTSMode }}' ${container_name})
    if [[ $uts_mode == "host" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_057() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local security_opt=$(docker inspect -f '{{ .HostConfig.SecurityOpt }}' ${container_name})
    if [[ $security_opt == "[host]" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_058() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local cgroup=$(docker inspect -f '{{ .HostConfig.CgroupParent }}' ${container_name})
    if [[ $cgroup != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_059() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local security_opt=$(docker inspect -f '{{ .HostConfig.SecurityOpt }}' ${container_name})
    if [[ $security_opt != "[no-new-privileges]" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_060() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local health_check=$(docker inspect -f '{{ .State.Health.Status }}' ${container_name})
    if [[ $health_check == "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_061() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local pids_limit=$(docker inspect -f '{{ .HostConfig.PidsLimit }}' ${container_name})
    if [[ $pids_limit == "0" || $pids_limit == "-1" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_062() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local user_ns_mode=$(docker inspect -f '{{ .HostConfig.UsernsMode }}' ${container_name})
    if [[ $user_ns_mode == "host" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_063() {
    num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item="Item_$num"
    local sock_mount=$(docker inspect -f 'Volumes={{ .Mounts }}' ${container_name} | grep docker.sock)
    if [[ $sock_mount != "" ]]; then
        _failed "[$item] ${check_items[$item]}"
    else
        _passed "[$item] ${check_items[$item]}"
    fi
}


check_item_001 && \
check_item_002 && \
check_item_003 && \
check_item_004 && \
check_item_005 && \
check_item_006 && \
check_item_007 && \
check_item_008 && \
check_item_009 && \
check_item_010 && \
check_item_011 && \
check_item_012 && \
check_item_013 && \
check_item_014 && \
check_item_015 && \
check_item_016 && \
check_item_017 && \
check_item_018 && \
check_item_019 && \
check_item_020 && \
check_item_021 && \
check_item_022 && \
check_item_023 && \
check_item_024 && \
check_item_025 && \
check_item_026 && \
check_item_027 && \
check_item_028 && \
check_item_029 && \
check_item_030 && \
check_item_031 && \
check_item_032 && \
check_item_033 && \
check_item_034 && \
check_item_035 && \
check_item_036 && \
check_item_037 && \
check_item_038 && \
check_item_039 && \
check_item_040 && \
check_item_041 && \
check_item_042 && \
check_item_043 && \
check_item_044 && \
check_item_045 && \
check_item_046 && \
check_item_047 && \
check_item_048 && \
check_item_049 && \
check_item_050 && \
check_item_051 && \
check_item_052 && \
check_item_053 && \
check_item_054 && \
check_item_055 && \
check_item_056 && \
check_item_057 && \
check_item_058 && \
check_item_059 && \
check_item_060 && \
check_item_061 && \
check_item_062 && \
check_item_063