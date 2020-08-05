#!/usr/bin/env bash

# ==================================================================================================================
# Description:   This is a script that automatically do the  Docker CIS Hardening.
# Based on:      CIS_Docker_1.13.0_Benchmark_v1.0.0
# Author:        Barry Qu
# Email:         quziyou@hotmail.com
# Creation Date: 2020-05-06
# Update Date:   2020-05-12
# ==================================================================================================================


# Trap signal-list
# ==================================================================================================================
trap _exit INT QUIT TERM


# Parameters
# ==================================================================================================================
stty_width=$(stty size|awk '{print $2}')
split_line=$(printf "%-${stty_width}s" "="| sed "s/ /=/g")
cur_dir="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
host_ip="127.0.0.1"
local_port=5389
internal_port=4978
container_name="arms_db"
container_user="mongodb"
container_memory="4G"
container_cpu=512
local_dir="/data/mongodb/"
internal_dir="/data/db/"
config_file=${internal_dir}mongoconf.yml
docker_audit_file="/etc/audit/rules.d/docker_hardening.rules"
report_file_name="${cur_dir}/Docker_CIS_Hardening_Report.txt"
service_file=$(systemctl show -p FragmentPath docker.service |cut -d "=" -f2)
socket_file=$(systemctl show -p FragmentPath docker.socket  |cut -d "=" -f2)
setting_row=$(grep -n "ExecStart=/usr/bin/dockerd-current" ${file} |cut -d ":" -f1)
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
# ==================================================================================================================
[ ${EUID} -ne 0 ] && printf '\033[1;31;31m%b\033[0m' "This script must be run as root.\n" && exit 1


# Ensure the Docker Deamon is running
# ==================================================================================================================
[[ $(ps  aux |grep docker |grep -v "grep docker") == "" ]]  && \
printf '\033[1;31;31m%b\033[0m' "Docker daemon must be running when you run this script.\n"  && \
exit 1


# Ensure Container of MongoDB is running
# ==================================================================================================================
[[ $(docker ps --format "table {{.Names}}" |grep -w ${container_name}) == "" ]] && \
printf '\033[1;31;31m%b\033[0m' "MongoDB Container must be running when you run this script.\n" && \
exit 1


# Ensure the Docker Deamon is running
# ==================================================================================================================
cp ${service_file} "${service_file}/docker.service.bak"


# Basic utility functions
# ==================================================================================================================

_red() {
    printf '\033[1;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[1;31;33m%b\033[0m' "$1"
}

_completed() {
    printf "%-95b" "$1"
    msg="[COMPLETED]"
    _green "$msg\n"
}

_failed() {
    printf "%-95b" "$1"
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

_sucess() {
    printf -- "%s" "[$(date)] "
    _green "$1"
    printf "\n"
    exit 0
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
    else
        _green "Execution command (${cmd}) sucessful."
        printf "\n"
    fi
}

_error_detect_item_001() {
    local cmd="$1"
    _info "${cmd}"
    local res=$(eval ${cmd})
    eval ${cmd} 1> /dev/null
    if [ $? -ne 0 ]; then
        _warn "[WARN] ${res}"
    else
        _green "Execution command (${cmd}) sucessful."
        _info "${res}"
        printf "\n"
    fi
}

report_writer() {
    if [[ ! -f ${report_file_name} ]]; then
        echo "Report for Docker CIS Hardening" > ${report_file_name}
    fi
    echo >> ${report_file_name}
    echo >> ${report_file_name}
    task_num="$1"
    task_name="$2"
    echo "${task_num}  ${task_name}" >> ${report_file_name}
    printf "%-135s\n" "="| sed "s/ /=/g" >> ${report_file_name}
}


# Functions for hardening
# ==================================================================================================================

harden_item_001() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    cmd="mountpoint -- $(docker info -f '{{ .DockerRootDir }}')"
    report_writer "${item_num}" "${task_name}"
    _error_detect_item_001 "$cmd" | tee -a $report_file_name
    printf "\n\n"
}


harden_item_002() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    if [[ $(getent group docker) == "" ]]; then
    	_error_detect "groupadd docker" | tee -a $report_file_name
    	for user in ${valid_docker_group_users[@]}; do
    		_error_detect "gpasswd -a $user docker" | tee -a $report_file_name
    	done
    else
	    docker_group_users=$(getent group docker |cut -d":" -f4 |sed "s/,/\n/g")
	    for user in ${docker_group_users[@]}; do
	        _error_detect "gpasswd -d ${user} docker" | tee -a $report_file_name
	    done
	    for user in ${valid_docker_group_users[@]}; do
    		_error_detect "gpasswd -a $user docker" | tee -a $report_file_name
    	done
	fi
	printf "\n\n"
}


harden_item_003() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /usr/bin/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /usr/bin/docker -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /usr/bin/docker" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_004() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /var/lib/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /var/lib/docker -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /var/lib/docker" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_005() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /etc/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /etc/docker -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /etc/docker" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_006() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep docker.service > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
    	local file=$(systemctl show -p FragmentPath docker.service |cut -d "=" -f2)
        _error_detect "echo '-w ${file} -k docker' >> ${docker_audit_file}" | tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep docker.service" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_007() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    socket_dir=$(dirname ${service_file})
    [[ ! -f ${socket_file} ]] && cp ./docker.socket ${socket_dir} \
    systemctl unmask docker.service && systemctl unmask docker.socket && systemctl restart docker
    socket_file=$(systemctl show -p FragmentPath docker.socket  |cut -d "=" -f2)
    auditctl -l | grep docker.sock > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w ${socket_file} -p rwxa -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep docker.sock" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_008() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /etc/default/docker > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /etc/default/docker -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /etc/default/docker" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_009() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /etc/docker/daemon.json > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /etc/docker/daemon.json -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /etc/docker/daemon.json" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_010() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /usr/bin/docker-containerd > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /usr/bin/docker-containerd -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /usr/bin/docker-containerd" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_011() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    auditctl -l | grep /usr/bin/docker-runc > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        _error_detect "echo '-w /usr/bin/docker-runc -k docker' >> ${docker_audit_file}" | \
        tee -a $report_file_name
        _error_detect "service auditd restart" | tee -a $report_file_name
    else
    	_error_detect "auditctl -l | grep /usr/bin/docker-runc" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_012() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local cmd=""
    icc=$(docker network ls --quiet | xargs xargs docker network inspect --format \
    '{{ .Name }}: {{ .Options }}' | sed 's/ /\n/g'| grep 'com.docker.network.bridge.enable_icc:' | \
    cut -d ':' -f 2)
    if [[ $icc == "true" ]]; then
    	local content="--icc=false \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}" | tee -a $report_file_name
        systemctl daemon-reload
        systemctl restart docker
    else
        local cmd="ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'icc'"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_013() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    log_leve=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'log-level' |cut -d '=' -f2)
    if [[ $log_leve != "info" ]]; then
    	local content="--log-level=info \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'log-level'"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_014() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    is_allow=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'iptables=' |cut -d '=' -f2)
    if [[ $is_allow == "false" ]]; then
    	local cmd="sed -i '/--iptables=/d' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'iptables='"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_015() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    insecure_registry=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'insecure-registry=' |cut -d '=' -f2)
    if [[ $insecure_registry != "" ]]; then
    	local cmd="sed -i '/insecure-registry=/d' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'insecure-registry='"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_016() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    storage_driver=$(docker info |grep "Storage Driver" |cut -d ':' -f2 |sed 's/ //')
    if [[ $storage_driver == "aufs" ]]; then
    	local content="--storage-driver overlay2 \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd='docker info |grep "Storage Driver" |cut -d ":" -f2 |sed "s/ //"'
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_017() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    default_ulimit=$(docker info |grep "default-ulimit")
    if [[ $default_ulimit == "" ]]; then
    	local content="--default-ulimit nproc=1024:2408 --default-ulimit nofile=100:200 \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd='docker info |grep "Storage Driver" |cut -d ":" -f2 |sed "s/ //"'
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_018() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    security_options=$(docker info --format '{{ .SecurityOptions }}')
    local cmd="docker info --format '{{ .SecurityOptions }}'"
    _info "${cmd}\n" | tee -a $report_file_name
    _info "Keep the default setting."
    _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    printf "\n\n"
}


harden_item_019() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    cgroup_parent=$(ps -ef | grep dockerd |grep "cgroup-parent")
    if [[ $cgroup_parent != "" ]]; then
    	local cmd="sed -i '/cgroup-parent=/d' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd='ps -ef | grep dockerd |grep "cgroup-parent"'
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_020() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    storage_opt=$(ps -ef | grep dockerd |grep "storage-opt")
    if [[ $storage_opt != "" ]]; then
    	local cmd="sed -i 's/\-\-storage-opt dm.basesize=..G //' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd='ps -ef | grep dockerd |grep "storage-opt"'
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_021() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    authorization_plugin=$(ps -ef | grep dockerd |grep "authorization-plugin")
    local cmd='ps -ef | grep dockerd |grep "authorization-plugin"'
    _info "${cmd}\n" | tee -a $report_file_name
    _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    printf "\n\n"
}


harden_item_022() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    log_driver=$(docker info --format '{{ .LoggingDriver }}')
    local cmd="docker info --format '{{ .LoggingDriver }}'"
    _info "${cmd}\n" | tee -a $report_file_name
    _info "Logging Driver will be set up by Containers."
    _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    printf "\n\n"
}


harden_item_023() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    disable_legacy_registry=$(ps -ef | grep dockerd | grep "disable-legacy-registry")
    if [[ $disable_legacy_registry == "" ]]; then
    	local content="--disable-legacy-registry \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd='ps -ef | grep dockerd | grep "disable-legacy-registry"'
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_024() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    live_restore=$(docker info --format '{{ .LiveRestoreEnabled }}')
    if [[ $live_restore != "true" ]]; then
    	local content="--live-restore \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${setting_row}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="docker info --format '{{ .LiveRestoreEnabled }}'"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_025() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    swarm=$(docker info |grep "Swarm" |cut -d " " -f2)
    if [[ $swarm == "active" ]]; then
    	local cmd="docker swarm leave --force"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd='docker info |grep "Swarm" |cut -d " " -f2'
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_026() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    userland_proxy=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'userland-proxy=' |cut -d '=' -f2)
    if [[ $userland_proxy != "false" ]]; then
    	local content="--userland-proxy=false \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="ps -ef | grep dockerd |sed 's/ /\n/g' |grep 'userland-proxy=' |cut -d '=' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_027() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    seccomp_profile=$(ps -ef | grep dockerd |sed 's/ /\n/g' |grep  'seccomp-profile=' |cut -d '=' -f2)
    if [[ $seccomp_profile == "" ]]; then
    	local content="--seccomp-profile=/etc/docker/seccomp.json \\\\"
    	local cmd="sed -i 'N;${setting_row}a${content}' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="ps -ef | grep dockerd |sed 's/ /\n/g' |grep  'seccomp-profile=' |cut -d '=' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_028() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    experimental=$(docker version --format '{{ .Server.Experimental }}')
    if [[ $experimental != "false" ]]; then
    	local content="--seccomp-profile=/etc/docker/seccomp.json \\\\"
    	local cmd="sed -i '/--experimental/d' ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="docker version --format '{{ .Server.Experimental }}'"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_029() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${service_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
    	local cmd="chown root:root ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${service_file} | grep -v root:root"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_030() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    permissions=$(stat -c %a ${service_file})
    if [[ $permissions -ne 644 ]]; then
    	local cmd="chmod 644 ${service_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %a ${service_file}"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_031() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${socket_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
    	local cmd="chown root:root ${socket_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${socket_file} | grep -v root:root"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_032() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    permissions=$(stat -c %a ${socket_file})
    if [[ $permissions -ne 644 ]]; then
    	local cmd="chmod 644 ${socket_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %a ${socket_file}"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_033() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local docker_dir="etc/docker"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${docker_dir} | grep -v root:root)
    if [[ $ownership != "" ]]; then
    	local cmd="chown root:root ${docker_dir}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${docker_dir} | grep -v root:root"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_034() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local docker_dir="etc/docker"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    permissions=$(stat -c %a ${docker_dir})
    if [[ $permissions -ne 755 ]]; then
    	local cmd="chmod 755 ${docker_dir}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %a ${docker_dir}"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_035() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local certs_dir="/etc/docker/certs.d"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${certs_dir}/* | grep -v root:root)
    if [[ $ownership != "" ]]; then
    	local cmd="chown -R root:root ${certs_dir}/*"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${certs_dir} | grep -v root:root"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_036() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local certs_dir="/etc/docker/certs.d/"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local cmd="find ${certs_dir} -mindepth 1 -type d |xargs -i find {} -type f |xargs chmod 444"
    _error_detect "${cmd}"  | tee -a $report_file_name
    printf "\n\n"
}


harden_item_037() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local sock_file="/var/run/docker.sock"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${sock_file} | grep -v root:docker)
    if [[ $ownership != "" ]]; then
    	local cmd="chown root:docker ${sock_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${sock_file} | grep -v root:docker"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_038() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local sock_file="/var/run/docker.sock"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    permissions=$(stat -c %a ${sock_file})
    if [[ $permissions -ne 660 ]]; then
    	local cmd="chmod 660 ${sock_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %a ${sock_file}"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_039() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local daemon_file="/etc/docker/daemon.json"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${daemon_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
    	local cmd="chown root:root ${daemon_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${daemon_file} | grep -v root:root"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_040() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local daemon_file="/etc/docker/daemon.json"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    permissions=$(stat -c %a ${daemon_file})
    if [[ $permissions -ne 644 ]]; then
    	local cmd="chmod 644 ${daemon_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %a ${daemon_file}"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_041() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local default_file="/etc/default/docker"
    [[ ! -f ${default_file} ]] && touch ${default_file}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    ownership=$(stat -c %U:%G ${default_file} | grep -v root:root)
    if [[ $ownership != "" ]]; then
    	local cmd="chown root:root ${default_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %U:%G ${default_file} | grep -v root:root"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_042() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    local default_file="/etc/default/docker"
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    permissions=$(stat -c %a ${default_file})
    if [[ $permissions -ne 644 ]]; then
    	local cmd="chmod 644 ${default_file}"
        _error_detect "${cmd}"  | tee -a $report_file_name
    else
        local cmd="stat -c %a ${default_file}"
        _info "${cmd}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


# Attention: Parameters (such as port, volume) must be set according to the actual situation.
harden_item_043() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local container_info=$(docker inspect --format '{{ .Id }}:{{ .Config.User }}' ${container_name})
    local container_user=$(echo ${container_info} |cut -d ":" -f2)
    if [[ $container_user == "" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
        _error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}:{{ .Config.User }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Container Info: ${container_info}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_044() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local content_trust=$(echo $DOCKER_CONTENT_TRUST)
    if [[ $content_trust -ne 1 ]]; then
    	local cmd="echo export DOCKER_CONTENT_TRUST=1 >> /etc/profile && source /etc/profile" 
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="echo $DOCKER_CONTENT_TRUST"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "DOCKER_CONTENT_TRUST: ${content_trust}\n" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_045() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local privileged_info=$(docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' ${container_name})
    local check_res=$(echo ${privileged_info |awk -F'=' '{print $NF}'})
    if [[ $check_res != "false" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Privileged Info: ${check_res}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_046() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local pind_info=$(docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' ${container_name})
    local pinds=$(echo ${pind_info} |sed  's/ /\n/g' |xargs -i echo {} |grep "Source:" |cut -d ":" -f2)
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
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "${pind_info}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_047() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local port=$(docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' ${container_name} |grep -Eo "HostPort:[0-9]{4,5}" |cut -d ':' -f2)
    if [[ $port -lt 1024 ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' ${container_name} |grep -Eo "HostPort:[0-9]{4,5}" |cut -d ':' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Port: ${port}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_048() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local net=$(docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}' ${container_name} |cut -d '=' -f2)
    if [[ $net == "host" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Network Mode: ${net}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_049() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local mem=$(docker inspect --format '{{ .Id }}: Memory={{ .HostConfig.Memory }}' ${container_name} |cut -d '=' -f2)
    if [[ $mem == "0" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: Memory={{ .HostConfig.Memory }}' ${container_name} |cut -d '='' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Memory: ${mem}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_050() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local cpu_share=$(docker inspect --format '{{ .Id }}: CpuShares={{ .HostConfig.CpuShares }}' ${container_name} |cut -d '=' -f2)
    if [[ $cpu_share == "0" || $cpu_share== "1024" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: CpuShares={{ .HostConfig.CpuShares }}' ${container_name} |cut -d '=' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "CPU Shares: ${cpu_share}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_051() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local host_ip=$(docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' ${container_name} |grep -Eo "HostIp:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" |cut -d ':' -f2)
    if [[ $host_ip == "" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}' ${container_name} |grep -Eo "HostIp:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" |cut -d ':' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Host IP: ${host_ip}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_052() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local restart_policy_name=$(docker inspect --format '{{ .HostConfig.RestartPolicy.Name }}' ${container_name})
    local restart_max_count=$(docker inspect --format '{{ .HostConfig.RestartPolicy.MaximumRetryCount }}' ${container_name})
    if [[ $restart_policy_name != "on-failure" || $restart_max_count -ne 5 ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
    	local cmd1="docker inspect --format '{{ .HostConfig.RestartPolicy.Name }}' ${container_name}"
        local cmd2="docker inspect --format '{{ .HostConfig.RestartPolicy.MaximumRetryCount }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Restart Policy Name: ${restart_policy_name}  Maximum Retry Count: ${restart_max_count}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_053() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local pid_mode=$(docker inspect --format '{{ .HostConfig.PidMode }}' ${container_name})
    if [[ $pid_mode == "host" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.PidMode }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Pid Mode: ${pid_mode}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_054() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local ipc_mod=$(docker inspect --format '{{ .HostConfig.IpcMode  }}' ${container_name})
    if [[ $ipc_mod == "host" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.PidMode }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "IPC Mode: ${ipc_mod}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_055() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local devices=$(docker inspect --format '{{ .HostConfig.Devices }}' ${container_name})
    if [[ $devices != "[]" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.PidMode }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Devices: ${devices}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_056() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local uts_mode=$(docker inspect --format '{{ .HostConfig.UTSMode }}' ${container_name})
    if [[ $uts_mode == "host" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.UTSMode }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "UTS Mode: ${uts_mode}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_057() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local security_opt=$(docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' ${container_name} |cut -d '=' -f2)
    if [[ $security_opt == "[host]" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' ${container_name} |cut -d '='' -f2"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Security Opt: ${security_opt}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_058() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local cgroup=$(docker inspect --format '{{ .HostConfig.CgroupParent }}' ${container_name})
    if [[ $cgroup != "" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.CgroupParent }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Cgroup Parent: ${cgroup}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_059() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local security_opt=$(docker inspect --format '{{ .HostConfig.SecurityOpt }}' ${container_name})
    if [[ $security_opt != "[no-new-privileges]" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.SecurityOpt }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Security Opt: ${security_opt}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_060() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local health_check=$(docker inspect --format '{{ .State.Health.Status }}' ${container_name})
    if [[ $health_check == "" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .State.Health.Status }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Health Status: ${health_check}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_061() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local pids_limit=$(docker inspect --format '{{ .HostConfig.PidsLimit }}' ${container_name})
    if [[ $pids_limit == "0" || $pids_limit == "-1" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.PidsLimit }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "PIDs Limit: ${pids_limit}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_062() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local user_ns_mode=$(docker inspect --format '{{ .HostConfig.UsernsMode }}' ${container_name})
    if [[ $user_ns_mode == "host" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format '{{ .HostConfig.UsernsMode }}' ${container_name}"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "User Name Space Mode: ${user_ns_mode}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}


harden_item_063() {
    local num=$(echo ${FUNCNAME[@]} | cut -d" " -f1 | cut -d"_" -f3)
    local item_num="Item_$num"
    local task_name=${check_items[$item_num]}
    echo $(_green "Doing   ${item_num}    ${task_name}..")
    echo "${split_line}"
    report_writer "${item_num}" "${task_name}"
    local sock_mount=$(docker inspect --format 'Volumes={{ .Mounts }}' ${container_name} | grep docker.sock)
    if [[ $sock_mount != "" ]]; then
    	local image_id=$(docker inspect --format '{{ .Image }}' ${container_name} |awk -F':' '{print $NF}')
    	local cmd1="docker stop ${container_name} && docker rm -f ${container_name}"
    	local cmd2="docker run -dit -u ${container_user} -v ${local_dir}:${internal_dir} -p ${host_ip}:${local_port}:${internal_port} 
    	            --detach --restart=on-failure:5 --name ${container_name} -m ${container_memory} --cpu-shares ${container_cpu} 
    	            --security-opt=no-new-privileges --health-cmd='ps aux |grep -w abc |grep -v grep || echo 1' 
    	            --pids-limit 100 ${image_id} --config ${internal_dir}${config_file}"
    	_error_detect "${cmd1}"  | tee -a $report_file_name
        _error_detect "${cmd2}"  | tee -a $report_file_name
    else
        local cmd="docker inspect --format 'Volumes={{ .Mounts }}' ${container_name} | grep docker.sock"
        _info "${cmd}\n" | tee -a $report_file_name
        _info "Sock File Mount: ${sock_mount}" | tee -a $report_file_name
        _green "Execution command (${cmd}) sucessful.\n" | tee -a $report_file_name
    fi
    printf "\n\n"
}



harden_item_001
harden_item_002
harden_item_003
harden_item_004
harden_item_005
harden_item_006
harden_item_007
harden_item_008
harden_item_009
harden_item_010
harden_item_011
harden_item_012
harden_item_013
harden_item_014
harden_item_015
harden_item_016
harden_item_017
harden_item_018
harden_item_019
harden_item_020
harden_item_021
harden_item_021
harden_item_022
harden_item_023
harden_item_024
harden_item_025
harden_item_026
harden_item_027
harden_item_028
harden_item_029
harden_item_030
harden_item_031
harden_item_032
harden_item_033
harden_item_034
harden_item_035
harden_item_036
harden_item_037
harden_item_038
harden_item_039
harden_item_040
harden_item_041
harden_item_042
harden_item_043
harden_item_044
harden_item_045
harden_item_046
harden_item_047
harden_item_048
harden_item_049
harden_item_050
harden_item_051
harden_item_052
harden_item_053
harden_item_054
harden_item_055
harden_item_056
harden_item_057
harden_item_058
harden_item_059
harden_item_060
harden_item_061
harden_item_062
harden_item_063