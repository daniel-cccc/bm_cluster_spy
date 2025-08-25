#!/bin/bash

#
# Description:
#   This script is a comprehensive diagnostic tool for gathering health and status
#   information from a Kubernetes cluster, with a focus on environments like GKE
#   on Bare Metal. It performs two main functions:
#
#   1. Kubernetes API Queries: It uses `kubectl` to fetch the status of key
#      resources like Clusters, NodePools, Nodes, BareMetalMachines, and Pods.
#      It specifically highlights non-running pods and collects logs and events from
#      critical management controllers. It also runs a quick API server
#      responsiveness test.
#
#   2. Node-Level SSH Checks: For nodes identified as control plane nodes (via a
#      specific NodePool annotation), it connects via SSH to perform deep inspection.
#      This includes checking system load (`top`), network connections (`netstat`),
#      static pod container status/logs (`crictl`), etcd health (`etcdctl`), and
#      containerd service logs (`journalctl`).
#
#   The script automatically discovers SSH private keys from secrets within the
#   cluster or can use a local SSH agent or a specified key file.
#
#
# Usage:
#   ./your_script_name.sh [LOGS_TAIL] [STATIC_LOGS_TAIL] [JOURNAL_LOGS] [POD_LOG_FILTER]
#
# Positional Arguments (all are optional):
#   [LOGS_TAIL]           - Number of log lines to fetch from standard Kubernetes pods.
#                           Default: 200
#
#   [STATIC_LOGS_TAIL]    - Number of log lines to fetch from static pods (e.g., etcd,
#                           kube-apiserver) using `crictl` on the node.
#                           Default: 200
#
#   [JOURNAL_LOGS]        - Number of log lines to fetch from `journalctl -u containerd`.
#                           Default: 1000
#
#   [POD_LOG_FILTER]      - A shell command string used to filter standard pod logs.
#                           Must be quoted to be passed correctly.
#                           Default: "| grep -i -E 'error|failed|fatal'"
#
# Environment Variables:
#   SSH_KEY_PATH          - If set, this script will use the SSH private key at this
#                           path for all SSH connections, bypassing the automatic key
#                           discovery from Kubernetes secrets.
#
#   JOURNALCTL_LINES      - Can be used to set the number of journalctl log lines if the
#                           third positional argument is not provided.
#
# Prerequisites:
#   - `kubectl` must be installed and configured with a context pointing to the
#     target cluster's admin cluster.
#   - The user running the script must have `get`, `list`, and `describe`
#     permissions for clusters, nodepools, nodes, baremetalmachines, pods, and secrets.
#   - `ssh` and `ssh-agent` must be available in the environment.
#   - For node-level checks, the control plane nodes must be accessible via SSH
#     from where the script is run.
#
# Examples:
#   # Run with all default settings
#   ./your_script_name.sh
#
#   # Get the last 500 log lines from pods and 100 from static pods
#   ./your_script_name.sh 500 100
#
#   # Use a custom filter to search for 'connection refused' in pod logs
#   ./your_script_name.sh 200 200 1000 "| grep 'connection refused'"
#
#   # Run using a specific SSH key instead of discovering from cluster secrets
#   SSH_KEY_PATH=~/.ssh/my_cluster_key.pem ./your_script_name.sh
#

# Globals
TEMP_KEY_FILE=""
SSH_AGENT_STARTED=0
CRICTL_TIMEOUT="--timeout=2s"
KUBECTL_TIMEOUT="--request-timeout=2s"
STATIC_PODS_GREP_LINES=30
JOURNALCTL_LINES_DEFAULT=1000
JOURNALCTL_GREP_LINES=30
# Define the CP nodepool annotation key and value.
ANNOTATION_KEY="baremetal.cluster.gke.io/control-plane"
ANNOTATION_VALUE="true"

# Set default value for tail, or use provided argument.
logs_tails_count=${1:-200}

# Set default value for tail for static pods, or use provided argument.
static_logs_tails_count=${2:-200}

# Set default tail line value for journalctl.
journalctl_logs_lines=${3:-"${JOURNALCTL_LINES:=$JOURNALCTL_LINES_DEFAULT}"}

# Set default pods logs filter, or use provided argument.
pods_logs_filter=${4:-"| grep -i -E 'error|failed|fatal'"}

# Set default static pods logs filter, or use provided argument.
static_pods_logs_filter=${5:-"| grep -i -E 'error|failed|fatal'"}

entry_new_line="\n-------------------------\n"
resource_new_line="--------------------------------------------------\n"

execute_kubectl_commands() {
    local input=$1
    local command_template=$2
    # Read each line of the command output.
    while read -r line; do
        namespace=$(echo "$line" | awk '{print $1}')
        resource=$(echo "$line" | awk '{print $2}')
        # skip header.
        if [ "$namespace" = "NAMESPACE" ] || [ "$namespace" = "NAME" ] || [ "$namespace" = "" ]; then
            continue
        fi
        local exec_command=$(sed "s/{resource}/$resource/g; s/{namespace}/$namespace/g" <<< "$command_template")
        echo -e "Executing: $exec_command\n"
        eval "$exec_command"
        echo -e $entry_new_line
    done <<< "$input"
}

echo -e "---------------------------------------------- Cluster Overview ----------------------------------------------"

command="kubectl $KUBECTL_TIMEOUT get cluster -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $entry_new_line
command="kubectl $KUBECTL_TIMEOUT get nodepool -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $entry_new_line
command="kubectl $KUBECTL_TIMEOUT get nodes -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $entry_new_line
command="kubectl $KUBECTL_TIMEOUT get baremetalmachine -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

# Get bm-system and kube-system pods, including jobs and controllers, which we should focus on.
echo -e $entry_new_line
command="kubectl $KUBECTL_TIMEOUT get pods -A -o wide | grep -E 'kube-system|bm-system' | grep -v -E 'Running|Completed'"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $resource_new_line
command="for i in {1..3}; do (time kubectl $KUBECTL_TIMEOUT describe cluster -A > /dev/null) 2>&1 | grep -i real; done"
echo -e "Executing: $command\n"
echo -e "API server response time:"
echo -e "$(eval "$command")\n"

echo -e "--------------------------------------------------------------------------------------------------------------"

command="kubectl $KUBECTL_TIMEOUT get cluster -A -o wide"
input=$(eval "$command")
echo -e "Executing: $command\n"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$input" "kubectl $KUBECTL_TIMEOUT  describe cluster {resource} -n {namespace} | sed -n '/^Status/,\$p'" 

echo -e $resource_new_line
command="kubectl $KUBECTL_TIMEOUT get pods -A -o wide | grep -E 'cluster-operator|cap-controller-manager|lifecycle-controllers-manager'"
input=$(eval "$command")
echo -e "Executing: $command\n"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$inout" "kubectl $KUBECTL_TIMEOUT describe pod {resource} -n {namespace} | sed -n '/^Events:/,\$p'"

echo -e $resource_new_line
execute_kubectl_commands "$input" "kubectl $KUBECTL_TIMEOUT logs {resource} -n {namespace} --all-containers --tail $logs_tails_count $pods_logs_filter"

echo -e $resource_new_line
command="kubectl $KUBECTL_TIMEOUT get pods -A -o wide | grep -v -E 'bm-system|Running|Completed'"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $resource_new_line
command="kubectl $KUBECTL_TIMEOUT get pods -A -o wide | grep bm-system | grep -v -E 'Running|Completed'"
echo -e "Executing: $command\n"
input="$(eval "$command")"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$input" "kubectl $KUBECTL_TIMEOUT logs {resource} -n {namespace} --tail $logs_tails_count $pods_logs_filter"

echo -e $resource_new_line
command="kubectl get node -A -o wide"
echo -e "Executing: $command\n"
input="$(eval "$command")"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$input" "kubectl $KUBECTL_TIMEOUT describe node {namespace} | sed -n '/  Resource/,/Events:/p' | sed '/Events:/d' | head -n 4"


echo -e $resource_new_line
command="kubectl $KUBECTL_TIMEOUT get baremetalmachine -A -o wide"
echo -e "Executing: $command\n"
input="$(eval "$command")"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$input" "kubectl $KUBECTL_TIMEOUT describe baremetalmachine {resource} -n {namespace} | sed -n '/^Status/,\$p'"

echo -e "===============================================================================================================\n"

setup_ssh_agent() {
    if [ -n "$SSH_KEY_PATH" ]; then
        TEMP_KEY_FILE=$SSH_KEY_PATH
        echo "SSH_KEY_PATH is set, $SSH_KEY_PATH. Using it to ssh to node."
        return 0
    fi
    if [ -n "$SSH_AUTH_SOCK" ] && [ -S "$SSH_AUTH_SOCK" ]; then
        SSH_AGENT_STARTED=1
    else
        # Start ssh-agent if ssh-agent is not running.
        eval $(ssh-agent -s)
        SSH_AGENT_STARTED=1
    fi
}

update_private_key() {
    local private_key=$1
    if [ -z "$private_key" ]; then
        return 0
    fi
    if [ $SSH_AGENT_STARTED -eq 1 ]; then
        echo "$private_key" | ssh-add -
    else
        # Create or update the temporary file for the SSH key.
        if [[ -z $TEMP_KEY_FILE ]]; then
            TEMP_KEY_FILE=$(mktemp)
            chmod 600 "$TEMP_KEY_FILE"
        fi
        echo "$private_key" > "$TEMP_KEY_FILE"
    fi
}

execute_ssh_command() {
    echo -e 
    local user_hostname=$1
    local ssh_command=$2

    if [ $SSH_AGENT_STARTED -eq 1 ]; then
        timeout 10 ssh -q -o StrictHostKeyChecking=no "$user_hostname" "$ssh_command"
    else
        timeout 10 ssh -q -o StrictHostKeyChecking=no -i "$TEMP_KEY_FILE" "$user_hostname" "$ssh_command"
    fi
}

cleanup() {
    if [ -n $TEMP_KEY_FILE ] && [ -z "$SSH_KEY_PATH" ]; then
        rm -f "$TEMP_KEY_FILE"
    fi
    if [ $SSH_AGENT_STARTED -eq 1 ]; then
        eval $(ssh-agent -k)
    fi
}

# Set up a trap to clean up on script exit.
trap cleanup EXIT

# fetch_logs_on_host to fetch logs on a given host.
fetch_logs_on_host() {
    local node_ip=$1
    # Initialize arrays.
    container_ids=()
    status=()
    container_names=()

    etcdctl_creds="ETCDCTL_API=3 etcdctl --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key --endpoints=https://localhost:"

    local commands="echo -e '${entry_new_line}' && top -b -n 1 | head -n 15 && "
    commands+="echo -e '${entry_new_line}' && netstat -ntupl -4 || ss -ntupl -4 && "
    commands+="echo -e '${entry_new_line}' && ls -il -R /etc/kubernetes/ && ls -il /var/lib/etcd && ls -il -R /var/lib/etcd/member/wal &&ls -il /var/lib/etcd-events && ls -il -R /var/lib/etcd-events/member/wal && "
    commands+="echo -e '${entry_new_line}' && "
    commands+="${etcdctl_creds}2379 --write-out=table  endpoint status && echo -e '\n' && "
    commands+="${etcdctl_creds}2379 member list && echo -e '\n' && "
    commands+="${etcdctl_creds}2382 --write-out=table  endpoint status && echo -e '\n' && "
    commands+="${etcdctl_creds}2382 member list"
    execute_ssh_command "$node_ip" "$commands"
    echo -e $entry_new_line

    echo -e $resource_new_line
    local command="echo -e 'Executing: crictl ps -a | wc -l' && crictl ps -a | wc -l"
    echo "$(execute_ssh_command "$node_ip" "$command")"

    command="crictl $CRICTL_TIMEOUT ps -a | grep -E 'etcd|kube-controller-manager|kube-apiserver|kube-scheduler|cilium-agent|anthos-baremetal-haproxy' | grep -v 'etcd-defrag'"
    pods="$(execute_ssh_command "$node_ip" "$command")"
    echo -e "Executing: $command"
    echo "$pods"

    while IFS= read -r line; do
        # Skip empty line.
        if [ -z "$(echo "$line" | awk '{print $1}')" ]; then
            continue
        fi
        container_ids+=("$(echo "$line" | awk '{print $1}')")
        status+=("$(echo "$line" | awk '{print $6}')")
        container_names+=("$(echo "$line" | awk '{print $7}')")
    done <<< "$pods"
    
    commands=""
    for ((i=0; i<${#container_ids[@]}; i++)); do
        local id="${container_ids[i]}"
        local name="${container_names[i]}"
        commands+="echo -e '${entry_new_line}Container Name: $name, ID: $id, Status: ${status[i]}, on host $node_ip\n' && timeout 2  crictl $CRICTL_TIMEOUT logs --tail=$static_logs_tails_count $id 2>&1 | head -n $STATIC_PODS_GREP_LINES && sleep 0.1 && "
    done
    commands+="sleep 0.5"
    echo "$(execute_ssh_command "$node_ip" "$commands")"

    echo -e $entry_new_linehttps://github.com/daniel-cccc/bm_cluster_spy/blob/main/cluster_spy.sh
    command="journalctl -u containerd --no-pager -n $journalctl_logs_lines | grep -i 'RunPodSandbox.*returns sandbox id' | grep -i -E 'etcd|kube-' | awk '{print \$6 \$10}' | head -n $JOURNALCTL_GREP_LINES"
    echo -e "Executing: $command on host: $node_ip"
    echo "$(execute_ssh_command "$ip" "$command")"
}   

declare -A ssh_keys_map

while IFS= read -r line; do
    # Extract namespace and secret name.
    namespace=$(echo "$line" | awk '{print $1}')
    secret_name=$(echo "$line" | awk '{print $2}')

    # Retrieve the SSH key content from the secret.
    ssh_key_content=$(kubectl $KUBECTL_TIMEOUT get secret "$secret_name" -n "$namespace" -o jsonpath="{.data.id_rsa}" | base64 --decode)

    ssh_keys_map[$namespace]=$ssh_key_content
done < <(kubectl get secret -A | grep ssh-key)

setup_ssh_agent

# Get the list of all NodePool resources across all namespaces that match the CP nodepool annotation.
NODEPOOLS=$(kubectl $KUBECTL_TIMEOUT get NodePool --all-namespaces -o jsonpath="{range .items[?(@.metadata.annotations['baremetal\.cluster\.gke\.io/control-plane']=='true')]}{.metadata.namespace}{'\t'}{.metadata.name}{'\n'}{end}")

if [ -z "$NODEPOOLS" ]; then
    echo "No NodePool resources found with the annotation ${ANNOTATION_KEY}=${ANNOTATION_VALUE}"
else
    while IFS=$'\t' read -r NAMESPACE NODEPOOL_NAME; do
        DESCRIPTION=$(kubectl $KUBECTL_TIMEOUT describe NodePool "$NODEPOOL_NAME" -n "$NAMESPACE")
        CLUSTER_NAME=$(echo "$DESCRIPTION" | awk '/^Spec:/{flag=1} flag && /Cluster Name:/{print $3; flag=0}')
        echo -e $resource_new_line
        echo "NodePool: $NODEPOOL_NAME, Cluster Name: $CLUSTER_NAME, Namespace: $NAMESPACE"

        # Extract Node IP and store them in an array.
        IFS=$'\n' read -r -d '' -a NODE_IPS < <(echo "$DESCRIPTION" | awk '/^Spec:/{flag=1} flag && /Address:/{print $2}' && printf '\0')
        if [ -z "${ssh_keys_map[$NAMESPACE]}" ] && [ -z "$SSH_KEY_PATH" ]; then
            echo "SSH key is empty skip SSH to nodes in $NODEPOOL_NAME"
            echo -e $entry_new_line
            continue
        fi
        # update up the SSH private key on each node pool.
        update_private_key "${ssh_keys_map[$NAMESPACE]}"
        for ip in "${NODE_IPS[@]}"; do
            echo -e $resource_new_line
            echo  -e "Node IP: $ip"
            fetch_logs_on_host "$ip" < /dev/null 
        done
        echo -e $resource_new_line
    done <<< "$NODEPOOLS"
fi
