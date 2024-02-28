#!/bin/bash

entry_new_line="\n-------------------------\n"
resource_new_line="--------------------------------------------------\n"

# Set default value for tail, or use provided argument
logs_tails_count=${1:-1000}

# Set default pods logs filter, or use provided argument
pods_logs_filter=${2:-"| grep -E 'error|failed|fatal'"}

execute_kubectl_commands() {
    local input=$1
    local command_template=$2
    # Read each line of the command output
    while read -r line; do
        namespace=$(echo "$line" | awk '{print $1}')
        resource=$(echo "$line" | awk '{print $2}')
        # skip header
        if [ "$namespace" = "NAMESPACE" ] || [ "$namespace" = "" ]; then
            continue
        fi
        local exec_command=$(sed "s/{resource}/$resource/g; s/{namespace}/$namespace/g" <<< "$command_template")
        echo -e "Executing: $exec_command\n"
        eval "$exec_command"
        echo -e $entry_new_line
    done <<< "$input"
}

echo -e "---------------------------------------------- Cluster Overview ----------------------------------------------"

command="kubectl get cluster -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"


echo -e $entry_new_line
command="kubectl get nodepool -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $entry_new_line
command="kubectl get nodes -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $entry_new_line
command="kubectl get baremetalmachine -A -o wide"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

# Get bm-system and kube-system pods, including jobs and controllers, which we should focus on.
echo -e $entry_new_line
command="kubectl get pods -A -o wide | grep -E 'kube-system|bm-system' | grep -v -E 'Running|Completed'"
echo -e "Executing: $command\n"
echo "$(eval "$command")"


echo -e "--------------------------------------------------------------------------------------------------------------"

command="kubectl get cluster -A -o wide"
input=$(eval "$command")
echo -e "Executing:  $command\n"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$input" "kubectl describe cluster {resource} -n {namespace} | sed -n '/^Status/,\$p'" 

echo -e $resource_new_line
command="kubectl get pods -A -o wide | grep -E 'cluster-operator|cap-controller-manager|lifecycle-controllers-manager'"
input=$(eval "$command")
echo -e "Executing:  $command\n"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$inout" "kubectl describe pod {resource} -n {namespace} | sed -n '/^Events:/,\$p'"

echo -e $resource_new_line
execute_kubectl_commands "$input" "kubectl logs {resource} -n {namespace} --all-containers --tail $logs_tails_count $pods_logs_filter"

echo -e $resource_new_line
command="kubectl get pods -A -o wide | grep -v -E 'bm-system|Running|Completed'"
echo -e "Executing: $command\n"
echo "$(eval "$command")"

echo -e $resource_new_line
command="kubectl get pods -A -o wide | grep bm-system | grep -v -E 'Running|Completed'"
echo -e "Executing:  $command\n"
input="$(eval "$command")"
echo "$input"
echo -e $entry_new_line
execute_kubectl_commands "$input" "kubectl logs {resource} -n {namespace} --tail $logs_tails_count $pods_logs_filter"
