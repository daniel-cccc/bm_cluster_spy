# bm_cluster_spy

# Kubernetes Cluster Health Diagnostics Script

A comprehensive diagnostic script for gathering health and status information from a Kubernetes cluster, with a special focus on environments like GKE on Bare Metal. It combines `kubectl` commands for a cluster-level overview with direct SSH checks on control-plane nodes for deep inspection.

## Overview

This script is designed to be a first-response tool for troubleshooting Kubernetes cluster issues. It automates the collection of critical data points from both the Kubernetes API and the nodes themselves.

It performs two main functions:

1.  **Kubernetes API Queries:** It uses `kubectl` to fetch the status of key resources like Clusters, NodePools, Nodes, BareMetalMachines, and Pods. It specifically highlights non-running pods and collects logs and events from critical management controllers. It also runs a quick API server responsiveness test.

2.  **Node-Level SSH Checks:** For nodes identified as control plane nodes (via a specific `NodePool` annotation), it connects via SSH to perform deep inspection. This includes checking system load (`top`), network connections (`netstat`), static pod container status/logs (`crictl`), etcd health (`etcdctl`), and `containerd` service logs (`journalctl`).

The script automatically discovers SSH private keys from secrets within the cluster, but can also use a local SSH agent or a specified key file.

## Features

* **Cluster-wide Summary:** Provides a quick overview of Cluster, NodePool, Node, and BareMetalMachine resources.
* **Problem Pod Identification:** Automatically finds and describes pods in non-`Running` or non-`Completed` states.
* **Log Aggregation:** Fetches logs from key operational pods and static pods on control plane nodes.
* **Control Plane Node Inspection:** SSHs into control plane nodes to check:
    * System load and running processes.
    * Network socket status.
    * `etcd` cluster health and membership.
    * Static pod container status and logs via `crictl`.
    * `containerd` logs via `journalctl`.
* **Automated SSH Key Discovery:** Finds and uses SSH keys stored in cluster secrets for node access.
* **Customizable Log Output:** Allows control over the number of log lines and filtering logic.

## Prerequisites

* `kubectl` must be installed and configured with a context pointing to the target cluster's admin or user cluster.
* The user running the script must have `get`, `list`, and `describe` permissions for clusters, nodepools, nodes, baremetalmachines, pods, and secrets across all relevant namespaces.
* `ssh` and `ssh-agent` must be available in the environment where the script is executed.
* For node-level checks, the control plane nodes must be network-accessible via SSH from where the script is run.

## Usage

Save the script as `troubleshoot.sh`, make it executable with `chmod +x troubleshoot.sh`, and run it from your terminal.

`./troubleshoot.sh [LOGS_TAIL] [STATIC_LOGS_TAIL] [JOURNAL_LOGS] [POD_LOG_FILTER]`

### Positional Arguments (Optional)

| Argument             | Description                                                                 | Default                                 |
| -------------------- | --------------------------------------------------------------------------- | --------------------------------------- |
| `[LOGS_TAIL]`        | Number of log lines to fetch from standard Kubernetes pods.                 | `200`                                   |
| `[STATIC_LOGS_TAIL]` | Number of log lines to fetch from static pods using `crictl`.               | `200`                                   |
| `[JOURNAL_LOGS]`     | Number of log lines to fetch from `journalctl -u containerd`.               | `1000`                                  |
| `[POD_LOG_FILTER]`   | A shell command string to filter standard pod logs. Must be quoted.         | `"| grep -i -E 'error|failed|fatal'"` |

### Environment Variables

* `SSH_KEY_PATH`: If set, this script will use the SSH private key at this path for all SSH connections, bypassing the automatic key discovery from Kubernetes secrets.

## Examples

**Run with all default settings:**

`./troubleshoot.sh`

**Get the last 500 log lines from Kubernetes pods and 100 from static pods:**

`./troubleshoot.sh 500 100`

**Use a custom filter to search for 'connection refused' in pod logs:**

`./troubleshoot.sh 200 200 1000 "| grep 'connection refused'"`

**Run using a specific SSH key instead of discovering it from the cluster:**

`SSH_KEY_PATH=~/.ssh/my_cluster_key.pem ./troubleshoot.sh`
