#!/usr/bin/env bash
# Proxmox VE host-side provisioner for Goliath (unprivileged Debian 12 LXC, no Docker).
# Run as root on your Proxmox VE node.
set -euo pipefail

CTID=""
HOSTNAME="goliath"
CORES="4"
MEMORY="4096"
DISK="32"
STORAGE="local-lvm"
BRIDGE="vmbr0"
IP_CFG="dhcp"
TOOLS_PROFILE="standard"
REPO_URL="https://github.com/davidcristianpetrea/Goliath.git"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ctid) CTID="${2:-}"; shift 2 ;;
    --hostname) HOSTNAME="${2:-goliath}"; shift 2 ;;
    --cores) CORES="${2:-4}"; shift 2 ;;
    --memory) MEMORY="${2:-4096}"; shift 2 ;;
    --disk) DISK="${2:-32}"; shift 2 ;;
    --storage) STORAGE="${2:-local-lvm}"; shift 2 ;;
    --bridge) BRIDGE="${2:-vmbr0}"; shift 2 ;;
    --ip) IP_CFG="${2:-dhcp}"; shift 2 ;;
    --tools) TOOLS_PROFILE="${2:-standard}"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: bash scripts/proxmox-create-lxc.sh [options]

Options:
  --ctid <id>         Container ID (default: next available via pvesh)
  --hostname <name>   Hostname (default: goliath)
  --cores <n>         CPU cores (default: 4)
  --memory <MB>       RAM in MB (default: 4096)
  --disk <GB>         Rootfs size in GB (default: 32)
  --storage <pool>    Proxmox storage pool (default: local-lvm)
  --bridge <br>       Network bridge (default: vmbr0)
  --ip <cidr|dhcp>    IP config, e.g. 192.168.1.50/24,gw=192.168.1.1 (default: dhcp)
  --tools <profile>   minimal | standard (default) | full | none
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

command -v pct >/dev/null 2>&1 || { echo "[x] pct not found — run this script on a Proxmox VE host." >&2; exit 1; }

if [[ -z "$CTID" ]]; then
  CTID="$(pvesh get /cluster/nextid)"
fi

echo "[*] Updating Proxmox LXC template index..."
pveam update
TEMPLATE="$(pveam available --section system | awk '/debian-12-standard/ {print $2}' | sort -V | tail -n1)"
[[ -n "$TEMPLATE" ]] || { echo "[x] Could not locate debian-12-standard template." >&2; exit 1; }

TEMPLATE_STORAGE="local"
if ! pveam list "$TEMPLATE_STORAGE" | grep -qF "$TEMPLATE"; then
  echo "[*] Downloading $TEMPLATE..."
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

echo "[*] Creating unprivileged LXC CT $CTID ($HOSTNAME: ${CORES}c / ${MEMORY}MB / ${DISK}GB)..."
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" \
  --memory "$MEMORY" \
  --swap 512 \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=${IP_CFG}" \
  --unprivileged 1 \
  --features nesting=1 \
  --onboot 1

echo "[*] Starting CT $CTID..."
pct start "$CTID"
sleep 5

echo "[*] Bootstrapping Goliath inside CT $CTID..."
pct exec "$CTID" -- bash -c "
  set -euo pipefail
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends git ca-certificates curl
  git clone --depth 1 '${REPO_URL}' /opt/goliath-src
  cd /opt/goliath-src
  bash scripts/lxc-install.sh --non-interactive --tools '${TOOLS_PROFILE}' --allow-private-llm
"
