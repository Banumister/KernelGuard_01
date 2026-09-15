#!/usr/bin/env bash
#
# KernelGuard installer — populates /opt/kernelguard and installs the
# systemd service, so the daemon doesn't depend on wherever this repo
# happened to be cloned.
#
# Usage:
#   sudo ./scripts/install.sh            # install/update
#   sudo ./scripts/install.sh --uninstall
#
# What it does:
#   1. Copies the repo into /opt/kernelguard (excluding .git and local
#      dev clutter).
#   2. Installs the BCC system packages needed to compile/load eBPF
#      programs (skipped with --skip-deps, e.g. if already installed).
#   3. Installs systemd/kernelguard.service into
#      /etc/systemd/system/ and runs `systemctl daemon-reload`.
#   4. Enables (but does not start) the service — start it yourself
#      once you've reviewed/placed a real policy file, with:
#        sudo systemctl start kernelguard
#
# This does NOT enable enforcement by itself: the shipped unit file
# runs `bpf_loader.py` with no --policy/--enforce-*, i.e. visibility
# only (see docs/ROADMAP.md, Week 4). Edit
# /etc/systemd/system/kernelguard.service's ExecStart line to add
# --policy/--enforce-network/--enforce-write once you have a policy
# file you trust in production.

set -euo pipefail

INSTALL_DIR="/opt/kernelguard"
UNIT_SRC="systemd/kernelguard.service"
UNIT_DEST="/etc/systemd/system/kernelguard.service"
SKIP_DEPS=0
UNINSTALL=0

for arg in "$@"; do
    case "$arg" in
        --skip-deps) SKIP_DEPS=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: this installer must be run as root (sudo ./scripts/install.sh)." >&2
    exit 1
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
    echo "Stopping and disabling kernelguard.service (if present)..."
    systemctl stop kernelguard.service 2>/dev/null || true
    systemctl disable kernelguard.service 2>/dev/null || true
    rm -f "$UNIT_DEST"
    systemctl daemon-reload
    echo "Removing $INSTALL_DIR ..."
    rm -rf "$INSTALL_DIR"
    echo "Uninstalled. Note: BCC system packages were not removed."
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f "$UNIT_SRC" ]]; then
    echo "ERROR: must be run from the KernelGuard repo root (missing $UNIT_SRC)." >&2
    exit 1
fi

if [[ "$SKIP_DEPS" -eq 0 ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "Installing BCC toolchain (apt)..."
        apt-get update -qq
        apt-get install -y bpfcc-tools "linux-headers-$(uname -r)" python3-bpfcc
    else
        echo "WARNING: no apt-get found — skipping automatic BCC install." >&2
        echo "Install the BCC toolchain for your distro manually, then re-run with --skip-deps." >&2
    fi
else
    echo "Skipping BCC dependency install (--skip-deps)."
fi

echo "Copying repo into $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
    --exclude '.git' \
    --exclude '.gitignore' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.pytest_cache' \
    ./ "$INSTALL_DIR"/

echo "Installing systemd unit to $UNIT_DEST ..."
cp "$UNIT_SRC" "$UNIT_DEST"
systemctl daemon-reload
systemctl enable kernelguard.service

cat <<EOF

KernelGuard installed to $INSTALL_DIR and kernelguard.service is enabled
(but not started).

Before starting it:
  1. Review/replace $INSTALL_DIR/policy/policy_schema.json with your
     real policy, or pass --policy explicitly.
  2. Edit $UNIT_DEST's ExecStart line to add the flags you want, e.g.:
       ExecStart=/usr/bin/python3 $INSTALL_DIR/controller/bpf_loader.py --policy $INSTALL_DIR/policy/policy_schema.json --enforce-network --enforce-write
  3. Reload and start:
       sudo systemctl daemon-reload
       sudo systemctl start kernelguard
       sudo systemctl status kernelguard

To uninstall: sudo ./scripts/install.sh --uninstall
EOF
