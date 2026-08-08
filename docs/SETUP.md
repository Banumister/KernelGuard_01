# Development environment setup

KernelGuard loads real eBPF programs into the Linux kernel, so it needs
a real Linux kernel with BPF support — a plain container/sandbox without
privileged access will not work. Every teammate should set up one of
the environments below.

## Requirements

- Linux kernel 4.1+ (5.x strongly recommended)
- Root / sudo access (loading eBPF programs requires `CAP_SYS_ADMIN`, or
  `CAP_BPF` + `CAP_PERFMON` on kernels 5.8+)
- The BCC toolchain (`bcc`) with its Python bindings, matched to your
  running kernel version
- Python 3.8+

## Option A — Native Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

# Verify:
sudo python3 -c "from bcc import BPF; print('bcc OK')"
```

## Option B — Fedora / RHEL family

```bash
sudo dnf install -y bcc bcc-tools python3-bcc kernel-devel-$(uname -r)
sudo python3 -c "from bcc import BPF; print('bcc OK')"
```

## Option C — Windows / macOS (via VS Code + a Linux VM)

BPF is a Linux kernel feature — it does not run on Windows or macOS
kernels, and WSL2's stock kernel usually lacks the headers BCC needs.
The reliable path:

1. Install [VirtualBox](https://www.virtualbox.org/) or use
   [Multipass](https://multipass.run/) to create an Ubuntu 22.04 VM.
2. Install the VS Code **Remote - SSH** extension and connect into the VM.
3. Follow Option A inside the VM.
4. Clone this repo inside the VM and work from there — your local VS
   Code editor experience is unchanged, but `sudo python3
   controller/bpf_loader.py` actually runs against a real kernel.

A cloud Linux VM (e.g. a small instance on any provider) works just as
well as a local VM, if you'd rather not run one locally.

## Running the Week 1 demo

```bash
git clone <your-repo-url>
cd kernelguard
sudo python3 controller/bpf_loader.py
# in another terminal, run anything — ls, python3, etc. — and watch
# KernelGuard log the execve() call.
```

Or launch a target script through the CLI wrapper:

```bash
python3 cli/kernelguard.py run path/to/untrusted.py
# then, in another terminal:
sudo python3 controller/bpf_loader.py --pid <printed PID>
```

## Python dev dependencies (linting/tests, no root needed)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r controller/requirements.txt
pytest
flake8 .
```
