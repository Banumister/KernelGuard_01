# Setup

This covers two different things, because they need different machines:

1. **Running the real tracer** (`ebpf/execve_trace.c` via
   `controller/bpf_loader.py`) — needs an actual Linux machine with root
   access. Windows, macOS, and most restricted cloud sandboxes cannot do
   this (see [Troubleshooting](#troubleshooting) below for why).
2. **Linting and running the test suite** (`tests/`) — plain Python,
   works anywhere, no root or Linux required.

## Requirements for the real tracer

- A Linux machine (a real install, a VM with a full boot — not most
  container-based sandboxes) with root/sudo access.
- A kernel-headers package that matches your exact running kernel
  version (`uname -r`) — BCC compiles the eBPF C code against these at
  load time.

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

Verify the install:

```bash
python3 -c "from bcc import BPF; print('bcc OK')"
```

If that fails with a "kernel headers not found" or
`/lib/modules/$(uname -r)/build: No such file or directory` error, the
`linux-headers` package didn't match your running kernel — check
`uname -r` against what actually got installed under
`/lib/modules/`, and reboot after a kernel update before reinstalling
headers if needed.

## Running KernelGuard

Once BCC is installed and importable, see the root
[README.md](../README.md#usage) for the actual commands
(`bpf_loader.py --pid`, `--policy`, `--block`, and the `cli/kernelguard.py
run` entrypoint). Everything under `controller/` and `ebpf/` must be run
as root — the eBPF program load itself requires it.

## Python dev dependencies (linting/tests, no root needed)

This is everything you need to contribute to the Python side (policy
logic, CLI, tests) without a Linux box:

```bash
pip install -r requirements.txt
pip install flake8
```

Run the checks CI and code review expect (see
[CONTRIBUTING.md](../CONTRIBUTING.md)) before opening a pull request:

```bash
pytest
flake8 .
```

## Troubleshooting

- **"No module named 'bcc'"** — `bcc` isn't pip-installable; it ships as
  a system package with native components tied to your kernel version.
  Use your OS package manager (see above), not `pip install bcc`.
- **"Unable to find kernel headers" / compile fails at `BPF(text=...)`**
  — the installed `linux-headers-*` package doesn't match `uname -r`
  exactly, or doesn't exist for your kernel at all. This is common on:
  - **WSL2** — Microsoft's WSL kernel usually has no matching headers
    package available through apt; a real Linux VM or dual-boot is more
    reliable.
  - **Cloud sandboxes / minimal containers** — these often run a custom
    or stripped-down kernel with no headers package published anywhere.
    BTF (`/sys/kernel/btf/vmlinux`) being present is not enough on its
    own for BCC's older, non-CO-RE compilation path.
- **"KernelGuard must be run as root"** — loading an eBPF program needs
  root/`CAP_SYS_ADMIN`/`CAP_BPF`. Use `sudo`.
- **No real Linux box available at all** — see
  [demo/README.md](../demo/README.md) for a way to show KernelGuard's
  expected behavior (real policy logic, simulated kernel-capture timing)
  on any machine, including Windows.
