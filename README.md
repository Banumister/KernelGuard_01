# KernelGuard — eBPF-Powered Runtime Security Sandbox

**Domain:** Systems Programming & Cybersecurity

## Problem statement

Untrusted Python code (like a downloaded pip package) runs with the full
permissions of the user. If a malicious script attempts to open an
unauthorized reverse shell or encrypt files (ransomware), standard Python
sandboxes (Docker, `pysandbox`, etc.) are either too heavy or easily
bypassed.

## The idea

KernelGuard uses Python's `bcc` (BPF Compiler Collection) library to write
eBPF programs directly into the Linux kernel. Instead of restricting
Python from *within* Python, KernelGuard operates at "Ring 0" (kernel
space): it intercepts raw syscalls (`execve`, `tcp_connect`, `vfs_write`)
made by specific Python processes. If a script tries to open a network
socket without pre-authorization, the eBPF program blocks the syscall
instantly and alerts the user.

## Project structure
kernelguard/
├── ebpf/
│ └── execve_trace.c # eBPF hooks: execve, tcp_connect, vfs_write, active blocking
├── controller/
│ ├── init.py
│ └── bpf_loader.py # Compiles/loads eBPF, PID filtering, policy tagging, --block
├── cli/
│ └── kernelguard.py # kernelguard run script.py --block-network entrypoint
├── policy/
│ ├── policy_schema.json # Example JSON policy (network + filesystem allow-lists)
│ └── policy_loader.py # Loads and evaluates policy rules
├── systemd/
│ └── kernelguard.service # systemd unit for running as a background daemon
├── tests/ # pytest tests that don't require root/kernel access
├── README.md
├── LICENSE
└── .gitignore


## Requirements

Running this for real needs a Linux machine with root access and the BCC
toolchain installed (`bcc` is not pip-installable — it's a system package
tied to your kernel version). On Ubuntu/Debian:

```bash
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

## Usage

Watch a specific process:

```bash
sudo python3 controller/bpf_loader.py --pid 1234
```

Apply a policy (tags each event allowed/blocked):

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --policy policy/policy_schema.json
```

Actively terminate a process on its next monitored syscall:

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --block
```

Or use the CLI, which launches the target script and supervises it in one step:

```bash
sudo python3 cli/kernelguard.py run untrusted.py --block-network --policy policy/policy_schema.json
```

## Testing

Tests that don't require root or a real kernel (policy logic, CLI argument
parsing) live in `tests/` and run with:

```bash
pip install pytest
pytest
```

## Key modules

- **eBPF C-code** — low-level programs hooking `execve`, `tcp_connect`,
  and `vfs_write` directly in the kernel, plus a `blocked_pids` map for
  active enforcement.
- **Python BPF Controller (`bcc`)** — compiles and loads the eBPF code,
  manages PID filtering and policy evaluation.
- **Policy engine** — JSON-defined allow-lists for network and filesystem
  access.
- **Security CLI** — `kernelguard run untrusted.py --block-network`.

## License

[MIT](LICENSE)