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

> **Note:** automatic blocking on a policy violation is a goal, not yet
> the current behavior — see [Known limitations](#known-limitations--current-scope)
> below for exactly what's implemented today.

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
├── demo/
│ └── kernelguard_demo.py # Cross-platform demo output (see demo/README.md)
├── docs/
│ └── ROADMAP.md # Week-by-week status
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

## Known limitations / current scope

Being upfront about what's actually implemented vs. still planned (full
detail in [docs/ROADMAP.md](docs/ROADMAP.md)):

- **Visibility, not enforcement, by default.** `bpf_loader.py --policy`
  tags every connection and file write as allowed or blocked — but a
  `[BLOCKED]` tag is a log line, not an action. Nothing is killed
  automatically when a policy is violated yet.
- **`cli/kernelguard.py run`'s `--block-network` / `--block-write` /
  `--policy` flags are parsed but not enforced.** The CLI prints a note
  saying so at runtime rather than silently pretending to protect you.
- **Manual blocking exists, but isn't automatic.** `bpf_loader.py --pid
  <PID> --block` will kill a specific PID on its next monitored syscall
  — the kernel-side mechanism (`blocked_pids` map, `bpf_send_signal(9)`
  in `ebpf/execve_trace.c`) is real and working, it's just not wired up
  to fire automatically from a policy violation. That's the core of
  Week 3.
- **Requires a real Linux kernel with BCC.** Nothing in this project can
  load or run on Windows, macOS, or most restricted cloud sandboxes —
  BCC needs to compile against a kernel-headers package matching
  `uname -r`. See `demo/README.md` for a way to demonstrate expected
  output on machines without that environment.

## License

[MIT](LICENSE)
