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

```
kernelguard/
├── ebpf/
│   └── execve_trace.c        # Kernel-space eBPF C program (syscall hooks)
├── controller/
│   ├── __init__.py
│   └── bpf_loader.py         # Python bcc daemon: compiles/loads eBPF, manages policy
├── cli/
│   └── kernelguard.py        # Security CLI entrypoint
├── policy/
│   └── policy_schema.json    # JSON-based policy definitions
├── systemd/
│   └── kernelguard.service   # Service packaging
├── tests/
│   └── test_basic.py         # Automated tests
├── README.md
├── LICENSE
└── .gitignore
```

## Key modules

- **eBPF C-code** — low-level programs hooking `execve`, `tcp_connect`,
  and `vfs_write` directly in the kernel.
- **Python BPF Controller (`bcc`)** — compiles and loads the eBPF code
  into the kernel and manages security policies.
- **cgroups integration** — scopes tracing to targeted Python PIDs
  rather than the whole system.
- **Security CLI** — defines security policies, e.g.
  `kernelguard run untrusted.py --block-network`.

## License

[MIT](LICENSE)
