# KernelGuard — eBPF-Powered Runtime Security Sandbox

**Domain:** Systems Programming & Cybersecurity
**Status:** Week 1 — eBPF foundations (see [docs/ROADMAP.md](docs/ROADMAP.md))

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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Project structure

```
kernelguard/
├── ebpf/          # Kernel-space eBPF C programs (syscall hooks)
├── controller/     # Python bcc daemon: compiles/loads eBPF, manages policy
├── cli/            # Security CLI (kernelguard run untrusted.py --block-network)
├── policy/         # JSON-based policy engine (Week 3)
├── systemd/        # Service packaging (Week 4)
├── tests/          # CI-safe smoke tests (no root/kernel required)
└── docs/           # Setup guide, architecture, roadmap
```

## Quickstart

Full BPF loading needs a real Linux kernel + root — see
[docs/SETUP.md](docs/SETUP.md) if you're on Windows/macOS or a
container. Once BCC is installed:

```bash
git clone <this-repo-url>
cd kernelguard
sudo python3 controller/bpf_loader.py
```

In another terminal, run anything (`ls`, `python3`, ...) and watch
KernelGuard log the `execve()` call in real time.

## Key modules

- **eBPF C-code** — low-level programs hooking `execve`, `tcp_connect`,
  `vfs_write` (see `ebpf/`).
- **Python BPF Controller (`bcc`)** — compiles and loads the eBPF code,
  manages policies (see `controller/`).
- **cgroups integration** — scopes tracing to targeted Python PIDs
  rather than the whole system (Week 2).
- **Security CLI** — define security policies, e.g.
  `kernelguard run untrusted.py --block-network` (see `cli/`).

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full week-by-week plan
and current checklist status.

## Contributing

This is a team internship project — see [CONTRIBUTING.md](CONTRIBUTING.md)
for branch naming, commit conventions, and the PR process.

## License

[MIT](LICENSE)
