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
space): it intercepts raw syscalls and scheduler events (`execve`,
`tcp_connect`, `vfs_write`, `unlinkat`, process `fork`/`clone`) made by
specific Python processes. If a script tries to open a network socket,
write a file, delete a file, or spawn a child process, KernelGuard can
log it, and for network/filesystem policy violations, actively kill the
process depending on the flags you pass.

> **Note:** automatic blocking on a policy violation is opt-in, not the
> default — see [Known limitations](#known-limitations--current-scope)
> below for exactly what's implemented today.

## Project structure
kernelguard/
├── ebpf/
│ └── execve_trace.c # eBPF hooks: execve, tcp_connect, vfs_write, unlinkat, fork/clone, active blocking
├── controller/
│ ├── init.py
│ └── bpf_loader.py # Compiles/loads eBPF, PID filtering, policy tagging, --enforce-network/--enforce-write/--block
├── cli/
│ └── kernelguard.py # kernelguard run script.py --block-network entrypoint (auto-attaches the tracer)
├── policy/
│ ├── policy_schema.json # Example JSON policy (network + filesystem allow-lists)
│ └── policy_loader.py # Loads and evaluates policy rules
├── systemd/
│ └── kernelguard.service # systemd unit for running as a background daemon
├── scripts/
│ └── install.sh # Installs into /opt/kernelguard and sets up the systemd service
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

Watch a specific process (visibility only — nothing is blocked):

```bash
sudo python3 controller/bpf_loader.py --pid 1234
```

Apply a policy (tags each event allowed/blocked, still visibility only):

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --policy policy/policy_schema.json
```

Actively enforce the policy — kill the process the moment it triggers a
blocked network connection, file write, and/or file deletion:

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --policy policy/policy_schema.json --enforce-network --enforce-write --enforce-delete
# --enforce is shorthand for all three flags together
```

Deletion is checked against its own `filesystem.allow_delete` list, so a
policy can grant write access to a path without also granting delete
access to it:

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --policy policy/policy_schema.json --enforce-delete
```

Enforce which child processes a script is allowed to spawn, against the
policy's `process.allow` list — deliberately **not** included in
`--enforce`'s shorthand (a policy without a `process` section stays
visibility-only, and even with one, killing a legitimate but
not-yet-allow-listed child is a real risk, so this one is opt-in on its
own):

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --policy policy/policy_schema.json --enforce-spawn
```

Actively terminate a process unconditionally on its next monitored syscall:

```bash
sudo python3 controller/bpf_loader.py --pid 1234 --block
```

Or use the CLI, which launches the target script and auto-attaches the
tracer in one step — no second terminal needed:

```bash
# visibility only (tags events, doesn't kill anything)
sudo python3 cli/kernelguard.py run untrusted.py --policy policy/policy_schema.json

# actively enforced
sudo python3 cli/kernelguard.py run untrusted.py --block-network --block-write --block-delete --block-spawn --policy policy/policy_schema.json
```

## Running as a daemon

`scripts/install.sh` copies the repo into `/opt/kernelguard` and installs
`systemd/kernelguard.service`:

```bash
sudo ./scripts/install.sh
# review/replace the policy file and ExecStart flags as instructed, then:
sudo systemctl start kernelguard
```

**Updating the policy without downtime.** Editing the policy file and
running `sudo systemctl reload kernelguard` sends `SIGHUP`, which
reloads it from disk in place — the tracer keeps running the whole time,
so nothing being watched gets missed. If the edited file is missing or
isn't valid JSON, the reload is rejected and the *previous* policy stays
in effect (with an error printed) rather than the daemon crashing or
running with no policy at all. Only relevant when `--policy` was passed
in `ExecStart`; without a policy loaded there's nothing to reload.

**Log file, independent of the terminal.** Add `--log-file
/var/log/kernelguard/events.log` to `ExecStart` to also mirror every
event to a plain-text file with automatic rotation (`--log-max-bytes`,
default ~10MB; `--log-backup-count`, default 3 — both optional), on top
of whatever `journalctl -u kernelguard` already shows.

Uninstall with `sudo ./scripts/install.sh --uninstall`.

## Testing

Tests that don't require root or a real kernel (policy logic, CLI argument
parsing, unit file / install script validation) live in `tests/` and run
with:

```bash
pip install pytest
pytest
```

## Key modules

- **eBPF C-code** — low-level programs hooking `execve`, `tcp_connect`,
  `vfs_write`, `unlinkat` (file deletion), and the `sched_process_fork`
  tracepoint (process spawn) directly in the kernel, plus a
  `blocked_pids` map for active enforcement.
- **Python BPF Controller (`bcc`)** — compiles and loads the eBPF code,
  manages PID filtering, policy evaluation, and enforcement.
- **Policy engine** — JSON-defined allow-lists for network access,
  independently for filesystem writes (`allow_write`) and filesystem
  deletes (`allow_delete`) — a path can be writable without also being
  deletable, or vice versa — and, opt-in per policy file, for which
  process names (`process.allow`) a script may spawn as children.
- **Security CLI** — `kernelguard run untrusted.py --block-network`,
  which auto-attaches the tracer for you.

## Known limitations / current scope

Being upfront about what's actually implemented vs. still planned (full
detail in [docs/ROADMAP.md](docs/ROADMAP.md)):

- **Enforcement is opt-in, not default.** `--policy` alone (on either
  `bpf_loader.py` or `cli/kernelguard.py run`) stays visibility-only —
  events get tagged `[ALLOWED]`/`[BLOCKED]` but nothing is killed. You
  have to explicitly add
  `--enforce`/`--enforce-network`/`--enforce-write`/`--enforce-delete`/`--enforce-spawn`
  (loader) or `--block-network`/`--block-write`/`--block-delete`/`--block-spawn`
  (CLI) to turn a `[BLOCKED]` tag into an actual `SIGKILL`.
  `--enforce-spawn`/`--block-spawn` are deliberately excluded from
  `--enforce`'s shorthand — see the next bullet.
- **Process spawn policy is opt-in per policy file, and never bundled
  into `--enforce`.** A policy file needs its own `process` section
  (`default` + an `allow` list of comm names) before fork events get
  tagged `[ALLOWED]`/`[BLOCKED]` at all — a policy written before this
  existed has no `process` section, so its forks stay visibility-only
  exactly as before, never silently deny-by-default. Even once a policy
  opts in, `--enforce-spawn`/`--block-spawn` has to be requested
  explicitly (not folded into `--enforce`), since killing a spawned
  child is more likely to break a legitimate script that just hasn't
  had its children allow-listed yet than a blocked network call or
  write would be.
- **Daemon mode is functional but not battle-tested.** `scripts/install.sh`
  + `systemd/kernelguard.service` run KernelGuard persistently, with
  `systemctl reload` for a no-downtime policy update and `--log-file`
  for a rotating on-disk event log. It hasn't been run under sustained
  real-world load yet, so treat it as new rather than hardened.
- **Requires a real Linux kernel with BCC.** Nothing in this project can
  load or run on Windows, macOS, or most restricted cloud sandboxes —
  BCC needs to compile against a kernel-headers package matching
  `uname -r`. See `demo/README.md` for a way to demonstrate expected
  output on machines without that environment.

## License

[MIT](LICENSE)
