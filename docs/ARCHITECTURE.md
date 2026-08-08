# Architecture

## Core idea

Most Python sandboxes try to restrict a script *from inside* the Python
process (monkey-patching builtins, restricted `exec`, seccomp wrappers).
Those are either bypassable (a script can often reach the same syscall
through a different code path) or so heavy they defeat the purpose
(spinning up a full container per untrusted script).

KernelGuard instead works one layer down, at the syscall boundary inside
the kernel itself ("Ring 0"). It doesn't matter how a malicious script
tries to open a socket or write a file — whether via `socket()`,
a C extension, `os.system()`, or a `subprocess` call — every one of
those paths eventually issues the same underlying syscall
(`connect`, `write`, `execve`, ...), and that's the point we intercept.

```
 ┌─────────────────────────────┐
 │      untrusted.py            │  <- runs with normal user permissions,
 │      (pip package, script)   │     completely unaware it's being watched
 └──────────────┬───────────────┘
                │ syscalls: execve(), connect(), write() ...
                ▼
 ┌─────────────────────────────┐
 │   Linux Kernel (Ring 0)      │
 │  ┌─────────────────────────┐ │
 │  │  eBPF hooks (ebpf/*.c)  │ │  <- kprobes/tracepoints on the syscalls
 │  │  - log event, OR        │ │     we care about; Week 3 adds -EPERM
 │  │  - return -EPERM        │ │     to actually block the call
 │  └───────────┬─────────────┘ │
 └──────────────┼───────────────┘
                │ perf buffer events
                ▼
 ┌─────────────────────────────┐
 │ Python BPF Controller        │  <- controller/bpf_loader.py
 │ (bcc: compiles/loads/manages)│     compiles the C above via LLVM,
 └──────────────┬───────────────┘     loads it into the kernel, streams
                │                     events back to user space
                ▼
 ┌─────────────────────────────┐
 │ Security CLI (cli/)          │  <- kernelguard run script.py --block-network
 │ + Policy Engine (policy/)    │     applies user-defined allow/deny rules
 └───────────────────────────────┘
```

## Components

- **`ebpf/`** — the actual kernel-space programs (C), one hook set per
  syscall family (process exec, network, filesystem).
- **`controller/`** — the Python daemon using `bcc` to compile eBPF C at
  runtime (via LLVM), load it into the kernel, and read events back
  through a BPF perf buffer.
- **cgroups integration** (Week 2) — scopes tracing to a specific target
  PID/process group instead of system-wide, so KernelGuard only watches
  the Python process it was asked to supervise.
- **`policy/`** (Week 3) — JSON-defined allow-lists (IPs, ports, file
  paths) that the controller checks before deciding whether to let a
  syscall through or return `-EPERM`.
- **`cli/`** — the user-facing entrypoint: `kernelguard run <script>
  --block-network`.
- **`systemd/`** (Week 4) — packaging so KernelGuard can run as a
  background service instead of a one-shot CLI invocation.

## Why this is hard to bypass

Because the interception point is inside the kernel, not inside the
Python interpreter, a malicious script cannot see or disable it without
already having the kernel privileges KernelGuard is trying to prevent it
from getting. This is the core thesis the "Interception Audit" and
"Performance Check" milestones (mid-project review) are meant to prove
out empirically, not just architecturally.
