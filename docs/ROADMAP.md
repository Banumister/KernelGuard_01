# Roadmap

Tracks the internship week-wise plan. Turn each row into a GitHub Issue
(or a Project board card) and assign an owner — see CONTRIBUTING.md for
branch naming that references these.

## Week 1 — eBPF Foundations

- [x] Write a basic eBPF C program that intercepts `execve()`
      (`ebpf/week1_execve_trace.c`)
- [x] Write the Python `bcc` script that loads the C program into the
      kernel and prints intercept logs to the console
      (`controller/bpf_loader.py`)

## Week 2 — Syscall Hooking + PID Filtering

- [ ] Expand the eBPF code to hook `tcp_connect` (network)
- [ ] Expand the eBPF code to hook `vfs_write` (filesystem)
- [ ] Update the Python daemon to accept a target PID and filter kernel
      events to just that process
- [ ] **Mid-project review — Interception Audit:** prove the tool logs
      every file a target Python script attempts to write to
- [ ] **Mid-project review — Performance Check:** confirm eBPF hooks add
      < 1ms latency to hooked syscalls (benchmark + write up results)

## Week 3 — Active Blocking + Policy Engine

- [ ] Upgrade the eBPF program from IDS (logging) to IPS (blocking):
      return `-EPERM` for unauthorized syscalls
- [ ] Build the JSON-based policy engine (`policy/`) — users define
      allowed IPs and file paths
- [ ] Wire the policy engine into the controller so blocking decisions
      are policy-driven, not hardcoded

## Week 4 — Packaging + Polish

- [ ] Package the daemon as a systemd service (`systemd/kernelguard.service`)
- [ ] Ensure kernel hooks are cleaned up gracefully on exit (no leaked
      kprobes/perf buffers)
- [ ] Finalize the CLI — clear, colored alert messages when a script is
      blocked
- [ ] **Final review:** end-to-end demo — a robust, production-ready
      Python security wrapper for executing untrusted dependencies safely
