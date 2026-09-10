# KernelGuard — Roadmap

This tracks what's done and what's left, week by week. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for branch naming and workflow —
branches should map to a row here where possible.

## Week 1 — execve() interception ✅ done

- [x] `ebpf/execve_trace.c`: kprobe on `execve()` reporting PID, PPID,
      command name, and executable path via `BPF_PERF_OUTPUT`.
- [x] `controller/bpf_loader.py`: loads the program, attaches the hook,
      prints events (`print_event`).
- [x] `cli/kernelguard.py run <script>`: launches a target script and
      prints its PID so the tracer can attach to it.
- [x] Error handling: `run` exits cleanly with a clear message if the
      target script doesn't exist, instead of a raw traceback.

## Week 2 — Visibility: network + filesystem, PID filtering, policy tagging ✅ done

- [x] `trace_connect_entry` / `trace_connect_return` kprobes on
      `tcp_v4_connect` — reports every outbound connection (PID, source/
      destination IP, destination port).
- [x] `trace_vfs_write` kprobe on `vfs_write` — reports every file write
      (PID, command, filename, byte count).
- [x] `--pid` filtering in `bpf_loader.py` — scope monitoring to one
      process instead of the whole machine.
- [x] `policy/policy_schema.json` + `policy/policy_loader.py` — JSON
      allow-list for network (host/port) and filesystem (path prefix)
      access, with a default-deny posture.
- [x] `--policy` flag tags each connection/write event as
      `[ALLOWED]` or `[BLOCKED - policy violation]`.
- [x] Test coverage: `tests/test_basic.py` (policy logic),
      `tests/test_cli.py` / `tests/test_cli_smoke.py` (CLI parsing and
      the missing-script error path).

**Scope note:** Week 2 is visibility only. Nothing is actually stopped
yet — `cli/kernelguard.py run` explicitly logs a note that
`--block-network` / `--block-write` / `--policy` are parsed but not
enforced. That's Week 3.

## Week 3 — Active enforcement 🚧 in progress

- [x] `blocked_pids` BPF hash map + `bpf_send_signal(9)` in
      `execve_trace.c` — the kernel-side mechanism to kill a flagged PID
      on its next monitored syscall already exists, for all three hooks
      (execve, tcp_connect, vfs_write).
- [x] `bpf_loader.py --block` — manually mark a PID as blocked when
      attaching the tracer directly.
- [x] Wire real-time enforcement into the policy engine: `bpf_loader.py
      --enforce` (requires `--policy`) now automatically adds a PID to
      `blocked_pids` the moment a connect/write is tagged `[BLOCKED]`,
      via `policy_loader.should_enforce()` + `bpf_loader.enforce_block()`.
      Deliberately opt-in — `--policy` alone still stays visibility-only,
      so existing usage doesn't change behavior underneath anyone.
- [x] Tests for the enforcement decision path: `tests/test_basic.py`
      covers `should_enforce()` (enabled+blocked → enforce; disabled,
      allowed, or no-policy → never enforce). Verified against the real
      `print_tcp_event`/`print_write_event` logic with a mocked BPF map,
      since `bpf_loader.py` can't be imported without `bcc` installed.
- [ ] Implement `--block-network` / `--block-write` on
      `cli/kernelguard.py run` so the CLI's own flags actually enforce,
      not just warn. This is separate from `bpf_loader.py --enforce`
      above and still open.

## Week 4 — Packaging & daemon mode ⏳ not started

- [x] `systemd/kernelguard.service` — stub unit file
      (`ExecStart=/usr/bin/python3 /opt/kernelguard/controller/bpf_loader.py`).
- [ ] Installer / packaging steps documenting how `/opt/kernelguard`
      gets populated (currently assumed, not scripted).
- [ ] `systemd/kernelguard.service` reviewed for a persistent daemon
      use case (currently mirrors the one-shot CLI invocation; a daemon
      needs to handle policy reload, log rotation, etc.).
- [ ] Document daemon installation in `README.md`.

## Environment note (applies to every week above)

Everything here needs a Linux kernel with root access and a
kernel-headers package matching `uname -r` for BCC to compile against
(see `README.md` > Requirements). Windows and most bare cloud sandboxes
can't run the real tracer for this reason — see `demo/README.md` for a
cross-platform way to show expected behavior without a Linux box.
