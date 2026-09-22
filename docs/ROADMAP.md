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

## Week 3 — Active enforcement ✅ done

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
- [x] Granular enforcement: `bpf_loader.py` now takes independent
      `--enforce-network` / `--enforce-write` flags (`--enforce` stays
      as shorthand for both together), so network and filesystem
      blocking can be turned on separately.
- [x] `cli/kernelguard.py run --block-network` / `--block-write` now
      actually enforce instead of just warning: `run` automatically
      launches `controller/bpf_loader.py` as a subprocess (translating
      `--block-network`/`--block-write`/`--policy` into
      `--enforce-network`/`--enforce-write`/`--policy`), so a single
      `kernelguard run` command is enough end-to-end — no second
      terminal needed. Without any of those flags it falls back to
      printing the old manual two-terminal attach instructions.
      `--block-network`/`--block-write` each require `--policy` and
      fail fast with a clear error if it's missing.
- [x] Tests: `tests/test_cli_smoke.py` covers the new
      `build_tracer_command()` translation (visibility-only, network-only,
      both-enforce), the `--block-*` without `--policy` fast-fail path,
      and the auto-attach behavior itself via a monkeypatched
      `subprocess.Popen` (so tests never actually spawn the real tracer,
      which needs bcc/root). 31/31 tests passing across the suite.

## Week 4 — Packaging & daemon mode ✅ done

- [x] `systemd/kernelguard.service` — stub unit file
      (`ExecStart=/usr/bin/python3 /opt/kernelguard/controller/bpf_loader.py`).
- [x] `scripts/install.sh` — installer script that copies the repo into
      `/opt/kernelguard`, installs Python dependencies, and installs +
      enables the systemd unit. Replaces the previous "currently
      assumed, not scripted" gap.
- [x] Install steps documented in `README.md` (daemon installation
      section pointing at `scripts/install.sh`).
- [x] `systemd/kernelguard.service` reviewed for a persistent daemon
      use case:
      - **Policy reload without restart** — `policy_loader.reload_policy()`
        re-reads the policy file from disk without exiting/crashing on a
        bad edit (missing file or invalid JSON keeps the previous policy
        in effect and reports why). `bpf_loader.py`'s new `handle_sighup`
        wires this to `SIGHUP`, and the unit's new
        `ExecReload=/bin/kill -HUP $MAINPID` makes
        `systemctl reload kernelguard` trigger it — no restart, no gap
        in tracing. Only active when `--policy` was passed at startup.
      - **Log rotation** — new `--log-file` (+ `--log-max-bytes`,
        `--log-backup-count`) flag on `bpf_loader.py` mirrors every
        event to a `RotatingFileHandler`-backed plain-text file
        (ANSI colors stripped), independent of `journalctl`'s own
        retention.
      - Tests: `tests/test_basic.py` covers `reload_policy()` directly
        (successful reload, missing file, invalid JSON, no path set —
        all without needing `bcc`); `tests/test_systemd_unit.py` checks
        the new `ExecReload` line. The signal handler and log-file path
        themselves were verified with the same mocked-`bcc` runtime
        simulation used throughout this project, since `bpf_loader.py`
        can't be imported without `bcc` installed.

## Week 5 — Extended syscall coverage 🚧 in progress

Weeks 1–4 covered the original planned scope end-to-end (interception,
visibility, enforcement, packaging/daemon). This week is new: widening
what KernelGuard actually watches beyond the original three syscalls.

- [x] `unlinkat()` (file deletion) tracing — `ebpf/execve_trace.c`'s
      new `trace_unlink`, hooked at the syscall entry (like
      `trace_execve`) rather than a VFS-internal function, since
      `vfs_unlink()`'s argument list has changed across kernel versions
      (e.g. the `mnt_userns` parameter) while the syscall ABI is stable.
      `controller/bpf_loader.py`'s new `print_unlink_event` evaluates
      deletions against the *same* `filesystem.allow_write` policy list
      and the same `--enforce-write`/`--block-write` flag as writes
      (documented as a known simplification in `README.md` — no
      separate `allow_delete` rule or flag yet). This directly serves
      the project's own ransomware/deletion threat model from the
      README's problem statement, which wasn't actually covered by any
      hook before this.
      Tests: `tests/test_cli_smoke.py`'s
      `test_ebpf_source_covers_all_hooked_events` (see below) is a
      regression check (no `bcc` needed) that the C source and the
      Python loader agree on all hooked syscalls; the handler itself
      was verified with the same mocked-`bcc` runtime-simulation
      pattern used throughout this project.
- [x] Process spawn/persistence tracking (`fork`/`clone`) —
      `ebpf/execve_trace.c`'s new `TRACEPOINT_PROBE(sched,
      sched_process_fork)` reports every child process a monitored
      process spawns (parent/child PID + comm), catching a script that
      forks to persist/evade even if it never `execve()`s into a
      different program. Uses the `sched:sched_process_fork`
      tracepoint rather than a kprobe on `do_fork`/`_do_fork`/
      `kernel_clone` — the internal function's name *and* argument
      list have changed repeatedly across kernel versions, while
      scheduler tracepoints are a stable, documented ABI. BCC
      auto-attaches `TRACEPOINT_PROBE`-defined functions when the
      program loads, so unlike the kprobes above, `load_bpf_program()`
      needed no new `b.attach_*()` call.
      `controller/bpf_loader.py`'s new `print_fork_event` is
      **visibility-only, with no policy check** — there's no "allowed
      to spawn children" concept in the policy schema (yet), so a fork
      is always just reported, the same way `execve` events always
      have been. Documented as a known limitation in `README.md`.
- [x] Regression test tying it together: `tests/test_cli_smoke.py`'s
      `test_ebpf_source_covers_all_hooked_events` (renamed from
      `..._all_four_hooked_syscalls`) now checks all five hooked
      events/syscalls across both the C source and the Python loader
      in one place, so a future syscall addition that forgets to wire
      up one side fails loudly.
- [ ] A dedicated filesystem policy action for deletion (separate from
      `allow_write`) if the shared-flag simplification for `unlinkat()`
      turns out to be too coarse in practice — not started.
- [ ] A policy concept for process spawning (e.g. "deny fork entirely"
      or an allow-list of comms a script may spawn) — not started;
      fork tracking above is visibility-only until this exists.

## Environment note (applies to every week above)

Everything here needs a Linux kernel with root access and a
kernel-headers package matching `uname -r` for BCC to compile against
(see `README.md` > Requirements). Windows and most bare cloud sandboxes
can't run the real tracer for this reason — see `demo/README.md` for a
cross-platform way to show expected behavior without a Linux box.
