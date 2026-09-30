# KernelGuard — Final Project Report

**An eBPF-Powered Runtime Security Sandbox for Untrusted Python Code**
**Domain:** Systems Programming & Cybersecurity
Repository: `https://github.com/Banumister/KernelGuard_01`

## 1. Executive summary

KernelGuard is a runtime security sandbox that watches and, optionally,
actively blocks what an untrusted Python script does at the kernel level
— network connections, file writes, file deletions, and child-process
spawning — using eBPF instead of a language-level or container-level
sandbox. The project moved through six phases of work: interception,
visibility, active enforcement, packaging as a daemon, extended syscall
coverage with per-category policy, and a final hardening pass. Every
phase on the original roadmap is complete and pushed to `main`; a sixth,
originally-unplanned phase (policy validation) was added at the end to
close a real usability/safety gap discovered while reviewing the rest of
the system. The codebase is roughly 2,100 lines across the eBPF C
source, the Python controller, the CLI, the policy engine, the demo
runner, and 73 automated tests, all of which pass.

The one piece that could not be verified by this development process
itself is the eBPF program actually loading into a real Linux kernel:
neither the developer's Windows machine nor the cloud environment used
to build large parts of this project can run eBPF (BCC requires a real
Linux kernel with a matching kernel-headers package). Every kernel-side
code path was instead verified by substituting a fake `bcc` module and
driving the real Python handler functions with synthetic kernel events —
a technique used consistently throughout this project and documented
below. [`docs/REAL_MACHINE_VALIDATION.md`](REAL_MACHINE_VALIDATION.md)
gives exact steps to close that last gap on any real Linux box.

## 2. Problem statement

Untrusted Python code — a downloaded package, a student submission being
auto-graded, a plugin — runs with the full permissions of whatever user
account executes it. If it tries to open a reverse shell, exfiltrate
data over the network, encrypt files for ransom, or persist itself by
spawning a background process, the interpreter has no idea and no way to
stop it. Existing options are either too heavy for the threat (a full
container or VM per untrusted script) or too easy to bypass (a
language-level sandbox like `pysandbox`, which tries to restrict Python
*from inside* Python — something the language was never designed to
support safely, and every historical attempt at it has eventually been
broken via some corner of the standard library or the C-level object
model).

KernelGuard takes a different approach: instead of restricting the
Python process from within, it watches (and can act on) what that
process actually asks the *kernel* to do, from outside the process
entirely. A malicious script cannot lie to the kernel about what syscall
it just made, the way it might trick a language-level guard about what
Python-level operation it performed.

## 3. Architecture

```
 Untrusted script (subprocess)
         |
         | syscalls: execve, connect, write, unlink, fork/clone
         v
 ┌─────────────────────────────────────────────┐
 │  Linux kernel                                │
 │  ┌─────────────────────────────────────────┐│
 │  │ eBPF programs (ebpf/execve_trace.c)      ││
 │  │  - kprobe: trace_execve                  ││
 │  │  - kprobe/kretprobe: trace_connect_*     ││
 │  │  - kprobe: trace_vfs_write               ││
 │  │  - kprobe: trace_unlink                  ││
 │  │  - tracepoint: sched_process_fork        ││
 │  │  - BPF_HASH blocked_pids (shared)        ││
 │  └─────────────────────────────────────────┘│
 └──────────────────┬────────────────────────────┘
                     │ perf buffers (events, tcp_events,
                     │ write_events, unlink_events, fork_events)
                     v
 ┌─────────────────────────────────────────────┐
 │  controller/bpf_loader.py (userspace, root)  │
 │   print_*_event handlers -> policy_loader.py │
 │   ENFORCE_* flags -> enforce_block()         │
 │     -> writes blocked_pids[pid] = 1          │
 │       (kernel kills that PID on its NEXT     │
 │        monitored syscall via bpf_send_signal)│
 └──────────────────┬────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        v                          v
 policy/policy_loader.py    cli/kernelguard.py
 (pure Python, no bcc,      (launches the target
  fully unit-tested)         script + auto-attaches
                              the tracer as a
                              subprocess)
```

**Key design choice: policy decisions live in pure Python, kernel code
stays minimal.** Every `trace_*` probe in `ebpf/execve_trace.c` does the
same three things: check `blocked_pids` for an active kill order, read
the event's raw data, and submit it to userspace over a perf buffer. All
of the actual *decision-making* — is this connection/write/deletion/
spawn allowed, should it be enforced — happens in
`controller/bpf_loader.py`'s `print_*_event` handlers, calling into
`policy/policy_loader.py`. This matters for two reasons: eBPF programs
are hard to test (they need a real kernel to even compile), while pure
Python is trivial to test; and keeping the in-kernel code small and
simple reduces the chance of a verifier rejection or a kernel-side bug,
since a live sandbox is the worst place to discover one.

**The `blocked_pids` kill switch is shared across every hook.** Once a
PID is written into that one `BPF_HASH`, *any* of the five probes will
`bpf_send_signal(9)` it on its very next monitored syscall — enforcement
doesn't care which category triggered the block, only that the PID is
now marked.

## 4. Threat model

**What KernelGuard defends against**, when run with `--policy` and the
matching `--enforce-*`/`--block-*` flags:
- A script exfiltrating data or opening a reverse shell to a host/port
  not on the network allow-list.
- A script writing to (e.g. dropping a payload) or deleting (e.g.
  ransomware-style destruction) files outside the allowed filesystem
  prefixes — with writes and deletes controlled independently, since a
  path being writable doesn't imply it should also be deletable.
- A script spawning a child process whose name isn't on an explicit
  allow-list, when the policy opts into spawn control at all (see §6.3
  for why this is off by default even with a policy loaded).

**What it explicitly does not defend against** (see §8, Known
limitations, for the full list):
- Anything that doesn't go through one of the five hooked
  syscalls/events. A script using a different syscall path to the same
  effect (e.g. `openat()` with `O_CREAT` instead of a `vfs_write()` path,
  or `rename()` instead of `unlinkat()` for destructive effect) is not
  currently watched.
- Kernel-level exploits or container/VM escapes — KernelGuard assumes a
  trusted kernel and a cooperative eBPF verifier; it is not itself a
  kernel-hardening tool.
- Anything that happens before the tracer attaches (there's an inherent
  race between process start and `--pid` attachment, same as any
  ptrace-style external monitor).
- A sufficiently privileged script disabling or evading monitoring
  itself (KernelGuard assumes the untrusted code runs as a normal user,
  not as root).

## 5. Week-by-week development summary

| Phase | Scope | Status |
|---|---|---|
| Week 1 | `execve()` interception via kprobe; CLI launches a script and prints its PID | ✅ done |
| Week 2 | `tcp_connect`/`vfs_write` visibility, `--pid` filtering, first JSON policy engine + `[ALLOWED]`/`[BLOCKED]` tagging (visibility only) | ✅ done |
| Week 3 | Active enforcement: `blocked_pids` + `bpf_send_signal`, `--enforce`/`--enforce-network`/`--enforce-write`, CLI auto-attaches the tracer | ✅ done |
| Week 4 | Packaging: `scripts/install.sh` + `systemd/kernelguard.service`; daemon review added no-downtime `SIGHUP` policy reload and rotating `--log-file` | ✅ done |
| Week 5 | Extended syscall coverage: `unlinkat()` deletion tracing and `sched_process_fork` spawn tracking, each with its **own** independent policy (`allow_delete`, tri-state `process` section) and enforcement flag | ✅ done |
| Week 6 | Hardening: `validate_policy()` catches malformed policy files (typo'd keys, wrong types) as warnings; CLI now validates `--policy` *before* launching the target script, closing a gap where a bad policy path previously let the untrusted script run unsupervised | ✅ done |

Every phase above ended with pushed, tested code — the full history is
in `docs/ROADMAP.md`, which carries far more implementation detail per
item than this summary.

## 6. Feature reference

### 6.1 Syscalls/events watched

| Event | Kernel attach point | Perf map | Handler |
|---|---|---|---|
| `execve()` | kprobe on the syscall | `events` | `print_event` |
| `tcp_v4_connect()` | kprobe + kretprobe | `tcp_events` | `print_tcp_event` |
| `vfs_write()` | kprobe | `write_events` | `print_write_event` |
| `unlinkat()` | kprobe on the syscall | `unlink_events` | `print_unlink_event` |
| `fork`/`clone` | `sched:sched_process_fork` tracepoint | `fork_events` | `print_fork_event` |

### 6.2 Policy schema (`policy/policy_schema.json`)

```json
{
  "policy_name": "example-untrusted-script",
  "network":    { "default": "deny", "allow": [{"host": "127.0.0.1", "port": 443}] },
  "filesystem": { "default": "deny", "allow_write": ["/tmp/"], "allow_delete": ["/tmp/"] },
  "process":    { "default": "deny", "allow": ["python3"] }
}
```
`network`/`filesystem` sections are two-state (allowed/blocked, falling
back to `default`). The `process` section is **tri-state** by design: a
policy file with no `process` key at all evaluates as "not opted in" and
leaves spawn events visibility-only, rather than retroactively treating
every older policy file as default-deny for spawning the moment this
feature shipped. `policy/policy_loader.py`'s `is_spawn_allowed()`
returns `None` in that case, and `None` is never allowed to reach the
enforcement decision (`should_enforce()` treats any non-`True` value as
a violation, so passing `None` through would have silently started
enforcing against every policy that never asked for it).

### 6.3 Enforcement flags

| Flag (`bpf_loader.py`) | Flag (`cli/kernelguard.py`) | In `--enforce` shorthand? |
|---|---|---|
| `--enforce-network` | `--block-network` | Yes |
| `--enforce-write` | `--block-write` | Yes |
| `--enforce-delete` | `--block-delete` | Yes |
| `--enforce-spawn` | `--block-spawn` | **No — opt-in on its own** |

Spawn enforcement is deliberately excluded from the `--enforce`
shorthand: killing a spawned child is judged more likely to break a
legitimate script that simply hasn't had its children allow-listed yet
than a blocked network call or file write would be, so it requires an
explicit, separate decision from whoever configures the policy.

### 6.4 Policy validation (Week 6)

`validate_policy()` checks a loaded policy for authoring mistakes —
unrecognized keys (catching typos like `alow_write`), a `default` value
that isn't `"allow"`/`"deny"`, list fields that aren't lists of strings,
and malformed `network.allow` rules — and returns human-readable
warnings. It never changes what a policy actually does; a typo'd key is
still just silently ignored the way it always was (falling back to
`default`, which can only make the policy *more* restrictive, never
more permissive). The value is purely diagnostic: surfacing "this
probably isn't the policy you meant to write" instead of only
discovering it while debugging unexpected `[BLOCKED]` tags. It is
checked in three places: at `bpf_loader.py` startup, after every
`SIGHUP` policy reload, and — closing a real gap — inside
`cli/kernelguard.py run` itself, *before* the target script is launched
at all, so a broken `--policy` path can no longer let an untrusted
script start running completely unsupervised while the tracer subprocess
fails behind it.

## 7. Verification strategy

Three layers of verification were used throughout, chosen to match what
each piece of code actually needs to run:

1. **Pure `pytest` coverage** for anything that doesn't need `bcc` or
   root — all of `policy/policy_loader.py`'s decision logic
   (`is_ip_allowed`, `is_path_allowed`, `is_delete_allowed`,
   `is_spawn_allowed`, `validate_policy`, `should_enforce`,
   `reload_policy`), all of `cli/kernelguard.py`'s argument parsing and
   `build_tracer_command()` translation, and structural checks on the
   systemd unit and install script. 73 tests, all passing, run in
   well under a second.
2. **Mocked-`bcc` runtime simulation** for `controller/bpf_loader.py`,
   which imports `bcc` at module load time and therefore can't even be
   imported in an environment without it. A fake `bcc` module is
   inserted into `sys.path` (just enough surface for the import to
   succeed), and the *real* `print_*_event` handler functions are
   called directly with synthetic event objects standing in for what a
   real perf buffer would deliver — exercising the actual policy
   lookup, tagging, and `enforce_block()`/`blocked_pids` logic exactly
   as it would run for real, just without a real kernel underneath it.
   This was used for every new hook and every new enforcement flag
   added after Week 2.
3. **Live execution** for anything with no `bcc` dependency at all —
   `demo/kernelguard_demo.py` was run directly (no mocking needed) to
   confirm its output, since it calls the real `policy_loader.py`
   against the real `policy_schema.json` for genuine file writes/
   deletes/spawns, simulating only the kernel-capture timing.

What none of the above can verify is the eBPF program itself actually
loading, compiling against a real kernel's BTF/headers, and the kernel
verifier accepting it — that step needs a real Linux box, which was not
available during development (see §1 and
[docs/REAL_MACHINE_VALIDATION.md](REAL_MACHINE_VALIDATION.md)).

## 8. Known limitations

- **Requires a real Linux kernel with BCC.** Cannot load or run on
  Windows, macOS, or most restricted cloud sandboxes.
- **Enforcement is opt-in, not default**, by deliberate design — loading
  a policy alone never kills anything until an explicit `--enforce-*`/
  `--block-*` flag is added.
- **Spawn enforcement is opt-in on top of an opt-in policy section** —
  see §6.3.
- **Daemon mode is functional but not battle-tested** under sustained
  real-world load.
- **Coverage is five specific syscalls/events, not a general syscall
  filter.** A script using a different code path to a similar effect
  (see §4) is not currently observed.
- **The eBPF layer itself was never run against a real kernel during
  development** — verified as thoroughly as possible without one (see
  §7), but §1's caveat stands until someone runs
  `docs/REAL_MACHINE_VALIDATION.md`'s checklist on real hardware.

## 9. Quick reference — running it

```bash
# Watch only (nothing blocked)
sudo python3 controller/bpf_loader.py --pid <PID>

# Watch + tag against a policy, still nothing blocked
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json

# Actively enforce network + write + delete (not spawn)
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json --enforce

# One-terminal CLI shortcut, fully enforcing
sudo python3 cli/kernelguard.py run untrusted.py --policy policy/policy_schema.json \
    --block-network --block-write --block-delete --block-spawn

# No real Linux/BCC box? See the cross-platform demo instead:
python3 demo/kernelguard_demo.py
```

Full detail: [README.md](../README.md) (usage, daemon mode, key
modules), [docs/ROADMAP.md](ROADMAP.md) (implementation history),
[docs/SETUP.md](SETUP.md) (environment setup + troubleshooting),
[docs/REAL_MACHINE_VALIDATION.md](REAL_MACHINE_VALIDATION.md) (real-box
validation checklist), [demo/README.md](../demo/README.md)
(cross-platform demo).

## 10. Conclusion and possible future work

KernelGuard demonstrates that a meaningful runtime security boundary for
untrusted Python code can be built from a small set of eBPF hooks plus a
pure-Python policy engine, without the overhead of a full container per
script and without trying to sandbox Python from the inside. All six
planned/added phases of work are complete, tested at every layer that
can be tested without a real kernel, and documented for the one
verification step (real-hardware validation) that couldn't be performed
during development.

Natural next steps, if this project continues beyond this submission:
run the full `docs/REAL_MACHINE_VALIDATION.md` checklist on real
hardware and fold the results back into this report; widen syscall
coverage to close the gaps noted in §8 (e.g. `openat()`/`rename()`);
and consider a structured (JSON) log output alongside the current
plain-text one, for ingestion into an external SIEM/alerting pipeline.
