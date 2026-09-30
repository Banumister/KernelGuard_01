# Real-machine validation

Everything in this repo has been verified two ways so far: `pytest` (pure
policy logic, CLI parsing, no kernel needed) and a mocked-`bcc` runtime
simulation (drives the real `bpf_loader.py` handler functions with fake
event objects, since `bcc` itself can't be installed here). Neither of
those actually loads the real eBPF program into a real kernel — that
needs a genuine Linux machine with root access and a kernel-headers
package matching `uname -r`, which **no environment used to build this
project has**: not your Windows machine, and not the cloud sandbox this
assistant runs in (confirmed directly — `bcc` isn't installable there).

This doc is the missing piece: exact steps to run the real tracer for
real, on a real Linux box, so you (or a reviewer) can confirm the eBPF
side actually works and not just the Python logic around it.

## 1. Get a real Linux box

Any of these work. Pick whichever is easiest for you — they're ordered
roughly by convenience, not by importance.

- **A free-tier cloud VM** — Oracle Cloud's Always Free tier, AWS's free
  tier, or Google Cloud's free trial all give you a real Ubuntu VM with a
  standard kernel and a headers package available via `apt`. This is the
  most reliable option since you don't control the kernel version, but a
  stock Ubuntu image always has matching headers in its own repos.
- **A local VM** — VirtualBox, UTM (Apple Silicon), or Hyper-V (Windows)
  with a fresh **Ubuntu 22.04 or 24.04 LTS Desktop/Server** ISO. Give it
  root/sudo access as normal.
- **`multipass`** (Canonical's lightweight Ubuntu VM tool) if you have it
  or can install it — `multipass launch --name kernelguard 22.04` gets
  you a working Ubuntu VM in under a minute on Windows, macOS, or Linux.

**Avoid WSL2 for this.** Its custom kernel usually has no matching
`linux-headers` package published anywhere `apt` can reach (see
`docs/SETUP.md`'s Troubleshooting section) — you'll hit a "kernel headers
not found" wall that a real VM or cloud instance doesn't have.

## 2. One-time setup on the Linux box

```bash
# System packages (BCC + matching kernel headers)
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc git

# Confirm bcc actually imports before going further
python3 -c "from bcc import BPF; print('bcc OK')"
```

If the last command fails, stop here and check `docs/SETUP.md`'s
Troubleshooting section before continuing — nothing below will work
until `bcc` imports cleanly.

```bash
git clone https://github.com/Banumister/KernelGuard_01.git
cd KernelGuard_01

# Sanity check: the pure-Python test suite should pass here exactly like
# it does everywhere else, since it doesn't touch bcc at all.
pip install pytest
pytest
```

## 3. Validation checklist

Run each of these and compare against "what to expect." Each one
exercises a different hook/feature, so work through them in order rather
than skipping to enforcement — visibility mode should work before you
turn on killing anything.

For every step below, open **two terminals**: one to run a target
script, one to run the tracer against its PID (or use the `cli/`
one-terminal shortcut, noted per step where it applies).

### 3.1 — execve() visibility (Week 1)

```bash
# terminal A
python3 -c "import time; time.sleep(60)"
# note the PID it prints if you add one, or `pgrep -f "time.sleep"`

# terminal B
sudo python3 controller/bpf_loader.py --pid <PID>
```
Then in a third terminal, make the sleeping process's shell run something
(or just watch any `execve` on the box if you drop `--pid`).
**Expect:** a `PID=... PPID=... COMM=... EXEC=...` line per new program
started.

### 3.2 — network + filesystem visibility, with policy tagging (Week 2)

```bash
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json
```
From the target process, connect to `127.0.0.1:443` (allowed) and to
some other host/port (blocked), and write a file under `/tmp/` (allowed)
and elsewhere (blocked).
**Expect:** `CONNECT ... [ALLOWED]` / `[BLOCKED - policy violation]` and
`WRITE ... [ALLOWED]` / `[BLOCKED - policy violation]` lines matching
`policy/policy_schema.json`'s `network.allow` / `filesystem.allow_write`.

### 3.3 — active enforcement (Week 3)

```bash
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json --enforce
```
Trigger a blocked connection or write from the target process.
**Expect:** an `AUTO-BLOCKED` line, and the target process actually dies
(`SIGKILL`) on its *next* monitored syscall — confirm with `echo $?` /
`wait` in the target's terminal, or `ps` showing it's gone.

### 3.4 — daemon mode: reload + log file (Week 4)

```bash
sudo cp policy/policy_schema.json /tmp/kg_policy.json
sudo python3 controller/bpf_loader.py --pid <PID> --policy /tmp/kg_policy.json --log-file /tmp/kg_events.log
```
Edit `/tmp/kg_policy.json` (e.g. add a host to `network.allow`), then in
a third terminal: `sudo kill -HUP <bpf_loader.py's PID>`.
**Expect:** `policy reloaded from /tmp/kg_policy.json` printed, the new
rule takes effect immediately (no restart), and `/tmp/kg_events.log`
contains the same event lines as the terminal (colors stripped).

Also worth doing at least once: install it for real —
```bash
sudo ./scripts/install.sh
# edit /opt/kernelguard's policy + ExecStart per the script's own instructions
sudo systemctl start kernelguard
sudo systemctl status kernelguard   # should be active (running)
sudo systemctl reload kernelguard   # should trigger the same SIGHUP reload
sudo ./scripts/install.sh --uninstall
```

### 3.5 — deletion tracing + its own policy (Week 5)

```bash
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json --enforce-delete
```
From the target, delete a file under `/tmp/` (allowed by
`filesystem.allow_delete`) and one elsewhere (blocked).
**Expect:** `DELETE -> ... [ALLOWED]` for the `/tmp/` one, `[BLOCKED -
policy violation]` + `AUTO-BLOCKED` (and the process dying) for the
other. Also confirm a file that's writable-but-not-deletable under a
policy you edit (narrow `allow_delete`, wide `allow_write`) behaves
independently — deletable ≠ writable.

### 3.6 — process-spawn tracing + its own policy (Week 5)

```bash
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json --enforce-spawn
```
From the target, spawn a child whose comm is `python3` (on the example
policy's `process.allow` list) and one that isn't (e.g. `nc`, `bash`).
**Expect:** `FORK -> ... [ALLOWED]` for the allowed comm, `[BLOCKED -
policy violation]` + `AUTO-BLOCKED` targeting the **child's** PID (not
the parent's) for the other — and the child process specifically dies,
while the parent keeps running.

### 3.7 — policy validation warnings (Week 6)

```bash
cp policy/policy_schema.json /tmp/typo_policy.json
sed -i 's/allow_write/alow_write/' /tmp/typo_policy.json
sudo python3 controller/bpf_loader.py --pid <PID> --policy /tmp/typo_policy.json
```
**Expect:** a `KernelGuard :: policy warning — "filesystem" section:
unrecognized key(s) ['alow_write']...` line printed right after the
"policy loaded from..." line, and the tracer keeps running normally
(writes under `/tmp/` now evaluate against `filesystem.default`, since
the typo'd key is invisible to `is_path_allowed()`).

Also try the CLI's fast-fail with a bad path, to confirm the target
script never launches at all:
```bash
python3 cli/kernelguard.py run some_script.py --policy /nonexistent.json
```
**Expect:** an immediate error and non-zero exit, and `some_script.py`
never starts (check with `ps`/`pgrep` — nothing new should appear).

### 3.8 — the one-terminal CLI shortcut

```bash
sudo python3 cli/kernelguard.py run demo/kernelguard_demo.py --policy policy/policy_schema.json --block-network --block-write --block-delete --block-spawn
```
**Expect:** `[KernelGuard] Attaching tracer (enforcing):` followed by
both the demo script's own output and the real tracer's live
`ALLOWED`/`BLOCKED` lines interleaved — this is the only place in this
whole validation pass where the *simulated* demo output and the *real*
kernel capture run side by side, so it's a good final sanity check that
they agree with each other.

## 4. What to do with the results

If everything above matches, that's real end-to-end confirmation that
the eBPF side works exactly as the mocked-`bcc` simulations predicted —
worth noting explicitly in a final report or review, since it's the one
part of this project that genuinely couldn't be verified any other way
during development. If anything *doesn't* match, save the terminal
output (`script kg_validation.log` before starting is an easy way to
capture everything) — that's a real bug the mocked simulation didn't
catch, and worth filing as an issue per `CONTRIBUTING.md`.
