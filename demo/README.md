# demo/

`kernelguard_demo.py` shows Week 1, Week 2, and Week 5 output in any
terminal, without needing a Linux kernel or BCC installed. It's for
demos and reviews on machines (like Windows dev boxes) where the real
tracer can't run.

## What's real vs. simulated

- **Real:** it launches actual child processes (execve in Week 1,
  fork/spawn in Week 5), writes and deletes actual files, and computes
  every `ALLOWED`/`BLOCKED` tag by calling this repo's real
  `policy/policy_loader.py` against the real `policy/policy_schema.json`.
- **Simulated:** the kernel-side capture of `execve()` / `tcp_connect()`
  / `vfs_write()` / `unlinkat()` / process `fork`/`clone`. Loading the
  real eBPF program (`ebpf/execve_trace.c`) requires a Linux kernel with
  root access and a kernel-headers package matching `uname -r` for BCC
  to compile against — not available on Windows or in most cloud
  sandboxes. The script prints a `[demo mode]` notice explaining this at
  runtime, so the output is honest about what it is.
- Process-spawn events have no rule check at all yet (they're always
  just reported, never `ALLOWED`/`BLOCKED`) — see the root README's
  "Known limitations" section. The demo's Week 5 fork step reflects
  that honestly rather than inventing a rule result for it.

## Running it

```bash
python demo/kernelguard_demo.py
```

## Running the real thing

For a genuine live capture, run the actual tracer on a Linux machine
with BCC installed (see the root `README.md` > Requirements):

```bash
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
sudo python3 controller/bpf_loader.py --pid <PID> --policy policy/policy_schema.json
```
