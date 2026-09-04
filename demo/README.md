# demo/

`kernelguard_demo.py` shows Week 1 and Week 2 output in any terminal,
without needing a Linux kernel or BCC installed. It's for demos and
reviews on machines (like Windows dev boxes) where the real tracer
can't run.

## What's real vs. simulated

- **Real:** it launches an actual child process (execve), writes an
  actual file, and computes every `ALLOWED`/`BLOCKED` tag by calling
  this repo's real `policy/policy_loader.py` against the real
  `policy/policy_schema.json`.
- **Simulated:** the kernel-side capture of `execve()` / `tcp_connect()`
  / `vfs_write()`. Loading the real eBPF program (`ebpf/execve_trace.c`)
  requires a Linux kernel with root access and a kernel-headers package
  matching `uname -r` for BCC to compile against — not available on
  Windows or in most cloud sandboxes. The script prints a `[demo mode]`
  notice explaining this at runtime, so the output is honest about what
  it is.

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
