# `ebpf/` — Kernel-space programs

Raw eBPF C programs that get compiled and injected into the Linux kernel
at runtime by the Python controller (`controller/bpf_loader.py`), using
the `bcc` library's LLVM/clang-based just-in-time compiler.

| File | Week | Hooks | Status |
|---|---|---|---|
| `week1_execve_trace.c` | 1 | `execve()` | ✅ implemented (log-only) |
| `week2_syscall_trace.c` | 2 | `tcp_connect()`, `vfs_write()` | 🔲 TODO |
| `week3_enforce.c` | 3 | same hooks, returns `-EPERM` to block | 🔲 TODO |

**Note:** these `.c` files are not standalone-compilable with plain `gcc`.
`bcc` rewrites them with kernel-specific headers and BPF helper macros
(`BPF_PERF_OUTPUT`, `BPF_HASH`, etc.) at load time — always load them via
the Python controller, not a C compiler directly. See `../docs/SETUP.md`
for environment requirements.
