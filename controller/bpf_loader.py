#!/usr/bin/env python3
"""
KernelGuard :: Week 1 - BCC Controller

Compiles ebpf/week1_execve_trace.c, loads it into the running kernel,
attaches it to the execve() syscall, and prints every intercepted
process-execution event to the console in real time.

Usage:
    sudo python3 controller/bpf_loader.py
    sudo python3 controller/bpf_loader.py --pid 12345

Must be run as root — loading eBPF programs requires CAP_SYS_ADMIN
(or CAP_BPF + CAP_PERFMON on newer kernels). See docs/SETUP.md for
how to install the BCC toolchain this script depends on.
"""
import argparse
import os
import sys
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    sys.exit(
        "ERROR: the 'bcc' Python module was not found.\n"
        "Install the BCC toolchain first — see docs/SETUP.md."
    )

BPF_SOURCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ebpf",
    "week1_execve_trace.c",
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="KernelGuard Week 1 — execve() syscall tracer"
    )
    parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help="Only show events from this PID (default: show every process)",
    )
    return parser.parse_args()


def load_bpf_program():
    with open(BPF_SOURCE_FILE, "r") as f:
        bpf_text = f.read()

    b = BPF(text=bpf_text)
    syscall_fn = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=syscall_fn, fn_name="trace_execve")
    return b


def make_print_event(bpf, target_pid):
    def print_event(cpu, data, size):
        event = bpf["events"].event(data)
        if target_pid is not None and event.pid != target_pid:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"[{ts}] PID={event.pid:<7} PPID={event.ppid:<7} "
            f"COMM={event.comm.decode('utf-8', 'replace'):<16} "
            f"EXEC={event.filename.decode('utf-8', 'replace')}"
        )

    return print_event


def main():
    if os.geteuid() != 0:
        sys.exit("KernelGuard must be run as root (sudo) to load eBPF programs.")

    args = parse_args()
    b = load_bpf_program()
    b["events"].open_perf_buffer(make_print_event(b, args.pid))

    print("KernelGuard :: watching execve() syscalls. Ctrl-C to stop.")
    if args.pid:
        print(f"Filtering for PID={args.pid}")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nKernelGuard stopped. Kernel hooks detached.")


if __name__ == "__main__":
    main()
