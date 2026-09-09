import os
import sys
import socket
import struct
import argparse
import ctypes as ct
import signal

try:
    from bcc import BPF
except ImportError:
    sys.exit(
        "ERROR: the 'bcc' Python module was not found.\n"
        "Install the BCC toolchain first."
    )

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"
))
from policy_loader import load_policy, is_ip_allowed, is_path_allowed, should_enforce

BPF_SOURCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ebpf",
    "execve_trace.c",
)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

TARGET_PID = None
POLICY = None
ENFORCE = False


def parse_args():
    parser = argparse.ArgumentParser(description="KernelGuard syscall tracer")
    parser.add_argument("--pid", type=int, default=None,
                         help="Only show events from this PID (default: show all processes)")
    parser.add_argument("--policy", type=str, default=None,
                         help="Path to a JSON policy file (see policy/policy_schema.json)")
    parser.add_argument("--enforce", action="store_true",
                         help="Combined with --policy: automatically block (kill) a PID "
                              "the next time it triggers a BLOCKED policy violation. "
                              "Without this flag, --policy only tags and logs violations "
                              "(visibility only). Requires --policy.")
    parser.add_argument("--block", action="store_true",
                         help="Actively block (kill) the target PID on its next monitored "
                              "syscall. Requires --pid.")
    return parser.parse_args()


def load_bpf_program():
    with open(BPF_SOURCE_FILE, "r") as f:
        bpf_text = f.read()

    b = BPF(text=bpf_text)
    syscall_fn = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=syscall_fn, fn_name="trace_execve")

    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
    b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write")
    return b


def print_event(cpu, data, size):
    event = b["events"].event(data)
    if TARGET_PID is not None and event.pid != TARGET_PID:
        return
    print(f"PID={event.pid:<7} PPID={event.ppid:<7} "
          f"COMM={event.comm.decode('utf-8', 'replace'):<16} "
          f"EXEC={event.filename.decode('utf-8', 'replace')}")


def enforce_block(pid, reason):
    """Actually add a PID to the kernel-side blocked_pids map, so the
    next monitored syscall from it gets SIGKILL'd (see
    ebpf/execve_trace.c). Only called when --enforce is set."""
    b["blocked_pids"][ct.c_uint32(pid)] = ct.c_uint8(1)
    print(f"{RED}KernelGuard :: PID={pid} AUTO-BLOCKED — {reason}. "
          f"It will be terminated on its next monitored syscall.{RESET}")


def print_tcp_event(cpu, data, size):
    event = b["tcp_events"].event(data)
    if TARGET_PID is not None and event.pid != TARGET_PID:
        return
    saddr = socket.inet_ntoa(struct.pack("I", event.saddr))
    daddr = socket.inet_ntoa(struct.pack("I", event.daddr))
    dport = socket.ntohs(event.dport)

    status = ""
    if POLICY is not None:
        allowed = is_ip_allowed(POLICY, daddr, dport)
        if allowed:
            status = f"{GREEN}[ALLOWED]{RESET}"
        else:
            status = f"{RED}[BLOCKED - policy violation]{RESET}"
            if should_enforce(POLICY, allowed, ENFORCE):
                enforce_block(event.pid, f"connection to {daddr}:{dport} violates policy")
    print(f"PID={event.pid:<7} CONNECT {saddr} -> {daddr}:{dport} {status}")


def print_write_event(cpu, data, size):
    event = b["write_events"].event(data)
    if TARGET_PID is not None and event.pid != TARGET_PID:
        return
    filename = event.filename.decode('utf-8', 'replace')

    status = ""
    if POLICY is not None:
        allowed = is_path_allowed(POLICY, filename)
        if allowed:
            status = f"{GREEN}[ALLOWED]{RESET}"
        else:
            status = f"{RED}[BLOCKED - policy violation]{RESET}"
            if should_enforce(POLICY, allowed, ENFORCE):
                enforce_block(event.pid, f"write to {filename} violates policy")
    print(f"PID={event.pid:<7} COMM={event.comm.decode('utf-8', 'replace'):<16} "
          f"WRITE {event.count} bytes -> {filename} {status}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("KernelGuard must be run as root (sudo) to load eBPF programs.")

    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, handle_sigterm)

    args = parse_args()
    TARGET_PID = args.pid
    if args.policy:
        POLICY = load_policy(args.policy)

    if args.enforce and not POLICY:
        sys.exit("--enforce requires --policy to know what to enforce against.")
    ENFORCE = args.enforce

    b = load_bpf_program()

    if ENFORCE:
        print(f"{YELLOW}KernelGuard :: --enforce is ON — policy violations will be "
              f"actively blocked, not just logged.{RESET}")

    if args.block:
        if not args.pid:
            sys.exit("--block requires --pid to specify which process to actively block.")
        b["blocked_pids"][ct.c_uint32(args.pid)] = ct.c_uint8(1)
        print(f"{RED}KernelGuard :: PID={args.pid} is ACTIVELY BLOCKED — "
              f"it will be terminated on its next monitored syscall.{RESET}")

    b["events"].open_perf_buffer(print_event)
    b["tcp_events"].open_perf_buffer(print_tcp_event)
    b["write_events"].open_perf_buffer(print_write_event)

    print(f"{YELLOW}KernelGuard :: watching execve(), tcp_connect(), and vfs_write() syscalls. "
          f"Ctrl-C to stop.{RESET}")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(f"{YELLOW}\nKernelGuard stopped. Kernel hooks detached.{RESET}")