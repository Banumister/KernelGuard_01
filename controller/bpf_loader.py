import os
import re
import sys
import socket
import struct
import argparse
import ctypes as ct
import signal
import logging
from logging.handlers import RotatingFileHandler

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
from policy_loader import (
    load_policy, is_ip_allowed, is_path_allowed, should_enforce, reload_policy,
)

BPF_SOURCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ebpf",
    "execve_trace.c",
)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
ANSI_RE = re.compile(r"\033\[[0-9;]*m")

TARGET_PID = None
POLICY = None
POLICY_PATH = None
ENFORCE_NETWORK = False
ENFORCE_WRITE = False
EVENT_LOGGER = None


def strip_ansi(text):
    """Remove terminal color codes before writing a line to the log
    file -- ANSI escapes are useful in a live terminal but just noise
    (and encoding risk) in a plain-text log meant for `grep`/log
    shippers."""
    return ANSI_RE.sub("", text)


def setup_file_logger(path, max_bytes, backup_count):
    """Wire up a rotating log file for event output, independent of
    whatever's printed to the terminal. Used with --log-file so a
    daemon running under systemd has its own bounded event history on
    disk instead of relying solely on the journal (which has its own,
    separately-configured retention)."""
    logger = logging.getLogger("kernelguard.events")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    return logger


def log_event(line):
    """Mirror an already-formatted, possibly colored terminal line to
    the rotating log file (colors stripped), if one is configured."""
    if EVENT_LOGGER is not None:
        EVENT_LOGGER.info(strip_ansi(line))


def parse_args():
    parser = argparse.ArgumentParser(description="KernelGuard syscall tracer")
    parser.add_argument("--pid", type=int, default=None,
                         help="Only show events from this PID (default: show all processes)")
    parser.add_argument("--policy", type=str, default=None,
                         help="Path to a JSON policy file (see policy/policy_schema.json)")
    parser.add_argument("--enforce", action="store_true",
                         help="Combined with --policy: automatically block (kill) a PID "
                              "the next time it triggers ANY BLOCKED policy violation "
                              "(network or filesystem). Shorthand for --enforce-network "
                              "--enforce-write together. Without any --enforce* flag, "
                              "--policy only tags and logs violations (visibility only). "
                              "Requires --policy.")
    parser.add_argument("--enforce-network", action="store_true",
                         help="Combined with --policy: automatically block (kill) a PID "
                              "on its next BLOCKED network connection specifically. "
                              "Requires --policy.")
    parser.add_argument("--enforce-write", action="store_true",
                         help="Combined with --policy: automatically block (kill) a PID "
                              "on its next BLOCKED file write specifically. "
                              "Requires --policy.")
    parser.add_argument("--block", action="store_true",
                         help="Actively block (kill) the target PID on its next monitored "
                              "syscall. Requires --pid.")
    parser.add_argument("--log-file", type=str, default=None,
                         help="Also write every event to this file (colors stripped), "
                              "with automatic rotation, so a daemon has its own bounded "
                              "event history instead of relying solely on the journal.")
    parser.add_argument("--log-max-bytes", type=int, default=10_000_000,
                         help="Rotate --log-file once it reaches this size in bytes "
                              "(default: 10,000,000 / ~10MB).")
    parser.add_argument("--log-backup-count", type=int, default=3,
                         help="Number of rotated log files to keep (default: 3). "
                              "Only used with --log-file.")
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

    unlink_fn = b.get_syscall_fnname("unlinkat")
    b.attach_kprobe(event=unlink_fn, fn_name="trace_unlink")
    return b


def print_event(cpu, data, size):
    event = b["events"].event(data)
    if TARGET_PID is not None and event.pid != TARGET_PID:
        return
    line = (f"PID={event.pid:<7} PPID={event.ppid:<7} "
            f"COMM={event.comm.decode('utf-8', 'replace'):<16} "
            f"EXEC={event.filename.decode('utf-8', 'replace')}")
    print(line)
    log_event(line)


def enforce_block(pid, reason):
    """Actually add a PID to the kernel-side blocked_pids map, so the
    next monitored syscall from it gets SIGKILL'd (see
    ebpf/execve_trace.c). Only called when --enforce is set."""
    b["blocked_pids"][ct.c_uint32(pid)] = ct.c_uint8(1)
    print(f"{RED}KernelGuard :: PID={pid} AUTO-BLOCKED — {reason}. "
          f"It will be terminated on its next monitored syscall.{RESET}")


def handle_sighup(signum, frame):
    """SIGHUP handler: reload the policy file from disk in place, so an
    operator can update rules on a running daemon with
    `systemctl reload kernelguard` instead of a full restart. Wired up
    only when --policy was given, since there's nothing to reload
    otherwise (see registration in __main__)."""
    global POLICY
    new_policy, error = reload_policy(POLICY_PATH, POLICY)
    if error:
        print(f"{RED}KernelGuard :: policy reload FAILED — {error}. "
              f"Keeping the previous policy in effect.{RESET}")
        return
    POLICY = new_policy
    print(f"{GREEN}KernelGuard :: policy reloaded from {POLICY_PATH}.{RESET}")


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
            if should_enforce(POLICY, allowed, ENFORCE_NETWORK):
                enforce_block(event.pid, f"connection to {daddr}:{dport} violates policy")
    line = f"PID={event.pid:<7} CONNECT {saddr} -> {daddr}:{dport} {status}"
    print(line)
    log_event(line)


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
            if should_enforce(POLICY, allowed, ENFORCE_WRITE):
                enforce_block(event.pid, f"write to {filename} violates policy")
    line = (f"PID={event.pid:<7} COMM={event.comm.decode('utf-8', 'replace'):<16} "
            f"WRITE {event.count} bytes -> {filename} {status}")
    print(line)
    log_event(line)


def print_unlink_event(cpu, data, size):
    event = b["unlink_events"].event(data)
    if TARGET_PID is not None and event.pid != TARGET_PID:
        return
    filename = event.filename.decode('utf-8', 'replace')

    # Deletion is evaluated against the same filesystem policy as writes
    # (allow_write is really "paths this script may modify", and
    # deleting a file is a modification) and gated by the same
    # --enforce-write / --block-write flag rather than a separate one,
    # to keep the operator-facing flag set from growing per syscall.
    status = ""
    if POLICY is not None:
        allowed = is_path_allowed(POLICY, filename)
        if allowed:
            status = f"{GREEN}[ALLOWED]{RESET}"
        else:
            status = f"{RED}[BLOCKED - policy violation]{RESET}"
            if should_enforce(POLICY, allowed, ENFORCE_WRITE):
                enforce_block(event.pid, f"deletion of {filename} violates policy")
    line = (f"PID={event.pid:<7} COMM={event.comm.decode('utf-8', 'replace'):<16} "
            f"DELETE -> {filename} {status}")
    print(line)
    log_event(line)


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("KernelGuard must be run as root (sudo) to load eBPF programs.")

    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, handle_sigterm)

    args = parse_args()
    TARGET_PID = args.pid
    POLICY_PATH = args.policy

    if args.log_file:
        EVENT_LOGGER = setup_file_logger(
            args.log_file, args.log_max_bytes, args.log_backup_count
        )
        print(f"{YELLOW}KernelGuard :: also logging events to {args.log_file} "
              f"(rotating at {args.log_max_bytes} bytes, keeping "
              f"{args.log_backup_count} backups).{RESET}")

    if args.policy:
        POLICY = load_policy(args.policy)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, handle_sighup)
            print(f"{YELLOW}KernelGuard :: policy loaded from {POLICY_PATH}. "
                  f"Send SIGHUP (or `systemctl reload kernelguard`) to reload it "
                  f"without restarting.{RESET}")

    ENFORCE_NETWORK = args.enforce or args.enforce_network
    ENFORCE_WRITE = args.enforce or args.enforce_write
    if (ENFORCE_NETWORK or ENFORCE_WRITE) and not POLICY:
        sys.exit("--enforce/--enforce-network/--enforce-write require --policy "
                  "to know what to enforce against.")

    b = load_bpf_program()

    if ENFORCE_NETWORK or ENFORCE_WRITE:
        parts = []
        if ENFORCE_NETWORK:
            parts.append("network")
        if ENFORCE_WRITE:
            parts.append("filesystem")
        print(f"{YELLOW}KernelGuard :: enforcement is ON for: {', '.join(parts)} — "
              f"policy violations in that category will be actively blocked, "
              f"not just logged.{RESET}")

    if args.block:
        if not args.pid:
            sys.exit("--block requires --pid to specify which process to actively block.")
        b["blocked_pids"][ct.c_uint32(args.pid)] = ct.c_uint8(1)
        print(f"{RED}KernelGuard :: PID={args.pid} is ACTIVELY BLOCKED — "
              f"it will be terminated on its next monitored syscall.{RESET}")

    b["events"].open_perf_buffer(print_event)
    b["tcp_events"].open_perf_buffer(print_tcp_event)
    b["write_events"].open_perf_buffer(print_write_event)
    b["unlink_events"].open_perf_buffer(print_unlink_event)

    print(f"{YELLOW}KernelGuard :: watching execve(), tcp_connect(), vfs_write(), and "
          f"unlinkat() (file deletion) syscalls. Ctrl-C to stop.{RESET}")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(f"{YELLOW}\nKernelGuard stopped. Kernel hooks detached.{RESET}")