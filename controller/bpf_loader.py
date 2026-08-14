import os
import sys
import socket
import struct

try:
    from bcc import BPF
except ImportError:
    sys.exit(
        "ERROR: the 'bcc' Python module was not found.\n"
        "Install the BCC toolchain first."
    )

BPF_SOURCE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ebpf",
    "execve_trace.c",
)


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
    print(f"PID={event.pid:<7} PPID={event.ppid:<7} "
          f"COMM={event.comm.decode('utf-8', 'replace'):<16} "
          f"EXEC={event.filename.decode('utf-8', 'replace')}")


def print_tcp_event(cpu, data, size):
    event = b["tcp_events"].event(data)
    saddr = socket.inet_ntoa(struct.pack("I", event.saddr))
    daddr = socket.inet_ntoa(struct.pack("I", event.daddr))
    dport = socket.ntohs(event.dport)
    print(f"PID={event.pid:<7} CONNECT {saddr} -> {daddr}:{dport}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("KernelGuard must be run as root (sudo) to load eBPF programs.")

    b = load_bpf_program()
    b["events"].open_perf_buffer(print_event)
    b["tcp_events"].open_perf_buffer(print_tcp_event)

    print("KernelGuard :: watching execve() and tcp_connect() syscalls. Ctrl-C to stop.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nKernelGuard stopped. Kernel hooks detached.")