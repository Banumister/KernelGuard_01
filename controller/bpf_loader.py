import os
import sys

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
    return b