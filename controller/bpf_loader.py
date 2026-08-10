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