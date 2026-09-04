#!/usr/bin/env python3
"""
KernelGuard demo-mode runner — simplified, plain-language output for
showing Week 1 / Week 2 behavior live in a terminal (e.g. VS Code's
integrated terminal) when a real Linux+BCC environment isn't available.

WHAT'S REAL vs SIMULATED:
- Real: the child-process launch, the actual file write, and every
  ALLOWED/BLOCKED decision — those call this repo's real
  policy/policy_loader.py against the real policy/policy_schema.json.
- Simulated: the kernel-side capture of execve()/tcp_connect()/
  vfs_write(). Loading an eBPF program requires a Linux kernel with root
  access and a matching kernel-headers package for BCC to compile
  against (see README.md > Requirements) — not available on this
  machine. The two blocked actions (a disallowed connect, a disallowed
  write) are described but not actually attempted.

Run the real tracer (controller/bpf_loader.py) on a Linux box with BCC
installed for a genuine live capture.

Usage: python demo/kernelguard_demo.py
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"
))
from policy_loader import load_policy, is_ip_allowed, is_path_allowed  # noqa: E402

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"

DEMO_PID_1 = 48213
DEMO_PID_2 = 48311


def pause(seconds=0.7):
    time.sleep(seconds)


def header(title):
    print()
    print("=" * 60)
    print(f" {title}")
    print("=" * 60)
    print()


def step(text):
    pause(0.5)
    print(f"Step: {text}")


def detected(kind, fields, allowed=None):
    pause(0.5)
    print()
    print(f"   >>> DETECTED: {kind} <<<")
    for label, value in fields:
        print(f"       {label:<22}: {value}")
    if allowed is not None:
        tag = f"{GREEN}ALLOWED{RESET}" if allowed else f"{RED}BLOCKED{RESET}"
        reason = "this is on the allow list" if allowed else "this is NOT on the allow list"
        print(f"       {'Rule check':<22}: {tag}  ({reason})")
    print()


def week1():
    header("WEEK 1 DEMO — Watching a new program start")

    step("I start a script through KernelGuard.")
    print(f"   Script: demo_week1.py")
    print(f"   KernelGuard gave it Process ID: {DEMO_PID_1}")

    step(f"KernelGuard attaches its watcher to Process ID {DEMO_PID_1}.")
    print(f"{CYAN}   Watcher is running. Waiting for activity...{RESET}")
    print(f"{DIM}   [demo mode: the real watcher needs a Linux computer with special "
          f"kernel access, so this part is played out with realistic timing.]{RESET}")

    step("The script starts another program — this is what we're watching for.")
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "dir"], capture_output=True)
        comm, path = "cmd.exe", r"C:\Windows\System32\cmd.exe"
    else:
        subprocess.run(["ls", "-la", "/tmp"], capture_output=True)
        comm, path = "ls", "/usr/bin/ls"

    detected(
        "a new program was started",
        [
            ("Program name", comm),
            ("Program location", path),
            ("Process ID", DEMO_PID_1),
            ("Started by (Parent ID)", os.getpid()),
        ],
    )

    pause(0.5)
    print("Step: Watching stopped (Ctrl+C).")


def week2():
    header("WEEK 2 DEMO — Watching internet connections and file saves")

    policy_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "policy", "policy_schema.json",
    )
    policy = load_policy(policy_path)

    step("I start a script through KernelGuard, with a rule file attached.")
    print(f"   Script: demo_week2.py")
    print(f"   Rule file: policy/policy_schema.json")
    print(f"   KernelGuard gave it Process ID: {DEMO_PID_2}")

    print(f"{DIM}   [demo mode: kernel-level watching is played out with realistic "
          f"timing; every rule check below is real, using this repo's own code.]{RESET}")

    step("The script tries to connect to the internet: 127.0.0.1 on port 443.")
    allowed = is_ip_allowed(policy, "127.0.0.1", 443)
    detected(
        "an internet connection",
        [("From Process ID", DEMO_PID_2), ("Connecting to", "127.0.0.1 : 443")],
        allowed=allowed,
    )

    step("The script tries a second connection: 93.184.216.34 on port 80.")
    allowed = is_ip_allowed(policy, "93.184.216.34", 80)
    detected(
        "an internet connection",
        [("From Process ID", DEMO_PID_2), ("Connecting to", "93.184.216.34 : 80")],
        allowed=allowed,
    )

    step("The script tries to save a file inside the allowed folder (/tmp/).")
    tmp_target = os.path.join(
        "/tmp" if os.name != "nt" else os.environ.get("TEMP", "."),
        "kernelguard_demo_output.txt",
    )
    payload = b"hello from kernelguard demo\n"
    with open(tmp_target, "wb") as f:
        f.write(payload)
    allowed = is_path_allowed(policy, "/tmp/kernelguard_demo_output.txt")
    detected(
        "a file save",
        [
            ("From Process ID", DEMO_PID_2),
            ("File name", "kernelguard_demo_output.txt"),
            ("Size", f"{len(payload)} bytes"),
        ],
        allowed=allowed,
    )

    step("The script tries to save a file in a restricted folder (/etc/). Not actually done.")
    allowed = is_path_allowed(policy, "/etc/kernelguard_test")
    detected(
        "a file save",
        [
            ("From Process ID", DEMO_PID_2),
            ("File name", "kernelguard_test"),
            ("Size", "32 bytes"),
        ],
        allowed=allowed,
    )

    pause(0.5)
    print("Step: Watching stopped (Ctrl+C).")
    print()


if __name__ == "__main__":
    week1()
    pause(1.0)
    week2()
