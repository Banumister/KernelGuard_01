#!/usr/bin/env python3
"""
KernelGuard demo-mode runner — for showing Week 1 / Week 2 output live in a
terminal (e.g. VS Code's integrated terminal) when a real Linux+BCC
environment isn't available.

WHAT'S REAL vs SIMULATED:
- Real: the child-process launch (execve), the actual /tmp file write, and
  every ALLOWED/BLOCKED decision — those come from actually importing and
  calling this repo's real policy/policy_loader.py against the real
  policy/policy_schema.json.
- Simulated: the kernel-side capture of execve()/tcp_connect()/vfs_write().
  Loading an eBPF program requires a Linux kernel with root access and a
  matching kernel-headers package for BCC to compile against (see
  README.md > Requirements) — not available on this machine. The two
  blocked actions (a disallowed connect, a disallowed write) are described
  but not actually attempted, so nothing touches the network or the
  filesystem outside /tmp.

Run the real tracer (controller/bpf_loader.py) on a Linux box with BCC
installed for a genuine live capture — this script's output format
matches it exactly.

Usage: python kernelguard_demo.py
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"
))
from policy_loader import load_policy, is_ip_allowed, is_path_allowed  # noqa: E402

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
RESET = "\033[0m"

DEMO_PID_1 = 48213
DEMO_PID_2 = 48311


def pause(seconds=0.6):
    time.sleep(seconds)


def banner():
    print(f"{YELLOW}KernelGuard :: watching execve(), tcp_connect(), and "
          f"vfs_write() syscalls. Ctrl-C to stop.{RESET}")


def demo_mode_notice():
    print(f"{DIM}[demo mode] this machine has no Linux kernel + BCC available, "
          f"so kernel-side capture is simulated below.")
    print(f"[demo mode] policy ALLOWED/BLOCKED decisions are REAL — computed "
          f"by this repo's own policy_loader.py.{RESET}\n")


def week1():
    print("=" * 70)
    print("WEEK 1 — execve() syscall hook")
    print("=" * 70)
    print()
    print(f"$ sudo python3 cli/kernelguard.py run demo_week1.py")
    pause(0.3)
    print(f"[KernelGuard] Launching target script: demo_week1.py")
    print(f"[KernelGuard] Target PID={DEMO_PID_1}.")
    print("[KernelGuard] In another terminal, attach the tracer with:")
    print(f"    sudo python3 controller/bpf_loader.py --pid {DEMO_PID_1}")
    print()
    pause(0.5)
    print(f"$ sudo python3 controller/bpf_loader.py --pid {DEMO_PID_1}")
    banner()
    demo_mode_notice()

    print("[demo] launching a real child process to trigger execve()...")
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "dir"], capture_output=True)
        comm, path = "cmd.exe", r"C:\Windows\System32\cmd.exe"
    else:
        subprocess.run(["ls", "-la", "/tmp"], capture_output=True)
        comm, path = "ls", "/usr/bin/ls"
    pause(0.8)
    print(f"PID={DEMO_PID_1:<7} PPID={os.getpid():<7} COMM={comm:<16} EXEC={path}")
    pause(0.4)
    print()
    print(f"{YELLOW}^C{RESET}")
    print(f"{YELLOW}KernelGuard stopped. Kernel hooks detached.{RESET}")
    print()


def week2():
    print("=" * 70)
    print("WEEK 2 — tcp_connect() + vfs_write() hooks, PID filtering, policy tagging")
    print("=" * 70)
    print()

    policy_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "policy", "policy_schema.json",
    )
    policy = load_policy(policy_path)

    print(f"$ sudo python3 cli/kernelguard.py run demo_week2.py --policy policy/policy_schema.json")
    pause(0.3)
    print("[KernelGuard] NOTE: policy enforcement is not implemented yet "
          "(see Week 3 in docs/ROADMAP.md). Running in log-only mode.")
    print("[KernelGuard] Launching target script: demo_week2.py")
    print(f"[KernelGuard] Target PID={DEMO_PID_2}.")
    print("[KernelGuard] In another terminal, attach the tracer with:")
    print(f"    sudo python3 controller/bpf_loader.py --pid {DEMO_PID_2} --policy policy/policy_schema.json")
    print()
    pause(0.5)
    print(f"$ sudo python3 controller/bpf_loader.py --pid {DEMO_PID_2} --policy policy/policy_schema.json")
    banner()
    demo_mode_notice()

    # --- network: one allowed, one blocked (classification is real; the
    #     blocked attempt is described, not made, to avoid touching the
    #     network) ---
    print("[demo] connect: 127.0.0.1:443 (in the policy allow-list)")
    pause(0.6)
    allowed = is_ip_allowed(policy, "127.0.0.1", 443)
    status = f"{GREEN}[ALLOWED]{RESET}" if allowed else f"{RED}[BLOCKED - policy violation]{RESET}"
    print(f"PID={DEMO_PID_2:<7} CONNECT 10.0.2.15 -> 127.0.0.1:443 {status}")
    print()

    print("[demo] connect: 93.184.216.34:80 (not in the policy allow-list; "
          "not actually dialed out)")
    pause(0.6)
    allowed = is_ip_allowed(policy, "93.184.216.34", 80)
    status = f"{GREEN}[ALLOWED]{RESET}" if allowed else f"{RED}[BLOCKED - policy violation]{RESET}"
    print(f"PID={DEMO_PID_2:<7} CONNECT 10.0.2.15 -> 93.184.216.34:80 {status}")
    print()

    # --- filesystem: one real write under /tmp, one described-not-performed ---
    tmp_target = os.path.join(
        "/tmp" if os.name != "nt" else os.environ.get("TEMP", "."),
        "kernelguard_demo_output.txt",
    )
    print(f"[demo] write: {tmp_target} (under the policy's allowed /tmp/ prefix)")
    payload = b"hello from kernelguard demo\n"
    with open(tmp_target, "wb") as f:
        f.write(payload)
    pause(0.6)
    allowed = is_path_allowed(policy, "/tmp/kernelguard_demo_output.txt")
    status = f"{GREEN}[ALLOWED]{RESET}" if allowed else f"{RED}[BLOCKED - policy violation]{RESET}"
    print(f"PID={DEMO_PID_2:<7} COMM=python3           "
          f"WRITE {len(payload)} bytes -> kernelguard_demo_output.txt {status}")
    print()

    print("[demo] write: /etc/kernelguard_test (outside every allowed prefix; "
          "not actually attempted)")
    pause(0.6)
    allowed = is_path_allowed(policy, "/etc/kernelguard_test")
    status = f"{GREEN}[ALLOWED]{RESET}" if allowed else f"{RED}[BLOCKED - policy violation]{RESET}"
    print(f"PID={DEMO_PID_2:<7} COMM=python3           "
          f"WRITE 32 bytes -> kernelguard_test {status}")
    print()

    print(f"{YELLOW}^C{RESET}")
    print(f"{YELLOW}KernelGuard stopped. Kernel hooks detached.{RESET}")
    print()


if __name__ == "__main__":
    week1()
    pause(1.0)
    week2()
