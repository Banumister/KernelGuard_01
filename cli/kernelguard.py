#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

CONTROLLER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "controller",
    "bpf_loader.py",
)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="kernelguard",
        description="eBPF-powered runtime security sandbox for untrusted Python code",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a Python script under KernelGuard supervision")
    run_parser.add_argument("script", help="Path to the untrusted Python script")
    run_parser.add_argument("--block-network", action="store_true",
                             help="Actively block the script if it attempts a monitored syscall")
    run_parser.add_argument("--policy", help="Path to a JSON policy file")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run":
        print(f"{YELLOW}[KernelGuard] Launching target script: {args.script}{RESET}")
        proc = subprocess.Popen([sys.executable, args.script])
        print(f"{YELLOW}[KernelGuard] Target PID={proc.pid}{RESET}")

        controller_cmd = ["sudo", "python3", CONTROLLER_PATH, "--pid", str(proc.pid)]
        if args.block_network:
            controller_cmd.append("--block")
        if args.policy:
            controller_cmd += ["--policy", args.policy]

        print(f"{GREEN}[KernelGuard] Starting supervision...{RESET}")
        tracer = subprocess.Popen(controller_cmd)

        try:
            proc.wait()
        finally:
            tracer.terminate()


if __name__ == "__main__":
    main()