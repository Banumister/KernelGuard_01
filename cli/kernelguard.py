#!/usr/bin/env python3
"""
KernelGuard Security CLI

    kernelguard run <script.py> [--block-network] [--block-write] [--policy policy.json]

Week 1 status: this is a skeleton. `run` launches the target script and
tells you how to attach the Week 1 execve() tracer to it. Policy
enforcement flags (--block-network / --block-write / --policy) are
parsed but not yet enforced — that lands in Week 3 (see docs/ROADMAP.md).
"""
import argparse
import subprocess
import sys


def build_parser():
    parser = argparse.ArgumentParser(
        prog="kernelguard",
        description="eBPF-powered runtime security sandbox for untrusted Python code",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run", help="Run a Python script under KernelGuard supervision"
    )
    run_parser.add_argument("script", help="Path to the untrusted Python script")
    run_parser.add_argument(
        "--block-network",
        action="store_true",
        help="[Week 3] Block unauthorized network syscalls",
    )
    run_parser.add_argument(
        "--block-write",
        action="store_true",
        help="[Week 3] Block unauthorized filesystem writes",
    )
    run_parser.add_argument(
        "--policy", help="[Week 3] Path to a JSON policy file (see policy/)"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run":
        if args.block_network or args.block_write or args.policy:
            print(
                "[KernelGuard] NOTE: policy enforcement is not implemented yet "
                "(see Week 3 in docs/ROADMAP.md). Running in log-only mode."
            )

        print(f"[KernelGuard] Launching target script: {args.script}")
        proc = subprocess.Popen([sys.executable, args.script])
        print(f"[KernelGuard] Target PID={proc.pid}.")
        print("[KernelGuard] In another terminal, attach the tracer with:")
        print(f"    sudo python3 controller/bpf_loader.py --pid {proc.pid}")
        proc.wait()


if __name__ == "__main__":
    main()
