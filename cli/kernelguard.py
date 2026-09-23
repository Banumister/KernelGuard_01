#!/usr/bin/env python3
"""
KernelGuard Security CLI

    kernelguard run <script.py> [--block-network] [--block-write] [--block-delete] [--block-spawn] [--policy policy.json]

`run` launches the target script and prints its PID. If --policy,
--block-network, --block-write, --block-delete, or --block-spawn are
given, it also automatically attaches controller/bpf_loader.py as the
tracer (translating these CLI-level flags into bpf_loader.py's
--enforce-network/--enforce-write/--enforce-delete/--enforce-spawn), so
a single `kernelguard run` invocation is enough — no second terminal
needed. Without any of those flags, it falls back to printing manual
attach instructions (useful for a plain execve()-only watch).

--block-network, --block-write, --block-delete, and --block-spawn each
require --policy, since there has to be a rule set to enforce against.
--block-spawn is checked against the policy's process.allow list, which
is opt-in per policy file — see bpf_loader.py's --enforce-spawn help.
"""
import argparse
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF_LOADER = os.path.join(REPO_ROOT, "controller", "bpf_loader.py")


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
        help="Automatically kill the script on its next BLOCKED network connection. "
             "Requires --policy.",
    )
    run_parser.add_argument(
        "--block-write",
        action="store_true",
        help="Automatically kill the script on its next BLOCKED file write. "
             "Requires --policy.",
    )
    run_parser.add_argument(
        "--block-delete",
        action="store_true",
        help="Automatically kill the script on its next BLOCKED file deletion. "
             "Checked against the policy's filesystem.allow_delete list, "
             "independent of allow_write. Requires --policy.",
    )
    run_parser.add_argument(
        "--block-spawn",
        action="store_true",
        help="Automatically kill a newly spawned CHILD process if its comm isn't "
             "on the policy's process.allow list. Only takes effect if the policy "
             "file has a \"process\" section at all -- a policy without one leaves "
             "spawn tracking visibility-only. Requires --policy.",
    )
    run_parser.add_argument(
        "--policy", help="Path to a JSON policy file (see policy/). Without "
                          "--block-network/--block-write/--block-delete/--block-spawn, "
                          "tags events allowed/blocked but doesn't kill anything "
                          "(visibility only)."
    )

    return parser


def build_tracer_command(pid, policy, block_network, block_write, block_delete=False,
                          block_spawn=False):
    """Pure function: builds the controller/bpf_loader.py invocation for a
    given set of CLI flags. Kept separate from main() so it's testable
    without actually spawning a subprocess or needing bcc installed."""
    cmd = [sys.executable, BPF_LOADER, "--pid", str(pid)]
    if policy:
        cmd += ["--policy", policy]
    if block_network:
        cmd.append("--enforce-network")
    if block_write:
        cmd.append("--enforce-write")
    if block_delete:
        cmd.append("--enforce-delete")
    if block_spawn:
        cmd.append("--enforce-spawn")
    return cmd


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run":
        if not os.path.isfile(args.script):
            print(
                f"[KernelGuard] ERROR: script not found: {args.script}\n"
                "[KernelGuard] Check the path and try again "
                "(relative paths are resolved from the current directory).",
                file=sys.stderr,
            )
            sys.exit(1)

        if (args.block_network or args.block_write or args.block_delete
                or args.block_spawn) and not args.policy:
            print(
                "[KernelGuard] ERROR: --block-network/--block-write/--block-delete/"
                "--block-spawn require --policy so there's a rule set to enforce against.",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"[KernelGuard] Launching target script: {args.script}")
        proc = subprocess.Popen([sys.executable, args.script])
        print(f"[KernelGuard] Target PID={proc.pid}.")

        tracer_proc = None
        if (args.policy or args.block_network or args.block_write or args.block_delete
                or args.block_spawn):
            tracer_cmd = build_tracer_command(
                proc.pid, args.policy, args.block_network, args.block_write,
                args.block_delete, args.block_spawn
            )
            mode = ("enforcing" if (args.block_network or args.block_write
                                     or args.block_delete or args.block_spawn)
                    else "visibility-only")
            print(f"[KernelGuard] Attaching tracer ({mode}):")
            print("    " + " ".join(tracer_cmd))
            tracer_proc = subprocess.Popen(tracer_cmd)
        else:
            print("[KernelGuard] In another terminal, attach the tracer with:")
            print(f"    sudo python3 controller/bpf_loader.py --pid {proc.pid}")

        try:
            proc.wait()
        finally:
            if tracer_proc is not None:
                tracer_proc.terminate()
                tracer_proc.wait()


if __name__ == "__main__":
    main()
