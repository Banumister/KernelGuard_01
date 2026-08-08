"""
Smoke tests that don't require root or a real kernel/BPF environment —
these just verify the CLI and controller modules import and parse args
correctly, so CI can run them on an ordinary GitHub Actions runner.

Real interception behavior (does execve() actually get logged?) has to be
verified manually on a Linux box with BCC installed — see docs/SETUP.md
and the "Interception Audit" deliverable in docs/ROADMAP.md (Week 2).
"""
import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_module(name, relative_path):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_cli_parser_builds():
    cli = _load_module("kernelguard_cli", "cli/kernelguard.py")
    parser = cli.build_parser()
    args = parser.parse_args(["run", "example.py", "--block-network"])
    assert args.command == "run"
    assert args.script == "example.py"
    assert args.block_network is True


def test_ebpf_source_file_exists():
    ebpf_source = REPO_ROOT / "ebpf" / "week1_execve_trace.c"
    assert ebpf_source.exists()
    text = ebpf_source.read_text()
    assert "trace_execve" in text
    assert "BPF_PERF_OUTPUT" in text
