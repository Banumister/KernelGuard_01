"""
Smoke tests that don't require root or a real kernel/BPF environment —
these just verify the CLI and controller modules import and parse args
correctly, so CI can run them on an ordinary GitHub Actions runner.

Real interception behavior (does execve() actually get logged?) has to be
verified manually on a Linux box with BCC installed — see docs/SETUP.md
and the roadmap notes in docs/ROADMAP.md.
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


def test_run_missing_script_exits_cleanly(tmp_path, monkeypatch, capsys):
    """`kernelguard run <missing-file>` should print a clear error and
    exit(1) instead of letting subprocess.Popen raise a raw traceback."""
    cli = _load_module("kernelguard_cli_missing", "cli/kernelguard.py")

    missing_script = tmp_path / "does_not_exist.py"
    monkeypatch.setattr(sys, "argv", ["kernelguard", "run", str(missing_script)])

    try:
        cli.main()
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 1

    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()
    assert str(missing_script) in captured.err

def test_ebpf_source_file_exists():
    ebpf_source = REPO_ROOT / "ebpf" / "execve_trace.c"
    assert ebpf_source.exists()
    text = ebpf_source.read_text()
    assert "execve" in text.lower()