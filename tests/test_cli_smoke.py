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


def test_ebpf_source_covers_all_hooked_events():
    # Regression check for the syscalls/events this project claims to
    # watch (see README's "Key modules" section) -- doesn't need bcc,
    # just confirms the C source and the Python side agree on what's
    # hooked.
    ebpf_source = (REPO_ROOT / "ebpf" / "execve_trace.c").read_text()
    for probe_fn, perf_map in [
        ("trace_execve", "events"),
        ("trace_connect_entry", "tcp_events"),
        ("trace_vfs_write", "write_events"),
        ("trace_unlink", "unlink_events"),
        ("sched_process_fork", "fork_events"),
    ]:
        assert probe_fn in ebpf_source, f"missing eBPF probe function: {probe_fn}"
        assert perf_map in ebpf_source, f"missing eBPF perf output map: {perf_map}"

    loader_source = (REPO_ROOT / "controller" / "bpf_loader.py").read_text()
    for name in ("print_event", "print_tcp_event", "print_write_event",
                 "print_unlink_event", "print_fork_event"):
        assert name in loader_source, f"missing bpf_loader.py handler: {name}"


def test_build_tracer_command_visibility_only():
    """--policy alone (no --block-*) should attach the tracer without
    either --enforce-* flag — visibility/tagging only."""
    cli = _load_module("kernelguard_cli_btc_vis", "cli/kernelguard.py")
    cmd = cli.build_tracer_command(123, "policy/policy_schema.json", False, False)
    assert cmd == [
        sys.executable, cli.BPF_LOADER,
        "--pid", "123",
        "--policy", "policy/policy_schema.json",
    ]


def test_build_tracer_command_with_both_enforce_flags():
    cli = _load_module("kernelguard_cli_btc_enf", "cli/kernelguard.py")
    cmd = cli.build_tracer_command(123, "policy/policy_schema.json", True, True)
    assert "--enforce-network" in cmd
    assert "--enforce-write" in cmd


def test_build_tracer_command_network_only():
    cli = _load_module("kernelguard_cli_btc_net", "cli/kernelguard.py")
    cmd = cli.build_tracer_command(123, "policy/policy_schema.json", True, False)
    assert "--enforce-network" in cmd
    assert "--enforce-write" not in cmd


class _FakeProc:
    """Stands in for subprocess.Popen's return value in CLI tests, so
    tests never actually spawn controller/bpf_loader.py (which needs
    bcc/root and would fail or hang outside a real Linux+BCC box)."""

    _next_pid = 40000

    def __init__(self):
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.terminated = False

    def wait(self):
        return 0

    def terminate(self):
        self.terminated = True


def test_run_block_network_without_policy_exits_cleanly(tmp_path, monkeypatch, capsys):
    """--block-network/--block-write need a policy to enforce against —
    this should fail fast with a clear message, before anything is
    launched."""
    cli = _load_module("kernelguard_cli_blockerr", "cli/kernelguard.py")

    def fail_popen(*a, **kw):
        raise AssertionError("subprocess.Popen must not be called when validation fails")

    monkeypatch.setattr(cli.subprocess, "Popen", fail_popen)

    script = tmp_path / "noop.py"
    script.write_text("pass\n")
    monkeypatch.setattr(sys, "argv", ["kernelguard", "run", str(script), "--block-network"])

    try:
        cli.main()
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 1

    captured = capsys.readouterr()
    assert "--policy" in captured.err


def test_run_with_policy_autoattaches_tracer_in_visibility_mode(tmp_path, monkeypatch, capsys):
    """`run --policy` alone should now auto-attach the tracer itself
    (single command, no second terminal needed) — but without either
    --enforce-* flag, since --policy alone stays visibility-only."""
    cli = _load_module("kernelguard_cli_autoattach_vis", "cli/kernelguard.py")

    calls = []

    def fake_popen(cmd, *a, **kw):
        calls.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    script = tmp_path / "noop.py"
    script.write_text("pass\n")
    monkeypatch.setattr(
        sys, "argv",
        ["kernelguard", "run", str(script), "--policy", "policy/policy_schema.json"],
    )

    cli.main()

    assert len(calls) == 2, "expected one Popen for the script, one for the tracer"
    script_cmd, tracer_cmd = calls
    assert script_cmd == [sys.executable, str(script)]
    assert tracer_cmd[0] == sys.executable
    assert tracer_cmd[1] == cli.BPF_LOADER
    assert "--policy" in tracer_cmd
    assert "--enforce-network" not in tracer_cmd
    assert "--enforce-write" not in tracer_cmd

    captured = capsys.readouterr()
    assert "Attaching tracer (visibility-only)" in captured.out


def test_run_with_block_network_autoattaches_enforcing_tracer(tmp_path, monkeypatch, capsys):
    cli = _load_module("kernelguard_cli_autoattach_enf", "cli/kernelguard.py")

    calls = []

    def fake_popen(cmd, *a, **kw):
        calls.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    script = tmp_path / "noop.py"
    script.write_text("pass\n")
    monkeypatch.setattr(
        sys, "argv",
        ["kernelguard", "run", str(script), "--block-network",
         "--policy", "policy/policy_schema.json"],
    )

    cli.main()

    assert len(calls) == 2
    tracer_cmd = calls[1]
    assert "--enforce-network" in tracer_cmd
    assert "--enforce-write" not in tracer_cmd

    captured = capsys.readouterr()
    assert "Attaching tracer (enforcing)" in captured.out


def test_run_without_any_flags_prints_manual_attach_instructions(tmp_path, monkeypatch, capsys):
    """No --policy/--block-*: fall back to the old two-terminal
    instructions instead of auto-attaching anything."""
    cli = _load_module("kernelguard_cli_manual", "cli/kernelguard.py")

    calls = []

    def fake_popen(cmd, *a, **kw):
        calls.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    script = tmp_path / "noop.py"
    script.write_text("pass\n")
    monkeypatch.setattr(sys, "argv", ["kernelguard", "run", str(script)])

    cli.main()

    assert len(calls) == 1, "only the script should be launched, no tracer auto-attached"
    captured = capsys.readouterr()
    assert "In another terminal, attach the tracer with:" in captured.out