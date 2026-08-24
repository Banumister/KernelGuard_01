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


def test_cli_parser_run_command():
    cli = _load_module("kernelguard_cli", "cli/kernelguard.py")
    parser = cli.build_parser()
    args = parser.parse_args(["run", "example.py", "--block-network", "--policy", "policy/policy_schema.json"])
    assert args.command == "run"
    assert args.script == "example.py"
    assert args.block_network is True
    assert args.policy == "policy/policy_schema.json"


def test_cli_parser_defaults():
    cli = _load_module("kernelguard_cli", "cli/kernelguard.py")
    parser = cli.build_parser()
    args = parser.parse_args(["run", "example.py"])
    assert args.block_network is False
    assert args.policy is None
    