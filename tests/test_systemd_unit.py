"""
Validates systemd/kernelguard.service is well-formed and points at the
right entrypoint. Doesn't require systemd itself (CI runners don't have
it) — just checks the unit file parses as valid INI-style sections with
the keys the service actually needs to run.
"""
import configparser
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
UNIT_FILE = REPO_ROOT / "systemd" / "kernelguard.service"


def _load_unit():
    parser = configparser.ConfigParser(strict=False)
    # systemd unit files are case-sensitive and don't lowercase keys the
    # way configparser does by default.
    parser.optionxform = str
    parser.read(UNIT_FILE)
    return parser


def test_unit_file_exists():
    assert UNIT_FILE.exists(), f"missing {UNIT_FILE}"


def test_unit_file_has_required_sections():
    unit = _load_unit()
    for section in ("Unit", "Service", "Install"):
        assert unit.has_section(section), f"missing [{section}] section"


def test_unit_section_has_description():
    unit = _load_unit()
    assert unit.get("Unit", "Description").strip() != ""


def test_service_section_points_at_bpf_loader():
    unit = _load_unit()
    exec_start = unit.get("Service", "ExecStart")
    assert "bpf_loader.py" in exec_start
    assert exec_start.strip().split()[0].endswith("python3"), (
        "ExecStart should invoke python3 directly"
    )


def test_service_runs_as_root():
    # eBPF program loading requires root — if this ever changes, the
    # service needs CAP_BPF/CAP_SYS_ADMIN granted explicitly instead.
    unit = _load_unit()
    assert unit.get("Service", "User") == "root"


def test_service_restarts_on_failure():
    unit = _load_unit()
    assert unit.get("Service", "Restart") == "on-failure"


def test_install_section_has_target():
    unit = _load_unit()
    assert unit.get("Install", "WantedBy").strip() != ""
