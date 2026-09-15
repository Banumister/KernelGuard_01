"""
Validates scripts/install.sh without actually running it (it needs root,
apt, and systemd — none of which CI has). Checks it parses as valid bash
and contains the pieces the installer promises: populating /opt/kernelguard,
installing the systemd unit, and a working --uninstall path.
"""
import pathlib
import shutil
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install.sh"


def test_install_script_exists():
    assert INSTALL_SCRIPT.exists(), f"missing {INSTALL_SCRIPT}"


def test_install_script_is_executable_or_at_least_readable():
    # Not every checkout preserves the executable bit (e.g. after a zip
    # download), so this just makes sure the file isn't empty/corrupt.
    text = INSTALL_SCRIPT.read_text()
    assert text.startswith("#!/usr/bin/env bash")
    assert len(text) > 200


def test_install_script_has_valid_bash_syntax():
    bash = shutil.which("bash")
    if bash is None:
        import pytest
        pytest.skip("bash not available on this runner")
    result = subprocess.run(
        [bash, "-n", str(INSTALL_SCRIPT)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"bash -n failed:\n{result.stderr}"


def test_install_script_targets_opt_kernelguard():
    text = INSTALL_SCRIPT.read_text()
    assert 'INSTALL_DIR="/opt/kernelguard"' in text


def test_install_script_installs_systemd_unit():
    text = INSTALL_SCRIPT.read_text()
    assert "systemd/kernelguard.service" in text
    assert "/etc/systemd/system/kernelguard.service" in text
    assert "systemctl daemon-reload" in text
    assert "systemctl enable kernelguard.service" in text


def test_install_script_requires_root():
    text = INSTALL_SCRIPT.read_text()
    assert "EUID" in text and "must be run as root" in text


def test_install_script_supports_uninstall():
    text = INSTALL_SCRIPT.read_text()
    assert "--uninstall" in text
    assert "rm -rf \"$INSTALL_DIR\"" in text


def test_install_script_does_not_autostart_service():
    # Enforcement flags should be a deliberate operator choice, not
    # switched on automatically by the installer — see docs/ROADMAP.md.
    # (The header comment and the final printed instructions both mention
    # "systemctl start kernelguard" as something the OPERATOR should run
    # afterwards — that's fine. What must never appear is an executable
    # line that runs it for them.)
    code_lines = [
        line for line in INSTALL_SCRIPT.read_text().splitlines()
        if not line.strip().startswith("#")
    ]
    code_only = "\n".join(code_lines)
    body_before_heredoc = code_only.split("cat <<EOF")[0]
    assert "systemctl start kernelguard" not in body_before_heredoc
    assert "systemctl enable kernelguard.service" in body_before_heredoc
