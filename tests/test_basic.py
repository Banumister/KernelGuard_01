import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"))
from policy_loader import load_policy, is_ip_allowed, is_path_allowed


SAMPLE_POLICY = {
    "network": {
        "default": "deny",
        "allow": [{"host": "127.0.0.1", "port": 443}]
    },
    "filesystem": {
        "default": "deny",
        "allow_write": ["/tmp/"]
    }
}


def test_load_policy():
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(SAMPLE_POLICY, f)
        loaded = load_policy(path)
        assert loaded == SAMPLE_POLICY
    finally:
        os.remove(path)


def test_load_policy_missing_file_exits():
    with pytest.raises(SystemExit):
        load_policy("/nonexistent/path/to/policy.json")


def test_load_policy_invalid_json_exits():
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("{ not valid json")
        with pytest.raises(SystemExit):
            load_policy(path)
    finally:
        os.remove(path)


def test_is_ip_allowed_matches_allow_list():
    assert is_ip_allowed(SAMPLE_POLICY, "127.0.0.1", 443) is True


def test_is_ip_allowed_rejects_unknown_host():
    assert is_ip_allowed(SAMPLE_POLICY, "8.8.8.8", 443) is False


def test_is_path_allowed_matches_prefix():
    assert is_path_allowed(SAMPLE_POLICY, "/tmp/output.txt") is True


def test_is_path_allowed_rejects_outside_prefix():
    assert is_path_allowed(SAMPLE_POLICY, "/etc/passwd") is False


def test_default_allow_overrides_list():
    open_policy = {"network": {"default": "allow"}, "filesystem": {"default": "allow"}}
    assert is_ip_allowed(open_policy, "1.2.3.4", 80) is True
    assert is_path_allowed(open_policy, "/anything") is True