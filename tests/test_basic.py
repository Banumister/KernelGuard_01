import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"))
from policy_loader import (
    load_policy, is_ip_allowed, is_path_allowed, is_delete_allowed,
    is_spawn_allowed, should_enforce, reload_policy,
)


SAMPLE_POLICY = {
    "network": {
        "default": "deny",
        "allow": [{"host": "127.0.0.1", "port": 443}]
    },
    "filesystem": {
        "default": "deny",
        "allow_write": ["/tmp/"],
        # Deliberately narrower than allow_write, and a different
        # subpath, so tests below can prove delete permission is
        # independent of write permission rather than aliasing it.
        "allow_delete": ["/tmp/scratch/"]
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
    assert is_delete_allowed(open_policy, "/anything") is True


def test_is_delete_allowed_matches_its_own_prefix():
    assert is_delete_allowed(SAMPLE_POLICY, "/tmp/scratch/file.txt") is True


def test_is_delete_allowed_rejects_outside_its_own_prefix():
    assert is_delete_allowed(SAMPLE_POLICY, "/etc/passwd") is False


def test_is_delete_allowed_is_independent_of_write_permission():
    # /tmp/output.txt is writable (allow_write: ["/tmp/"]) but NOT
    # deletable under SAMPLE_POLICY's narrower allow_delete list --
    # write and delete permission must not be aliases of each other.
    assert is_path_allowed(SAMPLE_POLICY, "/tmp/output.txt") is True
    assert is_delete_allowed(SAMPLE_POLICY, "/tmp/output.txt") is False


SPAWN_POLICY = {
    "process": {
        "default": "deny",
        "allow": ["python3"]
    }
}


def test_is_spawn_allowed_returns_none_when_policy_predates_it():
    # SAMPLE_POLICY has no "process" section at all -- a fork event
    # under this policy must stay visibility-only (None), not silently
    # become deny, so pre-existing policy files aren't retroactively
    # changed by this feature shipping.
    assert is_spawn_allowed(SAMPLE_POLICY, "bash") is None


def test_is_spawn_allowed_matches_allow_list():
    assert is_spawn_allowed(SPAWN_POLICY, "python3") is True


def test_is_spawn_allowed_rejects_comm_not_on_allow_list():
    assert is_spawn_allowed(SPAWN_POLICY, "bash") is False


def test_is_spawn_allowed_default_allow_overrides_list():
    open_policy = {"process": {"default": "allow"}}
    assert is_spawn_allowed(open_policy, "anything") is True


def test_is_spawn_allowed_matches_exactly_not_as_prefix():
    # Unlike is_path_allowed()/is_delete_allowed(), comm matching is
    # exact -- process names don't nest the way filesystem paths do, so
    # "python3-intruder" must not match an allow list entry of "python3".
    assert is_spawn_allowed(SPAWN_POLICY, "python3-intruder") is False


def test_should_enforce_true_when_enabled_policy_loaded_and_blocked():
    assert should_enforce(SAMPLE_POLICY, False, True) is True


def test_should_enforce_false_when_enforce_flag_off():
    # --policy alone (no --enforce) stays visibility-only, matching
    # Week 2 behavior — a violation must not get silently upgraded to
    # an actual kill just because a policy file was loaded.
    assert should_enforce(SAMPLE_POLICY, False, False) is False


def test_should_enforce_false_when_action_was_allowed():
    assert should_enforce(SAMPLE_POLICY, True, True) is False


def test_should_enforce_false_when_no_policy_loaded():
    assert should_enforce(None, False, True) is False


def test_reload_policy_picks_up_a_changed_file():
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(SAMPLE_POLICY, f)
        updated_policy = {"network": {"default": "allow"}, "filesystem": {"default": "allow"}}
        with open(path, "w") as f:
            json.dump(updated_policy, f)
        new_policy, error = reload_policy(path, SAMPLE_POLICY)
        assert error is None
        assert new_policy == updated_policy
    finally:
        os.remove(path)


def test_reload_policy_missing_file_keeps_old_policy():
    # A bad edit (e.g. the file got deleted/moved) must not crash a live
    # tracer or silently disable enforcement -- the previous policy stays
    # in effect and the caller is told why.
    new_policy, error = reload_policy("/nonexistent/path/to/policy.json", SAMPLE_POLICY)
    assert new_policy == SAMPLE_POLICY
    assert error is not None
    assert "not found" in error


def test_reload_policy_invalid_json_keeps_old_policy():
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("{ not valid json")
        new_policy, error = reload_policy(path, SAMPLE_POLICY)
        assert new_policy == SAMPLE_POLICY
        assert error is not None
        assert "not valid JSON" in error
    finally:
        os.remove(path)


def test_reload_policy_no_path_set_keeps_old_policy():
    # Mirrors bpf_loader.py's POLICY_PATH being None when --policy was
    # never passed at startup -- SIGHUP should be a no-op, not a crash.
    new_policy, error = reload_policy(None, SAMPLE_POLICY)
    assert new_policy == SAMPLE_POLICY
    assert error is not None