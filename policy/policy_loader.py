import json
import os
import sys



def load_policy(path):
    if not os.path.isfile(path):
        sys.exit(f"ERROR: policy file not found: {path}")
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f"ERROR: policy file is not valid JSON: {path}\n{e}")

def is_ip_allowed(policy, ip, port):
    network = policy.get("network", {})
    if network.get("default") == "allow":
        return True
    for rule in network.get("allow", []):
        if rule.get("host") == ip and rule.get("port") == port:
            return True
    return False


def is_path_allowed(policy, filepath):
    filesystem = policy.get("filesystem", {})
    if filesystem.get("default") == "allow":
        return True
    for allowed_prefix in filesystem.get("allow_write", []):
        if filepath.startswith(allowed_prefix):
            return True
    return False


def is_delete_allowed(policy, filepath):
    """Same shape as is_path_allowed(), but checks the filesystem
    section's allow_delete list instead of allow_write -- a policy can
    grant write access to a path without also granting delete access
    to it (or vice versa). Deletion is arguably higher-risk than a
    write (it's not undoable the way an unwanted write often is), so
    it gets its own list rather than reusing allow_write. Falls back
    to the same filesystem.default as writes when the path isn't on
    either list."""
    filesystem = policy.get("filesystem", {})
    if filesystem.get("default") == "allow":
        return True
    for allowed_prefix in filesystem.get("allow_delete", []):
        if filepath.startswith(allowed_prefix):
            return True
    return False


def is_spawn_allowed(policy, comm):
    """Tri-state, unlike is_path_allowed()/is_delete_allowed(): returns
    None when the policy has no "process" section at all, True/False
    once it does.

    Existing policy files written before process-spawn policy existed
    have no "process" key -- without this tri-state, they'd suddenly
    start getting every fork tagged/blocked against an implicit
    default-deny the moment this feature shipped, even though the
    person who wrote that policy never had spawn behavior in mind. None
    tells the caller "this policy doesn't opt in to spawn control, stay
    visibility-only" -- the same opt-in posture --enforce*/--block* flags
    already use elsewhere in this project. A caller MUST treat None as
    "don't call should_enforce()" rather than as falsy/deny: should_enforce
    treats any non-True value as a violation, so passing None straight
    through would incorrectly enforce against policies that never asked
    for spawn control at all.

    comm is matched exactly (e.g. "python3", "sh"), not as a prefix --
    process names don't nest the way filesystem paths do."""
    if "process" not in policy:
        return None
    process = policy["process"]
    if process.get("default") == "allow":
        return True
    return comm in process.get("allow", [])


def should_enforce(policy, allowed, enforce_enabled):
    """Decide whether a policy violation should trigger active blocking
    (killing the PID), as opposed to just being logged.

    Enforcement only fires when all three are true: an operator opted in
    with --enforce, a policy is actually loaded, and this specific event
    was not allowed by it. This is intentionally conservative — passing
    --policy alone still means visibility-only, matching Week 2 behavior;
    --enforce is what turns a [BLOCKED] tag into a real kill.
    """
    return bool(enforce_enabled) and policy is not None and not allowed


def reload_policy(path, current_policy):
    """Attempt to reload a policy file from disk, e.g. in response to a
    SIGHUP so an operator can update a running daemon's rules without
    restarting it (and losing whatever it's mid-way through tracing).

    Deliberately never raises/exits: a bad edit to the policy file on
    disk should not be able to crash or silently disable a live tracer.
    On any failure, returns the *unchanged* current_policy plus a
    human-readable error string; on success, returns (new_policy, None).
    """
    if not path:
        return current_policy, "no --policy was set at startup; nothing to reload"
    if not os.path.isfile(path):
        return current_policy, f"policy file not found: {path}"
    with open(path, "r") as f:
        try:
            new_policy = json.load(f)
        except json.JSONDecodeError as e:
            return current_policy, f"policy file is not valid JSON: {path}\n{e}"
    return new_policy, None