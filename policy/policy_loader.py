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