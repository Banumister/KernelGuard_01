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


KNOWN_TOP_LEVEL_KEYS = {"policy_name", "network", "filesystem", "process"}
KNOWN_NETWORK_KEYS = {"default", "allow"}
KNOWN_FILESYSTEM_KEYS = {"default", "allow_write", "allow_delete"}
KNOWN_PROCESS_KEYS = {"default", "allow"}


def _check_section(policy, warnings, name, known_keys, list_keys):
    """Shared shape-check for the network/filesystem/process sections:
    unrecognized keys, a bad "default" value, and list-typed fields that
    aren't actually lists of strings. Shared because all three sections
    follow the same {default, <list(s) of names>} shape."""
    if name not in policy:
        return
    section = policy[name]
    if not isinstance(section, dict):
        warnings.append(f'"{name}" section must be a JSON object, got '
                         f'{type(section).__name__}')
        return

    unknown = set(section.keys()) - known_keys
    if unknown:
        warnings.append(
            f'"{name}" section: unrecognized key(s) {sorted(unknown)} -- '
            f'ignored (check for typos)'
        )

    default = section.get("default")
    if default is not None and default not in ("allow", "deny"):
        warnings.append(
            f'"{name}.default" is {default!r}, expected "allow" or "deny" '
            f'-- falls through to deny since neither matched'
        )

    for key in list_keys:
        if key not in section:
            continue
        value = section[key]
        if not isinstance(value, list):
            warnings.append(f'"{name}.{key}" must be a list, got '
                             f'{type(value).__name__}')
            continue
        for item in value:
            if not isinstance(item, str):
                warnings.append(
                    f'"{name}.{key}" entries must be strings, found '
                    f'{type(item).__name__}: {item!r}'
                )


def validate_policy(policy):
    """Sanity-check an already-loaded policy dict for common authoring
    mistakes -- typos in a section/key name, or a value of the wrong
    shape -- that would otherwise fail completely silently.

    For example, a typo like "alow_write" instead of "allow_write"
    doesn't raise anywhere: is_path_allowed() just sees an empty
    allow_write list, so every write is quietly evaluated against
    filesystem.default instead. That's *safe* (it can only make the
    policy stricter than intended, never more permissive, since the
    default posture is deny), but it's also surprising -- someone
    reading their own policy file would reasonably expect it to behave
    as written, and would otherwise only discover the typo while
    debugging unexpected BLOCKED tags.

    Returns a list of human-readable warning strings (empty if nothing
    looks wrong). Deliberately never raises/exits, and deliberately
    doesn't change is_ip_allowed()/is_path_allowed()/etc.'s behavior --
    like reload_policy(), a policy file should never be able to crash or
    change enforcement just because validate_policy() ran. It's purely
    diagnostic: callers (bpf_loader.py, the CLI) decide whether/how to
    print the warnings; a policy with warnings still loads and runs.
    """
    warnings = []
    if not isinstance(policy, dict):
        return [f"policy must be a JSON object, got {type(policy).__name__}"]

    unknown_top = set(policy.keys()) - KNOWN_TOP_LEVEL_KEYS
    if unknown_top:
        warnings.append(
            f"unrecognized top-level key(s): {sorted(unknown_top)} -- "
            f"ignored (check for typos of network/filesystem/process)"
        )

    _check_section(policy, warnings, "network", KNOWN_NETWORK_KEYS, list_keys=())
    if "network" in policy and isinstance(policy["network"], dict):
        for i, rule in enumerate(policy["network"].get("allow", []) or []):
            if not isinstance(rule, dict) or "host" not in rule or "port" not in rule:
                warnings.append(
                    f'"network.allow[{i}]" should be an object like '
                    f'{{"host": "1.2.3.4", "port": 443}}, got {rule!r}'
                )
            elif not isinstance(rule.get("port"), int):
                warnings.append(
                    f'"network.allow[{i}].port" should be an integer, got '
                    f'{type(rule.get("port")).__name__}'
                )

    _check_section(policy, warnings, "filesystem", KNOWN_FILESYSTEM_KEYS,
                    list_keys=("allow_write", "allow_delete"))
    _check_section(policy, warnings, "process", KNOWN_PROCESS_KEYS,
                    list_keys=("allow",))

    return warnings


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