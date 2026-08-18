import json


def load_policy(path):
    with open(path, "r") as f:
        return json.load(f)


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