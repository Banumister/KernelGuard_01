# `policy/` — Security policy engine (Week 3)

This directory will hold the JSON-based policy engine described in Week 3
of the roadmap: user-defined rules for which IP addresses / ports and
which file paths a monitored script is allowed to touch.

`policy_schema.example.json` is a draft of the shape we're aiming for —
not parsed or enforced by any code yet. Whoever picks up the Week 3
work should:

1. Finalize the schema (see the example file).
2. Write a loader/validator in `policy/loader.py`.
3. Wire it into `controller/bpf_loader.py` so violations trigger the
   `-EPERM` blocking behavior instead of just logging.
