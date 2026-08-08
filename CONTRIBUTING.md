# Contributing to KernelGuard

This is a small internship team project. The process below is
deliberately lightweight — the goal is just to avoid stepping on each
other's work while multiple people touch kernel code, the Python
controller, and the CLI in parallel.

## Branch strategy

- **`main`** — always in a working, demoable state. Protected: no direct
  pushes, merge via reviewed pull request only.
- **`dev`** — integration branch. Feature branches merge here first;
  `dev` gets merged into `main` at each weekly milestone / review.
- **Feature branches** — one per task, branched from `dev`:

  ```
  feature/week1-execve-hook
  feature/week2-tcp-connect-hook
  feature/week2-pid-filtering
  feature/week3-policy-engine
  feature/week4-systemd-packaging
  fix/<short-description>
  ```

  Naming pattern: `feature/weekN-short-description` or
  `fix/short-description`. Match the task to a row in
  [docs/ROADMAP.md](docs/ROADMAP.md) where possible.

## Workflow

1. Pull the latest `dev`: `git checkout dev && git pull`
2. Branch: `git checkout -b feature/week1-execve-hook`
3. Commit in small, logical chunks (see commit convention below).
4. Push and open a pull request **into `dev`**, not `main`.
5. Tag at least one teammate for review — especially for anything
   touching `ebpf/*.c`, since a bad kernel hook can hang or crash a dev
   VM, not just the process being tested.
6. Squash-merge once approved; delete the branch after merge.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) style —
it keeps the history scannable and maps cleanly onto the weekly roadmap:

```
feat(ebpf): hook tcp_connect syscall
feat(controller): add --pid filtering to bpf_loader
fix(cli): handle missing script path gracefully
docs(setup): add Fedora install instructions
test(cli): add smoke test for policy flag parsing
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`.
Common scopes: `ebpf`, `controller`, `cli`, `policy`, `systemd`, `docs`.

## Code review notes specific to this project

- **Kernel code (`ebpf/`) needs extra care.** Test changes on a real
  Linux VM (see [docs/SETUP.md](docs/SETUP.md)) before opening a PR —
  CI cannot compile/load eBPF programs (no privileged runner), so it
  only lints Python and checks the repo structure. A reviewer should
  ask "did you run this against a real kernel?" before approving any
  `ebpf/*.c` change.
- **Always detach hooks on exit.** If you add a new kprobe/tracepoint
  attach call, make sure there's a corresponding cleanup path (see
  Week 4 goals) — leaked kernel hooks can affect the whole dev machine,
  not just your test.
- Run `pytest` and `flake8` locally before pushing (see
  [docs/SETUP.md](docs/SETUP.md#python-dev-dependencies-lintingtests-no-root-needed)).

## Issues

File an issue for anything not already tracked as a checklist item in
[docs/ROADMAP.md](docs/ROADMAP.md) — bugs, questions, or new ideas.
Use the templates under `.github/ISSUE_TEMPLATE/`.
