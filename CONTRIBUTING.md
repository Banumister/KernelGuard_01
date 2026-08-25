# Contributing to KernelGuard

## Branch strategy

- **`main`** — kept in a working state. Avoid pushing directly for
  anything beyond small fixes; prefer a feature branch + pull request.
- **Feature branches** — one per piece of work, branched from `main`:
feature/short-description
fix/short-description
test/short-description
docs/short-description

## Workflow

1. `git checkout main && git pull`
2. `git checkout -b feature/your-change`
3. Make your changes, committing in small logical steps.
4. `git push -u origin feature/your-change`
5. Open a pull request into `main` and tag a teammate for review.

## Commit messages

Using [Conventional Commits](https://www.conventionalcommits.org/) style keeps the history easy to scan: