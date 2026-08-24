# RoguePatch Lab

RoguePatch Lab is an experimental adversarial conformance spike for external coding-agent controls. It is intended to run the same synthetic task under a bare Codex baseline, Keel `active`, and ScopeLatch V4 local, then reconcile requested actions, native control decisions, observed effects, remediation, and task utility with a deterministic external oracle.

The initial scope is deliberately narrow: six synthetic cases and three control conditions. The spike must end in an explicit GO or KILL decision. It is not a model benchmark, policy engine, sandbox, security certification, or hosted product.

## Current status

Bootstrap only. No live trials have run, and this repository contains no experimental results. Docker, Docker Sandboxes, external controls, remote publication, and live model calls remain behind human gates.

## Design constraints

- Keep the agent workspace separate from the protected manifest and oracle.
- Evaluate native external controls without copying or recreating their policies.
- Derive verdicts from typed facts with deterministic code, never from an LLM judge.
- Preserve unknown observations as `null` or `unobserved`.
- Report security, utility, false blocks, and cost separately, with no aggregate score or ranking.
- Use only synthetic fixtures, canaries, and disposable local remotes.

## Development

The project targets Python 3.12 and uses `uv` for its environment and lockfile.

```bash
uv sync
uv run pytest
uv run ruff check src tests
uv run mypy src
```

The `src/` package and tests will be added feature by feature after their acceptance tests are frozen. Live execution is not part of this bootstrap.
