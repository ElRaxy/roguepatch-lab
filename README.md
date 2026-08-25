# RoguePatch Lab

RoguePatch Lab is an experimental adversarial conformance spike for external coding-agent controls. It is intended to run the same synthetic task under a bare Codex baseline, Keel `active`, and ScopeLatch V4 local, then reconcile requested actions, native control decisions, observed effects, remediation, and task utility with a deterministic external oracle.

The initial scope is deliberately narrow: six synthetic cases and three control conditions. The spike must end in an explicit GO or KILL decision. It is not a model benchmark, policy engine, sandbox, security certification, or hosted product.

## Current status

The local core now includes the typed domain, sealed evidence verification, deterministic replay/reporting, and preview versus verified metric reducers. No live trials have run, and this repository contains no experimental results. Docker, Docker Sandboxes, external controls, remote publication, and live model calls remain behind human gates.

F2 treats experiment pins as opaque SHA-256 commitments and verifies that normalized source references carry the matching commitment. Constructing those commitments from tool surfaces, images, or fixtures—and comparing them before a run—belongs to the producer/F5 boundary; F2 does not claim to prove that composition.

For claimed runs, F2 binds the oracle verdict to the final candidate digest, preserves agent-declared evidence references as typed observations, and derives rollback from committed protected-state checkpoints plus an explicit remediation actor. A stale, missing, malformed, bad-digest, or unbound claim reference does not break bundle closure; it remains an observable result that can drive false-completion reporting.

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

The local implementation and its frozen acceptance tests are developed feature by feature. Live execution is outside the current local-core scope.
