# Standards review — `main...HEAD` + worktree pre-live F1

Fecha: 2026-08-26
Score: **0,86 / 1,00**
Alcance auditado: commits `0dab4b3..7dcb79c` y los seis paths productivos/meta pendientes del worktree.

## Critical (bloquea merge)

- Ninguno.

## Important

- **Conventional Commits exige descripción en castellano** · commits `0dab4b3`, `c8c2b4a`,
  `39598a1`, `7dcb79c` · Los cuatro respetan `tipo(scope): descripción`, pero sus descripciones están
  en inglés. Antes de integrar F1, reescribirlas en castellano y usar también castellano para el
  commit candidato pendiente. Ejemplos equivalentes: `test(preflight): congelar contrato de
  aislamiento F1`, `fix(preflight): cerrar frontera de confianza del doctor`,
  `feat(preflight): fallar cerrado antes de las pruebas live` y
  `test(preflight): congelar pruebas de aceptación F1`.

- **Search-first / no duplicación y separación de API interna** ·
  `src/roguepatch/adapters/sbx_backend.py:36`,
  `src/roguepatch/adapters/docker_oracle.py:62`,
  `src/roguepatch/approval.py:222` · Los dos adapters vuelven a definir en paralelo los mismos
  validadores de texto, booleanos, SHA-256, tree digest y path POSIX, además de una segunda
  `_CanonicalRecord` y otra variante de `_closed_action_registry`. A la vez ambos consumen
  `_command_spec_sha256` y `_action_registry_sha256` como símbolos privados de `approval.py`.
  Consolidar la lógica compartida en una única API pública dentro de un path ya permitido por
  `boundary[]`; mantener una sola validación cerrada del registro y hacer que ambos adapters la
  consuman. Esto elimina dos fuentes susceptibles de deriva sin ampliar alcance ni tocar los tests
  congelados.

## Suggestion

- **Bloques nuevos mayores de 30 líneas / cohesión** ·
  `src/roguepatch/adapters/sbx_backend.py:1`,
  `src/roguepatch/adapters/docker_oracle.py:1` · Son 884 y 1.338 líneas respectivamente. El plan sí
  exige ejecución subagent-driven, pero antes del tramo live conviene dejar en el handoff la
  evidencia de delegación y revisar que records/validadores/orquestación permanezcan agrupados por
  una responsabilidad real. No hacer un refactor adyacente amplio: limitarlo a la duplicación
  señalada arriba o actualizar previamente `boundary[]`.

## Verificaciones positivas

- **Boundary ADR-0050:** PASS. `git diff --name-only main...HEAD` y el worktree actual quedan dentro
  de `feature_list.json.features[id=1].boundary[]`; el informe nuevo entra por la excepción meta
  `progress/`. No hay scope creep.
- **Frozen:** PASS. Los cuatro paths de `frozen[]` no tienen diff contra `HEAD`. Hashes actuales:
  `test_r01_r02_preflight.py` =
  `dd2fb66b23f626c7e2667e9b8c17d3d26f6a7c9bd5742ecf51f47e58439d0372`,
  `test_r05_r06_isolation.py` =
  `02fef1ac3b2964bbe29dd7638f05db4197c5721472bb950920e88fb354f284f3`,
  `test_no_host_fallback.py` =
  `17992a4d2926496cb27eb01e02f45888aff3079b8bd1b03aeb1f32684e1e49e9` y
  `test_oracle_candidate_immutability.py` =
  `99c1f238035acd600a264db3915940638f0a5ed3e4920299683ee71f327f0691`.
- **Cambios quirúrgicos:** PASS de alcance. No hay refactor de módulos adyacentes, dependencias
  nuevas ni paths de deploy cliente. Cada hunk corresponde a G1, R1/R2, R5/R6 o al scaffold
  pre-live de F1.
- **Efectos reales:** PASS offline. El scan no encuentra `subprocess`, SSH, red, Docker/SBX live ni
  escrituras host nuevas en los adapters. Las dos entradas live siguen fail-closed y los tests live
  solo se habilitan con `ROGUEPATCH_LIVE=1`.
- **Frontera LLM/código:** PASS. Los adapters producen facts tipados y los veredictos se derivan por
  código determinista; no se consume prosa de modelo como autoridad.
- **Secrets/PII:** PASS. No hay claves, tokens, `.env`, credenciales reales ni boot-session raw. El
  hostname, cuenta y rutas de Alex presentes son los bindings G1 aprobados y no secretos. Tampoco se
  incluyen `AGENTS.md`, `.Codex/` ni artefactos de cliente.
- **Scaffold factual:** PASS. `progress/environment-preflight.md` declara expresamente que no contiene
  evidencia live, conserva todas las casillas pendientes y no acredita GREEN.
- **Calidad local:** PASS. `git diff --check`; `UV_OFFLINE=1 uv run ruff check .`;
  `UV_OFFLINE=1 uv run ruff format --check .`; `UV_OFFLINE=1 uv run mypy src`; y
  `UV_OFFLINE=1 uv run pytest -q` con **552 passed, 2 skipped**. Los skips son exactamente los dos
  tests live del iMac.

VEREDICTO: needs_changes

Reglas cargadas: `AGENTS.md` raíz, `CLAUDE.md` raíz, `projects/roguepatch-lab/CLAUDE.md`,
`src/Anubis/roguepatch-lab/AGENTS.md`, `.claude/rules/development.md`,
`.claude/rules/git.md`, `.claude/rules/llm-decision-boundary.md`,
`.claude/rules/search-first.md`. `godmode-triage.md` y las rules Strev/Anuubis cliente no matchean
los paths del diff.
