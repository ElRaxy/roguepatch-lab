# Review final pre-live F1

- Fecha: 2026-08-26
- Rama: `codex/f1-preflight`
- Estado: GREEN offline/pre-live aprobado
- Quality score final: `0.97`
- Efectos live ejecutados: ninguno

## Contrato cerrado

- Source público exacto, Git root independiente y mount físico read-only.
- Trece targets protegidos, veintiuna acciones G1 y veinte records físicos.
- Identidad del engine observada en acción separada y ligada al checker.
- Traza append-only ligada a action, command, registry, result y microVM.
- Gate R1 obligatorio: doctor, engine privado oracle, ausencia de Docker Desktop, daemon host y
  socket compartido.
- Discovery separado, registry offline no ejecutable y mínimo 40 GiB antes de cualquier efecto.

## Verificación

- `uv run pytest -q`: `704 passed, 2 skipped`.
- Los dos skips son integraciones live opt-in reservadas al iMac autorizado.
- `uv run ruff check src tests`: PASS.
- `uv run ruff format --check src tests`: PASS.
- `uv run mypy src`: PASS.
- `git diff --check`: PASS.

## Contratos congelados

- R1/R2: `dd2fb66b23f626c7e2667e9b8c17d3d26f6a7c9bd5742ecf51f47e58439d0372`.
- R5/R6: `32ad1d3a37f9c1867644839e6b5c3769dfd903787ac775eb7e8df80ec7c189d0`.
- No host fallback: `f74da6ec881e66567c11347d041ceb2c5b3a10f94d5acf8e29ef975e86f6e9ff`.
- Candidate immutability: `99c1f238035acd600a264db3915940638f0a5ed3e4920299683ee71f327f0691`.

## Gate pendiente

No se materializan receipts, instalaciones, sidecars ni microVMs hasta que el iMac tenga al menos
40 GiB libres y los bindings discovery/G1 estén completos. El último dato observado fue inferior al
umbral, por lo que transferencia de código no equivale a autorización live.
