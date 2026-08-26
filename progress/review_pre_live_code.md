# Review pre-live de código F1

- Fecha: 2026-08-26
- Base revisada: `7dcb79ce090cad425e971a2764434566cf5292bf`
- Alcance: diff de `codex/f1-preflight` contra `main` más cambios no commiteados
- Tipo: primera revisión de implementación posterior al segundo addendum aprobado
- `quality_score`: **0.72**
- Veredicto: **NEEDS_CHANGES**; no apto aún para commit candidato, transferencia o ejecución live

## Lo que está bien

- Los cuatro tests congelados están intactos tanto frente a `HEAD` como frente a los hashes del
  último review RED:
  - R1/R2: `dd2fb66b23f626c7e2667e9b8c17d3d26f6a7c9bd5742ecf51f47e58439d0372`.
  - R5/R6: `02fef1ac3b2964bbe29dd7638f05db4197c5721472bb950920e88fb354f284f3`.
  - no-host-fallback: `17992a4d2926496cb27eb01e02f45888aff3079b8bd1b03aeb1f32684e1e49e9`.
  - candidate immutability: `99c1f238035acd600a264db3915940638f0a5ed3e4920299683ee71f327f0691`.
- El registro nominal contiene los 17 `G1_ACTION_IDS` y el validador final exige una traza de 16
  acciones en orden: create agente, diez probes, freeze, destroy agente, create oracle, checker y
  destroy oracle.
- `SandboxSpec` rechaza traversal léxico, symlinks declarados, source inexistente, realpath fuera
  de `/Users/alex/RoguePatchLab`, mounts extra, socket, egress y shared skills.
- No hay imports ni llamadas de `subprocess`, `Popen`, `os.system`, SSH, Docker o SBX en producción.
  El único punto de ejecución es el `CommandProbe` inyectado y `SbxBackend` restringe el ejecutable
  a `sbx` con `shell=False`.
- El gate de disco ejecuta las comprobaciones 40/30/20 en orden causal en el happy path; los tests
  prueban los cuatro puntos de decisión y el KILL bajo umbral.
- Los errores de checker preservan el error primario y los fallos de destroy conservan referencia
  manual, traza y disposición KILL en los caminos actualmente cubiertos.
- `DockerOracleRunner` es deliberadamente inerte y solo valida hechos tipados.
- El scaffold `progress/environment-preflight.md` no inventa evidencia live y mantiene todos los
  efectos bloqueados.

## Findings

### Critical 1 — R5 no está ligado causalmente al create que ejecuta el agente

`src/roguepatch/adapters/sbx_backend.py:317-330` considera cerrado cualquier registro no vacío.
Por ello `resolve_source_path()` acepta un registro de una sola acción `g1.source.resolve`; se
confirmó offline con un probe mínimo (`accepted_registry_size=1`). Después,
`run_f1_oracle_sequence()` valida otro registro completo pero no compara su digest con el digest
del `SourcePathProof` (`docker_oracle.py:1078-1085`). Más grave aún, el create recibe únicamente
`role`, `limits` y `private_engine`; no recibe `agent_spec`, el source canónico ni el proof
(`docker_oracle.py:1102-1109`).

Así, un proof seguro puede acompañar a un `CommandSpec` de create distinto sin que el código lo
detecte. El test R5 prueba el objeto declarativo, pero no la unión proof -> registro G1 -> argv de
create -> ejecución.

Acción requerida:

1. Usar un único validador de registro G1 que exija exactamente los 17 IDs también en R5 y en
   `SbxBackend`.
2. Exigir que `agent_spec.source_path_proof.action_registry_sha256` coincida con el registro ligado
   al receipt.
3. Hacer que `executor.create` reciba el `SandboxSpec` completo o un `AgentCreateSpec` canónico cuyo
   digest quede dentro del `CommandSpec` registrado y de la traza.
4. Añadir un test no congelado que intente combinar proof de registro parcial o distinto con una
   secuencia de registro completo.

### Critical 2 — La inmutabilidad del candidate y la separación de engine son afirmadas, no observadas

El puerto `F1OracleExecutor.checker()` devuelve solo `CommandResult`
(`docker_oracle.py:588-596`). El orquestador construye después `OracleVerificationFacts` copiando
el `candidate_digest` de entrada tanto en `observed_digest_before` como en
`observed_digest_after` (`docker_oracle.py:1243-1252`) y vuelve a copiarlo en los facts finales
(`docker_oracle.py:1328-1329`). Un executor que no mida nada o un checker que modifique el árbol
puede pasar mientras devuelva exit 0.

La misma forma aparece en la frontera de engine: `private_engine=True` se pasa como intención al
executor y `engine_shared=False` se escribe de forma constante en los facts
(`docker_oracle.py:1190-1196`, `:1300-1309`, `:1326`). No existe una observación de identidad de
engine/socket ligada al resultado del executor. Esto incumple R6 y la regla de frontera de decisión:
los facts deben describir lo observado, no la configuración solicitada.

Acción requerida: el executor debe devolver un registro tipado y hasheado con digest observado
antes y después, identidad del engine privado y ausencia de socket compartido. Esos datos deben
ligarse al result digest del checker y alimentar al `DockerOracleRunner`; el orquestador no debe
rellenarlos desde el input. Añadir un test de secuencia donde el executor observe un digest posterior
distinto y otro donde reporte engine compartido.

### Critical 3 — No todos los caminos posteriores a create garantizan cleanup

Tras crear la microVM agente, la validación del `SandboxRef`, la comprobación de la última traza y
la consulta post-create ocurren antes del bloque protegido de cleanup
(`docker_oracle.py:1103-1137`). Si el executor devuelve rol incorrecto, omite/misbindea la traza o
la autoridad de disco lanza por facts incompletos, la microVM queda activa sin destroy ni referencia
manual. El mismo hueco existe tras crear la microVM oracle (`docker_oracle.py:1190-1225`).

Acción requerida: desde el primer create que produzca un identificador, todo el resto del tramo debe
estar bajo `try/finally`. Un resultado de create debe conservar una cleanup reference incluso si sus
facts son inválidos. Añadir tests para ref inválida, traza ausente/misbindeada y excepción de disk
authority después de cada create; todos deben demostrar destroy o `OracleCleanupError` con KILL y
referencia manual.

### Important 1 — El candidato no contiene aún una ruta live ejecutable

`approval.py:158-160` deja el registro productivo vacío; `_collect_host_identity()` siempre falla
(`approval.py:296-301`); no existe `run_live_preflight`; `run_live_oracle_boundary_probe()` siempre
lanza `LiveOracleGateError` (`docker_oracle.py:1335-1338`); tampoco existe una implementación
productiva de `F1OracleExecutor`. Por tanto, `ROGUEPATCH_LIVE=1` no puede ejecutar ninguno de los
dos tests de integración, incluso con G1 y disco válidos.

El fail-closed actual es seguro, pero se desvía del Task 4 Step 4/Step 6: el commit candidato que se
transfiera debe contener los adapters live auditados, porque cambiar código después invalida commit,
registro y receipt. Resolver los argv oficiales y el collector mediante puertos inyectables y
probarlos offline antes de declarar candidato; mantener el receipt y el disco como bloqueos reales.

### Important 2 — El límite del oracle se rechaza demasiado tarde

`OracleContainerSpec` acepta CPU/RAM superiores a 2/2048 porque valida mínimos
(`docker_oracle.py:335-338`). La igualdad exacta se verifica solo en los facts finales, después de
crear y destruir el oracle (`docker_oracle.py:969-973`). En el iMac de 8 GiB, una spec de 4 GiB puede
producir el efecto host antes de ser rechazada.

Acción requerida: exigir exactamente 2 CPU y 2048 MiB en `OracleContainerSpec.__post_init__` y antes
de cualquier `executor.create`; añadir un test de orquestación que confirme cero calls para valores
mayores y menores.

### Important 3 — El backend de producción no tiene cobertura conductual

La cobertura total es 87 %, pero `SbxBackend` (`sbx_backend.py:824-884`) aparece íntegramente sin
ejecutar. Los tests solo inspeccionan su firma/allowlist. No demuestran que una acción registrada
emite exactamente un record, que una acción distinta se rechaza antes del probe ni que un resultado
fallido queda trazado como FAILED. Esta ausencia permitió que su validador de registro divergiera del
validador cerrado del oracle.

Acción requerida: pruebas unitarias con `FakeCommandProbe` para registro exacto, acción/command
drift, resultado truncado/timeout/fallido y cadena de trace; sin tocar tests congelados.

### Suggestion — Reducir duplicación de invariantes de seguridad

`approval.py`, `sbx_backend.py` y `docker_oracle.py` mantienen helpers propios para SHA/path/registro.
Centralizar el contrato cerrado del registro y los tipos de observación reduciría el riesgo de que
un módulo acepte "no vacío" y otro "exactamente 17". También conviene renombrar
`LivePreflightDecision.create_allowed` a `pre_create_disk_safe`: entre 30 y 40 GiB puede ser `True`
aunque el estado global siga `BLOCKED_LOW_DISK`, una semántica correcta por fases pero fácil de usar
mal.

## EARS y compatibilidad

| Requisito | Test canónico | Resultado | Evaluación de review |
|---|---|---:|---|
| R1 | `test_r1_doctor_fails_closed` | PASS | Cubierto; compatibilidad intacta |
| R2 | `test_r2_human_gate_blocks_side_effects` | PASS | Cubierto; compatibilidad intacta |
| R5 | `test_r5_trial_isolation_contract` y negativos `test_r5_*` | PASS | Test nominal existe, pero falta causalidad proof -> create |
| R6 | `test_r6_oracle_boundary_probe` y negativos `test_r6_*` | PASS | Registro/traza nominales cubiertos; observación de candidate/engine y cleanup incompletos |

La suite completa de F2 y F1 pasa, por lo que no hay regresión observable en R10-R17 ni en el
contrato previo R1/R2. Los findings son brechas no ejercitadas por los tests actuales, no fallos de
compatibilidad detectados.

## Boundary

`git diff --name-only main...HEAD`, el diff no commiteado y los untracked revisados quedan dentro de
`boundary[]` de F1. `progress/environment-preflight.md` es además un meta path permitido. No se
detecta scope creep. No hay staging.

## Verificación offline

- Target F1: `186 passed`.
- Suite completa: `552 passed, 2 skipped` (solo integraciones live opt-in).
- `ruff check .`: PASS.
- `ruff format --check .`: PASS (`34 files already formatted`).
- `mypy src`: PASS estricto.
- Coverage: 87 % total; `docker_oracle.py` 87 %, `sbx_backend.py` 82 % con la clase productiva sin
  ejecución, `approval.py` 85 %, `doctor.py` 90 %.
- `git diff --check`: PASS.
- No se usó SSH, Docker, SBX, subprocess, red, staging ni commit.

```yaml
iteration_number: 1
recommended_escalation: false
status: needs_changes
```
