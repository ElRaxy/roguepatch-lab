# F1 environment preflight

Estado: scaffold offline. No contiene observaciones live ni autoriza efectos.

## Alcance congelado

- Host autorizado: alias SSH `imac`, cuenta `alex`.
- Raíz dedicada: `/Users/alex/RoguePatchLab`.
- El portátil solo coordina y ejecuta tests con doubles.
- Docker Desktop, daemon de host, fallback host y checkouts VanguardIA del iMac están prohibidos.
- Agente y oracle deben usar microVMs SBX distintas, secuenciales, con 2 CPU y 2048 MiB.
- El único engine permitido es el engine privado dentro de la microVM oracle.

## Evidencia live pendiente

- [ ] Identidad del host ligada a `roguepatch.host-fingerprint.v1`.
- [ ] Checkout dedicado recibido y verificado byte a byte.
- [ ] Disco disponible de al menos 40 GiB antes de receipt o instalación.
- [ ] Receipt G1 owner `alex`, modo `0600` y bindings exactos.
- [ ] Instalación standalone de SBX verificada sin Docker Desktop.
- [ ] Autenticación SBX resuelta mediante gate humano si fuese necesaria.
- [ ] Al menos 30 GiB libres justo antes de cada `sbx create`.
- [ ] Al menos 20 GiB libres justo después de cada `sbx create`.
- [ ] Traza F1 completa y cleanup de ambas microVMs verificados.

Mientras cualquier casilla siga pendiente, este documento no acredita GREEN live.
