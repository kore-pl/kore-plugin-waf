# kore-plugin-waf — Plugin WAF

## Qué hace

Un plugin de gestión de WAF (**L1.5+ · independiente del motor + plano de datos nft real**) con dos
responsabilidades separadas: la **capa de motor** solo detecta los motores WAF ya instalados en el host
(modsecurity / naxsi / coraza / crowdsec), cuenta las reglas y analiza los registros de bloqueo; el
**plano de datos** lo implementa el propio kore con `nft` (conjuntos de prohibición, limitación de
escaneos SYN y límite de concurrencia por IP), con conmutación observe/enforce y tres niveles de
protección (flexible/estándar/estricto desde 0.5.0). Este repositorio **no incluye ningún motor WAF**
y **nunca ejecuta nft en el proceso del plugin**: todas las escrituras pasan por el canal root-action
de ADR-0018 (ADR-0022 fija la forma de los comandos).

- Protocolo: `kore.plugin.v1`, `lifecycle=lazy`, nivel de profundidad `basic`; capacidades `system:read` + `system:admin`.
- Privilegios: declara `requires_root: true` y 12 `root_actions` (todas sentencias nft, `irreversible:false`, todas reversibles).
- Etiqueta de escenario: `sec`; presupuesto de recursos 6 MiB / 15% CPU / 16 pids.

## Superficie de métodos (10 métodos de negocio)

| Método | Entrada | Resultado |
| --- | --- | --- |
| `waf.status` | `{}` | Motor: disponibilidad / versión / reglas / modo; nivel; estado de `backend` |
| `waf.rules` | `{engine?}` | Conjuntos de reglas del motor + reglas nft de la cadena de datos |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | Entradas de registros de bloqueo y estadísticas |
| `waf.toggle` | `{mode, level?, confirm?}` | Conmutación observe/enforce/off con nivel; verificación tras escribir |
| `waf.ban` | `{ip, ttl_s?, reason?}` | Prohibición idempotente (v4/v6, `ttl_s=0` permanente, 60–2592000) |
| `waf.unban` | `{ip}` | Desprohibir (no estar en el conjunto también cuenta como éxito) |
| `waf.bans` | `{limit?}` | Lista de prohibiciones con tiempos restantes |
| `waf.rule.add` / `remove` / `toggle` | ver README | Lista blanca controlada, comparación con `nft -j list`, rollback si no coincide |
| `waf.config.get` / `set` | `{}` / `{values}` | Configuración 0600, efectiva en la siguiente llamada |

Se aceptan tanto `waf.<verbo>` como el verbo suelto; `waf.blockLog` es un alias de compatibilidad de
`waf.logs`. `name` solo permite letras minúsculas / dígitos / `-` / `_` (1-32) y `expr` solo
comparadores de la lista blanca (`ip saddr`, `ip6 saddr`, `tcp dport`, `udp dport`, `ct state`,
`tcp flags syn`); los objetos de parámetros se decodifican estrictamente y un campo mal escrito devuelve `E_INVALID`.

## Detección de motores y conteo de reglas

`engine=auto` toma el primer resultado en orden modsecurity → naxsi → coraza → crowdsec; cada motor
devuelve evidencia `probed[]` y nunca presenta un resultado vacío como "no hay motor". Con un motor
explícito y `rules_dirs` / `log_paths` configurados existentes, se respetan las rutas declaradas.
modsecurity / coraza cuentan líneas de directiva `SecRule` (incluidas las indentadas, sin comentarios
ni SecAction), naxsi cuenta `MainRule` + `BasicRule` y crowdsec cuenta un escenario como `rule_count=1`.
`enabled` solo significa que el archivo está en un directorio activo con reglas válidas, no que se haya
confirmado la cadena include.

## Registros de bloqueo

Solo se lee la cola (1 MiB por defecto, configurable 64 KiB–8 MiB), analizando registros de error de
ModSecurity / secciones de auditoría, `NAXSI_FMT` / `NAXSI_EXLOG` de Naxsi y líneas JSON. `action` es
`blocked` / `detected`; si no se obtiene el ID de regla se deja vacío, sin adivinar. `since` admite
`1h` / `30m` / `7d` / RFC3339 / `YYYY-MM-DD`; las entradas no analizables se descartan con `since` y
se cuentan en `skipped_unparsed`; `limit` por defecto 50, máximo 200. Un registro ilegible devuelve
`E_NEED_ROOT` + pista, no una lista vacía que finja "no hay bloqueos"; el formato de crowdsec no se
analiza en esta versión y devuelve `E_UNSUPPORTED`.

## Plano de datos: reglas nft reales

kore crea `table inet kore_waf` en su propio espacio de nombres y no toca `filter` / `nat` del host:
dos conjuntos de prohibición (`banned4` / `banned6`, con CIDR y timeout) y una cadena base en input.
Cuatro reglas básicas (enforce): descarte de conjuntos (v4/v6), limitación de SYN (60/s, ráfaga 120)
y límite de concurrencia por IP de 200; observe usa las mismas reglas con el veredicto `counter log`.
Los niveles ajustan la cobertura dentro del mismo modo: `loose` 2 reglas, `standard` 4 (por defecto),
`strict` 6 (añade descarte de conexiones malformadas y limitación de fuerza bruta SSH). El nivel y el
modo se infieren releyendo la cadena, **sin nuevos root-actions**; cambiar de modo sin `level` mantiene
el nivel actual y `off` limpia la cadena, por lo que el nivel vuelve a cero y al reactivar se usa standard.

Flujo (`waf.toggle`): parámetros/confirmación → disponibilidad de nft y del canal → atajo si modo y
nivel coinciden → inicializar si hace falta → aplicar reglas → verificación por lectura (modo, nivel y
número de reglas deben coincidir para `applied=true`). Todas las acciones son `irreversible:false`:
`enforce` puede volver a `observe`/`off` y las prohibiciones se pueden quitar. Se eliminó
`modsec-set-mode` de 0.2.0 (`sed -i` sobre un archivo de modo): escribir archivos arbitrarios equivale
a poder de escritura arbitrario y no es auditable.

## Contrato de configuración

Se guarda en `<KORE_STATE_DIR>/config.json` (0600, escritura atómica), prioridad **config.json >
variables de entorno > valores por defecto**, fusión campo a campo, efectivo en la siguiente llamada
(`restart_required=false`). Campos: `engine` (auto), `rules_dirs` ([]), `log_paths` ([]),
`mode_config_path` (""), `max_log_bytes` (1048576). Variables: `KORE_WAF_ENGINE` /
`KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` / `KORE_WAF_MAX_LOG_BYTES`;
la variable histórica `KORE_WAF_RULES_ROOT` se mapea a directorios de reglas.

## Degradación y límites honestos

Sin motor, el plano de motor devuelve `E_UNSUPPORTED` + pista de instalación y el plano de datos sigue
funcionando; sin `nft`, `backend.available=false`; con nft pero sin canal root, `E_NEED_ROOT`; si la
lectura no coincide, `applied=false` + motivo. Elementos no verificados declarados explícitamente: no
hay motor WAF en ejecución en el host de pruebas; el backend `ipset` no está implementado y se retiró de
la tabla de formas del núcleo; no se completó el extremo a extremo bajo un kored root real (las rutas de
rechazo están verificadas, las de éxito las cubren las pruebas de integración root del núcleo); solo se
verificó nft 1.1.6; los registros observe van al log del núcleo y aquí no se analizan.

## Instalación y verificación

```sh
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

`make dist` es determinista (entradas fijas, mtime/owner/mode normalizados, `gzip -9n`), dos builds
dan el mismo sha256. Artefactos: `dist/waf-<versión>.tar.gz` + `.sha256`. No abras un issue público
para vulnerabilidades; divúlgala de forma privada según
[SECURITY.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/SECURITY.md).
