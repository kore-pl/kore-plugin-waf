# kore-plugin-waf — WAF-Plugin

## Was es macht

Ein WAF-Verwaltungsplugin (**L1.5+ · engine-unabhängig + echtes nft-Datenplane**) mit zwei getrennten
Aufgaben: Die **Engine-Ebene** erkennt nur auf dem Host bereits installierte WAF-Engines
(modsecurity / naxsi / coraza / crowdsec), zählt Regeln und parst Blockierungs-Logs; die
**Datenebene** wird von kore selbst mit `nft` implementiert (Sperrsets, SYN-Scan-Ratenbegrenzung,
Pro-IP-Gleichzeitigkeitslimit), mit observe/enforce-Umschaltung und drei Schutzstufen
(locker/standard/streng seit 0.5.0). Dieses Repository **enthält keine WAF-Engine** und führt **niemals
nft im Plugin-Prozess aus**: alle Schreibvorgänge laufen über den root-action-Kanal aus ADR-0018
(ADR-0022 legt die Befehlsform fest).

- Protokoll: `kore.plugin.v1`, `lifecycle=lazy`, Tiefe `basic`; Capabilities `system:read` + `system:admin`.
- Privilegien: deklariert `requires_root: true` und 12 `root_actions` (alles nft-Anweisungen, `irreversible:false`, alle umkehrbar).
- Szenario-Tag: `sec`; Ressourcenbudget 6 MiB / 15% CPU / 16 pids.

## Methodenoberfläche (10 Geschäftsmethoden)

| Methode | Eingabe | Ergebnis |
| --- | --- | --- |
| `waf.status` | `{}` | Engine: Verfügbarkeit / Version / Regeln / Modus; Stufe; `backend`-Zustand |
| `waf.rules` | `{engine?}` | Engine-Regelsets + nft-Kettenregeln der Datenebene |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | Blockierungs-Logeinträge und Statistik |
| `waf.toggle` | `{mode, level?, confirm?}` | observe/enforce/off-Umschaltung mit Stufe; Rückleseprüfung nach Schreiben |
| `waf.ban` | `{ip, ttl_s?, reason?}` | Idempotente Sperre (v4/v6, `ttl_s=0` dauerhaft, 60–2592000) |
| `waf.unban` | `{ip}` | Entsperren (Abwesenheit im Set gilt ebenfalls als Erfolg) |
| `waf.bans` | `{limit?}` | Sperrliste mit Restlaufzeiten |
| `waf.rule.add` / `remove` / `toggle` | siehe README | Kontrollierte Matcher-Whitelist, `nft -j list`-Abgleich, Rollback bei Abweichung |
| `waf.config.get` / `set` | `{}` / `{values}` | Konfiguration 0600, beim nächsten Aufruf wirksam |

Sowohl `waf.<Verb>` als auch das nackte `<Verb>` werden akzeptiert; `waf.blockLog` ist ein
Kompatibilitätsalias für `waf.logs`. `name` erlaubt nur Kleinbuchstaben / Ziffern / `-` / `_` (1-32),
`expr` nur Matcher aus der Whitelist (`ip saddr`, `ip6 saddr`, `tcp dport`, `udp dport`, `ct state`,
`tcp flags syn`); Parameterobjekte werden strikt dekodiert, ein falsch geschriebenes Feld liefert `E_INVALID`.

## Engine-Erkennung und Regelzählung

`engine=auto` nimmt in der Reihenfolge modsecurity → naxsi → coraza → crowdsec den ersten Treffer; jede
Engine liefert `probed[]`-Beweise und gibt nie ein leeres Ergebnis als „keine Engine" aus. Bei explizit
gewählter Engine und vorhandenen konfigurierten `rules_dirs` / `log_paths` gelten die deklarierten
Installationspfade. modsecurity / coraza zählen `SecRule`-Direktivzeilen (auch eingerückte, ohne
Kommentare und SecAction), naxsi zählt `MainRule` + `BasicRule`, crowdsec zählt ein Szenario als
`rule_count=1`. `enabled` bedeutet nur, dass die Datei in einem aktiven Verzeichnis mit gültigen Regeln
liegt, nicht dass eine include-Kette bestätigt ist.

## Blockierungs-Logs

Nur das Ende wird gelesen (standardmäßig 1 MiB, konfigurierbar 64 KiB–8 MiB) und ModSecurity-
Fehlerprotokolle / Audit-Abschnitte, Naxsi `NAXSI_FMT` / `NAXSI_EXLOG` sowie JSON-Zeilen geparst.
`action` ist `blocked` / `detected`; ist keine Regel-ID verfügbar, bleibt sie leer statt geraten zu
werden. `since` unterstützt `1h` / `30m` / `7d` / RFC3339 / `YYYY-MM-DD`; nicht parsebare Einträge
werden mit `since` verworfen und in `skipped_unparsed` gezählt; `limit` beträgt standardmäßig 50,
maximal 200. Ein nicht lesbares Protokoll liefert `E_NEED_ROOT` + Hinweis, keine leere Liste, die
„keine Blockierungen" vortäuscht; das crowdsec-Format wird in dieser Version nicht geparst und liefert
`E_UNSUPPORTED`.

## Datenebene: echte nft-Regeln

kore erstellt `table inet kore_waf` im eigenen Namespace und berührt nie `filter` / `nat` des Hosts:
zwei Sperrsets (`banned4` / `banned6`, mit CIDR und timeout) und eine Base-Chain an input. Vier
Grundregeln (enforce): Verwerfen über Sperrsets (v4/v6), SYN-Scan-Ratenbegrenzung (60/s, Burst 120)
und Pro-IP-Gleichzeitigkeitslimit 200; observe nutzt dieselben Regeln mit `counter log` als Verdict.
Stufen passen die Abdeckung innerhalb desselben Modus an: `loose` 2 Regeln, `standard` 4 (Standard),
`strict` 6 (zusätzlich Verwerfen fehlerhafter Verbindungen und SSH-Brute-Force-Begrenzung). Stufe und
Modus werden durch Rücklesen der Chain abgeleitet — **ohne neue root-actions**; ein Moduswechsel ohne
`level` behält die aktuelle Stufe, und `off` leert die Chain, sodass die Stufe auf null zurückgesetzt
wird und das Reaktivieren standard verwendet.

Ablauf (`waf.toggle`): Parameter/Bestätigung → nft- und Kanalverfügbarkeit → Kurzschluss bei gleicher
Stufe und Modus → ggf. Initialisierung → Regeln anwenden → Rückleseprüfung (Modus, Stufe und
Regelanzahl müssen für `applied=true` alle übereinstimmen). Alle Aktionen sind `irreversible:false`:
`enforce` kann zurück zu `observe`/`off` und Sperren können entfernt werden. `modsec-set-mode` aus
0.2.0 (`sed -i` auf eine Modusdatei) wurde entfernt — beliebiges Dateischreiben bedeutet beliebige
Schreibmacht und ist nicht auditierbar.

## Konfigurationsvertrag

Gespeichert unter `<KORE_STATE_DIR>/config.json` (0600, atomares Schreiben), Priorität **config.json >
Umgebungsvariablen > Code-Defaults**, Feld für Feld zusammengeführt, beim nächsten Aufruf wirksam
(`restart_required=false`). Felder: `engine` (auto), `rules_dirs` ([]), `log_paths` ([]),
`mode_config_path` (""), `max_log_bytes` (1048576). Umgebungsvariablen: `KORE_WAF_ENGINE` /
`KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` / `KORE_WAF_MAX_LOG_BYTES` ;
die historische Variable `KORE_WAF_RULES_ROOT` wird auf Regelverzeichnisse abgebildet.

## Degradation und ehrliche Grenzen

Ohne Engine liefert die Engine-Ebene `E_UNSUPPORTED` + Installationshinweis, während die Datenebene
weiter funktioniert; ohne `nft` ist `backend.available=false`; mit nft aber ohne root-Kanal
`E_NEED_ROOT`; bei abweichendem Rücklesen `applied=false` + Grund. Explizit genannte ungeprüfte Punkte:
keine laufende WAF-Engine auf dem Testhost; das `ipset`-Backend ist nicht implementiert und wurde aus
der Kernel-Formtabelle entfernt; Ende-zu-Ende unter einem echten root-kored nicht abgeschlossen
(Ablehnungspfade geprüft, Erfolgspfade durch Kernel-Root-Integrationstests abgedeckt); nur nft 1.1.6
geprüft; observe-Logs landen in Kernel-Logs und werden hier nicht geparst.

## Installation und Prüfung

```sh
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

`make dist` ist deterministisch (feststehende Einträge, normalisierte mtime/owner/mode, `gzip -9n`),
zwei Builds ergeben identisches sha256. Release-Artefakte: `dist/waf-<Version>.tar.gz` + `.sha256`.
Schwachstellen nicht in einem öffentlichen Issue melden — vertraulich gemäß
[SECURITY.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/SECURITY.md) offenlegen.
