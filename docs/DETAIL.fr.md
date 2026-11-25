# kore-plugin-waf — Plugin WAF

## Ce que fait ce plugin

Un plugin de gestion WAF (**L1.5+ · indépendant du moteur + plan de données nft réel**) avec deux
responsabilités distinctes : la **couche moteur** ne fait que détecter les moteurs WAF déjà installés
sur l'hôte (modsecurity / naxsi / coraza / crowdsec), compter les règles et analyser les journaux de
blocage ; le **plan de données** est implémenté par kore lui-même avec `nft` (ensembles de bannissement,
limitation des scans SYN et plafond de concurrence par IP), avec bascule observe/enforce et trois
niveaux de protection (souple/standard/strict depuis 0.5.0). Ce dépôt **ne contient aucun moteur WAF**
et **n'exécute jamais nft dans le processus du plugin** : toutes les écritures passent par le canal
root-action de l'ADR-0018 (l'ADR-0022 verrouille la forme des commandes).

- Protocole : `kore.plugin.v1`, `lifecycle=lazy`, niveau de profondeur `basic` ; capacités `system:read` + `system:admin`.
- Privilèges : déclare `requires_root: true` et 12 `root_actions` (toutes des instructions nft, `irreversible:false`, toutes réversibles).
- Étiquette de scénario : `sec` ; budget de ressources 6 Mio / 15% CPU / 16 pids.

## Surface de méthodes (10 méthodes métier)

| Méthode | Entrée | Résultat |
| --- | --- | --- |
| `waf.status` | `{}` | Moteur : disponibilité / version / règles / mode ; niveau ; état de `backend` |
| `waf.rules` | `{engine?}` | Jeux de règles du moteur + règles nft de la chaîne de données |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | Entrées de journaux de blocage et statistiques |
| `waf.toggle` | `{mode, level?, confirm?}` | Bascule observe/enforce/off avec niveau ; vérification après écriture |
| `waf.ban` | `{ip, ttl_s?, reason?}` | Bannissement idempotent (v4/v6, `ttl_s=0` permanent, 60–2592000) |
| `waf.unban` | `{ip}` | Débannissement (l'absence de l'ensemble compte aussi comme succès) |
| `waf.bans` | `{limit?}` | Liste des bannissements avec durées restantes |
| `waf.rule.add` / `remove` / `toggle` | voir README | Liste blanche de correspondances, comparaison `nft -j list`, rollback si incohérent |
| `waf.config.get` / `set` | `{}` / `{values}` | Configuration 0600, effective à l'appel suivant |

`waf.<verbe>` et le verbe nu sont acceptés ; `waf.blockLog` est un alias de compatibilité de `waf.logs`.
`name` n'autorise que lettres minuscules / chiffres / `-` / `_` (1-32) et `expr` seulement les
correspondances de la liste blanche (`ip saddr`, `ip6 saddr`, `tcp dport`, `udp dport`, `ct state`,
`tcp flags syn`) ; les objets de paramètres sont décodés strictement et un champ mal orthographié renvoie `E_INVALID`.

## Détection des moteurs et comptage des règles

`engine=auto` prend le premier résultat dans l'ordre modsecurity → naxsi → coraza → crowdsec ; chaque
moteur renvoie des preuves `probed[]` et jamais un résultat vide présenté comme « pas de moteur ». Avec
un moteur explicite et des `rules_dirs` / `log_paths` configurés existants, les chemins déclarés sont
honorés. modsecurity / coraza comptent les lignes de directive `SecRule` (y compris indentées, hors
commentaires et SecAction), naxsi compte `MainRule` + `BasicRule` et crowdsec compte un scénario comme
`rule_count=1`. `enabled` signifie seulement que le fichier est dans un répertoire actif avec des règles
valides, pas qu'une chaîne include est confirmée.

## Journaux de blocage

Seule la fin est lue (1 Mio par défaut, configurable 64 Kio–8 Mio), en analysant les journaux d'erreur
ModSecurity / sections d'audit, `NAXSI_FMT` / `NAXSI_EXLOG` de Naxsi et les lignes JSON. `action` vaut
`blocked` / `detected` ; si l'identifiant de règle est introuvable, il reste vide plutôt que d'être
deviné. `since` accepte `1h` / `30m` / `7d` / RFC3339 / `YYYY-MM-DD` ; les entrées non analysables sont
ignorées avec `since` et comptées dans `skipped_unparsed` ; `limit` vaut 50 par défaut, maximum 200. Un
journal illisible renvoie `E_NEED_ROOT` + indice, pas une liste vide prétendant « aucun blocage » ; le
format crowdsec n'est pas analysé dans cette version et renvoie `E_UNSUPPORTED`.

## Plan de données : règles nft réelles

kore crée `table inet kore_waf` dans son propre espace de noms et ne touche jamais `filter` / `nat` de
l'hôte : deux ensembles de bannissement (`banned4` / `banned6`, avec CIDR et timeout) et une chaîne de
base sur input. Quatre règles de base (enforce) : rejet des ensembles (v4/v6), limitation des scans SYN
(60/s, rafale 120) et plafond de concurrence par IP de 200 ; observe utilise les mêmes règles avec le
verdict remplacé par `counter log`. Les niveaux ajustent la couverture dans le même mode : `loose` 2
règles, `standard` 4 (par défaut), `strict` 6 (ajoute le rejet des connexions mal formées et la
limitation de force brute SSH). Le niveau et le mode sont déduits par relecture de la chaîne, **sans
nouvelle root-action** ; changer de mode sans `level` conserve le niveau actuel et `off` vide la chaîne,
donc le niveau revient à zéro et la réactivation utilise standard.

Flux (`waf.toggle`) : paramètres/confirmation → disponibilité de nft et du canal → raccourci si mode et
niveau correspondent → initialisation si nécessaire → application des règles → vérification par lecture
(mode, niveau et nombre de règles doivent tous correspondre pour `applied=true`). Toutes les actions
sont `irreversible:false` : `enforce` peut revenir à `observe`/`off` et les bannissements peuvent être
retirés. `modsec-set-mode` de 0.2.0 (`sed -i` sur un fichier de mode) a été supprimé : écrire un fichier
arbitraire équivaut à un pouvoir d'écriture arbitraire et n'est pas auditable.

## Contrat de configuration

Persistance dans `<KORE_STATE_DIR>/config.json` (0600, écriture atomique), priorité **config.json >
variables d'environnement > valeurs par défaut**, fusion champ par champ, effectif à l'appel suivant
(`restart_required=false`). Champs : `engine` (auto), `rules_dirs` ([]), `log_paths` ([]),
`mode_config_path` (""), `max_log_bytes` (1048576). Variables : `KORE_WAF_ENGINE` /
`KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` / `KORE_WAF_MAX_LOG_BYTES` ;
l'ancienne variable `KORE_WAF_RULES_ROOT` est mappée aux répertoires de règles.

## Dégradation et limites honnêtes

Sans moteur, le plan moteur renvoie `E_UNSUPPORTED` + indice d'installation tandis que le plan de données
fonctionne ; sans `nft`, `backend.available=false` ; avec nft mais sans canal root, `E_NEED_ROOT` ; en
cas de relecture incohérente, `applied=false` + motif. Éléments non vérifiés explicitement déclarés :
aucun moteur WAF en fonctionnement sur l'hôte de test ; le backend `ipset` n'est pas implémenté et a été
retiré de la table de formes du noyau ; le bout en bout sous un kored root réel n'a pas été terminé (les
chemins de rejet sont vérifiés, les chemins de succès sont couverts par les tests d'intégration root du
noyau) ; seul nft 1.1.6 a été vérifié ; les journaux observe vont dans les journaux du noyau et ne sont
pas analysés ici.

## Installation et vérification

```sh
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

`make dist` est déterministe (entrées fixes, mtime/owner/mode normalisés, `gzip -9n`) : deux builds
donnent le même sha256. Artefacts : `dist/waf-<version>.tar.gz` + `.sha256`. N'ouvrez pas d'issue
publique pour une vulnérabilité — divulguez-la de façon privée selon
[SECURITY.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/SECURITY.md).
