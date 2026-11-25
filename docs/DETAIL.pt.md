# kore-plugin-waf — Plugin WAF

## O que faz

Um plugin de gerenciamento de WAF (**L1.5+ · independente do mecanismo + plano de dados nft real**) com
duas responsabilidades separadas: a **camada de mecanismo** apenas detecta os mecanismos WAF já
instalados no host (modsecurity / naxsi / coraza / crowdsec), conta as regras e analisa os logs de
bloqueio; o **plano de dados** é implementado pelo próprio kore com `nft` (conjuntos de banimento,
limitação de varredura SYN e limite de concorrência por IP), com alternância observe/enforce e três
níveis de proteção (flexível/padrão/rigoroso desde 0.5.0). Este repositório **não inclui nenhum mecanismo
WAF** e **nunca executa o nft no processo do plugin**: todas as gravações passam pelo canal root-action
do ADR-0018 (ADR-0022 fixa a forma dos comandos).

- Protocolo: `kore.plugin.v1`, `lifecycle=lazy`, nível de profundidade `basic`; permissões `system:read` + `system:admin`.
- Privilégios: declara `requires_root: true` e 12 `root_actions` (todas instruções nft, `irreversible:false`, todas reversíveis).
- Tag de cenário: `sec`; orçamento de recursos 6 MiB / 15% CPU / 16 pids.

## Superfície de métodos (10 métodos de negócio)

| Método | Entrada | Resultado |
| --- | --- | --- |
| `waf.status` | `{}` | Motor: disponibilidade / versão / regras / modo; nível; estado de `backend` |
| `waf.rules` | `{engine?}` | Conjuntos de regras do motor + regras nft da cadeia de dados |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | Entradas de log de bloqueio e estatísticas |
| `waf.toggle` | `{mode, level?, confirm?}` | Alternância observe/enforce/off com nível; verificação por leitura após gravar |
| `waf.ban` | `{ip, ttl_s?, reason?}` | Banimento idempotente (v4/v6, `ttl_s=0` permanente, 60–2592000) |
| `waf.unban` | `{ip}` | Desbanimento (ausência no conjunto também conta como sucesso) |
| `waf.bans` | `{limit?}` | Lista de banimentos com tempos restantes |
| `waf.rule.add` / `remove` / `toggle` | ver README | Lista branca controlada, comparação `nft -j list`, rollback se divergir |
| `waf.config.get` / `set` | `{}` / `{values}` | Configuração 0600, efetiva na próxima chamada |

São aceitos tanto `waf.<verbo>` quanto o verbo puro; `waf.blockLog` é um alias de compatibilidade de
`waf.logs`. `name` permite apenas letras minúsculas / dígitos / `-` / `_` (1-32) e `expr` apenas
correspondências da lista branca (`ip saddr`, `ip6 saddr`, `tcp dport`, `udp dport`, `ct state`,
`tcp flags syn`); os objetos de parâmetros são decodificados estritamente e um campo escrito errado
retorna `E_INVALID`.

## Detecção de mecanismos e contagem de regras

`engine=auto` escolhe o primeiro resultado na ordem modsecurity → naxsi → coraza → crowdsec; cada
mecanismo retorna evidências `probed[]` e nunca apresenta um resultado vazio como "sem mecanismo". Com
mecanismo explícito e `rules_dirs` / `log_paths` configurados existentes, os caminhos declarados são
respeitados. modsecurity / coraza contam linhas de diretiva `SecRule` (inclusive indentadas, sem
comentários ou SecAction), naxsi conta `MainRule` + `BasicRule` e crowdsec conta um cenário como
`rule_count=1`. `enabled` significa apenas que o arquivo está em diretório ativo com regras válidas,
não que uma cadeia include foi confirmada.

## Logs de bloqueio

Apenas o fim é lido (1 MiB por padrão, configurável de 64 KiB a 8 MiB), analisando logs de erro do
ModSecurity / seções de auditoria, `NAXSI_FMT` / `NAXSI_EXLOG` do Naxsi e linhas JSON. `action` é
`blocked` / `detected`; quando o ID da regra não pode ser obtido, ele fica vazio em vez de ser advinhado.
`since` aceita `1h` / `30m` / `7d` / RFC3339 / `YYYY-MM-DD`; entradas não analisáveis são descartadas com
`since` e contabilizadas em `skipped_unparsed`; `limit` tem padrão 50 e máximo 200. Um log ilegível
retorna `E_NEED_ROOT` + dica, não uma lista vazia fingindo "sem bloqueios"; o formato crowdsec não é
analisado nesta versão e retorna `E_UNSUPPORTED`.

## Plano de dados: regras nft reais

o kore cria `table inet kore_waf` em seu próprio namespace e nunca toca `filter` / `nat` do host:
dois conjuntos de banimento (`banned4` / `banned6`, com CIDR e timeout) e uma cadeia base em input.
Quatro regras básicas (enforce): descarte pelos conjuntos (v4/v6), limitação de varredura SYN (60/s,
rajada 120) e limite de concorrência por IP de 200; observe usa as mesmas regras com o veredito
`counter log`. Os níveis ajustam a cobertura dentro do mesmo modo: `loose` 2 regras, `standard` 4
(padrão), `strict` 6 (adiciona descarte de conexões malformadas e limitação de força bruta SSH). Nível e
modo são inferidos pela leitura da cadeia — **sem novos root-actions**; trocar de modo sem `level` mantém
o nível atual, e `off` limpa a cadeia, então o nível volta a zero e a reativação usa standard.

Fluxo (`waf.toggle`): parâmetros/confirmação → disponibilidade de nft e do canal → atalho se modo e nível
coincidirem → inicializar se necessário → aplicar regras → verificação por leitura (modo, nível e número
de regras devem coincidir para `applied=true`). Todas as ações são `irreversible:false`: `enforce` pode
voltar a `observe`/`off` e banimentos podem ser removidos. O `modsec-set-mode` do 0.2.0 (`sed -i` em
arquivo de modo) foi removido — gravar arquivos arbitrários equivale a poder de escrita arbitrário e não
é auditável.

## Contrato de configuração

Persistido em `<KORE_STATE_DIR>/config.json` (0600, escrita atômica), prioridade **config.json >
variáveis de ambiente > padrões do código**, mesclado campo a campo, efetivo na próxima chamada
(`restart_required=false`). Campos: `engine` (auto), `rules_dirs` ([]), `log_paths` ([]),
`mode_config_path` (""), `max_log_bytes` (1048576). Variáveis: `KORE_WAF_ENGINE` /
`KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` / `KORE_WAF_MAX_LOG_BYTES` ;
a variável histórica `KORE_WAF_RULES_ROOT` é mapeada para diretórios de regras.

## Degradação e limites honestos

Sem mecanismo, a camada de mecanismo retorna `E_UNSUPPORTED` + dica de instalação enquanto o plano de
dados continua funcionando; sem `nft`, `backend.available=false`; com nft mas sem canal root, `E_NEED_ROOT`;
em caso de leitura divergente, `applied=false` + motivo. Itens não verificados explicitamente declarados:
nenhum mecanismo WAF em execução no host de teste; o backend `ipset` não foi implementado e foi removido
da tabela de formas do núcleo; o ponta a ponta sob um kored root real não foi concluído (caminhos de rejeição
verificados, caminhos de sucesso cobertos pelos testes de integração root do núcleo); apenas o nft 1.1.6
foi verificado; os logs observe vão para os logs do núcleo e não são analisados aqui.

## Instalação e verificação

```sh
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

`make dist` é determinístico (entradas fixas, mtime/owner/mode normalizados, `gzip -9n`), duas compilações
geram o mesmo sha256. Artefatos: `dist/waf-<versão>.tar.gz` + `.sha256`. Não abra uma issue pública para
vulnerabilidades — divulgue-a de forma privada conforme
[SECURITY.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/SECURITY.md).
