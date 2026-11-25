# kore-plugin-waf — WAF plugin

## What it does

A WAF management plugin (**L1.5+ · engine-agnostic + real nft data plane**) with two separated
responsibilities: the **engine layer** only probes WAF engines already installed on the host
(modsecurity / naxsi / coraza / crowdsec), counts rules and parses block logs; the **data plane** is
implemented by kore itself with `nft` (ban sets / SYN scan rate limiting / per-IP concurrency caps),
supporting `observe` (log only) and `enforce` (block) switching plus three protection levels
(loose/standard/strict, since 0.5.0). This repository **ships no WAF engine** and **never execs nft in
the plugin process**: all writes go through the ADR-0018 root-action channel (ADR-0022 locks command shapes).

- Protocol: `kore.plugin.v1`, `lifecycle=lazy`, depth level `basic`; capabilities `system:read` + `system:admin`.
- Privilege: declares `requires_root: true` plus 12 `root_actions` (all nft statements, `irreversible:false`, all reversible).
- Scenario tag: `sec`; resource budget 6 MiB / 15% CPU / 16 pids.

## Method surface (10 business methods)

| Method | Input | Result highlights |
| --- | --- | --- |
| `waf.status` | `{}` | Engine plane availability / version / rules count / mode; level; data-plane `backend` state |
| `waf.rules` | `{engine?}` | Engine rulesets + data-plane nft chain rules (handle / verdict / counters) |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | Block-log entries and parse statistics |
| `waf.toggle` | `{mode, level?, confirm?}` | observe/enforce/off switch with level; readback verification after write |
| `waf.ban` | `{ip, ttl_s?, reason?}` | Idempotent ban (v4/v6, `ttl_s=0` permanent, 60-2592000) |
| `waf.unban` | `{ip}` | Unban (absence from the set also counts as success) |
| `waf.bans` | `{limit?}` | Ban list with remaining timeouts |
| `waf.rule.add` / `remove` / `toggle` | see README | Controlled matcher allowlist, `nft -j list` readback comparison, rollback on mismatch |
| `waf.config.get` / `set` | `{}` / `{values}` | Config persisted 0600, effective on the next call |

Both `waf.<verb>` and the bare `<verb>` are accepted; `waf.blockLog` is a compatibility alias for
`waf.logs`. `name` allows only lowercase letters / digits / `-` / `_` (1-32); `expr` accepts only
allowlisted matchers (`ip saddr`, `ip6 saddr`, `tcp dport`, `udp dport`, `ct state`, `tcp flags syn`);
parameter objects are decoded strictly, so a misspelled field returns `E_INVALID`.

## Engine detection and rule counting

`engine=auto` picks the first hit in order modsecurity -> naxsi -> coraza -> crowdsec; each engine
returns `probed[]` evidence and never passes an empty result off as "no engine". With an explicit
engine and configured `rules_dirs` / `log_paths` present, the user-declared install paths are honoured.
modsecurity / coraza count `SecRule` directive lines (including indented ones, excluding comments and
SecAction), naxsi counts `MainRule` + `BasicRule`, crowdsec counts one scenario as `rule_count=1`.
`enabled` only means the file is in an active directory with valid rules, not that an include chain is confirmed.

## Block logs

Only the tail is read (default 1 MiB, configurable 64 KiB-8 MiB), parsing ModSecurity error logs /
audit log sections, Naxsi `NAXSI_FMT` / `NAXSI_EXLOG`, and JSON lines. `action` is `blocked` / `detected`;
when a rule ID cannot be obtained it stays empty rather than being guessed. `since` supports `1h` /
`30m` / `7d` / RFC3339 / `YYYY-MM-DD`; unparseable entries are dropped with `since` and counted in
`skipped_unparsed`; `limit` defaults to 50 and caps at 200. Unreadable logs return `E_NEED_ROOT` + hint
rather than an empty list pretending "no blocks"; the crowdsec log format is not parsed in this version
and returns `E_UNSUPPORTED`.

## Data plane: real nft rules

kore creates `table inet kore_waf` in its own namespace and never touches the host's `filter` / `nat`:
two ban sets (`banned4` / `banned6`, supporting CIDR and timeout) and a base chain hooked to input.
Four baseline rules (enforce): ban-set drops (v4/v6), SYN scan rate limiting (60/s, burst 120), and a
per-IP concurrency cap of 200; observe uses the same rules with the verdict replaced by `counter log`.
Levels adjust coverage within the same mode: `loose` 2 rules (ban list only), `standard` 4 (default),
`strict` 6 (adds malformed-connection drop and SSH brute-force rate limiting). Level and mode are
inferred by reading back the chain — **no new root actions**; switching mode without `level` keeps the
current level, and `off` clears the chain so the level resets to zero and re-enabling uses standard.

Flow (`waf.toggle`): parameters/confirmation -> nft and channel availability -> short-circuit when
mode and level match -> initialize if needed -> apply rules -> readback verification (mode, level and
rule count must all match for `applied=true`). Every action is `irreversible:false`: `enforce` can go
back to `observe`/`off` and bans can be removed. The 0.2.0 `modsec-set-mode` (`sed -i` on a mode file)
was removed — arbitrary file writes mean arbitrary write power and are unauditable.

## Configuration contract

Persisted at `<KORE_STATE_DIR>/config.json` (0600, atomic write), precedence **config.json >
environment variables > code defaults**, merged field by field, effective on the next call
(`restart_required=false`). Fields: `engine` (auto), `rules_dirs` ([]), `log_paths` ([]),
`mode_config_path` (""), `max_log_bytes` (1048576). Environment variables: `KORE_WAF_ENGINE` /
`KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` / `KORE_WAF_MAX_LOG_BYTES`;
the legacy `KORE_WAF_RULES_ROOT` maps to rule directories.

## Degradation and honest boundaries

With no engine the engine plane returns `E_UNSUPPORTED` + install hint while the data plane still works;
without `nft`, `backend.available=false`; with nft but no root channel, `E_NEED_ROOT`; on readback mismatch,
`applied=false` + reason. Explicitly disclosed unverified items: no running WAF engine on the test host;
the `ipset` backend is not implemented and was removed from the kernel shape table; end-to-end under a real
root kored was not completed (rejection paths verified, success paths covered by kernel-side root
integration tests); only nft 1.1.6 was verified; observe logs land in kernel logs and are not parsed here.

## Installation and verification

```sh
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

`make dist` is deterministic (fixed entries, normalized mtime/owner/mode, `gzip -9n`), two builds give
identical sha256. Release artifacts: `dist/waf-<version>.tar.gz` + `.sha256`. Do not open a public issue
for vulnerabilities — disclose privately per
[SECURITY.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/SECURITY.md).
