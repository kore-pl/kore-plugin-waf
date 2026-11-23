# kore-plugin-waf

WAF 管理插件（**L1.5+ · 引擎无关 + 真实 nft 数据面**）：
两层职责分开——**引擎层**只读探测宿主已装的 WAF 引擎（modsecurity / naxsi / coraza / crowdsec）并统计规则、解析拦截日志；
**数据面**由 kore 自己用 `nft` 落地（封禁集合 / SYN 扫描限速 / 单 IP 并发上限），支持 `observe`（只记录）与 `enforce`（阻断）切换。
本仓**不内置任何 WAF 引擎**，也**不在插件进程里 exec nft**：一切写操作都经 ADR-0018 的 root-action 通道（ADR-0022 锁死命令形状）。

- 协议：`kore.plugin.v1`，`lifecycle=lazy`，`depth_level=basic`
- 能力：`system:read` + `system:admin`（写方法 `waf.ban` / `waf.unban` / `waf.toggle` / `waf.config.set` 走 admin）
- 提权：声明 `requires_root: true` + **12 个 `root_actions`**（全为 nft 语句，全部 `irreversible:false`——都能反向操作）
- 场景标签：`sec`

## 1. 方法面（7 个业务方法 + 配置契约）

| 方法 | 入参 | 结果要点 |
| --- | --- | --- |
| `waf.status` | `{}` | 引擎平面：`available / engine / version / rules_count / mode(on\|off\|detection) / probed`；数据面：`backend{tool,available,channel,table,chain,present,mode,banned_count,rules_count}` |
| `waf.rules` | `{engine?}` | 引擎规则集 `rulesets[] / total` + 数据面 `nft{table,chain,present,mode,rules[{handle,summary,verdict,packets,bytes}],bans_count}` |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | `sources[] / entries[{time,ip,uri,rule_id,action}] / count / limit / scanned_lines` |
| `waf.toggle` | `{mode: observe\|enforce\|off, confirm?}` | `previous_mode / mode / applied / verified / rules[] / steps[]`；`off` 必须 `confirm=true` |
| `waf.ban` | `{ip, ttl_s?, reason?}` | `ip / family / set / ttl_s / banned / steps[]`（幂等；`ttl_s=0` 永久，60–2592000） |
| `waf.unban` | `{ip}` | `ip / set / removed / steps[]`（不在集合里也算成功） |
| `waf.bans` | `{limit?}` | `present / mode / count / bans[{ip,timeout_s,expires_s,set}]` |
| `waf.config.get` / `waf.config.set` | `{}` / `{values}` | 契约见 [docs/PLUGIN-CONFIG.md](https://github.com/pengtang1024/kore/blob/main/docs/PLUGIN-CONFIG.md)，字段见 §5 |

`waf.<verb>` 与裸 `<verb>` 都接受；`waf.blockLog` 是 `waf.logs` 的兼容别名（0.1.x 客户端不炸）。
参数对象严格解码：拼错字段名返回 `E_INVALID`，不静默忽略。

## 2. 引擎检测策略

`engine=auto` 按 **modsecurity → naxsi → coraza → crowdsec** 顺序取第一个命中；也可在配置或方法参数里显式指定。
每个引擎都返回 `probed[]` 证据（命中的文件 / 命令输出），不拿空结果冒充"没有引擎"。

| 引擎 | 证据 | 版本 | 模式 |
| --- | --- | --- | --- |
| modsecurity | `/etc/modsecurity`、`/etc/nginx/modsecurity.conf`、`ngx_http_modsecurity_module.so` / `mod_security2.so`、`nginx -V` 含 modsecurity | `dpkg-query`/`rpm` 查 `libmodsecurity3`；CRS 版本读 `/usr/share/modsecurity-crs/VERSION` | 配置文件里最后一个 `SecRuleEngine On\|Off\|DetectionOnly`，`DetectionOnly` → `detection` |
| naxsi | `ngx_http_naxsi_module.so`、`/etc/nginx/naxsi.rules`、`naxsi_core.rules`、`nginx -V` 含 naxsi | `dpkg-query` 查 `libnginx-mod-http-naxsi` | `LearningMode` → `detection`，`SecRulesEnabled` → `on`，都没有 → `off` |
| coraza | `coraza` / `coraza-caddy` 二进制、coraza nginx 模块、`/etc/coraza` | `<bin> version` / `--version` | `SecRuleEngine`（同 modsecurity） |
| crowdsec | `cscli` 存在且 `cscli version` 成功 | `cscli version` 解析 | 有已注册 bouncer → `on`；否则只有告警 → `detection` |

**非标准安装路径**：显式选择引擎且配置的 `rules_dirs` / `log_paths` 存在时，按「用户声明的安装路径」认定可用，
`probed[].evidence` 会写明依据（例如 `配置声明的路径存在：/opt/waf/rules 目录存在`），不冒充默认路径探测成功。

**诚实边界**：Apache 的 `mod_security2.so` 可作为 modsecurity 证据，但本插件只声明了 `nginx-reload` 提权动作，
Apache 部署切换模式后需运维自行 `graceful`（`toggle` 结果会明确提示）。

## 3. 规则计数口径

- **modsecurity / coraza**：统计 `SecRule` 指令行——行首允许缩进、`#` 注释行不算、`SecAction`/`SecRuleUpdateTargetById` 不算。
  真实 OWASP CRS 文件里存在大量**缩进的 SecRule**（条件链可读性排版），朴素 `grep '^SecRule '` 会少算。
- **naxsi**：统计 `MainRule` + `BasicRule`。
- **crowdsec**：一个场景按 `rule_count=1` 计（它没有 ModSecurity 的规则行级计数，不拿别的数字冒充）。
- `enabled`：文件型引擎表示「文件位于生效目录且含有效规则」，**不等于**已确认引擎 include 链；
  只看配置无法证明 include 关系，这是本版明确的能力边界。crowdsec 取 `cscli` 的 `enabled`。

## 4. 拦截日志

- 只读**尾部**：默认 1 MiB，可配 64 KiB–8 MiB；文件被截断时 `truncated=true`，首个残行丢弃。
- 解析格式（任一匹配）：
  - ModSecurity 错误日志行：`[client IP] ModSecurity: Access denied ... [id "..."] [uri "..."]`
  - ModSecurity **审计日志分节**：`--<id>-A--`（时间 + 客户端 IP）、`-B--`（请求行 URI）、`-H--`（响应码 → blocked）、`-Z--`
  - `NAXSI_FMT:` / `NAXSI_EXLOG:` 键值行（`id0` 取规则、`block=1 && learning=0` → blocked，URI 做 URL 解码）
  - JSON 行：扁平字段，或 ModSecurity JSON 审计结构（`transaction.*` / `audit_data.messages[].details.ruleId`）
- `action`：`blocked` / `detected`；审计日志拿不到规则 ID 时 `rule_id` 留空，**不猜**。
- `since`：`1h` / `30m` / `7d` / RFC3339 / `YYYY-MM-DD`；时间不可解析的条目在带 `since` 时丢弃并计入 `skipped_unparsed`。
- `limit`：缺省 50、上限 200；超过返回 `E_INVALID`（防一次拉爆）。
- crowdsec 日志格式不同，本版不解析：返回 `error_code=E_UNSUPPORTED` + hint（`cscli alerts list`）。
- 日志存在但无读权限（如 `/var/log/modsec_audit.log` 需 root/adm）：返回 `error_code=E_NEED_ROOT` + hint，不返回空列表冒充"没有拦截"。

## 5. 配置契约

落盘 `<KORE_STATE_DIR>/config.json`（0600、原子写），优先级 **config.json > 环境变量 > 代码默认值**，逐字段合并。
保存后下一次方法调用立即生效（`restart_required=false`）。

| key | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `engine` | select | `auto` | `auto/modsecurity/naxsi/coraza/crowdsec` |
| `rules_dirs` | list(string) | `[]` | 留空用内置缺省目录；每项绝对路径 |
| `log_paths` | list(string) | `[]` | 留空用内置缺省路径；每项绝对路径 |
| `mode_config_path` | string | `""` | 留空按引擎取缺省（modsecurity: `/etc/modsecurity/kore-mode.conf`；coraza: `/etc/coraza/kore-mode.conf`） |
| `max_log_bytes` | int | `1048576` | 64 KiB–8 MiB |

环境变量兼容：`KORE_WAF_ENGINE` / `KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` /
`KORE_WAF_MAX_LOG_BYTES`；列表变量接受 JSON 数组或逗号分隔。
历史变量 `KORE_WAF_RULES_ROOT` 映射为规则目录（仅在未显式配置规则目录时生效）。

## 6. 数据面：真实 nft 规则（root 动作，ADR-0018 / ADR-0022）

kore 在自己的命名空间里建一张表，**不碰宿主的 `filter` / `nat`**（内核形状校验要求 nft 表名 `kore_` 前缀）：

```
table inet kore_waf            # 表
  set banned4  { ipv4_addr; flags interval,timeout }   # 封禁集合（支持 CIDR 与临时封禁）
  set banned6  { ipv6_addr; flags interval,timeout }
  chain input  { type filter hook input priority -10; policy accept }
```

基础防护四条规则（`enforce`）：

| 规则 | 作用 |
| --- | --- |
| `ip saddr @banned4 counter drop` | 命中封禁集合的 IPv4 丢包 |
| `ip6 saddr @banned6 counter drop` | 命中封禁集合的 IPv6 丢包 |
| `tcp flags syn tcp dport { 80, 443 } meter kore_syn4 { ip saddr limit rate over 60/second burst 120 packets } counter drop` | SYN 高频扫描限速（每源 IP 60/s，突发 120） |
| `tcp dport { 80, 443 } ct count over 200 counter drop` | 单 IP 到 80/443 的并发连接上限 200 |

`observe` 模式用同一组规则，但 verdict 换成 `counter log prefix kore-waf-*`（只计数 + 记日志，不阻断）。
阈值写死在 `info.json` 的 argv 里（argv 变了 dist sha 就变），因此**不是运行期配置项**——改阈值等于发新版本。

| action | 用途 |
| --- | --- |
| `nft-init-table` / `nft-init-set4` / `nft-init-set6` / `nft-init-chain` | 建表 / 集合 / base chain（`nft add` 对同定义幂等） |
| `nft-mode-observe` / `nft-mode-enforce` | 清链后重装四条规则（幂等） |
| `nft-flush` | 关闭防护：清链，保留表与封禁名单 |
| `nft-ban4` / `nft-ban6` | 追加参数 `{ <ip> [timeout <时长>] }` 加入封禁集合 |
| `nft-unban4` / `nft-unban6` | 追加参数 `{ <ip> }` 移除元素 |
| `nft-list` | `nft -j list table inet kore_waf`，供状态与回读校验 |

流程（`waf.toggle`）：参数/确认 → nft 与通道可用性 → 同模式短路（不提权）→ 必要时初始化 → 下发 → **回读校验**
（模式与规则条数都要对上，否则 `applied=false` + 原因）。`waf.ban` 同样是「下发 → 回读集合确认元素在」，
不把退出码 0 当成功。全部动作 `irreversible:false`：`enforce` 可回 `observe`/`off`，封禁可 `unban`。

> 0.2.0 的 `modsec-set-mode`（`sed -i` 改模式文件）已**删除**：root 执行 `sed -i <任意表达式> <任意文件>`
> 等于任意文件写、审计也看不懂改了什么（ADR-0022）。引擎自身的模式现在只**只读展示**（`waf.status`）。

## 7. 降级矩阵（无引擎 / 无 nft / 无权限）

| 场景 | status | rules | logs | toggle / ban |
| --- | --- | --- | --- | --- |
| 无任何引擎 | 引擎平面 `available=false` + `E_UNSUPPORTED` + 安装 hint；数据面照常 | 引擎 `rulesets=[]`，数据面照常 | `entries=[]` + hint | 数据面照常（与引擎解耦） |
| 无 `nft` | `backend.available=false` + 安装 hint | `nft.present=false` | 正常 | 结构化不可用（`applied=false` + hint），**不是协议错误** |
| 有 nft、无 root 通道 | `backend.channel=false` + hint | 数据面 `present=false` | 正常 | 协议错误 `E_NEED_ROOT` + `detail.hint` |
| 有通道、nft 版本不支持 meter/ct count | — | — | — | `E_UNSUPPORTED` + 原始 stderr（提示升级 nftables） |
| 引擎存在但规则目录为空 | `available=true`、`rules_count=0` + hint | `total=0` + hint | 正常 | 数据面照常 |
| 日志不可读（权限） | 正常 | 正常 | `E_NEED_ROOT` + hint | — |
| 回读不一致（中间态） | — | — | — | `applied=false` + 「规则已下发但回读不一致」 |

## 8. 测试与已验证范围（诚实披露）

```bash
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

覆盖（**含真实 nft 数据面**）：

| 层 | 文件 | 内容 |
| --- | --- | --- |
| 单元（mock 文件系统） | `internal/wafop/detect_test.go` | 四引擎检测、nginx -V 证据、版本/模式、显式引擎 + 配置目录认定、无引擎四证据 |
| 单元（构造规则文件） | `internal/wafop/rules_test.go` | SecRule 计数（含缩进/注释）、配置目录优先、Naxsi、crowdsec JSON、无引擎降级 |
| 单元（构造日志行） | `internal/wafop/logs_test.go` | ModSecurity 错误日志、审计日志分节、Naxsi、JSON、since/limit/rule_id、真实文件尾部截断、0000 权限 → `E_NEED_ROOT` |
| **单元（nft 数据面）** | `internal/wafop/nft_test.go` | 有状态 nft 假后端：初始化幂等、模式下发+回读、回读不一致不谎报、v4/v6 封禁解封、TTL 校验、**真实 `nft -j` 输出 fixture 解析**（`testdata/nft-state-enforce.json` 由隔离 netns 采集）、通道缺失/内核拒绝/语法不支持的错误映射 |
| 单元（方法面契约） | `internal/wafop/toggle_test.go` | `waf.toggle` 参数/确认/成功/回读；`waf.ban|unban|bans` 契约与参数校验 |
| 单元（降级/提权拒绝） | `internal/wafop/degrade_test.go` | 无引擎四方法、`E_NEED_ROOT` + hint、`E_UNAUTHORIZED` |
| 故障注入（四类） | `tests/fault/` | kill → `E_UPSTREAM`、timeout → `E_UPSTREAM`、disk → `E_INTERNAL`、cgroup → `E_UNSUPPORTED`；四方法逐一注入 |
| 端到端（构造真实布局） | `e2e_constructed_test.go` | 真实文件结构 + 环境变量指向：env → config → 检测 → 规则计数 → 日志解析 → `E_NEED_ROOT` |
| 配置契约 | `methods_test.go` | 默认值/source、0600 落盘、非法值不落盘不改内存、env 优先级、历史变量、热生效、reload |
| **清单 schema + 内核形状表** | `rootactions_schema_test.go` + kore `pkg/pluginapi` 的 `TestWafPluginRootActionsCrossRepo` | info.json 的 12 条 root_actions 逐条过 `ValidateRootAction`；kore 侧跨仓测试再按 ADR-0022 形状表校验一遍（含追加参数样本） |

**真实 nft 验证（隔离 netns，不碰宿主）**：用 `unshare -rn` 起独立网络命名空间，按 `info.json` 的声明 argv
逐条驱动真实 nft（1.1.6）：建表/集合/链 → 临时与永久封禁 → 重复封禁幂等 → `enforce` 四条 drop 规则 →
`observe` 四条 log-only 规则 → 解封（含解封不存在元素 exit 1）→ `nft-flush` 清链（集合保留）→ `nft -j` JSON 快照。
宿主侧 `nft list ruleset` / `iptables -S` / `ufw status` 三项 sha256 前后一致、`kore_waf` 不出现在宿主表清单里。

**未验证 / 明确不假装**：

1. 本机**没有任何运行中的 WAF 引擎**（无 modsecurity/naxsi/coraza/crowdsec、无 nginx），引擎平面仍是"构造文件 + 上游真实 CRS 规则文件"验证。
2. **`ipset` 后端未实现**：本机无 `ipset` 二进制，无法做真实验证；kore 的形状表已按固定形状放开 `ipset`
   （`create/add/del/test/list/destroy`），但插件当前只用 nft。接 ipset 前必须先补隔离验证。
3. **未在真 root kored 下跑完端到端**：本会话以非 root 用户运行，root-action 通道的拒绝路径（`E_NEED_ROOT`）已验证，
   成功路径的**内核侧**由 kore `internal/core/privilege` 的 root 集成测试覆盖（需 root 环境才执行，否则 skip）；
   插件侧 nft 命令的真实性由上面的 netns 验证覆盖。二者拼起来才等于"真 root 端到端"，本轮未在同一进程链里跑通。
4. nft 版本兼容只验证了 1.1.6；老版本缺 `meter` / `ct count` 时按 `E_UNSUPPORTED` + 原始 stderr 降级（未逐一实测旧版本）。
5. `observe` 模式的日志前缀（`kore-waf-*`）用 `nft log` 落到内核日志，本插件**不解析内核日志**（只解析引擎日志）——观察数据需配 `journalctl -k` 查看，这是已知边界。

## 9. 打包与可复现

`make dist` 使用确定性参数（`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner` + `gzip -9n` + chmod 归一），
`size_bytes` 由打包脚本从包内回填收敛；两次构建 sha256 一致，干净 clone 复现一致。

## 10. 版本历史

见 [CHANGELOG.md](CHANGELOG.md)：`0.3.0` 接真实 nft 数据面（封禁集合 / 基础防护 / observe·enforce 切换，删除 sed 写入口）；
`0.2.0` 去 noop（引擎检测 / 规则统计 / 日志解析 / 配置契约）。
