# kore-plugin-waf

WAF 管理插件（**L1.5 · 引擎无关 + 可降级**）：管理宿主**已安装**的 Web 应用防火墙规则与拦截日志。
本仓**不内置任何 WAF 引擎**（与 nginx 同类裁决：引擎跟随宿主 / 站点插件安装），只做检测、读取、统计、模式切换与配置管理。

- 协议：`kore.plugin.v1`，`lifecycle=lazy`，`depth_level=basic`
- 能力：`system:read` + `system:admin`（`waf.toggle` / `waf.config.set` 按方法级 capability 走 admin）
- 提权：声明 `requires_root: true` + 2 个 `root_actions`（ADR-0018），插件自身永不提权
- 场景标签：`sec`

## 1. 方法面（5 个业务方法 + 配置契约）

| 方法 | 入参 | 结果要点 |
| --- | --- | --- |
| `waf.status` | `{}` | `available / engine / version / rules_count / mode(on\|off\|detection) / error_code / hint / probed` |
| `waf.rules` | `{engine?}` | `engine / available / rulesets[{name,path,rule_count,enabled}] / total` |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | `sources[] / entries[{time,ip,uri,rule_id,action}] / count / limit / scanned_lines` |
| `waf.toggle` | `{mode, confirm?}` | `previous_mode / mode / applied / reloaded / steps[]`；无 root 通道时协议错误 `E_NEED_ROOT` |
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

## 6. 模式切换（root 动作，ADR-0018）

`info.json` 声明：

| action | argv | 用途 |
| --- | --- | --- |
| `modsec-set-mode` | `/bin/sed -i.bak`（追加 `-e <表达式> <模式文件>`） | 改写 kore 管理的模式包含文件，`.bak` 保留上一版 |
| `nginx-reload` | `nginx -s reload` | 使模式变更生效 |

流程：参数校验 → 同模式短路（不提权）→ `mode=off` 必须 `confirm=true`（否则 `E_UNAUTHORIZED`）→
无通道返回 `E_NEED_ROOT` + hint → 模式文件安全护栏（必须存在、≤64 KiB、**内容含 `SecRuleEngine`**，防止配置误指 `/etc/passwd` 被 sed 覆盖）→
经通道写入 → **回读校验**（不把退出码 0 当成功）→ reload nginx。

模式文件需要被引擎主配置 include（示例）：

```apache
# /etc/modsecurity/modsecurity.conf 末尾
Include /etc/modsecurity/kore-mode.conf
```

`/etc/modsecurity/kore-mode.conf` 初始内容：`SecRuleEngine Off`（或 `On` / `DetectionOnly`）。
`root_actions` 不标 `irreversible`：`sed -i.bak` 保留上一版可回滚、reload 可回滚；**关闭拦截**这一高风险动作由插件侧强制 `confirm` 把关。
任何一步失败返回 `applied=false` + `error_code` + `steps[]`，不谎报"已生效"。

## 7. 降级矩阵（无引擎 / 无权限）

| 场景 | status | rules | logs | toggle |
| --- | --- | --- | --- | --- |
| 无任何引擎 | `available=false` + `E_UNSUPPORTED` + 安装 hint | 同左，`rulesets=[]` | 同左，`entries=[]` | 结构化 `available=false` + `E_UNSUPPORTED`（不是协议错误） |
| 引擎存在但规则目录为空 | `available=true`、`rules_count=0` + hint | `available=true`、`total=0` + hint 让用户补规则目录 | 正常 | 按引擎能力 |
| 日志不可读（权限） | 正常 | 正常 | `E_NEED_ROOT` + hint | — |
| 有引擎、切换需要 root 但无通道 | — | — | — | 协议错误 `E_NEED_ROOT` + `detail.hint` |
| naxsi / crowdsec 请求切换模式 | — | — | — | 结构化 `E_UNSUPPORTED` + 在引擎配置里改的提示 |

## 8. 测试与已验证范围（诚实披露）

```bash
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

覆盖：

| 层 | 文件 | 内容 |
| --- | --- | --- |
| 单元（mock 文件系统） | `internal/wafop/detect_test.go` | 四引擎检测、nginx -V 证据、版本/模式、显式引擎 + 配置目录认定、无引擎四证据 |
| 单元（构造规则文件） | `internal/wafop/rules_test.go` | SecRule 计数（含缩进/注释）、配置目录优先、Naxsi、crowdsec JSON（键大小写不敏感）、无引擎降级 |
| 单元（构造日志行） | `internal/wafop/logs_test.go` | ModSecurity 错误日志、审计日志分节、Naxsi、JSON、since/limit/rule_id、真实文件尾部截断、0000 权限 → `E_NEED_ROOT` |
| 单元（降级/提权拒绝） | `internal/wafop/degrade_test.go`、`toggle_test.go` | 无引擎四方法、`E_NEED_ROOT` + hint、`E_UNAUTHORIZED`、模式文件护栏、回读校验、写入失败不谎报 |
| 故障注入（四类） | `tests/fault/` | kill → `E_UPSTREAM`、timeout → `E_UPSTREAM`、disk → `E_INTERNAL`、cgroup → `E_UNSUPPORTED`；四方法逐一注入 |
| 端到端（构造真实布局） | `e2e_constructed_test.go` | 真实文件结构 + 环境变量指向：env → config → 检测 → 模式 → 规则计数 5 → 日志解析 2 条 → `E_NEED_ROOT` |
| 配置契约 | `methods_test.go` | 默认值/source、0600 落盘、非法值不落盘不改内存、env 优先级、历史变量、热生效、reload |

**真实数据交叉验证（一次性，不随仓库提交）**：从上游 OWASP CRS `main` 下载
`REQUEST-913/920/942` 三个真实规则文件（合计 176 KB），用插件同一实现统计：

| 文件 | 朴素 `grep '^SecRule '` | 缩进感知 `grep -cE '^[[:space:]]*SecRule[[:space:]]'` | 本插件 |
| --- | --- | --- | --- |
| REQUEST-913 | 9 | 9 | 9 |
| REQUEST-920 | 68 | 105 | 105 |
| REQUEST-942 | 68 | 73 | 73 |
| 合计 | 145 | 187 | **187** |

结论：解析器与独立 grep 的缩进感知口径**逐文件一致**；朴素列首 grep 会少算 42 条（CRS 条件链缩进）。

**未验证 / 明确不假装**：

1. 本机**没有任何运行中的 WAF 引擎**（无 modsecurity/naxsi/coraza/crowdsec、无 nginx），
   引擎检测与解析用构造文件 + 上游真实 CRS 规则文件验证，**未对接运行引擎**。
2. 尝试 `docker pull owasp/modsecurity-crs:4-nginx-alpine` 验证真实发行版布局，本机镜像源不可用（拉取失败），
   故没有"真实引擎/真实发行版布局"的运行时证据。
3. `waf.toggle` 的**成功路径未在真 root + 真引擎下验证**：
   - 本机非 root（uid=1000、无有效 capability、`NoNewPrivs=1`）且无运行引擎 → 只验证了拒绝路径
     （`E_NEED_ROOT` / `E_UNAUTHORIZED`）与单测里的模拟通道成功路径；
   - 内核侧 root-action 通道已具备并装配插件 bearer 鉴权（`cmd/kored/serve_boot.go` 的 `PluginAuth`），
     但本机 `systemd-run --uid=0` 被 polkit 拒绝，无法完成端到端提权实测——需真 root + 真引擎联调后复验。
4. 深层 include 链、Apache modsecurity 的 reload、crowdsec 日志解析、规则启用/停用的真实生效性均未覆盖。

## 9. 打包与可复现

`make dist` 使用确定性参数（`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner` + `gzip -9n` + chmod 归一），
`size_bytes` 由打包脚本从包内回填收敛；两次构建 sha256 一致，干净 clone 复现一致。

## 10. 版本历史

见 [CHANGELOG.md](CHANGELOG.md)：`0.2.0` 去 noop（引擎检测 / 规则统计 / 日志解析 / 模式切换 / 配置契约）。
