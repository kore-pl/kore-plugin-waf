# kore-plugin-waf — WAF 插件

## 它做什么

WAF 管理插件（**L1.5+ · 引擎无关 + 真实 nft 数据面**）：两层职责分开——**引擎层**只读探测宿主
已装的 WAF 引擎（modsecurity / naxsi / coraza / crowdsec）并统计规则、解析拦截日志；**数据面**
由 kore 自己用 `nft` 落地（封禁集合 / SYN 扫描限速 / 单 IP 并发上限），支持 `observe`（只记录）
与 `enforce`（阻断）切换，以及宽松 / 标准 / 严格三档防护等级（0.5.0 起）。本仓**不内置任何 WAF
引擎**，也**不在插件进程里 exec nft**：一切写操作都经 ADR-0018 的 root-action 通道（ADR-0022 锁死命令形状）。

- 协议：`kore.plugin.v1`，`lifecycle=lazy`，深度等级 `basic`；能力 `system:read` + `system:admin`。
- 提权：声明 `requires_root: true` + 12 个 `root_actions`（全为 nft 语句，`irreversible:false`，都能反向操作）。
- 场景标签：`sec`；资源预算 6 MiB / 15% CPU / 16 pids。

## 方法面（10 个业务方法）

| 方法 | 入参 | 结果要点 |
| --- | --- | --- |
| `waf.status` | `{}` | 引擎平面可用性 / 版本 / 规则数 / 模式；等级；数据面 `backend` 状态 |
| `waf.rules` | `{engine?}` | 引擎规则集 + 数据面 nft 链规则（handle / verdict / 计数器） |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | 拦截日志条目与解析统计 |
| `waf.toggle` | `{mode, level?, confirm?}` | observe / enforce / off 切换与等级，写后回读校验 |
| `waf.ban` | `{ip, ttl_s?, reason?}` | 幂等封禁（v4/v6，`ttl_s=0` 永久，60–2592000） |
| `waf.unban` | `{ip}` | 解封（不在集合里也算成功） |
| `waf.bans` | `{limit?}` | 封禁列表与剩余超时 |
| `waf.rule.add` / `remove` / `toggle` | 见 README | 受控匹配器白名单，写后 `nft -j list` 回读比对，不一致即回滚 |
| `waf.config.get` / `set` | `{}` / `{values}` | 配置落盘 0600，下一次调用立即生效 |

`waf.<verb>` 与裸 `<verb>` 都接受；`waf.blockLog` 是 `waf.logs` 的兼容别名。
`name` 只允许小写字母 / 数字 / `-` / `_`（1–32），`expr` 只接受白名单匹配器（`ip saddr`、
`ip6 saddr`、`tcp dport`、`udp dport`、`ct state`、`tcp flags syn`）；参数对象严格解码，拼错字段回 `E_INVALID`。

## 引擎检测与规则计数

`engine=auto` 按 modsecurity → naxsi → coraza → crowdsec 顺序取第一个命中，每个引擎都返回 `probed[]`
证据，不拿空结果冒充"没有引擎"。显式选择引擎且配置的 `rules_dirs` / `log_paths` 存在时按用户声明的
安装路径认定可用。modsecurity / coraza 统计 `SecRule` 指令行（含缩进、排除注释与 SecAction），
naxsi 统计 `MainRule` + `BasicRule`，crowdsec 一个场景按 `rule_count=1`。`enabled` 只表示文件位于
生效目录且含有效规则，不等于已确认 include 链。

## 拦截日志

只读尾部（默认 1 MiB，可配 64 KiB–8 MiB），解析 ModSecurity 错误日志 / 审计日志分节、Naxsi
`NAXSI_FMT` / `NAXSI_EXLOG`、JSON 行。`action` 为 `blocked` / `detected`；拿不到规则 ID 时留空
不猜。`since` 支持 `1h` / `30m` / `7d` / RFC3339 / `YYYY-MM-DD`，无法解析的条目在带 `since` 时
丢弃并计入 `skipped_unparsed`；`limit` 缺省 50、上限 200。日志不可读回 `E_NEED_ROOT` + hint，
不返回空列表冒充"没有拦截"；crowdsec 日志格式本版不解析，回 `E_UNSUPPORTED`。

## 数据面：真实 nft 规则

kore 在自己的命名空间建 `table inet kore_waf`，不碰宿主 `filter` / `nat`：两个封禁集合
（`banned4` / `banned6`，支持 CIDR 与 timeout）与挂在 input 的 base chain。基础防护四条
（enforce）：封禁集合 drop（v4/v6）、SYN 高频扫描限速（60/s 突发 120）、单 IP 并发上限 200；
observe 用同组规则但 verdict 换成 `counter log`（只计数记日志）。等级在同一模式下调整覆盖面：
`loose` 2 条（只有封禁名单）、`standard` 4 条（缺省）、`strict` 6 条（追加畸形连接丢弃与 SSH 暴破限速）。
等级与模式从链上回读推断，**不新增 root 动作**；切模式不带 `level` 时沿用当前等级，`off` 清链
后等级归零、重开按 standard。

流程（`waf.toggle`）：参数/确认 → nft 与通道可用性 → 同模式同等级短路 → 必要时初始化 → 下发规则
→ 回读校验（模式、等级与规则条数都对上才 `applied=true`）。全部动作 `irreversible:false`：
`enforce` 可回 `observe`/`off`，封禁可 `unban`。0.2.0 的 `modsec-set-mode`（`sed -i` 改模式文件）
已删除——任意文件写等于任意写权限，审计也看不懂改了什么。

## 配置契约

落盘 `<KORE_STATE_DIR>/config.json`（0600、原子写），优先级 **config.json > 环境变量 > 代码默认值**，
逐字段合并，保存后下一次调用立即生效（`restart_required=false`）。字段：`engine`(auto)、
`rules_dirs`([])、`log_paths`([])、`mode_config_path`("")、`max_log_bytes`(1048576)。环境变量兼容
`KORE_WAF_ENGINE` / `KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` /
`KORE_WAF_MAX_LOG_BYTES`；历史变量 `KORE_WAF_RULES_ROOT` 映射为规则目录。

## 降级与诚实边界

无引擎时引擎平面回 `E_UNSUPPORTED` + 安装 hint，数据面照常；无 `nft` 时
`backend.available=false`；有 nft 无 root 通道时 `E_NEED_ROOT`；回读不一致时 `applied=false` +
原因。未验证项如实披露：本机无运行中的 WAF 引擎；`ipset` 后端未实现且已从内核形状表移除；
未在真 root kored 下跑完端到端（拒绝路径已验证，成功路径由内核侧 root 集成测试覆盖）；
nft 只验证 1.1.6；observe 日志落在内核日志，本插件不解析。

## 安装与验证

```sh
gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test -timeout 200s ./...
make build && make dist
```

`make dist` 确定性打包（条目固定、mtime/owner/mode 归一、`gzip -9n`），两次构建 sha256 一致。
发布产物 `dist/waf-<版本>.tar.gz` + `.sha256`。漏洞不要开公开 issue，按
[SECURITY.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/SECURITY.md) 私下披露。
