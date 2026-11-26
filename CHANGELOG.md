## 0.5.4 — 2026-11-26

### 修复（安全正确性 · 规则复活）

- **显式 `waf.rule.remove` 真删 registry**：此前 `applyRuleRemove` 只删 nft 数据面规则、保留进程内 registry 条目，用户删除自定义规则后再启停任意内置规则会触发 `rebuildChain` 从 registry 重放，把已删规则重新装回（防护策略与用户意图不符）。现按现成形参分流：显式 remove 成功后 `forgetCustom(name)` 清 registry（之后 `rule.toggle enabled=true` 报 `E_INVALID` 未知自定义规则）；内置规则的 toggle off 仍保留 registry，`toggle on` 可原 expr 恢复。
- **回归断言**：`tests/e2e/rule_e2e_test.go` 在 remove→内置 toggle off/on 后，用独立 `nft -j` 回读断言链里不含已删规则，并断言再次 toggle on 返回 `E_INVALID`。真机（私有 netns + nftables 1.1.6）修复前复现复活、修复后不复活均有证据。
- 版本 bump 原因：二进制行为变更会改变 dist 包 sha；同一 `id@version` 只允许一个 sha（RELEASE §1），按 patch 递增。

## 0.5.3 — 2026-11-26

### 修复（文案 / 易用性）

- **参数对象错误文案**：`decodeStrict` 的 `缺少必填参数对象` 改为 `请传入参数对象 params（不能为空或 null）`，满足 G-33 A3「invalid 文案给可操作提示」；仅改错误提示字面量，不改校验逻辑与协议。
- 版本 bump 原因：文案改动会改变二进制与 dist 包 sha；同一 `id@version` 只允许一个 sha（RELEASE §1），按 patch 递增。

## 0.5.2 — 2026-11-25

### 新增（开源工程标准化）

- **文档本地化**：新增 `locale/zh.json` 与 `en/es/fr/de/ru/pt.json` 七语言元数据，以及 `docs/DETAIL.md` 与六个忠实译文；README 顶部加七语言切换行（简体中文优先、指向 DETAIL 文档），三者一一对应、无死链，全部 JSON 通过语法校验。仅 zh/en/es/fr/de/ru/pt 七种语言，无日语与 `ja` 文件。
- **贡献与分支模型**：`CONTRIBUTING.md` 增补 Git Flow 分支模型（main/develop 长期分支、feature/fix/release/hotfix 短期分支 kebab-case 命名、release/hotfix 双向 `--no-ff` 合流、不 force push / rebase / push 分支）与 SSH 签名 tag 约定。
- **安全基础设施**：新增 `.github/dependabot.yml`（gomod / github-actions / npm，每周）与 `.github/CODEOWNERS`（`* @kore-pl`）；通过 `gh api` 开启 vulnerability-alerts / automated-security-fixes / secret scanning / push protection 并回读核验（开不了的功能如实报告）。
- **社区提示**：README 开源区新增中文自然的 ⭐ Star 求取提示。
- 版本 bump 原因：本轮为纯文档 / 工程化变更，不改运行时行为、`info.json` 版本与 dist 包体内容；按 patch 递增并打签名 tag `v0.5.2`，历史 tag 不动、不推送。

## 0.5.1 — 2026-11-25

### 修复（文案 / 发版一致性）

- **等级参数错误文案**：`level=xxx 非法` 补「请传 loose / standard / strict 之一（不传按 standard）」，
  满足 G-33 A3「invalid 文案给可操作提示」。
- 版本 bump 原因：0.5.0 的 dist 已按上一提交打包，文案改动会改变二进制与包 sha；
  同一 `id@version` 只允许一个 sha（RELEASE §1），因此按 patch 递增重打。

## 0.5.0 — 2026-11-25

### 新增（防护等级 · 对标宝塔/1Panel 的 WAF 等级与规则可见可管）

- **`waf.toggle.level`：宽松 / 标准 / 严格 三档防护等级**。等级在**同一模式**下调整内置防护覆盖面：
  `loose` 只留封禁名单 2 条、`standard` 现有 4 条、`strict` 追加 `ct state invalid counter drop`
  与 SSH 暴破限速（`tcp dport 22`，每源 10/min 突发 20），共 6 条。
  **不新增 root 动作**（协议单插件上限 16 条已用满）：等级复用 `nft-add-rule` / `nft-delete-rule`，
  仍是同一条受控通道 + 同一条审计链（ADR-0018 / ADR-0022）。
- **`waf.status.level` / `waf.toggle.level` 从链上回读推断**：先按规则名，其次按规则特征 token，
  最后按条数 2/4/6 兜底——等级是数据面事实而非配置值，插件或内核重启后不会与事实漂移。
- **切模式沿用当前等级**：`waf.toggle` 不带 `level` 时不改变等级；`off` 清链后等级归零，重新开启按标准。

### 修复（规则重建的形态丢失）

- **拦截模式重建会悄悄降级成只记录**：`waf.rule.toggle` 的 `rebuildChain` 固定使用观察模式 token
  （`counter log`），在 `enforce` 模式下停用/启用任一内置规则都会把整链变成只记录——现在按**当前模式与
  等级**重装（模式/等级由最近一次成功下发记录，缺失时从链回读推断）。
- **内置规则模板参数残缺**：`builtinRules` 的 `syn-rate` / `conn-rate` token 缺 `meter ... limit rate`
  与 `ct count over N` 参数，重建后会把「限速规则」装成全量日志规则；本次按 `info.json` 的 argv 逐 token 对齐，
  并补 `EnforceTokens`（拦截模式 drop / 观察模式 log）。
- **`ct count` 链识别补老形态**：除 `"ct count"` 对象，也接受摊平成 `ct` / `count` 两个 token 的输出，
  避免内建规则在某些 nft 版本上回读不出名字（等级判定与宽松降级依赖该识别）。

### 测试

- 新增 `internal/wafop/level_test.go`：等级归一与非法值、`LevelFromChain` 表驱动（含自定义规则不干扰）、
  严格 / 宽松真实下发路径（6 / 2 条 + 回读校验 + `nft-add-rule` / `nft-delete-rule` 调用）、
  切模式沿用等级、`waf.status` 报告等级。
- `fakeNft` 改为按 token 渲染 `nft -j` 规则结构（此前只有 verdict，等级与内置识别无从测起），
  并模拟 `nft-add-rule` / `nft-delete-rule`；幂等断言从「回读次数」改为「不得再下发写动作」。

## 0.4.5 — 2026-11-24

### 元数据（depth_level 校正，非功能变更）

- **`depth_level` 由 `production` 回落到 `basic`**（`info.json`，依据 `PLUGIN-CATALOG.md` §6.1 升级判据）：
  升 `production` 需**两条都满足**——①边界用例覆盖（异常输入 / 并发 / 权限不足 / 资源耗尽各 ≥1 例并进 CI）
  ②故障注入通过。本仓 `tests/fault/` 四类故障注入真实 PASS（②达成），但 `tests/boundary/` 不存在、
  `grep -rn "t.Parallel" tests/` 0 命中，①无证据 → 原 `production` 属单维度达标的**过度声明**，
  索引的 `basic` 才是正确值。
- **不是降级缺陷**：零代码变更，`nft` 命令面 / 规则链 / 故障矩阵均未改；边界用例与高级配置延 v1.1。
- 版本 bump 原因：`info.json` 在 dist 包体内，改元数据即改变包 sha，必须 bump（RELEASE §1）。

## 0.4.4 — 2026-11-23

### 修复（真机 e2e 抓出的 P1 / P3）

- **P1 · `waf.rules.chain` 恒为 `null`**：`internal/wafop/types.go` 声明了 `Chain []ChainRule`，
  但 `ListRules` 从不赋值，`waf.rules` 的 `chain` 永远返回空——UI 拿到空数组后走 `nft.rules`
  降级分支，「内置」徽标与内置行的删除按钮禁用**永不生效**（用户看不到哪条是内置的，点了才被后端 400 拦）。
  现在 `ListRules` 接受可选 root-action 通道并回读 `kore_waf input` 链，`chain[]` 带 `builtin` 布尔
  （内置 4 条用既有特征识别：`@banned4` / `@banned6` / `kore_syn4` / `ct count`）。
  **复用** 0.4.3 修好的三层解析 `parseChainRules`（`rule.comment` → `expr[].comment` → 特征识别），
  没有第二套解析实现；`nft.rules[]` 降级字段保留，老路径不受影响。
  chain 与引擎解耦：宿主没装 WAF 引擎时照样有值；数据面不可用时降级为空数组而不是打挂引擎规则集。
- **P3 · 回读链里自定义规则 `expr` 为空串**：`rule.add` / `rule.remove` / `rule.toggle` 返回的
  `chain[]` 中自定义规则只有 name/action，`expr` 是 `""`（前端显示空白行）。现在按 nft `-j` 的
  `expr[]` 反解出可读匹配条件（`ip saddr 10.20.0.0/16`、`tcp dport 8443`、`tcp dport { 80, 443 }`），
  支持 payload 匹配 / `ct count over N` / 集合 / CIDR；认不出的结构以 `raw:{...}` 保留原文，
  **绝不返回空串**；新增 `expr_tokens`（原始 token 数）便于核对是否完整反解。
- 测试：用本机 nft 1.1.6 在私有 netns（`unshare -rn`）采集的真实 `nft -j list table inet kore_waf`
  输出做 fixture（`internal/wafop/testdata/nft-list-116-mixed.json`：4 条内置 + 2 条自定义），
  断言 `chain` 长度 == nft 规则数、内置 4 条 `builtin=true`、自定义规则 `expr` 非空且带 token 数。

## 0.4.3 — 2026-11-23

### 修复（已发版缺陷）

- **nft JSON comment 解析**：`nft -j list table` 在 nft 1.1.x 上把 `comment "kore-rule-<name>"`
  放在 **rule 对象顶层**（`"comment":"kore-rule-x"`），0.4.1/0.4.2 只扫 `expr[]`，导致
  `waf.rules.chain` 恒为空、`waf.rule.add` 写后回读必失败并回滚——**已发版功能「新增规则」在 nft 1.1.x 上 100% 失败**。
  现在三层兜底：① `rule.comment` ② `expr[].comment` ③ 都没有视为非 kore 规则跳过；
  动作识别改为「键存在即动作」（nft 用 `null` 表示 drop/accept）。
- **内置规则识别**：4 条内置规则没有 comment，改用 expr 特征（`@banned4` / `@banned6` / `kore_syn4` / `ct count`）
  识别并标 `builtin=true`，UI 才能同时列出内置与自定义规则。
- **静默空兜底**：JSON 里有规则对象、却一条 kore 规则都没解析出来时返回 `E_UPSTREAM` 并附原始输出片段，
  不再静默当成「没有规则」。
- 测试：用本机 nft 1.1.6 的**真实 `-j` 输出**做 fixture（`internal/wafop/testdata/nft-list-116*.json`），
  覆盖内置+自定义混合、只有内置、comment 缺失、非目标 chain、空表、解析兜底。

# Changelog

## 0.4.2 (2026-11-23)

- test: 新增 `TestMethodCapabilitiesCoverBusinessVerbs`（method_capabilities 一致性表：声明 ⊆ 实现、反向断言、条数相等、取值在允许能力集合内、info/manifest 版本一致），满足 PLUGIN-MATURITY §3.5 #12
- 说明：0.4.1（`201635ab…` / 2934045）发布进行中、**作废不改**；测试会改变 dist，故按 RELEASE §0 升 0.4.2


## 0.4.1 (2026-11-23)

- build(deps): `pluginapi v0.1.3 → v0.1.5`（v0.1.5 含 ADR-0022 增补的两条 nft 受控形状）；**干净依赖下 `TestInfoJSONRootActionsSchema` 与 `TestMethodCapabilitiesCoverBusinessVerbs` 真绿**（不再依赖本地 replace）
- test: 补 `toggle 幂等`、`回读不一致触发回滚`、`内置 toggle 允许` 三条用例（过渡期已在本地 replace 下验证，本版在 v0.1.5 真模块下复核）
- 说明：0.4.0 未发版（tag/release 均未创建），直接以 0.4.1 发布；require 变化必然改变 dist sha，符合 RELEASE §0
- 已知：`size_bytes` 与包体实际字节数可能差 1–2 字节（Makefile 固定点问题，另行系统性修复；本版如实记录、不改 description 凑数）


## 0.4.0 (2026-11-23)

- feat(protocol): 新增 `waf.rule.add` / `waf.rule.remove` / `waf.rule.toggle`——在 kore 自有 `table inet kore_waf` 的 input 链上增删/启停规则；参数 `{name, expr, action, enabled}`，结果回带写后回读的 `chain[]`
- feat(protocol): `waf.rules` 增 `chain[]: {name, expr, action, enabled, builtin, handle}`，内置 4 条基础防护 `builtin=true`
- feat(safety): expr 只接受受控匹配器白名单（`ip saddr` / `ip6 saddr` / `tcp dport` / `udp dport` / `ct state` / `tcp flags syn`），值逐项校验；其余 `E_UNSUPPORTED` + hint（含 `; flush ruleset` / `include` / 任意 nft 语法）
- feat(safety): 每条规则带 `comment kore-rule-<name>`，写后 `nft -j list` 回读比对；不一致返回 `E_UPSTREAM` 并回滚（按 comment 反查 handle 删除）
- feat(safety): 内置 4 条规则不可删除（`E_INVALID`「内置规则只能停用不能删除」），只能 toggle；toggle 幂等
- feat(protocol): 新增 root_actions `nft-add-rule`（固定头 + 受控表达式追加，≤28 token、单语句）与 `nft-delete-rule`（handle 正整数），形状由内核 RootCommandPolicies（ADR-0022 增补）二次兜底
- test: 白名单/注入拒绝、内置删除拒绝、action 仅 drop|accept、name 收紧、回读/回滚路径
- **依赖**：内核形状在 kore `48a9bbe`；插件 `go.mod` 仍 require `pluginapi v0.1.3`，待 SDK 发布含新形状的版本后 `TestInfoJSONRootActionsSchema` 才能在干净依赖下通过（本地以 replace 指向 kore 工作树验证全绿）


## 0.3.1 (2026-11-23)

### Changed

- 提升为 `production` 深度等级（故障注入测试已覆盖）

## 0.3.0 (2026-11-23)

从「引擎无关管理」升级为**真实 nft 数据面**（L1.5 → L2 方向），并删除危险的 `sed` 写入口。

- feat: **nft 数据面**——kore 自有 `table inet kore_waf`（`banned4`/`banned6` 封禁集合 + 挂在 input 的 base chain），
  基础防护四条规则：封禁集合 drop、IPv6 封禁、SYN 高频扫描限速（每源 60/s 突发 120）、单 IP 并发连接上限 200
- feat: `waf.toggle {mode: observe|enforce|off}` 重写——模式 = **规则集形态**：observe 只 `counter log` 不阻断，
  enforce `counter drop`，off 清链（保留表与封禁名单）；下发后**回读校验**模式与规则条数，不一致 `applied=false`
- feat: `waf.ban {ip, ttl_s?, reason?}` / `waf.unban {ip}` / `waf.bans {limit?}`——IP/CIDR 封禁走 nft 集合，
  临时封禁用集合 `timeout` 标志；全部幂等（重复封禁、解封不存在元素都不报错），写入后回读确认
- feat: `waf.status` 增 `backend{tool,available,channel,table,chain,present,mode,banned_count,rules_count}`——
  引擎平面（只读探测）与数据面（可写）分开报；`waf.rules` 增 `nft{...rules,bans}` 展示真实规则与计数器
- **fix(security)**: 删除 `modsec-set-mode`（`/bin/sed -i` 改模式文件）与 `nginx-reload` 两个 root 动作。
  前者以 root 执行「任意 sed 表达式 + 任意文件路径」= 任意文件写，审计也看不出改了什么；
  引擎模式现在只做只读展示。对应内核侧 ADR-0022（命令 + 子命令 + 参数形状三级校验）
- feat: `info.json` 改为 **12 条 nft root_actions**（init table/set4/set6/chain、mode observe/enforce、flush、
  ban4/ban6、unban4/unban6、list），全部 `irreversible:false`（都能反向操作）；`method_capabilities`
  补全 7 个业务方法（读 `system:read`，`ban`/`unban`/`toggle`/`config.set` 为 `system:admin`）
- refactor: `RootActionFunc` 返回结构化 `RootActionOutput{stdout,stderr,exit_code}`——退出码非 0 是命令结果而非
  协议错误，`waf.toggle` 能据此区分「对象不存在」「语法不支持」「权限拒绝」
- test: nft 假后端（有状态）+ 真实 `nft -j` 输出 fixture（隔离 netns 采集）+ 方法面契约；故障注入四类覆盖新方法
- build: 版本 0.2.0 → 0.3.0（feat + 破坏性方法语义变更 → minor）
- deps: **需要内核/SDK 侧的受控命令形状表（ADR-0022），即 `pkg/pluginapi ≥ v0.1.3`**。本仓 `go.mod` 当前钉
  `v0.1.2`，该版本的白名单只有旧的 8 个命令，因此 `TestInfoJSONRootActionsSchema`（读 info.json 的 12 条
  `root_actions` 调 `ValidateRootAction`）会**显式 skip** 并打印需要的版本；`v0.1.3` 发布后把 require 升上去，
  该测试自动转为真跑。SDK 版本未跟上期间，清单的字段级约束由 `TestInfoJSONRootActionsLocalSchema` 兜底，
  形状校验由内核侧 `pkg/pluginapi` 的 nft 形状夹具覆盖。内核侧若尚未包含形状表（即提交晚于
  `kore@f086312`），插件启用时 `nft-*` 动作会以 `E_INVALID` 被拒——此时插件按降级矩阵返回
  「数据面不可用 + hint」，不会静默成功。

**已验证 / 未验证（诚实披露）**：真实 nft（1.1.6）在 `unshare -rn` 隔离 netns 里按 info.json 的声明 argv 跑通
建表/集合/链 → 封禁（v4/v6/超时）→ enforce/observe 切换 → 解封 → 清链 → JSON 快照，宿主
`nft list ruleset` / `iptables -S` / `ufw status` 前后 sha256 一致；未在真 root kored 下完成端到端（本会话非 root），
`ipset` 后端未实现（本机无 ipset 二进制），引擎平面仍无运行中的真实引擎。详见 README §8。

## 0.2.0 (2026-11-23)

去 noop：从「结构化占位」升级为**引擎无关 + 可降级**的真实 WAF 管理（L1.5）。

- feat: `waf.status` 检测 modsecurity / naxsi / coraza / crowdsec（配置文件、模块文件、`nginx -V`、`cscli version` 多证据），返回 `available/engine/version/rules_count/mode/error_code/hint/probed`；无引擎时 `available=false` + `E_UNSUPPORTED` + 安装建议，不报协议错误
- feat: `waf.rules` 扫描 `/etc/modsecurity/*.conf`、`/usr/share/modsecurity-crs/rules/*.conf`、naxsi `MainRule/BasicRule`、`cscli scenarios list -o json`；统计 `SecRule` 指令行（行首缩进正确计数，注释/`SecAction` 不计）
- feat: `waf.logs` 只读日志尾部（默认 1 MiB，64 KiB–8 MiB 可配），解析 ModSecurity 错误日志、审计日志 A/B/H/Z 分节、NAXSI_FMT/EXLOG、JSON 行；支持 `since`（1h/30m/7d/RFC3339）、`rule_id` 过滤，上限 200 条
- feat: `waf.toggle` 切换 `on/detection/off`：`mode=off` 强制 `confirm=true`；无 root 通道返回 `E_NEED_ROOT` + hint；经 ADR-0018 root-action 通道写入模式文件并**回读校验**、reload nginx，任何一步失败 `applied=false` 不谎报
- feat: 模式文件安全护栏（必须存在、≤64 KiB、内容含 `SecRuleEngine`，防止误指 `/etc/passwd` 被 sed 覆盖）；`sed -i.bak` 保留上一版
- feat: `waf.config.get/set` 配置契约（engine/rules_dirs/log_paths/mode_config_path/max_log_bytes），0600 原子写、逐字段 `file > env > default`、保存即热生效（`restart_required=false`）；兼容 `KORE_WAF_*` 与历史 `KORE_WAF_RULES_ROOT`
- feat: `info.json` 声明 `requires_root: true` + `root_actions`（`modsec-set-mode` / `nginx-reload`）与方法级 capability（读方法 `system:read`，`toggle`/`config.set` 为 `system:admin`）
- feat: 故障注入扩到生产级四类（kill / timeout / disk / cgroup），四个方法逐一注入；新增构造真实文件布局的端到端验证（env → config → 检测 → 规则 → 日志）
- refactor: `waf.blockLog` 更名为 `waf.logs`，保留 `blockLog` 兼容别名；规则/日志参数改为严格解码（未知字段 `E_INVALID`）
- build: 版本 0.1.1 → 0.2.0（feat → minor）

**已验证 / 未验证（诚实披露）**：本机无任何运行中的 WAF 引擎，检测与解析用构造文件 + 上游 OWASP CRS 真实规则文件验证
（缩进感知口径 187 条，与独立 grep 逐文件一致）；docker 拉取 modsecurity 镜像失败，未获得真实发行版布局证据；
`waf.toggle` 成功路径未在真 root + 真引擎下验证（本机非 root、polkit 拒绝 `systemd-run --uid=0`）。详见 README §8。

## 0.1.1 (2026-11-23)

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## 0.1.0 (2026-11-22)

- feat: 新建 waf 插件骨架（M5 批3，depth_level=basic），复用 kore.plugin.v1 握手与会话循环
- feat: waf.rules / waf.blockLog 方法级参数校验与结构化占位结果，rule_id 限 WAF-0000 格式、limit 上限 1000 防 DoS，不接 ModSecurity/nginx 模块
- feat: 基础故障注入测试（kill -9 / 超时），验证方法级错误返回；会话测试逐帧配对 shutdown 响应
- build: 确定性打包（--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner + gzip -9n，chmod 归一）
- build: 静态 manifest.json 作 go:embed 源，info.json 只作包内元数据，避免 size_bytes 回填的自指震荡
