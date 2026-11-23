# Changelog

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
