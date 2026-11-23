# Changelog

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
`waf.toggle` 成功路径未在真 root + 真引擎下验证（内核侧 `Options.PluginAuth` 尚未在 `cmd/kored` 装配）。详见 README §8。

## 0.1.1 (2026-11-23)

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## 0.1.0 (2026-11-22)

- feat: 新建 waf 插件骨架（M5 批3，depth_level=basic），复用 kore.plugin.v1 握手与会话循环
- feat: waf.rules / waf.blockLog 方法级参数校验与结构化占位结果，rule_id 限 WAF-0000 格式、limit 上限 1000 防 DoS，不接 ModSecurity/nginx 模块
- feat: 基础故障注入测试（kill -9 / 超时），验证方法级错误返回；会话测试逐帧配对 shutdown 响应
- build: 确定性打包（--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner + gzip -9n，chmod 归一）
- build: 静态 manifest.json 作 go:embed 源，info.json 只作包内元数据，避免 size_bytes 回填的自指震荡
