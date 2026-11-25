# kore-plugin-waf

WAF 管理插件：**引擎层**只读探测宿主已装的 WAF 引擎（modsecurity / naxsi / coraza / crowdsec）并统计规则、解析拦截日志；**数据面**由 kore 自己用 `nft` 落地封禁集合、SYN 扫描限速与单 IP 并发上限。本仓不内置任何 WAF 引擎，也不在插件进程里 exec nft：一切写操作经 root-action 通道。

- 协议：`kore.plugin.v1` · `lifecycle=lazy` · 深度等级 `basic`
- 能力：`system:read` + `system:admin`；声明 `requires_root: true` + 12 个可逆 `root_actions`
- 0.5.0 起支持宽松 / 标准 / 严格三档防护等级

## 导航

- [Installation](Installation) — 安装与构建
- [Configuration](Configuration) — 配置契约与环境变量
- [Usage](Usage) — 协议方法与数据面
- [FAQ](FAQ) — 常见问题
- [Changelog](Changelog) — 版本记录

项目主页：<https://github.com/kore-pl/kore-plugin-waf>
