# 配置契约

落盘 `<KORE_STATE_DIR>/config.json`（0600、原子写），优先级 **config.json > 环境变量 > 代码默认值**，逐字段合并；保存后下一次方法调用立即生效（`restart_required=false`）。

| key | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `engine` | select | `auto` | auto / modsecurity / naxsi / coraza / crowdsec |
| `rules_dirs` | list(string) | `[]` | 留空用内置缺省目录；每项绝对路径 |
| `log_paths` | list(string) | `[]` | 留空用内置缺省路径；每项绝对路径 |
| `mode_config_path` | string | `""` | 留空按引擎取缺省 |
| `max_log_bytes` | int | `1048576` | 64 KiB–8 MiB |

环境变量兼容：`KORE_WAF_ENGINE` / `KORE_WAF_RULES_DIRS` / `KORE_WAF_LOG_PATHS` / `KORE_WAF_MODE_CONFIG` / `KORE_WAF_MAX_LOG_BYTES`；列表变量接受 JSON 数组或逗号分隔。历史变量 `KORE_WAF_RULES_ROOT` 映射为规则目录（仅在未显式配置时生效）。

## 防护等级

`waf.toggle` 的 `level` 取 `loose` / `standard` / `strict`：分别 2 / 4 / 6 条内置规则。等级是数据面事实——`waf.status.level` / `waf.toggle.level` 从 `kore_waf` 链回读推断（规则名 → 规则特征 → 条数 2/4/6），插件或内核重启后不与事实漂移。切模式不带 `level` 时沿用链上当前等级；`off` 清链后等级归零，重开按 standard。
