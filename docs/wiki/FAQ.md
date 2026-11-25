# 常见问题（FAQ）

## 本仓内置 WAF 引擎吗？

不内置。引擎层只**只读探测**宿主已装的 modsecurity / naxsi / coraza / crowdsec，统计规则、解析日志；每个引擎返回 `probed[]` 证据，不拿空结果冒充「没有引擎」。

## 写操作为什么经 root-action 而不是插件直接 exec nft？

ADR-0018 要求提权写操作走受控通道，ADR-0022 锁死命令形状。0.2.0 的 `modsec-set-mode`（`sed -i` 改任意文件）已删除——任意文件写等于任意写权限、审计也看不懂。全部 12 个 root_actions 都是 nft 语句且 `irreversible:false`。

## 没有 root 通道时能用吗？

引擎检测、规则统计、日志解析照常；写方法（`waf.toggle` / `waf.ban` 等）回 `E_NEED_ROOT` + hint，不是协议错误意义上的失败而是如实的结构化不可用。

## observe 和 enforce 的区别？

同一组规则：`observe` 的 verdict 是 `counter log prefix kore-waf-*`（只计数+记日志，不阻断），`enforce` 是 `drop`。注意 observe 日志落到**内核日志**，本插件不解析内核日志（只解析引擎日志），需配 `journalctl -k` 查看。

## 防护等级会漂移吗？

不会。`level` 从链上回读推断，不由插件内存里的配置值决定；切模式不带 `level` 时沿用当前等级；`off` 清链后归零、重开按 standard。

## 支持 ipset 吗？

不支持。`ipset` 后端未实现且已从内核形状表移除（避免零消费者的特权命令扩大攻击面）。将来真要接需先改内核形状并自带 ipset 隔离环境验证。
