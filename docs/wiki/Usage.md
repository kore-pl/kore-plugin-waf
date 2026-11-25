# 使用

## 协议方法（10 个业务方法）

| 方法 | 入参 | 结果要点 |
| --- | --- | --- |
| `waf.status` | `{}` | 引擎平面 + 等级 + 数据面 backend 状态 |
| `waf.rules` | `{engine?}` | 引擎规则集 + 数据面 nft 链规则 |
| `waf.logs` | `{limit?, since?, rule_id?, engine?}` | 拦截日志条目（尾部读取） |
| `waf.toggle` | `{mode, level?, confirm?}` | observe/enforce/off 切换 + 等级，写后回读校验 |
| `waf.ban` | `{ip, ttl_s?, reason?}` | 幂等封禁（v4/v6，ttl 永久或 60–2592000） |
| `waf.unban` | `{ip}` | 解封（不在集合里也算成功） |
| `waf.bans` | `{limit?}` | 封禁列表与剩余超时 |
| `waf.rule.add` / `remove` / `toggle` | 见 README | 受控匹配器白名单，写后回读，不一致即回滚 |
| `waf.config.get` / `set` | `{}` / `{values}` | 配置读写 |

`waf.<verb>` 与裸 `<verb>` 都接受；`waf.blockLog` 是兼容别名。参数对象严格解码，拼错字段回 `E_INVALID`。

## 数据面：真实 nft 规则

kore 在自己的命名空间建 `table inet kore_waf`，不碰宿主 `filter` / `nat`：两个封禁集合 `banned4` / `banned6`（支持 CIDR 与 timeout）+ 挂 input 的 base chain。基础防护四条：封禁集合 drop、SYN 扫描限速（60/s 突发 120）、单 IP 并发上限 200；observe 模式 verdict 换成 `counter log`。strict 再加畸形连接丢弃与 SSH 暴破限速。

流程：参数/确认 → nft 与通道可用性 → 同模式同等级短路 → 初始化 → 下发规则 → 回读校验（模式、等级、条数都对上才 `applied=true`）。全部动作可反向：`enforce` 可回 `observe`/`off`，封禁可 `unban`。
