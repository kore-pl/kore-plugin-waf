# kore-plugin-waf

WAF 插件（**基础级骨架**，depth_level=basic）：覆盖 WAF 规则集 / 拦截日志的方法面。本仓只交付协议骨架与参数校验，**不真接 ModSecurity/nginx 模块、不内置任何 WAF 二进制**（裁决 37 / 提案 §2.1 批 3）。基础级边界用例延 v1.1，核心路径可用，不标"生产级 / 开箱可用"。

## 协议面

- `kore.plugin.v1`，`lifecycle=lazy`，`depth_level=basic`
- 能力声明：`system:read`；场景标签：`sec`
- 可选前置：`site`（仅作前置串联提示；按 `PLUGIN-PROTOCOL.md` 的 `depends_on` 硬依赖语义，可选依赖不写入 `depends_on`，本插件可独立安装）
- 方法：`waf.rules` / `waf.blockLog`（同时接受裸 `rules` / `blockLog`）
- 握手的 stdout 留给协议帧，日志一律写 stderr

## 参数约束（骨架口径）

| 字段 | 规则 | 违反错误码 |
| --- | --- | --- |
| `rule_id` | 可选；非空时必须匹配 `WAF-0000`（`WAF-` + 四位数字） | `E_INVALID` |
| `limit` | 可选；0 取缺省 20，1..1000 合法，负数或 >1000 拒绝（防 DoS） | `E_INVALID` |
| `params` | 必须是 JSON 对象，不得为空或 `null` | `E_INVALID` |

规则根目录（`KORE_WAF_RULES_ROOT`，缺省 `/var/lib/kore/waf`）仅用于逻辑校验与结果回填；不读真实文件系统、不接 WAF 引擎。结果中 `applied=false`、`rules`/`entries` 为空数组，如实表示这是结构化占位而非真实数据。未知方法返回 `E_NOTFOUND`。

二进制的握手字段来自静态 `manifest.json`（`//go:embed`，不含 `size_bytes`）；`info.json` 只作包内元数据，`size_bytes` 由打包脚本回填。两者解耦，避免"改包体 → 改二进制 → 再改包体"的自指震荡。

## 基础故障注入

`tests/fault/` 覆盖 kill -9 与超时两类（基础级 8 的边界用例延 v1.1，不冒进做生产级四类）：

| 故障 | 文件 | 期望错误码 |
| --- | --- | --- |
| kill -9 | `kill_test.go` | `E_UPSTREAM` |
| 超时 | `timeout_test.go` | `E_UPSTREAM` |

每个用例对两个方法注入故障，断言 nil 结果 + 结构化错误码；`sanityNoFault` 反证无故障时正常返回，避免"永远失败"的假通过。会话测试中每个 `kore.shutdown` 请求都配对读取一次响应帧并核对 ID/ReqID。

## 构建与验收

```bash
gofmt -l . && go vet ./... && go test -timeout 200s ./...
make build && make dist
tar -tzf dist/waf-0.1.0.tar.gz | head -1   # info.json
```

`dist` 使用确定性参数归档（`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner` + `gzip -9n`，chmod 归一），重复构建 sha256 不变；`size_bytes` 由打包脚本回填。
