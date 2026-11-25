# 贡献指南（CONTRIBUTING）

本仓库是 **kore** 的「WAF 插件」插件：id `waf`，生命周期 `lazy`，深度等级 `basic`，协议 `kore.plugin.v1`，`requires_kore` 为 `>=0.1.0 <0.2.0`。它独立成仓：独立版本线、独立 CI（**少触发**：push main / tag `v*` / PR / 手动，2026-11-23 策略：CI 少执行）、独立发版。日常验证用本地 `make check`；发布前跑两次 `make dist` 核对 sha 一致。内核与协议仓库 `kore` 的改动不在本仓做。

## 1. 能改与不能改

**能改**：本插件实现（Go 源码、`web/` 前端、`info.json` 声明值）、本仓文档与 `CHANGELOG.md`。

**不能改**：

- **不 import `kore/internal/*`**：内核内部包不对外，编译期即被拒绝；插件只允许 `github.com/pengtang1024/kore/pkg/pluginapi`。
- **不引入第三方依赖**：本仓只依赖 `kore/pkg/pluginapi` + 标准库。需要新依赖须先在 `kore` 仓提 ADR 进白名单（G-02），批准前不得合入本仓。
- **不提交 `go.work` / `go.work.sum` 与跨仓 `replace`**：`replace => ../kore/...` 或绝对路径禁止入库（G-17）；同仓嵌套 module 的 `replace => ./` 才允许。
- **不改 `LICENSE`**：MIT 全文与 `kore` 仓逐字相同（sha256 一致）。换许可是元数据级破坏性变更，必须先改 `kore` 仓 ADR 并同步全部仓库。

## 2. 开发环境

- Go 1.26（`go.mod` 声明 `go 1.26`）。
- 构建基线固定：`CGO_ENABLED=0`、`GOWORK=off`、`GOAMD64=v1`；产物是静态单二进制，不绑定构建机 glibc（G-16）。
- 只有本地跨仓联调才用 `go.work`（`go work init ../kore .`），**不提交**；用 `go.work` 掩盖的依赖问题会在干净检出时暴露。
- `make check` 一律 `GOWORK=off`，不要指望本地 `go.work` 在别处生效。

## 3. 构建与验证

| 命令 | 作用 |
| --- | --- |
| `make build` | 产出 `bin/waf`（静态、`-trimpath -buildvcs=false -s -w`） |
| `make check` | gofmt（有输出即失败）→ `go vet` → `go test -timeout 200s` |
| `make dist` | 打包 `dist/waf-0.5.1.tar.gz` 与同名 `.sha256` |

`make dist` 是**位级可复现**的：条目固定、mtime / owner / group / mode 全量归一、`gzip -9n`；同一源码在任意干净 clone、任意 umask 下重打包，sha256 必须逐字相同。包内首条目是 `info.json`（安装器先读它），随后是 `bin/waf` 与 `SHA256SUMS`。

## 4. 提交与 PR

- 提交信息：`type(scope): 中文描述`，type ∈ `feat` / `fix` / `perf` / `refactor` / `docs` / `test` / `chore` / `build`。
- 每个提交用 `git commit -s` 签 DCO（inbound = outbound，按 MIT 授权，无 CLA）：`Signed-off-by: 名字 <邮箱>`。
- **精确 `git add <file>`，禁止 `git add .` / `git add -A`**；提交前 `git status --short` 人工核对。
- PR 必须贴 `make check` 的**命令原文 + 退出码 + 关键输出**；没跑或没贴视为未验证。
- 改 `info.json`、方法表或 `capabilities` 时，必须同步 `CHANGELOG.md` 并说明兼容性影响：新增方法算 MINOR，改参数 / 返回值语义算破坏性。
- 破坏性协议改动必须在 `kore` 仓出 ADR 并升主版本；本仓不得单方面改协议。

## 5. 发版

1. SemVer：`MAJOR.MINOR.PATCH`。`0.x` 允许破坏性变更，但必须同时有 `kore` ADR、`CHANGELOG.md` 标 `BREAKING`、`requires_kore` 区间同步。
2. `info.json.version` 与 `manifest.json.version` **同步 bump**，`CHANGELOG.md` 记条目。
3. 打 tag `v0.5.1`（形如 `vX.Y.Z`），推 tag 触发 release 产物。
4. `make dist` 产出 `dist/waf-0.5.1.tar.gz` + `.sha256`；tag 的 release 附件就是这两个文件。
5. 发完在 `kore-plugins` 仓更新 `index/plugins.json`（`sha256` / `size_bytes` / `download_url` 与包一致）、`versions.lock.json`（追加本版本）与 `presets/*.json`（固定版本引用）。**同一 `id@version` 只允许一个 sha，任何改变 dist sha 的改动必须 bump 版本**。

## 6. 硬约束摘要

| 编号 | 约束 |
| --- | --- |
| G-17 | 三件套齐备：`info.json`（含 `depends_on` / `conflicts` / `scenario_tags` / `size_bytes` / `requires_kore` / `depth_level` / `lifecycle`）、`Makefile` 的 `dist` 目标、`CHANGELOG.md` |
| G-19 | 插件内**不写 ticker / 轮询 / 周期任务**：定时只来自内核 scheduler，插件侧用请求级 `context.WithTimeout` / `time.Timer` 并确保 `Stop()`；lazy 插件必须能真正空闲退出 |
| G-20 | 深度等级如实声明：`production` 必须有 `tests/fault/` 故障注入用例，`basic` 不得被预设标为"开箱可用" |
| capabilities | 最小化：只声明真实需要的能力（`info.json.capabilities` 即全部授权面），不占用未使用的能力 |
| socket | 插件 socket 由主壳创建、`chown kore-<id>`、权限 `0600`，只有本插件可读写；插件不得连接其他插件 socket，跨插件调用一律经内核 bus |

## 7. 安全与行为准则

- 发现漏洞**不要开公开 issue**，按 [SECURITY.md](SECURITY.md) 私下披露。
- 参与即表示同意 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- 能力声明与宿主写入面（文件、进程、网络、数据库等）按真实实现写；不得声明未实现的权限，也不得在文档里承诺未实现的能力。
