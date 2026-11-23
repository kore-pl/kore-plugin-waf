# AGENTS — 本仓给 AI / agent 贡献者的约定

- 只改本仓（`kore-plugin-waf`）；内核与协议仓库 `kore` 不在本仓改。
- 协议与门禁以 `kore` 仓为准：[docs/PLUGIN-PROTOCOL.md](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-PROTOCOL.md)、[docs/PLUGIN-SDK.md](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-SDK.md)、[AGENTS.md](https://github.com/kore-pl/kore/blob/main/AGENTS.md)。
- 验证命令：`make check`（gofmt → vet → test）、`make build`；发版产物用 `make dist`。
- 只依赖 `kore/pkg/pluginapi` 与标准库；不 import `kore/internal/*`，不提交 `go.work` 与跨仓 `replace`。
- 精确 `git add <file>`，禁止 `git add .`；提交用 `git commit -s` 签 DCO。
- 提交格式：`type(scope): 中文描述`。
- 安全与凭据：漏洞走 [SECURITY.md](SECURITY.md)，不开公开 issue；不写明文口令 / token，不把密钥提交进仓库。
- 能力声明按真实实现写；不为未实现的能力写文档或占位承诺。
