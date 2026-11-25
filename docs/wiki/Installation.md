# 安装与构建

独立 Go 模块，只依赖 `kore/pkg/pluginapi` 与标准库，不引入第三方依赖、不提交 `go.work` 与跨仓 `replace`。Go 1.26。

```sh
git clone https://github.com/kore-pl/kore-plugin-waf.git
cd kore-plugin-waf
make build          # 产出 bin/waf
make check          # gofmt → go vet → go test
make dist           # 产出 dist/waf-<版本>.tar.gz + .sha256
```

构建基线：`CGO_ENABLED=0 GOWORK=off GOAMD64=v1 -trimpath -buildvcs=false -ldflags="-s -w"`。产物是静态单二进制。`make dist` 位级可复现（条目固定、mtime/owner/group/mode 归一、`gzip -9n`），同一源码两次打包 sha256 一致。

## 提权前置

数据面写操作需要宿主提供 ADR-0018 的 root-action 通道（声明 `requires_root: true`、12 个 nft 语句 root_actions，全部 `irreversible:false`）。没有通道时 `waf.toggle` / `waf.ban` 等写方法回 `E_NEED_ROOT` + hint，不会静默成功。nft 需要 1.1.6 及以上（老版本缺 meter / ct count 时回 `E_UNSUPPORTED` + 原始 stderr）。
