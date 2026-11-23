## 变更说明

<!-- 这个 PR 改了什么、为什么改；一句话能说清就一句话。 -->

## 影响面

- [ ] 插件方法（新增 / 修改 / 删除）
- [ ] `info.json` / `manifest.json` 声明
- [ ] 构建脚本（`Makefile` / `dist`）
- [ ] 文档（README / CHANGELOG / 其他）
- [ ] 前端（`web/`）

## 验证

```text
命令: make check
退出码: 0
输出: （粘贴关键输出）
```

- [ ] 已贴 `make check` 的命令原文 + 退出码
- [ ] 构建产物可复现：`make dist` 连跑两次，`sha256sum dist/*.tar.gz` 逐字相同
- [ ] 未提交 `go.work` / `go.work.sum` 与跨仓 `replace`

## 版本与 CHANGELOG

- [ ] `info.json.version` / `manifest.json.version` 已同步 bump
- [ ] `CHANGELOG.md` 已按新增 / 变更 / 修复 / 破坏性记录

## 协议或能力变更

- [ ] 不涉及
- [ ] 涉及：附 kore 仓 ADR 链接，并说明兼容性（`requires_kore` 是否变化、是否升主版本）

## 关联 issue

<!-- Closes #编号 -->

## 安全影响

<!-- 是否引入新的写能力、新的外部输入、新的权限面；没有就写"无"。 -->
