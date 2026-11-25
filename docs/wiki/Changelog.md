# 版本记录

完整记录见 [CHANGELOG.md](https://github.com/kore-pl/kore-plugin-waf/blob/main/CHANGELOG.md)。最近版本：

## 0.5.2 (2026-11-25)
- 新增七语言文档、README 语言行、安全/CONTRIBUTING 工程化文件；纯文档与开源工程标准化，不改运行时行为。

## 0.5.1 (2026-11-25)
- 修复等级参数错误文案；dist 按 patch 重打（同一 id@version 只允许一个 sha）。

## 0.5.0 (2026-11-25)
- 新增 `waf.toggle.level` 三档防护等级（2/4/6 条内置规则，不新增 root 动作）；等级从链上回读；修复规则重建形态丢失（拦截模式被悄悄降级为只记录）。

## 0.4.5 (2026-11-24)
- `depth_level` 由 production 回落到 basic（如实声明：缺边界用例覆盖）。

## 0.4.4 (2026-11-23)
- 修复 `waf.rules.chain` 恒空等真机 e2e 问题。

## 0.3.0
- 接真实 nft 数据面（封禁集合 / 基础防护 / observe·enforce 切换），删除 sed 写入口。
