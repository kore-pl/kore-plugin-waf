# 安全漏洞披露

本文件是**本插件仓（`kore-plugin-waf`）的漏洞披露流程**，不是安全设计文档。

## 范围

覆盖：`WAF 插件`（id `waf`）的实现、`info.json` 的能力声明、`web/` 前端与 `make dist` 产物。

不覆盖：内核与协议问题——请按 [kore SECURITY.md](https://github.com/kore-pl/kore/blob/main/SECURITY.md) 报告；第三方依赖上游的已知漏洞请同时反馈上游。

## 支持版本

| 版本 | 支持状态 | 说明 |
| --- | --- | --- |
| `0.3.1`（当前最新） | ✅ 接收并修复 | 只对最新补丁版本提供安全修复 |
| 更早的 `0.x` 版本 | ❌ 不支持 | 请先升级到最新版本 |

0.x 阶段按最小支持面处理：同一 minor 的最新补丁版本获得修复，旧补丁版本不单独回补。

## 本仓攻击面

- **RPC 方法**：`waf.*` 全部方法（方法表见 `README.md`），参数校验缺失会导致越权或注入。
- **capabilities**：`info.json.capabilities` 即本插件的全部授权面；多声明一项就是多一条攻击路径。
- **独立进程与 UDS**：插件以独立进程运行，socket 由主壳创建、`chown kore-<id>`、权限 `0600`；绕过 socket 权限或连接他人 socket 都属漏洞。
- **宿主写入面**：按 `capabilities` 实际授予的写能力（文件 / 进程 / 网络 / 数据库等），越出声明范围的写入属漏洞。
- **前端**：`web/` 在独立 origin iframe 内运行，通过 postMessage 与主壳通信；XSS、消息伪造或跨插件数据读取都属安全边界问题。

## 报告

1. **优先 GitHub Security Advisory**：本仓 Security 页 → "Report a vulnerability"（私密渠道，不产生公开 issue）。
2. **备用邮箱**：`pengtang1024@users.noreply.github.com`，主题 `[kore security] waf`。
3. **不要开公开 issue、不要在讨论区或 PR 里贴 PoC。**
4. 报告请包含：受影响版本、复现步骤或 PoC、影响面判断、是否已公开、署名偏好。

## 时限与披露

- **72 小时内**确认收到并给初判；复杂问题同步排查计划。
- 修复后协调披露，默认 **90 天**窗口；若已被实际利用需要提前披露，请先沟通。
- 修复发布后在 `CHANGELOG.md` 记安全修复（不写利用细节），并按需发布安全公告。

## 致谢

在获得同意后于发布说明中致谢；不希望具名的按匿名处理。
