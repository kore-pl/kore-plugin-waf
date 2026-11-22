# Changelog

## 0.1.1 (2026-11-23)

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## 0.1.0 (2026-11-22)

- feat: 新建 waf 插件骨架（M5 批3，depth_level=basic），复用 kore.plugin.v1 握手与会话循环
- feat: waf.rules / waf.blockLog 方法级参数校验与结构化占位结果，rule_id 限 WAF-0000 格式、limit 上限 1000 防 DoS，不接 ModSecurity/nginx 模块
- feat: 基础故障注入测试（kill -9 / 超时），验证方法级错误返回；会话测试逐帧配对 shutdown 响应
- build: 确定性打包（--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner + gzip -9n，chmod 归一）
- build: 静态 manifest.json 作 go:embed 源，info.json 只作包内元数据，避免 size_bytes 回填的自指震荡
