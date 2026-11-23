package wafop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// modsecLogFixture 是 ModSecurity 错误日志样本（含拦截、检测、无关行）。
const modsecLogFixture = `[Wed Oct 11 14:32:00 2023] [error] [client 203.0.113.7] ModSecurity: Access denied with code 403 (phase 2). Matches "union" [file "/etc/modsecurity/crs/REQUEST-942.conf"] [line "60"] [id "942100"] [uri "/login?x=1"] [hostname "example.com"]
2026/11/23 11:59:00 [error] 12#12: *9 ModSecurity: Warning. detected [client 198.51.100.9] [id "920350"] [uri "/api/items"]
this line is unrelated
`

// modsecDetectionForLogs 返回已检测到 modsecurity 的判定。
func modsecDetectionForLogs() Detection {
	return Detection{Engine: EngineModSecurity, Found: true, Mode: ModeOn}
}

// TestLogsParseModSecurity 解析 ModSecurity 错误日志：拦截/检测动作与字段。
func TestLogsParseModSecurity(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/var/log/nginx/error.log", modsecLogFixture)
	env.addDir("/etc/modsecurity")
	settings := Settings{Engine: "auto", LogPaths: []string{"/var/log/nginx/error.log"}}
	result, err := Logs(env.env(), settings, LogsParams{})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if !result.Available || result.Engine != EngineModSecurity {
		t.Fatalf("应可用且引擎为 modsecurity，实际 %+v", result)
	}
	if result.Count != 2 {
		t.Fatalf("应解析出 2 条，实际 %d（%+v）", result.Count, result.Entries)
	}
	if len(result.Sources) != 1 || result.Sources[0].Matched != 2 || result.Sources[0].Lines == 0 {
		t.Fatalf("来源统计不正确: %+v", result.Sources)
	}
	entries := result.Entries
	if entries[0].IP != "203.0.113.7" && entries[1].IP != "203.0.113.7" {
		t.Fatalf("客户端 IP 未解析: %+v", entries)
	}
	var blocked, detected bool
	for _, entry := range entries {
		if entry.RuleID == "942100" && entry.URI == "/login?x=1" && entry.Action == "blocked" &&
			entry.IP == "203.0.113.7" && entry.Time != "" {
			blocked = true
		}
		if entry.RuleID == "920350" && entry.Action == "detected" {
			detected = true
		}
	}
	if !blocked || !detected {
		t.Fatalf("拦截/检测记录解析不完整: %+v", entries)
	}
}

// TestLogsParseNaxsi 解析 Naxsi 的 NAXSI_FMT：block=1 & learning=0 → blocked。
func TestLogsParseNaxsi(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/nginx/naxsi.rules", "MainRule \"str:select\" id:1000;\n")
	env.addFile("/var/log/nginx/error.log", strings.Join([]string{
		`2026/11/23 11:58:00 [error] 1#1: *1 NAXSI_FMT: ip=203.0.113.9&server=example.com&uri=%2Fadmin%3Fx%3D1&learning=0&vers=0.56&total_processed=1&total_blocked=1&block=1&cscore0=$SQL&score0=8&zone0=ARGS&id0=1007&method0=GET`,
		`2026/11/23 11:58:30 [error] 1#1: *2 NAXSI_FMT: ip=198.51.100.3&server=example.com&uri=/safe&learning=1&block=1&id0=1008`,
	}, "\n"))
	result, err := Logs(env.env(), Settings{Engine: "auto", LogPaths: []string{"/var/log/nginx/error.log"}}, LogsParams{})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if result.Count != 2 {
		t.Fatalf("应解析 2 条，实际 %d（%+v）", result.Count, result.Entries)
	}
	if result.Entries[0].Action == "" || result.Entries[1].Action == "" {
		t.Fatalf("动作未解析: %+v", result.Entries)
	}
	var blocked, detected bool
	for _, entry := range result.Entries {
		switch {
		case entry.RuleID == "1007" && entry.Action == "blocked" && entry.URI == "/admin?x=1":
			blocked = true
		case entry.RuleID == "1008" && entry.Action == "detected":
			detected = true
		}
	}
	if !blocked || !detected {
		t.Fatalf("Naxsi 动作/URI 解析不完整: %+v", result.Entries)
	}
}

// TestLogsParseAuditSections 解析 ModSecurity 审计日志分节（A/B/H/Z）。
func TestLogsParseAuditSections(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\n")
	env.addFile("/var/log/modsec_audit.log", strings.Join([]string{
		`--abc123-A--`,
		`[10/Oct/2023:13:14:15 +0000] 203.0.113.50 12345 10.0.0.1 80`,
		`--abc123-B--`,
		`GET /admin?id=1 HTTP/1.1`,
		`Host: example.com`,
		`--abc123-H--`,
		`HTTP/1.1 403 Forbidden`,
		`--abc123-Z--`,
	}, "\n"))
	result, err := Logs(env.env(), Settings{Engine: "auto", LogPaths: []string{"/var/log/modsec_audit.log"}}, LogsParams{})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if result.Count != 1 {
		t.Fatalf("审计日志应解析 1 条，实际 %d（%+v）", result.Count, result.Entries)
	}
	entry := result.Entries[0]
	if entry.IP != "203.0.113.50" || entry.URI != "/admin?id=1" || entry.Action != "blocked" {
		t.Fatalf("审计日志字段不正确: %+v", entry)
	}
	if entry.RuleID != "" {
		t.Fatalf("审计日志不含规则 ID，不应编造: %+v", entry)
	}
}

// TestLogsParseJSON 解析扁平与嵌套 JSON 日志。
func TestLogsParseJSON(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\n")
	env.addFile("/var/log/modsec_audit.log", strings.Join([]string{
		`{"time":"2026-11-23T11:58:00Z","client_ip":"203.0.113.11","uri":"/json","rule_id":"942100","action":"blocked"}`,
		`{"transaction":{"time_stamp":"2026-11-23T11:57:00Z","client_ip":"203.0.113.12","is_interrupted":true,"request":{"uri":"/nested"}},"audit_data":{"messages":[{"details":{"ruleId":"942200"}}]}}`,
	}, "\n"))
	result, err := Logs(env.env(), Settings{Engine: "auto", LogPaths: []string{"/var/log/modsec_audit.log"}}, LogsParams{})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if result.Count != 2 {
		t.Fatalf("应解析 2 条 JSON，实际 %d（%+v）", result.Count, result.Entries)
	}
	var flat, nested bool
	for _, entry := range result.Entries {
		if entry.URI == "/json" && entry.IP == "203.0.113.11" && entry.Action == "blocked" {
			flat = true
		}
		if entry.URI == "/nested" && entry.IP == "203.0.113.12" && entry.RuleID == "942200" && entry.Action == "blocked" {
			nested = true
		}
	}
	if !flat || !nested {
		t.Fatalf("JSON 解析不完整: %+v", result.Entries)
	}
}

// TestLogsSinceAndLimit since 过滤 + limit 截断 + 时间倒序。
func TestLogsSinceAndLimit(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\n")
	env.addFile("/var/log/modsec_audit.log", strings.Join([]string{
		`{"time":"2026-11-23T11:59:00Z","client_ip":"1.1.1.1","uri":"/new","rule_id":"1","action":"blocked"}`,
		`{"time":"2026-11-23T10:00:00Z","client_ip":"2.2.2.2","uri":"/old","rule_id":"2","action":"blocked"}`,
		`{"time":"2026-11-23T11:30:00Z","client_ip":"3.3.3.3","uri":"/mid","rule_id":"3","action":"detected"}`,
	}, "\n"))
	settings := Settings{Engine: "auto", LogPaths: []string{"/var/log/modsec_audit.log"}}
	result, err := Logs(env.env(), settings, LogsParams{Since: "1h", Limit: 1})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if result.Count != 1 {
		t.Fatalf("limit=1 应只返回 1 条，实际 %d", result.Count)
	}
	if result.Entries[0].URI != "/new" {
		t.Fatalf("since 1h 应只剩 /new 且按时间倒序，实际 %+v", result.Entries)
	}
}

// TestLogsRuleIDFilter 按 rule_id 精确过滤。
func TestLogsRuleIDFilter(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\n")
	env.addFile("/var/log/modsec_audit.log", strings.Join([]string{
		`{"time":"2026-11-23T11:59:00Z","client_ip":"1.1.1.1","uri":"/a","rule_id":"942100","action":"blocked"}`,
		`{"time":"2026-11-23T11:58:00Z","client_ip":"1.1.1.2","uri":"/b","rule_id":"920350","action":"detected"}`,
	}, "\n"))
	settings := Settings{Engine: "auto", LogPaths: []string{"/var/log/modsec_audit.log"}}
	result, err := Logs(env.env(), settings, LogsParams{RuleID: "942100"})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if result.Count != 1 || result.Entries[0].RuleID != "942100" {
		t.Fatalf("rule_id 过滤失败: %+v", result.Entries)
	}
}

// TestLogsTailTruncation 真实文件截断：只读尾部、丢弃首个残行。
func TestLogsTailTruncation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "modsec_audit.log")
	var builder strings.Builder
	builder.WriteString(`{"time":"2026-11-23T01:00:00Z","client_ip":"9.9.9.9","uri":"/first-should-be-dropped","rule_id":"1","action":"blocked"}` + "\n")
	filler := strings.Repeat("x", 1024)
	for i := 0; i < 100; i++ {
		builder.WriteString(filler + "\n")
	}
	builder.WriteString(`{"time":"2026-11-23T11:59:00Z","client_ip":"8.8.8.8","uri":"/last","rule_id":"2","action":"blocked"}` + "\n")
	if err := os.WriteFile(logPath, []byte(builder.String()), 0o644); err != nil {
		t.Fatalf("写测试日志: %v", err)
	}
	settings := Settings{
		Engine:      EngineModSecurity,
		LogPaths:    []string{logPath},
		MaxLogBytes: MinMaxLogBytes,
	}
	result, err := Logs(OSEnvironment(), settings, LogsParams{Limit: 200})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if len(result.Sources) != 1 || !result.Sources[0].Truncated {
		t.Fatalf("应发生尾部截断: %+v", result.Sources)
	}
	if result.Sources[0].Bytes > int(MinMaxLogBytes) {
		t.Fatalf("读取字节数超过上限: %d", result.Sources[0].Bytes)
	}
	for _, entry := range result.Entries {
		if entry.URI == "/first-should-be-dropped" {
			t.Fatalf("截断前的首行不应被解析: %+v", entry)
		}
	}
	found := false
	for _, entry := range result.Entries {
		if entry.URI == "/last" && entry.IP == "8.8.8.8" {
			found = true
		}
	}
	if !found {
		t.Fatalf("尾部记录应被解析，实际 %+v", result.Entries)
	}
}

// TestLogsPermissionDenied 真实文件 0000：返回 E_NEED_ROOT 而不是空数据。
func TestLogsPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "error.log")
	if err := os.WriteFile(logPath, []byte("ModSecurity: Access denied\n"), 0o000); err != nil {
		t.Fatalf("写测试日志: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0o644) })
	settings := Settings{Engine: EngineModSecurity, LogPaths: []string{logPath}}
	result, err := Logs(OSEnvironment(), settings, LogsParams{})
	if err != nil {
		t.Fatalf("权限不足不应返回协议错误: %v", err)
	}
	if result.ErrorCode != "E_NEED_ROOT" || result.Hint == "" {
		t.Fatalf("应 E_NEED_ROOT + hint，实际 %+v", result)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("不可读时不应伪造条目: %+v", result.Entries)
	}
}

// TestLogsNoEngine 无引擎：结构化不可用。
func TestLogsNoEngine(t *testing.T) {
	env := newFakeEnv()
	result, err := Logs(env.env(), Settings{Engine: "auto"}, LogsParams{})
	if err != nil {
		t.Fatalf("无引擎不应报错: %v", err)
	}
	if result.Available || result.ErrorCode != "E_UNSUPPORTED" || result.Hint == "" {
		t.Fatalf("应 available=false + E_UNSUPPORTED + hint，实际 %+v", result)
	}
	if result.Entries == nil || result.Sources == nil {
		t.Fatal("entries/sources 应为空数组而不是 null")
	}
}

// TestParseSinceFormats 校验 since 的时长/绝对时间两种口径。
func TestParseSinceFormats(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cutoff, ok, err := parseSince("2h", now)
	if err != nil || !ok || !cutoff.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("2h 解析失败: %v %v %v", cutoff, ok, err)
	}
	cutoff, ok, err = parseSince("7d", now)
	if err != nil || !ok || !cutoff.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("7d 解析失败: %v %v %v", cutoff, ok, err)
	}
	if _, _, err := parseSince("yesterday", now); err == nil {
		t.Fatal("非法 since 应报错")
	}
}
