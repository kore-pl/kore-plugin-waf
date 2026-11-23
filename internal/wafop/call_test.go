package wafop

import (
	"encoding/json"
	"testing"
)

// TestBusinessVerb 方法名归一化：waf.<verb> 与裸 <verb> 都接受，blockLog 兼容到 logs。
func TestBusinessVerb(t *testing.T) {
	cases := map[string]string{
		"waf.status": "status", "waf.rules": "rules", "waf.logs": "logs",
		"waf.toggle": "toggle", "status": "status", "rules": "rules",
		"logs": "logs", "toggle": "toggle",
		"waf.blockLog": "logs", "blockLog": "logs",
	}
	for method, want := range cases {
		got, ok := businessVerb(method)
		if !ok || got != want {
			t.Fatalf("businessVerb(%q)=(%q,%v)，期望 (%q,true)", method, got, ok, want)
		}
	}
	for _, method := range []string{"waf.exec", "waf.blocklog", "rulesx", ""} {
		if _, ok := businessVerb(method); ok {
			t.Fatalf("%q 不应被接受", method)
		}
	}
}

// TestCallNilParams status/ping 之外的方法缺 params 时按空对象处理（logs/toggle 再校验必填）。
func TestCallNilParams(t *testing.T) {
	env := newFakeEnv()
	runtime := New(Options{Env: env.env()})
	if _, perr := runtime.Call("waf.status", nil); perr != nil {
		t.Fatalf("status 无参数应合法: %v", perr)
	}
	if _, perr := runtime.Call("waf.logs", nil); perr != nil {
		t.Fatalf("logs 无参数应取缺省值: %v", perr)
	}
	if _, perr := runtime.Call("waf.toggle", nil); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("toggle 缺 mode 应 E_INVALID，实际 %v", perr)
	}
}

// TestCallResultsShape 正常路径结果是显式结构（不是空壳）。
func TestCallResultsShape(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\nSecRule ARGS \"@rx a\" \"id:1\"\n")
	runtime := New(Options{Env: env.env()})
	raw, perr := runtime.Call("waf.rules", json.RawMessage(`{}`))
	if perr != nil {
		t.Fatalf("rules: %v", perr)
	}
	var result RulesResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 rules: %v", err)
	}
	if !result.Available || result.Total != 1 || len(result.RuleSets) != 1 {
		t.Fatalf("rules 结果不完整: %+v", result)
	}
	if result.RuleSets[0].Name == "" || result.RuleSets[0].RuleCount != 1 {
		t.Fatalf("规则集字段不完整: %+v", result.RuleSets[0])
	}

	logRaw, perr := runtime.Call("waf.logs", json.RawMessage(`{"limit":7}`))
	if perr != nil {
		t.Fatalf("logs: %v", perr)
	}
	var logs LogsResult
	if err := json.Unmarshal(logRaw, &logs); err != nil {
		t.Fatalf("解析 logs: %v", err)
	}
	if logs.Limit != 7 || !logs.Available {
		t.Fatalf("logs 结果不完整: %+v", logs)
	}
}

// TestCallUnknownMethod 未知方法返回 E_NOTFOUND。
func TestCallUnknownMethod(t *testing.T) {
	env := newFakeEnv()
	runtime := New(Options{Env: env.env()})
	_, perr := runtime.Call("waf.exec", json.RawMessage(`{}`))
	if perr == nil || perr.Code != "E_NOTFOUND" {
		t.Fatalf("未知方法错误=%v，期望 E_NOTFOUND", perr)
	}
}

// TestSetSettingsHotApplies config.set 语义：替换 settings 后下一次调用立即使用新目录。
func TestSetSettingsHotApplies(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/opt/waf/rules/a.conf", "SecRule ARGS \"@rx a\" \"id:1\"\n")
	runtime := New(Options{Env: env.env()})
	runtime.SetSettings(Settings{Engine: EngineModSecurity, RulesDirs: []string{"/opt/waf/rules"}})
	raw, perr := runtime.Call("waf.status", nil)
	if perr != nil {
		t.Fatalf("status: %v", perr)
	}
	var status StatusResult
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("解析 status: %v", err)
	}
	if !status.Available || status.RulesCount != 1 {
		t.Fatalf("热替换设置未生效: %+v", status)
	}
}
