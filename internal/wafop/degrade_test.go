package wafop

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestNoEngineDegradation 无引擎时四个读/写方法都返回可用信息，不报协议错误。
func TestNoEngineDegradation(t *testing.T) {
	env := newFakeEnv()
	runtime := New(Options{Env: env.env(), Settings: Settings{Engine: "auto"}})

	statusRaw, perr := runtime.Call("waf.status", nil)
	if perr != nil {
		t.Fatalf("无引擎时 status 不应报错: %v", perr)
	}
	var status StatusResult
	if err := json.Unmarshal(statusRaw, &status); err != nil {
		t.Fatalf("解析 status: %v", err)
	}
	if status.Available || status.Engine != EngineNone || status.ErrorCode != pluginapi.E_UNSUPPORTED {
		t.Fatalf("status 降级字段不正确: %+v", status)
	}
	if status.Hint == "" || status.RulesCount != 0 || status.Mode != ModeOff || !status.RequiresRoot {
		t.Fatalf("status 降级信息不完整: %+v", status)
	}
	if len(status.Probed) != 4 {
		t.Fatalf("应附四条探测证据，实际 %d", len(status.Probed))
	}

	rulesRaw, perr := runtime.Call("waf.rules", json.RawMessage(`{}`))
	if perr != nil {
		t.Fatalf("无引擎时 rules 不应报错: %v", perr)
	}
	var rules RulesResult
	if err := json.Unmarshal(rulesRaw, &rules); err != nil {
		t.Fatalf("解析 rules: %v", err)
	}
	if rules.Available || rules.ErrorCode != pluginapi.E_UNSUPPORTED || rules.Hint == "" || rules.RuleSets == nil {
		t.Fatalf("rules 降级字段不正确: %+v", rules)
	}

	logsRaw, perr := runtime.Call("waf.logs", json.RawMessage(`{}`))
	if perr != nil {
		t.Fatalf("无引擎时 logs 不应报错: %v", perr)
	}
	var logs LogsResult
	if err := json.Unmarshal(logsRaw, &logs); err != nil {
		t.Fatalf("解析 logs: %v", err)
	}
	if logs.Available || logs.ErrorCode != pluginapi.E_UNSUPPORTED || logs.Hint == "" || logs.Entries == nil {
		t.Fatalf("logs 降级字段不正确: %+v", logs)
	}

	toggleRaw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr != nil {
		t.Fatalf("无引擎时 toggle 不应报协议错误: %v", perr)
	}
	var toggle ToggleResult
	if err := json.Unmarshal(toggleRaw, &toggle); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if toggle.Applied || toggle.Available || toggle.ErrorCode != pluginapi.E_UNSUPPORTED || toggle.Hint == "" {
		t.Fatalf("toggle 降级字段不正确: %+v", toggle)
	}
}

// TestBlockLogAlias blockLog 兼容别名等价于 logs。
func TestBlockLogAlias(t *testing.T) {
	env := newFakeEnv()
	runtime := New(Options{Env: env.env()})
	for _, method := range []string{"waf.logs", "logs", "waf.blockLog", "blockLog"} {
		raw, perr := runtime.Call(method, json.RawMessage(`{"limit":5}`))
		if perr != nil {
			t.Fatalf("%s 不应报错: %v", method, perr)
		}
		var result LogsResult
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("%s 结果解析失败: %v", method, err)
		}
		if result.Limit != 5 {
			t.Fatalf("%s limit 未生效: %+v", method, result)
		}
	}
}

// TestCallReject 参数非法与未知方法返回对应协议错误。
func TestCallReject(t *testing.T) {
	env := newFakeEnv()
	runtime := New(Options{Env: env.env()})
	cases := []struct {
		method string
		params string
		code   string
	}{
		{"waf.toggle", `{"mode":"banana"}`, pluginapi.E_INVALID},
		{"waf.toggle", `{}`, pluginapi.E_INVALID},
		{"waf.logs", `{"limit":201}`, pluginapi.E_INVALID},
		{"waf.logs", `{"limit":-1}`, pluginapi.E_INVALID},
		{"waf.logs", `{"since":"yesterday"}`, pluginapi.E_INVALID},
		{"waf.logs", `{"nope":1}`, pluginapi.E_INVALID},
		{"waf.logs", `{"limit":5} trailing`, pluginapi.E_INVALID},
		{"waf.rules", `{"engine":"squid"}`, pluginapi.E_INVALID},
		{"waf.exec", `{}`, pluginapi.E_NOTFOUND},
	}
	for _, c := range cases {
		result, perr := runtime.Call(c.method, json.RawMessage(c.params))
		if perr == nil || perr.Code != c.code {
			t.Fatalf("%s(%s) 错误=%v，期望 %s", c.method, c.params, perr, c.code)
		}
		if result != nil {
			t.Fatalf("%s 出错时不应带结果: %s", c.method, result)
		}
	}
}

// TestCallRejectsNonObjectParams params 必须是 JSON 对象。
func TestCallRejectsNonObjectParams(t *testing.T) {
	env := newFakeEnv()
	runtime := New(Options{Env: env.env()})
	for _, params := range []string{`[]`, `"x"`, `123`, `null`, ``} {
		if _, perr := runtime.Call("waf.logs", json.RawMessage(params)); perr != nil && perr.Code != pluginapi.E_INVALID {
			t.Fatalf("params=%q 应 E_INVALID，实际 %v", params, perr)
		}
	}
}

// TestStatusCountsRules 引擎可用时 status 汇总规则条数。
func TestStatusCountsRules(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\nSecRule ARGS \"@rx a\" \"id:1\"\n")
	env.addFile("/usr/share/modsecurity-crs/rules/a.conf", "SecRule ARGS \"@rx b\" \"id:2\"\n")
	runtime := New(Options{Env: env.env()})
	raw, perr := runtime.Call("waf.status", nil)
	if perr != nil {
		t.Fatalf("status: %v", perr)
	}
	var status StatusResult
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("解析 status: %v", err)
	}
	if !status.Available || status.Engine != EngineModSecurity || status.RulesCount != 2 {
		t.Fatalf("status 汇总不正确: %+v", status)
	}
	if status.Mode != ModeOn || !strings.Contains(status.ModeSource, "modsecurity.conf") {
		t.Fatalf("模式与来源不正确: %+v", status)
	}
}

// TestRulesEngineOverride rules 可用 engine 参数临时覆盖首选引擎。
func TestRulesEngineOverride(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/nginx/naxsi.rules", "MainRule \"str:x\" id:1;\n")
	env.addFile("/usr/lib/nginx/modules/ngx_http_naxsi_module.so", "")
	runtime := New(Options{Env: env.env(), Settings: Settings{Engine: EngineModSecurity}})
	raw, perr := runtime.Call("waf.rules", json.RawMessage(`{"engine":"naxsi"}`))
	if perr != nil {
		t.Fatalf("rules: %v", perr)
	}
	var result RulesResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 rules: %v", err)
	}
	if result.Engine != EngineNaxsi || !result.Available || result.Total != 1 {
		t.Fatalf("engine 覆盖未生效: %+v", result)
	}
}
