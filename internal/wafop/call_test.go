package wafop

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestBusinessVerb 方法名归一化：waf.<verb> 与裸 <verb> 都接受。
func TestBusinessVerb(t *testing.T) {
	cases := map[string]string{
		"waf.rules": "rules", "waf.blockLog": "blockLog",
		"rules": "rules", "blockLog": "blockLog",
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

// TestCallResults 两方法正常路径返回结构化占位结果（applied=false）。
func TestCallResults(t *testing.T) {
	rules, perr := Call("waf.rules", json.RawMessage(`{"rule_id":"WAF-0001","limit":5}`), testRoot, nil)
	if perr != nil || !strings.Contains(string(rules), `"applied":false`) || !strings.Contains(string(rules), `"limit":5`) {
		t.Fatalf("waf.rules 结果=%s err=%v", rules, perr)
	}
	log, perr := Call("waf.blockLog", json.RawMessage(`{"limit":7}`), testRoot, nil)
	if perr != nil || !strings.Contains(string(log), `"applied":false`) || !strings.Contains(string(log), `"limit":7`) {
		t.Fatalf("waf.blockLog 结果=%s err=%v", log, perr)
	}
}

// TestCallParamValidation 非法参数形状、规则 ID 格式、limit 越界均返回 E_INVALID。
func TestCallParamValidation(t *testing.T) {
	bad := []struct {
		method string
		params string
	}{
		{"waf.rules", `[]`},
		{"waf.rules", `not-json`},
		{"waf.rules", `{"rule_id":"RULE-0001"}`},
		{"waf.rules", `{"limit":1001}`},
		{"waf.rules", `{"limit":-3}`},
		{"waf.blockLog", `{"rule_id":"waf-0001"}`},
		{"waf.blockLog", `{"limit":100000}`},
	}
	for _, c := range bad {
		_, perr := Call(c.method, json.RawMessage(c.params), testRoot, nil)
		if perr == nil || perr.Code != pluginapi.E_INVALID {
			t.Fatalf("Call(%s,%s) 错误=%v，期望 E_INVALID", c.method, c.params, perr)
		}
	}
}

// TestCallUnknownMethod 未知方法返回 E_NOTFOUND。
func TestCallUnknownMethod(t *testing.T) {
	_, perr := Call("waf.exec", json.RawMessage(`{}`), testRoot, nil)
	if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("未知方法错误=%v，期望 E_NOTFOUND", perr)
	}
}

// TestCallMissingParams 缺少 params 对象返回 E_INVALID。
func TestCallMissingParams(t *testing.T) {
	for _, raw := range []string{``, `null`} {
		_, perr := Call("waf.rules", json.RawMessage(raw), testRoot, nil)
		if perr == nil || perr.Code != pluginapi.E_INVALID {
			t.Fatalf("Call(空 params=%q) 错误=%v，期望 E_INVALID", raw, perr)
		}
	}
}
