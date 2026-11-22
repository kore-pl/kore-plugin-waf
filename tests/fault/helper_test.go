// Package fault 对 waf 插件做基础故障注入（kill / timeout），验证方法级错误返回。
// 基础级 depth_level=basic：边界用例延 v1.1，这里只覆盖两类核心故障路径。
package fault

import (
	"encoding/json"
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

const testRoot = "/var/lib/kore/waf"

// faultExecutor 按注入类别让每个方法都失败，模拟两类运行时故障。
type faultExecutor struct {
	kind wafop.FaultKind
}

func (f faultExecutor) Rules(root, ruleID string, limit int) ([]wafop.Rule, error) {
	return nil, wafop.NewFaultError(f.kind, "rules 执行面故障")
}

func (f faultExecutor) BlockLog(root, ruleID string, limit int) ([]wafop.BlockLogEntry, error) {
	return nil, wafop.NewFaultError(f.kind, "blockLog 执行面故障")
}

// methods 是两类故障注入覆盖的方法及其合法参数。
var methods = []struct {
	name   string
	method string
	params string
}{
	{"rules", "waf.rules", `{"rule_id":"WAF-0001","limit":5}`},
	{"blockLog", "waf.blockLog", `{"limit":7}`},
}

// assertFault 对每个方法注入故障，断言返回 nil 结果 + 预期的协议错误码与类别关键词。
func assertFault(t *testing.T, kind wafop.FaultKind, wantCode, wantHint string) {
	t.Helper()
	exec := faultExecutor{kind: kind}
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			result, perr := wafop.Call(m.method, json.RawMessage(m.params), testRoot, exec)
			if perr == nil {
				t.Fatalf("%s 注入 %s 后未返回错误（结果=%s）", m.method, kind, result)
			}
			if result != nil {
				t.Fatalf("%s 出错时不应带结果: %s", m.method, result)
			}
			if perr.Code != wantCode {
				t.Fatalf("%s 错误码=%q，期望 %q（message=%q）", m.method, perr.Code, wantCode, perr.Message)
			}
			if !contains(perr.Message, wantHint) {
				t.Fatalf("%s 错误信息 %q 未含类别关键词 %q", m.method, perr.Message, wantHint)
			}
		})
	}
}

// contains 是 strings.Contains 的本地封装，避免每个 fault 文件重复 import strings。
func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// sanityNoFault 验证无故障时两方法正常返回，证明故障断言不是"永远失败"的假通过。
func sanityNoFault(t *testing.T) {
	t.Helper()
	for _, m := range methods {
		result, perr := wafop.Call(m.method, json.RawMessage(m.params), testRoot, nil)
		if perr != nil {
			t.Fatalf("无故障时 %s 意外返回错误: %v", m.method, perr)
		}
		if len(result) == 0 {
			t.Fatalf("无故障时 %s 返回空结果", m.method)
		}
	}
}

// verifyErrorContract 断言错误体是标准协议结构（含 code 字段）。
func verifyErrorContract(t *testing.T, perr *pluginapi.Error) {
	t.Helper()
	if perr == nil {
		t.Fatal("错误体为 nil")
	}
	if perr.Code == "" || perr.Message == "" {
		t.Fatalf("错误体字段不完整: %+v", perr)
	}
}
