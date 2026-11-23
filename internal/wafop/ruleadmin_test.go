package wafop

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCompileRuleExprWhitelist 覆盖匹配器白名单：合法形状通过，注入/越权形状拒绝。
func TestCompileRuleExprWhitelist(t *testing.T) {
	legal := map[string][]string{
		"ip saddr 1.2.3.4":         {"ip", "saddr", "1.2.3.4"},
		"ip saddr 10.0.0.0/8":      {"ip", "saddr", "10.0.0.0/8"},
		"ip6 saddr 2001:db8::1":    {"ip6", "saddr", "2001:db8::1"},
		"tcp dport 80":             {"tcp", "dport", "80"},
		"udp dport 53":             {"udp", "dport", "53"},
		"ct state new,established": {"ct", "state", "new,", "established"},
		"tcp flags syn":            {"tcp", "flags", "syn"},
	}
	for expr, want := range legal {
		got, perr := CompileRuleExpr(expr)
		if perr != nil {
			t.Fatalf("%q 应通过：%v", expr, perr)
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Fatalf("%q token 不符：got %v want %v", expr, got, want)
		}
	}
	illegal := []string{
		"; flush ruleset",
		"include /etc/nftables.conf",
		"meta l4proto tcp",
		"ip saddr 1.2.3.4 drop",
		"tcp dport { 80, 443 }",
		"tcp flags ack",
	}
	for _, expr := range illegal {
		if _, perr := CompileRuleExpr(expr); perr == nil || perr.Code != "E_UNSUPPORTED" {
			t.Fatalf("%q 应返回 E_UNSUPPORTED，实际 %+v", expr, perr)
		}
	}
	badValues := []string{"ip saddr 999.1.1.1", "ip6 saddr 1.2.3.4", "tcp dport 70000", "ct state bogus"}
	for _, expr := range badValues {
		if _, perr := CompileRuleExpr(expr); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("%q 应返回 E_INVALID，实际 %+v", expr, perr)
		}
	}
	many := "ip saddr " + strings.Repeat("1.2.3.4 ", 30)
	if _, perr := CompileRuleExpr(many); perr == nil {
		t.Fatalf("超长表达式应被拒绝")
	}
}

// TestCheckActionAndName 覆盖 action / name 的收紧语义。
func TestCheckActionAndName(t *testing.T) {
	for _, action := range []string{"drop", "accept"} {
		if perr := checkAction(action); perr != nil {
			t.Fatalf("action %q 应通过：%v", action, perr)
		}
	}
	for _, action := range []string{"log", "reject", "return", ""} {
		if perr := checkAction(action); perr == nil {
			t.Fatalf("action %q 应拒绝", action)
		}
	}
	for _, name := range []string{"ok-rule", "r1", "a_b"} {
		if perr := ValidateRuleName(name); perr != nil {
			t.Fatalf("name %q 应通过：%v", name, perr)
		}
	}
	for _, name := range []string{"", "Bad", "bad name", "-x", "_x", strings.Repeat("a", 33)} {
		if perr := ValidateRuleName(name); perr == nil {
			t.Fatalf("name %q 应拒绝", name)
		}
	}
}

// TestBuiltinRuleRemoveRejected 覆盖「内置只能停用不能删除」。
func TestBuiltinRuleRemoveRejected(t *testing.T) {
	runtime := New(Options{Env: newFakeEnv().env()})
	raw, _ := json.Marshal(ruleParams{Name: "ban-ipv4"})
	if _, perr := runtime.Call("waf.rule.remove", raw); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("内置规则删除应 E_INVALID，实际 %+v", perr)
	} else if !strings.Contains(perr.Message, "内置规则只能停用不能删除") {
		t.Fatalf("错误信息缺少口径：%s", perr.Message)
	}
}

// TestRuleAddPrecheck 覆盖 rule.add 的参数前置校验（未触达 nft）。
func TestRuleAddPrecheck(t *testing.T) {
	runtime := New(Options{Env: newFakeEnv().env()})
	cases := []struct {
		params ruleParams
		code   string
	}{
		{ruleParams{Name: "ban-ipv4", Expr: "ip saddr 1.2.3.4", Action: "drop"}, "E_INVALID"},
		{ruleParams{Name: "x", Expr: "", Action: "drop"}, "E_INVALID"},
		{ruleParams{Name: "x", Expr: "ip saddr 1.2.3.4", Action: "log"}, "E_INVALID"},
		{ruleParams{Name: "x", Expr: "; flush ruleset", Action: "drop"}, "E_UNSUPPORTED"},
	}
	for _, tc := range cases {
		raw, _ := json.Marshal(tc.params)
		_, perr := runtime.Call("waf.rule.add", raw)
		if perr == nil || perr.Code != tc.code {
			t.Fatalf("%+v 应 %s，实际 %+v", tc.params, tc.code, perr)
		}
	}
}
