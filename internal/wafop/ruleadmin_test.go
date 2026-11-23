package wafop

import (
	"encoding/json"
	"fmt"
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

// fakeNft 是内存版 nft：root-action 调用维护规则集，供 toggle/回读/回滚测试使用。
type fakeRuleNft struct {
	rules   []map[string]any
	next    int
	dropAdd bool
	deleted []string
}

func newFakeRuleNft() *fakeRuleNft { return &fakeRuleNft{next: 0} }

func (f *fakeRuleNft) root(action string, args []string) (RootActionOutput, error) {
	switch action {
	case ActionNftList:
		nftables := []map[string]any{
			{"metainfo": map[string]any{"version": "1.1.0"}},
			{"table": map[string]any{"name": NftTable}},
		}
		for _, rule := range f.rules {
			nftables = append(nftables, map[string]any{"rule": rule})
		}
		raw, _ := json.Marshal(map[string]any{"nftables": nftables})
		return RootActionOutput{Stdout: raw}, nil
	case ActionNftAddRule:
		if f.dropAdd {
			return RootActionOutput{ExitCode: 0}, nil
		}
		f.next++
		comment := ""
		for index, token := range args {
			if token == "comment" && index+1 < len(args) {
				comment = args[index+1]
			}
		}
		expr := []map[string]any{{"comment": comment}}
		expr = append(expr, map[string]any{"drop": true})
		f.rules = append(f.rules, map[string]any{"handle": f.next, "expr": expr})
		return RootActionOutput{ExitCode: 0}, nil
	case ActionNftDeleteRule:
		f.deleted = append(f.deleted, args...)
		if len(args) == 1 {
			handle := args[0]
			kept := f.rules[:0]
			for _, rule := range f.rules {
				if fmt.Sprint(rule["handle"]) != handle {
					kept = append(kept, rule)
				}
			}
			f.rules = kept
		}
		return RootActionOutput{ExitCode: 0}, nil
	case ActionNftFlush:
		f.rules = nil
		return RootActionOutput{ExitCode: 0}, nil
	}
	return RootActionOutput{ExitCode: 0}, nil
}

func newRuleTestRuntime(fake *fakeRuleNft) *Runtime {
	env := newFakeEnv()
	env.lookPath["nft"] = "/usr/sbin/nft"
	return New(Options{Env: env.env(), RootAction: fake.root})
}

// TestRuleToggleIdempotent 证明 custom 规则 add/toggle/remove 幂等。
func TestRuleToggleIdempotent(t *testing.T) {
	fake := newFakeRuleNft()
	runtime := newRuleTestRuntime(fake)
	addBody := `{"name":"block-ssh","expr":"tcp dport 2222","action":"drop"}`
	if _, perr := runtime.Call("waf.rule.add", json.RawMessage(addBody)); perr != nil {
		t.Fatalf("add 失败：%+v", perr)
	}
	result, perr := runtime.Call("waf.rule.add", json.RawMessage(addBody))
	if perr != nil {
		t.Fatalf("重复 add 应幂等成功：%+v", perr)
	}
	var again RuleChangeResult
	if err := json.Unmarshal(result, &again); err != nil || again.Applied {
		t.Fatalf("重复 add 必须 applied=false：%+v %v", again, err)
	}
	off, perr := runtime.Call("waf.rule.toggle", json.RawMessage(`{"name":"block-ssh","enabled":false}`))
	if perr != nil {
		t.Fatalf("toggle off 失败：%+v", perr)
	}
	var offResult RuleChangeResult
	_ = json.Unmarshal(off, &offResult)
	if !offResult.Applied {
		t.Fatalf("首次 toggle off 应 applied=true")
	}
	offAgain, perr := runtime.Call("waf.rule.toggle", json.RawMessage(`{"name":"block-ssh","enabled":false}`))
	if perr != nil {
		t.Fatalf("重复 toggle off 应幂等：%+v", perr)
	}
	var offAgainResult RuleChangeResult
	_ = json.Unmarshal(offAgain, &offAgainResult)
	if offAgainResult.Applied {
		t.Fatalf("重复 toggle off 必须 applied=false")
	}
	on, perr := runtime.Call("waf.rule.toggle", json.RawMessage(`{"name":"block-ssh","enabled":true}`))
	if perr != nil {
		t.Fatalf("toggle on 失败：%+v", perr)
	}
	var onResult RuleChangeResult
	_ = json.Unmarshal(on, &onResult)
	if !onResult.Applied || len(onResult.Chain) == 0 {
		t.Fatalf("toggle on 应 applied=true 且回读链非空：%+v", onResult)
	}
}

// TestRuleAddReadbackRollback 证明写后回读不到规则时返回 E_UPSTREAM 且标记已回滚。
func TestRuleAddReadbackRollback(t *testing.T) {
	fake := newFakeRuleNft()
	fake.dropAdd = true // 模拟「命令退出 0 但规则没落地」
	runtime := newRuleTestRuntime(fake)
	_, perr := runtime.Call("waf.rule.add", json.RawMessage(`{"name":"block-1","expr":"ip saddr 1.2.3.4","action":"drop"}`))
	if perr == nil || perr.Code != "E_UPSTREAM" {
		t.Fatalf("回读不到应 E_UPSTREAM，实际 %+v", perr)
	}
	if !strings.Contains(perr.Message, "已回滚") {
		t.Fatalf("错误信息应说明已回滚：%s", perr.Message)
	}
}

// TestBuiltinRuleToggleAllowed 证明内置规则允许 toggle、且重复 toggle 幂等。
func TestBuiltinRuleToggleAllowed(t *testing.T) {
	fake := newFakeRuleNft()
	runtime := newRuleTestRuntime(fake)
	if _, perr := runtime.Call("waf.rule.toggle", json.RawMessage(`{"name":"ban-ipv4","enabled":false}`)); perr != nil {
		t.Fatalf("内置 toggle 应允许：%+v", perr)
	}
	second, perr := runtime.Call("waf.rule.toggle", json.RawMessage(`{"name":"ban-ipv4","enabled":false}`))
	if perr != nil {
		t.Fatalf("重复内置 toggle 应幂等：%+v", perr)
	}
	var result RuleChangeResult
	_ = json.Unmarshal(second, &result)
	if result.Applied {
		t.Fatalf("重复内置 toggle 必须 applied=false")
	}
}
