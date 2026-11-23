package wafop

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// 回归 P1（0.4.3 真机 e2e）：ListRules 从不给 Chain 赋值，waf.rules.chain 恒为 null，
// UI 走 nft.rules 降级分支，「内置」徽标与内置行删除按钮禁用永不生效。
//
// fixture 来源：本机 nftables 1.1.6，在私有 netns（`unshare -rn`）里按 info.json 的
// nft-mode-enforce 装 4 条内置规则 + 2 条带 `comment kore-rule-*` 的自定义规则后，
// 用 `nft -j list table inet kore_waf` 采集，不是手写理想 JSON。
const mixedChainFixture = "testdata/nft-list-116-mixed.json"

// mixedChainRuleCount 是 fixture 里的规则对象总数（4 内置 + 2 自定义）。
const mixedChainRuleCount = 6

// loadMixedFixture 读真实 nft 输出并返回原样 stdout 与规则条数（从 fixture 自己数，
// 不在测试里写死「应该有几条」以外的推导）。
func loadMixedFixture(t *testing.T) ([]byte, int) {
	t.Helper()
	raw, err := os.ReadFile(mixedChainFixture)
	if err != nil {
		t.Fatalf("读 fixture %s: %v", mixedChainFixture, err)
	}
	var payload struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("fixture 不是合法 nft -j 输出: %v", err)
	}
	count := 0
	for _, object := range payload.Nftables {
		if _, ok := object["rule"]; ok {
			count++
		}
	}
	return raw, count
}

// realChainRoot 用真实 nft 输出冒充 root-action 通道的 `nft -j list` 回包。
func realChainRoot(stdout []byte) RootActionFunc {
	return func(action string, args []string) (RootActionOutput, error) {
		if action == ActionNftList {
			return RootActionOutput{Stdout: stdout}, nil
		}
		return RootActionOutput{ExitCode: 0}, nil
	}
}

// chainEnv 构造「nft 存在 + 装了 modsecurity 规则文件」的环境。
func chainEnv() *fakeEnv {
	env := newFakeEnv()
	env.lookPath["nft"] = "/usr/sbin/nft"
	env.addFile("/opt/waf/rules/a.conf", "SecRule ARGS \"@rx a\" \"id:1\"\n")
	return env
}

// TestListRulesFillsChain 断言 ListRules 返回的 chain 条数 == nft 里的规则数，
// 每条带正确的 builtin 取值，且自定义规则 expr 非空。
func TestListRulesFillsChain(t *testing.T) {
	stdout, wantRules := loadMixedFixture(t)
	if wantRules != mixedChainRuleCount {
		t.Fatalf("fixture 规则数应为 %d，实际 %d", mixedChainRuleCount, wantRules)
	}
	env := chainEnv()
	settings := Settings{Engine: EngineModSecurity, RulesDirs: []string{"/opt/waf/rules"}}
	result, err := ListRules(env.env(), settings, modsecDetection(), realChainRoot(stdout))
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if result.Chain == nil {
		t.Fatal("chain 不能为 nil（JSON 里会变 null，UI 拿到 null 仍走降级分支）")
	}
	if len(result.Chain) != wantRules {
		t.Fatalf("chain 长度应等于 nft 规则数 %d，实际 %d: %+v", wantRules, len(result.Chain), result.Chain)
	}
	builtinCount := 0
	for _, rule := range result.Chain {
		if rule.Builtin {
			builtinCount++
			if rule.Expr == "" {
				t.Fatalf("内置规则 %s 的 expr 不应为空", rule.Name)
			}
			continue
		}
		if rule.Expr == "" {
			t.Fatalf("自定义规则 %s 的 expr 不能为空串（前端会显示空白行）: %+v", rule.Name, rule)
		}
	}
	if builtinCount != len(builtinRules) {
		t.Fatalf("内置规则应为 %d 条，实际 %d: %+v", len(builtinRules), builtinCount, result.Chain)
	}
}

// TestListRulesChainBuiltinFlags 逐条核对内置 4 条的 builtin=true 与自定义 2 条的 false。
func TestListRulesChainBuiltinFlags(t *testing.T) {
	stdout, _ := loadMixedFixture(t)
	env := chainEnv()
	settings := Settings{Engine: EngineModSecurity, RulesDirs: []string{"/opt/waf/rules"}}
	result, err := ListRules(env.env(), settings, modsecDetection(), realChainRoot(stdout))
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	byName := map[string]ChainRule{}
	for _, rule := range result.Chain {
		byName[rule.Name] = rule
	}
	wantBuiltin := []string{"ban-ipv4", "ban-ipv6", "syn-rate", "conn-rate"}
	for _, name := range wantBuiltin {
		rule, ok := byName[name]
		if !ok {
			t.Fatalf("chain 里缺少内置规则 %s: %+v", name, result.Chain)
		}
		if !rule.Builtin {
			t.Fatalf("%s 应 builtin=true: %+v", name, rule)
		}
		if rule.Handle == 0 {
			t.Fatalf("%s 应带 nft handle: %+v", name, rule)
		}
	}
	wantCustom := map[string]string{
		"allow-office": "ip saddr",
		"allow-admin":  "tcp dport 8443",
	}
	for name, exprPart := range wantCustom {
		rule, ok := byName[name]
		if !ok {
			t.Fatalf("chain 里缺少自定义规则 %s: %+v", name, result.Chain)
		}
		if rule.Builtin {
			t.Fatalf("%s 应 builtin=false: %+v", name, rule)
		}
		if !strings.Contains(rule.Expr, exprPart) {
			t.Fatalf("%s 的 expr 应含 %q，实际 %q", name, exprPart, rule.Expr)
		}
		if rule.ExprTokens == 0 {
			t.Fatalf("%s 应保留原始 token 数: %+v", name, rule)
		}
	}
}

// TestListRulesChainWithoutRootDegrades 没有 root 通道时 chain 降级为空数组（不是 nil），
// 引擎规则集照常返回——数据面问题不该打挂引擎面。
func TestListRulesChainWithoutRootDegrades(t *testing.T) {
	env := chainEnv()
	settings := Settings{Engine: EngineModSecurity, RulesDirs: []string{"/opt/waf/rules"}}
	result, err := ListRules(env.env(), settings, modsecDetection())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if result.Chain == nil || len(result.Chain) != 0 {
		t.Fatalf("无通道时 chain 应为空数组，实际 %+v", result.Chain)
	}
	if result.Total != 1 {
		t.Fatalf("引擎规则集应照常统计（1 条 SecRule），实际 %d", result.Total)
	}
}

// TestRenderRuleExprPieces 覆盖 raw 反解：标量 / 集合 / CIDR / ct count / 动作跳过。
func TestRenderRuleExprPieces(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"端口标量", `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},{"accept":null}]`, "tcp dport 8443"},
		{"端口集合", `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[80,443]}}}]`, "tcp dport { 80, 443 }"},
		{"CIDR", `[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.20.0.0","len":16}}}}]`, "ip saddr 10.20.0.0/16"},
		{"ct count over", `[{"ct count":{"val":200,"inv":true}},{"counter":{"packets":0,"bytes":0}}]`, "ct count over 200"},
		{"只跳过 counter/动作", `[{"counter":{"packets":0,"bytes":0}},{"drop":null}]`, ""},
	}
	for _, tc := range cases {
		var exprs []json.RawMessage
		if err := json.Unmarshal([]byte(tc.expr), &exprs); err != nil {
			t.Fatalf("%s: 解析用例失败: %v", tc.name, err)
		}
		if got := renderRuleExpr(exprs); got != tc.want {
			t.Fatalf("%s: 期望 %q，实际 %q", tc.name, tc.want, got)
		}
	}
}

// TestParseChainRulesCustomExprNotEmpty 回读链里自定义规则 expr 非空（P3）。
func TestParseChainRulesCustomExprNotEmpty(t *testing.T) {
	stdout, _ := loadMixedFixture(t)
	rules, perr := parseChainRules(stdout, NftChain)
	if perr != nil {
		t.Fatalf("解析失败: %+v", perr)
	}
	for _, rule := range rules {
		if rule.Expr == "" {
			t.Fatalf("规则 %s 的 expr 为空串（P3 回归）: %+v", rule.Name, rule)
		}
	}
}
