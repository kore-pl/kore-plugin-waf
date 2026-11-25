package wafop

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNormalizeLevel 等级参数校验与归一。
func TestNormalizeLevel(t *testing.T) {
	cases := map[string]string{
		"":         LevelStandard,
		"loose":    LevelLoose,
		"STANDARD": LevelStandard,
		" strict ": LevelStrict,
	}
	for raw, want := range cases {
		got, perr := NormalizeLevel(raw)
		if perr != nil {
			t.Fatalf("NormalizeLevel(%q) 不应报错：%v", raw, perr)
		}
		if got != want {
			t.Fatalf("NormalizeLevel(%q)=%q，期望 %q", raw, got, want)
		}
	}
	if _, perr := NormalizeLevel("aggressive"); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("非法等级应 E_INVALID：%v", perr)
	}
	if msg := perrMessage(t, "aggressive"); !strings.Contains(msg, "loose") || !strings.Contains(msg, "standard") {
		t.Fatalf("错误文案应列出可选等级：%s", msg)
	}
}

// perrMessage 取非法等级的提示文案。
func perrMessage(t *testing.T, raw string) string {
	t.Helper()
	_, perr := NormalizeLevel(raw)
	if perr == nil {
		t.Fatalf("NormalizeLevel(%q) 应报错", raw)
	}
	return perr.Message
}

// TestLevelFromChain 由链回读结果推断等级（含自定义规则不干扰）。
func TestLevelFromChain(t *testing.T) {
	chain := func(names ...string) []ChainRule {
		out := make([]ChainRule, 0, len(names))
		for _, name := range names {
			out = append(out, ChainRule{Name: name, Builtin: true, Action: "drop"})
		}
		return out
	}
	cases := []struct {
		name  string
		chain []ChainRule
		want  string
	}{
		{"空链", nil, ""},
		{"只有封禁", chain("ban-ipv4", "ban-ipv6"), LevelLoose},
		{"标准", chain("ban-ipv4", "ban-ipv6", "syn-rate", "conn-rate"), LevelStandard},
		{"严格", chain("ban-ipv4", "ban-ipv6", "syn-rate", "conn-rate", "invalid-state", "ssh-rate"), LevelStrict},
		{"自定义不影响", append(chain("ban-ipv4", "ban-ipv6", "syn-rate", "conn-rate"),
			ChainRule{Name: "allow-office", Builtin: false}), LevelStandard},
	}
	for _, item := range cases {
		if got := LevelFromChain(item.chain); got != item.want {
			t.Fatalf("%s：LevelFromChain=%q，期望 %q", item.name, got, item.want)
		}
	}
}

// TestToggleLevelStrictLoose 严格 / 宽松等级的真实下发路径（fake 通道）。
//
// 断言三件事：① 等级改变了内置规则条数（6 / 2），② 回读校验通过，③ 严格等级
// 追加的两条规则确实经 nft-add-rule 落链、宽松等级确实删掉了限速规则。
func TestToggleLevelStrictLoose(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	runtime := New(Options{Env: env.env(), RootAction: root.Call})

	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"enforce","level":"strict"}`))
	if perr != nil {
		t.Fatalf("严格等级下发失败：%v", perr)
	}
	var strict ModeResult
	if err := json.Unmarshal(raw, &strict); err != nil {
		t.Fatalf("解析严格等级结果：%v", err)
	}
	if strict.Level != LevelStrict || !strict.Applied || !strict.Verified {
		t.Fatalf("严格等级结果不符：%+v", strict)
	}
	if len(strict.Rules) != LevelRuleCountFor(LevelStrict) {
		t.Fatalf("严格等级应有 %d 条规则，实际 %d", LevelRuleCountFor(LevelStrict), len(strict.Rules))
	}
	if !containsAction(root.actions, ActionNftAddRule) {
		t.Fatalf("严格等级应经 nft-add-rule 追加规则：%v", root.actions)
	}
	// 追加的两条必须真的落链（fake 按 token 识别）。
	chain, err := NewNftBackend(env.env(), root.Call).nftChainRules()
	if err != nil {
		t.Fatalf("回读链失败：%v", err)
	}
	if LevelFromChain(chain) != LevelStrict {
		t.Fatalf("链上等级应为严格，实际 %q：%+v", LevelFromChain(chain), chain)
	}

	raw, perr = runtime.Call("waf.toggle", json.RawMessage(`{"mode":"enforce","level":"loose"}`))
	if perr != nil {
		t.Fatalf("宽松等级下发失败：%v", perr)
	}
	var loose ModeResult
	if err := json.Unmarshal(raw, &loose); err != nil {
		t.Fatalf("解析宽松等级结果：%v", err)
	}
	if loose.Level != LevelLoose || !loose.Applied || !loose.Verified {
		t.Fatalf("宽松等级结果不符：%+v", loose)
	}
	if len(loose.Rules) != LevelRuleCountFor(LevelLoose) {
		t.Fatalf("宽松等级应有 %d 条规则，实际 %d", LevelRuleCountFor(LevelLoose), len(loose.Rules))
	}
	for _, rule := range loose.Rules {
		if strings.Contains(rule.Summary, "kore_syn4") || strings.Contains(rule.Summary, "ct count") {
			t.Fatalf("宽松等级不应保留限速规则：%+v", rule)
		}
	}
}

// TestToggleKeepsLevelOnModeSwitch 不带 level 切模式时沿用当前等级。
func TestToggleKeepsLevelOnModeSwitch(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	runtime := New(Options{Env: env.env(), RootAction: root.Call})

	if raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"enforce","level":"strict"}`)); perr != nil {
		t.Fatalf("严格等级下发失败：%v", perr)
	} else {
		var first ModeResult
		_ = json.Unmarshal(raw, &first)
		if first.Level != LevelStrict {
			t.Fatalf("首次等级应为严格：%+v", first)
		}
	}
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"observe"}`))
	if perr != nil {
		t.Fatalf("切观察模式失败：%v", perr)
	}
	var observe ModeResult
	if err := json.Unmarshal(raw, &observe); err != nil {
		t.Fatalf("解析观察模式结果：%v", err)
	}
	if observe.Level != LevelStrict {
		t.Fatalf("不传 level 时应沿用严格等级，实际 %q", observe.Level)
	}
	if len(observe.Rules) != LevelRuleCountFor(LevelStrict) {
		t.Fatalf("观察模式应保留 6 条严格规则，实际 %d", len(observe.Rules))
	}
	for _, rule := range observe.Rules {
		if rule.Verdict == "drop" {
			t.Fatalf("观察模式不应有 drop 规则：%+v", rule)
		}
	}
}

// TestStatusReportsLevel status 暴露数据面实际等级。
func TestStatusReportsLevel(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	if _, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"enforce","level":"loose"}`)); perr != nil {
		t.Fatalf("宽松等级下发失败：%v", perr)
	}
	raw, perr := runtime.Call("waf.status", json.RawMessage(`{}`))
	if perr != nil {
		t.Fatalf("读取状态失败：%v", perr)
	}
	var status StatusResult
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("解析状态：%v", err)
	}
	if status.Level != LevelLoose || status.Backend.Level != LevelLoose {
		t.Fatalf("状态应报告宽松等级：%+v", status)
	}
}
