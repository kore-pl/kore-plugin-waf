package wafop

import (
	"encoding/json"
	"os"
	"testing"
)

// 以下 fixture 全部来自本机 nft 1.1.6 的 `nft -j list ...` 真实输出（不是手写理想 JSON）。

// TestParseChainRulesRealOutput 覆盖「内置带 comment + 自定义带 comment + 无 comment 普通规则」：
// nft 1.1.6 的 comment 在 rule 对象顶层，0.4.1 只扫 expr 导致恒空（已发版缺陷）。
func TestParseChainRulesRealOutput(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft-list-116.json")
	if err != nil {
		t.Fatalf("读 fixture: %v", err)
	}
	rules, perr := parseChainRules(raw, NftChain)
	if perr != nil {
		t.Fatalf("解析失败: %+v", perr)
	}
	if len(rules) != 2 {
		t.Fatalf("应解析出 2 条 kore 规则（1 内置 + 1 自定义），实际 %d: %+v", len(rules), rules)
	}
	if rules[0].Name != "ban-ipv4" || !rules[0].Builtin || rules[0].Action != "drop" {
		t.Fatalf("首条应为内置 ban-ipv4/drop: %+v", rules[0])
	}
	if rules[1].Name != "allow-office" || rules[1].Builtin || rules[1].Action != "accept" {
		t.Fatalf("次条应为自定义 allow-office/accept: %+v", rules[1])
	}
}

// TestParseChainRulesBuiltinOnly 覆盖「4 条内置规则没有 comment、只能靠 token 签名识别」。
func TestParseChainRulesBuiltinOnly(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft-list-116-builtin.json")
	if err != nil {
		t.Fatalf("读 fixture: %v", err)
	}
	rules, perr := parseChainRules(raw, NftChain)
	if perr != nil {
		t.Fatalf("解析失败: %+v", perr)
	}
	names := map[string]bool{}
	for _, r := range rules {
		if !r.Builtin {
			t.Fatalf("四条都应是内置: %+v", r)
		}
		names[r.Name] = true
	}
	for _, want := range []string{"ban-ipv4", "ban-ipv6", "syn-rate", "conn-rate"} {
		if !names[want] {
			t.Fatalf("缺少内置规则 %s，实际 %v", want, names)
		}
	}
}

// TestParseChainRulesRejectsForeignChain 用真实结构 + 改写 chain 名，确保只收目标链。
func TestParseChainRulesRejectsForeignChain(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft-list-116.json")
	if err != nil {
		t.Fatalf("读 fixture: %v", err)
	}
	var doc map[string][]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fixture 解析: %v", err)
	}
	for i, obj := range doc["nftables"] {
		rawRule, ok := obj["rule"]
		if !ok {
			continue
		}
		var rule map[string]json.RawMessage
		if err := json.Unmarshal(rawRule, &rule); err != nil {
			t.Fatal(err)
		}
		rule["chain"] = json.RawMessage(`"input-alt"`)
		rebuilt, _ := json.Marshal(rule)
		doc["nftables"][i] = map[string]json.RawMessage{"rule": rebuilt}
	}
	rewritten, _ := json.Marshal(doc)
	if _, perr := parseChainRules(rewritten, NftChain); perr == nil {
		t.Fatal("规则挂在别的 chain 上时应当 0 条且触发兜底 E_UPSTREAM")
	}
}

// TestParseChainRulesSilentEmptyGuard 覆盖兜底：JSON 有规则对象但一条都认不出 → 必须报错，不能静默空。
func TestParseChainRulesSilentEmptyGuard(t *testing.T) {
	raw := []byte(`{"nftables":[{"rule":{"family":"inet","table":"kore_waf","chain":"input","handle":9,"expr":[{"counter":{"packets":1,"bytes":2}}]}}]}`)
	if _, perr := parseChainRules(raw, NftChain); perr == nil {
		t.Fatal("有规则对象但解析 0 条时应返回错误")
	}
}

// TestParseChainRulesEmptyIsOK 覆盖「表里确实没有规则」：允许返回空，不报错。
func TestParseChainRulesEmptyIsOK(t *testing.T) {
	raw := []byte(`{"nftables":[{"metainfo":{"version":"1.1.6"}},{"table":{"family":"inet","name":"kore_waf","handle":1}}]}`)
	rules, perr := parseChainRules(raw, NftChain)
	if perr != nil || len(rules) != 0 {
		t.Fatalf("无规则时应返回空且不报错: %v %+v", rules, perr)
	}
}
