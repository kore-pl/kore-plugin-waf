package wafop

// 防护等级（0.5.0 起）：在**同一模式**（observe / enforce）下调整内置防护的覆盖面。
//
//	loose   ：只有封禁名单（v4/v6 命中即 drop/记录），不装扫描限速与并发上限
//	standard：现有 4 条基础防护（封禁 + SYN 限速 + 并发上限）
//	strict  ：标准 4 条 + 无效连接状态丢弃 + SSH 暴力破解限速
//
// 设计约束：
//   - 等级**不新增 root_action**：协议 §3.1.3 单插件最多 16 条，本插件已用满
//     （封禁/建表/模式下发等）。等级复用现成的 nft-add-rule / nft-delete-rule
//     （同一受控形状、同一审计通道），argv 形状仍由内核二次校验（ADR-0022）。
//   - 等级**不落配置文件**：它是数据面的实际形态，从 kore_waf 链上回读推断
//     （LevelFromChain），因此重启插件/重启内核后不会与事实漂移。
//   - 关闭防护（off）清空链后等级无意义，重新开启按 standard 下发。

import (
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 等级枚举。空串按 standard 处理（老客户端不带 level 时行为不变）。
const (
	// LevelLoose 只保留封禁名单。
	LevelLoose = "loose"
	// LevelStandard 是缺省等级（4 条基础防护）。
	LevelStandard = "standard"
	// LevelStrict 在标准之上追加两条更严格的规则。
	LevelStrict = "strict"
)

// strictExtraRules 是 strict 等级追加的两条规则（顺序即装载顺序）。
//
// 它们没有 comment（与内置 4 条一样由 token 签名识别），expr 仅供 UI 展示；
// 每条都在 28 个 nft token 以内（内核 Tail 上限）。
var strictExtraRules = []builtinRule{
	{Name: "invalid-state", Expr: "ct state invalid",
		Tokens:        []string{"ct", "state", "invalid", "counter", "log", "prefix", "kore-waf-state"},
		EnforceTokens: []string{"ct", "state", "invalid", "counter", "drop"}},
	{Name: "ssh-rate",
		Expr: "tcp dport 22 meter kore_ssh4 { ip saddr limit rate over 10/minute burst 20 }",
		Tokens: []string{"tcp", "dport", "22", "meter", "kore_ssh4", "{", "ip", "saddr",
			"limit", "rate", "over", "10/minute", "burst", "20", "}", "counter", "log", "prefix", "kore-waf-ssh"},
		EnforceTokens: []string{"tcp", "dport", "22", "meter", "kore_ssh4", "{", "ip", "saddr",
			"limit", "rate", "over", "10/minute", "burst", "20", "}", "counter", "drop"}},
}

// allBuiltinRules 是全部内置规则模板（标准 4 条 + 严格追加 2 条）。
func allBuiltinRules() []builtinRule {
	out := make([]builtinRule, 0, len(builtinRules)+len(strictExtraRules))
	out = append(out, builtinRules...)
	out = append(out, strictExtraRules...)
	return out
}

// builtinTemplateByName 在全部模板里找规则（含 strict 追加的两条）。
func builtinTemplateByName(name string) (builtinRule, bool) {
	for _, rule := range allBuiltinRules() {
		if rule.Name == name {
			return rule, true
		}
	}
	return builtinRule{}, false
}

// isStrictExtra 报告某规则是否属于 strict 追加项。
func isStrictExtra(name string) bool {
	for _, rule := range strictExtraRules {
		if rule.Name == name {
			return true
		}
	}
	return false
}

// builtinTokensFor 返回某内置规则在给定模式下的 nft token 序列。
// 观察模式一律 counter log（不 verdict），拦截模式 counter drop。
func builtinTokensFor(rule builtinRule, mode string) []string {
	if mode == ModeEnforce && len(rule.EnforceTokens) > 0 {
		return append([]string{}, rule.EnforceTokens...)
	}
	return append([]string{}, rule.Tokens...)
}

// NormalizeLevel 校验并归一等级；空串按 standard（老客户端兼容）。
func NormalizeLevel(raw string) (string, *pluginapi.Error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "":
		return LevelStandard, nil
	case LevelLoose, LevelStandard, LevelStrict:
		return value, nil
	}
	return "", invalid("level=" + raw + " 非法；请传 loose / standard / strict 之一（不传按 standard）")
}

// LevelRuleCountFor 返回给定等级的内置规则条数（回读校验用）。
func LevelRuleCountFor(level string) int {
	switch level {
	case LevelLoose:
		return len(builtinRules) - 2 // 只留封禁名单两条
	case LevelStrict:
		return len(builtinRules) + len(strictExtraRules)
	}
	return len(builtinRules)
}

// levelRuleNames 返回某等级应装载的内置规则名（顺序即装载顺序）。
func levelRuleNames(level string) []string {
	names := make([]string, 0, len(builtinRules)+len(strictExtraRules))
	for _, rule := range builtinRules {
		if level == LevelLoose && (rule.Name == "syn-rate" || rule.Name == "conn-rate") {
			continue
		}
		names = append(names, rule.Name)
	}
	if level == LevelStrict {
		for _, rule := range strictExtraRules {
			names = append(names, rule.Name)
		}
	}
	return names
}

// LevelFromChain 由链上**内置**规则推断实际生效等级。
//
//	有 strict 追加项            → strict
//	有扫描限速 / 并发上限        → standard
//	只有封禁名单                → loose
//	一条内置规则都没有（off / 未初始化） → ""
//
// 只认内置规则名，自定义规则（用户自建）不影响等级判定。
func LevelFromChain(chain []ChainRule) string {
	has := map[string]bool{}
	any := false
	for _, rule := range chain {
		if !rule.Builtin {
			continue
		}
		if strings.TrimSpace(rule.Name) == "" {
			continue
		}
		any = true
		has[rule.Name] = true
	}
	if !any {
		return ""
	}
	if has["invalid-state"] || has["ssh-rate"] {
		return LevelStrict
	}
	if has["syn-rate"] || has["conn-rate"] {
		return LevelStandard
	}
	return LevelLoose
}

// LevelFromSummaries 由 nft 规则摘要（NftRule.summary）兜底推断等级。
//
// 只在链回读失败/不可用时用：摘要里没有规则名，只能按特征 token 判断，因此
// 自定义规则若恰好写了 `ct state invalid` 会与 strict 追加项混淆。
// **能读链时一律用 LevelFromChain**（有 name/handle，可区分内置与自定义）。
func LevelFromSummaries(rules []NftRule) string {
	hasBan, hasRate, hasStrict := false, false, false
	for _, rule := range rules {
		text := rule.Summary
		switch {
		case strings.Contains(text, "kore_ssh4"), strings.Contains(text, "ct state invalid"):
			hasStrict = true
		case strings.Contains(text, "kore_syn4"), strings.Contains(text, "ct count"):
			hasRate = true
		case strings.Contains(text, "@banned4"), strings.Contains(text, "@banned6"):
			hasBan = true
		}
	}
	switch {
	case hasStrict:
		return LevelStrict
	case hasRate:
		return LevelStandard
	case hasBan:
		return LevelLoose
	}
	return ""
}

// currentLevel 返回数据面实际生效等级：优先按链回读（可区分内置/自定义），
// 其次按规则摘要特征，最后按「等级 ↔ 条数」一一对应关系兜底。
//
// 三级兜底的原因：老版本 nft 的 -j 结构 / 注释形态不同，链名解析可能不可用；
// 此时条数仍是可靠证据（本插件控制的等级只有 2 / 4 / 6 条三种形态）。
func (b *NftBackend) currentLevel(state NftState) string {
	if chain, err := b.nftChainRules(); err == nil {
		if level := LevelFromChain(chain); level != "" {
			return level
		}
	}
	if level := LevelFromSummaries(state.Rules); level != "" {
		return level
	}
	return levelFromRuleCount(len(state.Rules))
}

// levelFromRuleCount 把内置规则条数映射回等级（数量是等级的构造性证据）。
func levelFromRuleCount(count int) string {
	switch count {
	case LevelRuleCountFor(LevelLoose):
		return LevelLoose
	case LevelRuleCountFor(LevelStandard):
		return LevelStandard
	case LevelRuleCountFor(LevelStrict):
		return LevelStrict
	}
	return ""
}

// modeFromChain 由链上是否有 drop 规则推断模式（空链按 observe 处理）。
func modeFromChain(chain []ChainRule) string {
	for _, rule := range chain {
		if rule.Action == "drop" {
			return ModeEnforce
		}
	}
	return ModeObserve
}
