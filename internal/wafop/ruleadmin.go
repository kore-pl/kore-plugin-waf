package wafop

// 本文件实现 waf.rule.add / remove / toggle：在 kore 自有 table inet kore_waf 的
// input 链上增删/启停规则。
//
// 边界（ADR-0022 增补，2026-11-23）：
//   - 只有**受控匹配器白名单**能进 nft：ip saddr / ip6 saddr / tcp dport / udp dport /
//     ct state / tcp flags syn；其余一律 E_UNSUPPORTED + hint，绝不把用户输入当 nft 语法；
//   - 每条规则带 `comment kore-rule-<name>`，写后 `nft -j list` 回读比对；
//   - 内置 4 条基础防护不可删（E_INVALID），只能 toggle；
//   - 装配层只拼「已校验的 token 序列」，形状由内核 RootCommandPolicies 二次兜底。

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// ChainRule 是 kore_waf input 链上的一条规则（waf.rules.chain[]）。
type ChainRule struct {
	Name    string `json:"name"`
	Expr    string `json:"expr"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
	Builtin bool   `json:"builtin"`
	Handle  int    `json:"handle,omitempty"`
}

// builtinRule 是内置基础防护规则的模板（与 info.json 的 nft-mode-* 对应）。
type builtinRule struct {
	Name   string
	Expr   string
	Action string
	Tokens []string
}

// builtinRules 是 4 条内置规则；顺序即装载顺序。
var builtinRules = []builtinRule{
	{Name: "ban-ipv4", Expr: "ip saddr @banned4", Action: "drop",
		Tokens: []string{"ip", "saddr", "@banned4", "counter", "drop"}},
	{Name: "ban-ipv6", Expr: "ip6 saddr @banned6", Action: "drop",
		Tokens: []string{"ip6", "saddr", "@banned6", "counter", "drop"}},
	{Name: "syn-rate", Expr: "tcp flags syn tcp dport { 80, 443 } meter kore_syn4", Action: "observe",
		Tokens: []string{"tcp", "flags", "syn", "tcp", "dport", "{", "80,", "443", "}", "counter", "log", "prefix", "kore-waf-scan"}},
	{Name: "conn-rate", Expr: "tcp dport { 80, 443 } ct count over 200", Action: "observe",
		Tokens: []string{"tcp", "dport", "{", "80,", "443", "}", "ct", "count", "over", "200", "counter", "log", "prefix", "kore-waf-conn"}},
}

// builtinByName 返回内置模板。
func builtinByName(name string) (builtinRule, bool) {
	for _, rule := range builtinRules {
		if rule.Name == name {
			return rule, true
		}
	}
	return builtinRule{}, false
}

// ruleParams 是 rule.add / rule.remove / rule.toggle 的入参。
type ruleParams struct {
	Name    string `json:"name"`
	Expr    string `json:"expr,omitempty"`
	Action  string `json:"action,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// RuleChangeResult 是 rule.* 的结果：写后回读的完整链 + 本次变更。
type RuleChangeResult struct {
	Applied bool        `json:"applied"`
	DryRun  bool        `json:"dry_run"`
	Action  string      `json:"op"` // add|remove|toggle
	Rule    ChainRule   `json:"rule"`
	Chain   []ChainRule `json:"chain"`
}

// ruleCommentPrefix 是规则名在 nft 里的可读标记（nft 注释不能带引号/空格，故用短横线）。
const ruleCommentPrefix = "kore-rule-"

// ValidateRuleName 校验规则名（与 nft comment 字符集兼容）。
func ValidateRuleName(name string) *pluginapi.Error {
	if len(name) < 1 || len(name) > 32 {
		return invalid("name 长度必须在 1–32 之间")
	}
	for index, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			return invalid(fmt.Sprintf("name 只允许小写字母、数字、- 和 _（第 %d 个字符 %q 非法）", index+1, r))
		}
	}
	if name[0] == '-' || name[0] == '_' {
		return invalid("name 必须以小写字母或数字开头")
	}
	return nil
}

// CompileRuleExpr 把受控匹配器表达式编译成 nft token 序列。
// 白名单：ip saddr / ip6 saddr / tcp dport / udp dport / ct state / tcp flags syn。
func CompileRuleExpr(expr string) ([]string, *pluginapi.Error) {
	unsupportedExpr := func(msg string) *pluginapi.Error {
		return &pluginapi.Error{Code: pluginapi.E_UNSUPPORTED, Message: msg,
			Detail: jsonHint("允许的匹配器：ip saddr <IP/CIDR>、ip6 saddr <IPv6/CIDR>、tcp dport <端口[,端口]>、udp dport <端口[,端口]>、ct state <new|established|related|invalid[,..]>、tcp flags syn")}
	}
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) == 0 {
		return nil, unsupportedExpr("expr 不能为空")
	}
	switch {
	case len(fields) == 3 && fields[0] == "ip" && fields[1] == "saddr":
		if perr := checkIPValue(fields[2], false); perr != nil {
			return nil, perr
		}
		return []string{"ip", "saddr", fields[2]}, nil
	case len(fields) == 3 && fields[0] == "ip6" && fields[1] == "saddr":
		if perr := checkIPValue(fields[2], true); perr != nil {
			return nil, perr
		}
		return []string{"ip6", "saddr", fields[2]}, nil
	case len(fields) == 3 && (fields[0] == "tcp" || fields[0] == "udp") && fields[1] == "dport":
		tokens, perr := checkPortsValue(fields[2])
		if perr != nil {
			return nil, perr
		}
		return append([]string{fields[0], "dport"}, tokens...), nil
	case len(fields) == 3 && fields[0] == "ct" && fields[1] == "state":
		states, perr := checkStatesValue(fields[2])
		if perr != nil {
			return nil, perr
		}
		return append([]string{"ct", "state"}, states...), nil
	case len(fields) == 3 && fields[0] == "tcp" && fields[1] == "flags" && fields[2] == "syn":
		return []string{"tcp", "flags", "syn"}, nil
	}
	return nil, unsupportedExpr("expr 不在受控匹配器白名单内：" + expr)
}

// checkIPValue 校验 IP/CIDR（v4 或 v6）。
func checkIPValue(value string, wantV6 bool) *pluginapi.Error {
	head := value
	if index := strings.IndexByte(value, '/'); index >= 0 {
		head = value[:index]
	}
	ip := net.ParseIP(head)
	if ip == nil {
		return invalid("不是合法 IP/CIDR：" + value)
	}
	if wantV6 != (ip.To4() == nil) {
		return invalid(fmt.Sprintf("地址族不匹配：%s 需要 %s", value, map[bool]string{true: "IPv6", false: "IPv4"}[wantV6]))
	}
	return nil
}

// checkPortsValue 校验端口或逗号分隔的端口列表（1–65535），返回 nft token 序列。
func checkPortsValue(value string) ([]string, *pluginapi.Error) {
	parts := strings.Split(value, ",")
	if len(parts) > 16 {
		return nil, invalid("端口列表最多 16 项")
	}
	for _, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, invalid("端口必须是 1–65535：" + part)
		}
	}
	if len(parts) == 1 {
		return []string{parts[0]}, nil
	}
	tokens := []string{"{"}
	for index, part := range parts {
		token := strings.TrimSpace(part)
		if index < len(parts)-1 {
			token += ","
		}
		tokens = append(tokens, token)
	}
	return append(tokens, "}"), nil
}

// checkStatesValue 校验 ct state 枚举。
func checkStatesValue(value string) ([]string, *pluginapi.Error) {
	allowed := map[string]bool{"new": true, "established": true, "related": true, "invalid": true}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for index, part := range parts {
		state := strings.ToLower(strings.TrimSpace(part))
		if !allowed[state] {
			return nil, invalid("ct state 只允许 new/established/related/invalid：" + part)
		}
		if index < len(parts)-1 {
			state += ","
		}
		out = append(out, state)
	}
	return out, nil
}

// jsonHint 构造 detail.hint。
func jsonHint(hint string) json.RawMessage {
	raw, _ := json.Marshal(struct {
		Hint string `json:"hint"`
	}{Hint: hint})
	return raw
}

// ruleTokens 把一条自定义规则编译成 nft 追加 token（动作 + comment）。
func ruleTokens(name, expr, action string) ([]string, *pluginapi.Error) {
	exprTokens, perr := CompileRuleExpr(expr)
	if perr != nil {
		return nil, perr
	}
	tokens := append([]string{}, exprTokens...)
	tokens = append(tokens, action, "comment", ruleCommentPrefix+name)
	if len(tokens) > 28 {
		return nil, invalid(fmt.Sprintf("规则表达式过长（%d 个 token，上限 28）", len(tokens)))
	}
	return tokens, nil
}

// checkAction 只接受 drop / accept。
func checkAction(action string) *pluginapi.Error {
	if action != "drop" && action != "accept" {
		return invalid("action 只接受 drop 或 accept")
	}
	return nil
}

// nftChainRules 回读链上规则（handle + comment + verdict）。
func (b *NftBackend) nftChainRules() ([]ChainRule, error) {
	output, err := b.call(ActionNftList, nil)
	if err != nil {
		if commandErr, ok := err.(*NftCommandError); ok && isNftMissing(commandErr.Stderr) {
			return []ChainRule{}, nil
		}
		return nil, err
	}
	var payload struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output.Stdout, &payload); err != nil {
		return nil, NewOpError(OpFailed, "解析 nft JSON 失败: "+err.Error())
	}
	rules := []ChainRule{}
	for _, object := range payload.Nftables {
		rawRule, ok := object["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Handle int               `json:"handle"`
			Expr   []json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(rawRule, &rule); err != nil {
			continue
		}
		var comment, verdict string
		for _, exprRaw := range rule.Expr {
			var expr struct {
				Comment string `json:"comment"`
				Accept  *bool  `json:"accept"`
				Drop    *bool  `json:"drop"`
			}
			if err := json.Unmarshal(exprRaw, &expr); err != nil {
				continue
			}
			if expr.Comment != "" {
				comment = expr.Comment
			}
			if expr.Drop != nil {
				verdict = "drop"
			}
			if expr.Accept != nil {
				verdict = "accept"
			}
		}
		if comment == "" || !strings.HasPrefix(comment, ruleCommentPrefix) {
			continue
		}
		name := strings.TrimPrefix(comment, ruleCommentPrefix)
		builtin := false
		for _, candidate := range builtinRules {
			if candidate.Name == name {
				builtin = true
			}
		}
		rules = append(rules, ChainRule{Name: name, Action: verdict, Enabled: true,
			Builtin: builtin, Handle: rule.Handle})
	}
	return rules, nil
}
