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
	"bytes"
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
	// ExprTokens 是 nft 里该规则的原始 expr token 数：Expr 只还原「匹配条件」，
	// counter/log 等语句不进 Expr，保留 token 数便于核对是否完整反解。
	ExprTokens int `json:"expr_tokens,omitempty"`
}

// builtinRule 是内置基础防护规则的模板（与 info.json 的 nft-mode-* 对应）。
type builtinRule struct {
	Name   string
	Expr   string
	Action string
	// Tokens 是观察模式（counter log）的 token 序列；历史字段，保持原义。
	Tokens []string
	// EnforceTokens 是拦截模式（counter drop）的 token 序列；空表示与 Tokens 相同
	// （历史内置规则在 info.json 里按模式各有一份固定 argv，这里只补 strict 追加项）。
	EnforceTokens []string
}

// builtinRules 是 4 条内置规则；顺序即装载顺序。
//
// Tokens 是**观察模式**（counter log，无 verdict）的 token 序列，EnforceTokens 是拦截
// 模式（counter drop）。两者都必须与 info.json 的 nft-mode-* argv 等价——0.5.0 之前
// Tokens 只是「差不多」的残片（syn-rate/conn-rate 缺 meter/limit 与 ct count 参数），
// 规则重建会把限速规则装成全量日志规则；本次随等级功能一并修正。
var builtinRules = []builtinRule{
	{Name: "ban-ipv4", Expr: "ip saddr @banned4", Action: "drop",
		Tokens:        []string{"ip", "saddr", "@banned4", "counter", "log", "prefix", "kore-waf-ban4"},
		EnforceTokens: []string{"ip", "saddr", "@banned4", "counter", "drop"}},
	{Name: "ban-ipv6", Expr: "ip6 saddr @banned6", Action: "drop",
		Tokens:        []string{"ip6", "saddr", "@banned6", "counter", "log", "prefix", "kore-waf-ban6"},
		EnforceTokens: []string{"ip6", "saddr", "@banned6", "counter", "drop"}},
	{Name: "syn-rate", Expr: "tcp flags syn tcp dport { 80, 443 } meter kore_syn4 { ip saddr limit rate over 60/second burst 120 packets }",
		Action: "observe",
		Tokens: []string{"tcp", "flags", "syn", "tcp", "dport", "{", "80,", "443", "}", "meter", "kore_syn4",
			"{", "ip", "saddr", "limit", "rate", "over", "60/second", "burst", "120", "packets", "}",
			"counter", "log", "prefix", "kore-waf-scan"},
		EnforceTokens: []string{"tcp", "flags", "syn", "tcp", "dport", "{", "80,", "443", "}", "meter", "kore_syn4",
			"{", "ip", "saddr", "limit", "rate", "over", "60/second", "burst", "120", "packets", "}",
			"counter", "drop"}},
	{Name: "conn-rate", Expr: "tcp dport { 80, 443 } ct count over 200", Action: "observe",
		Tokens:        []string{"tcp", "dport", "{", "80,", "443", "}", "ct", "count", "over", "200", "counter", "log", "prefix", "kore-waf-conn"},
		EnforceTokens: []string{"tcp", "dport", "{", "80,", "443", "}", "ct", "count", "over", "200", "counter", "drop"}},
}

// builtinByName 返回内置模板（含 strict 等级追加的两条）。
//
// 注意 builtinRules 只含标准 4 条：它同时是「标准等级规则集」与旧测试的
// 数量基准。strict 追加项在 level.go 的 strictExtraRules 里。
func builtinByName(name string) (builtinRule, bool) {
	return builtinTemplateByName(name)
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

// nftChainRules 回读链上规则（name/expr/action/enabled/builtin/handle）。
//
// nft 1.1.x 把 `comment "kore-rule-x"` 放在 **rule 对象顶层**（"comment":"kore-rule-x"），
// 不在 expr[] 里；0.4.1 只扫 expr 导致 chain 恒空、rule.add 写后回读必失败（已发版缺陷）。
// 这里三层兜底：① rule.comment ② expr 里的 {"comment":...} ③ 都没有 → 非 kore 规则跳过；
// 内置 4 条规则本身没有 comment，用 token 签名识别（否则 UI 拿不到「内置+自定义」混合列表）。
func (b *NftBackend) nftChainRules() ([]ChainRule, error) {
	output, err := b.call(ActionNftList, nil)
	if err != nil {
		if commandErr, ok := err.(*NftCommandError); ok && isNftMissing(commandErr.Stderr) {
			return []ChainRule{}, nil
		}
		return nil, err
	}
	return parseChainRules(output.Stdout, NftChain)
}

// parseChainRules 解析 `nft -j list table/chain` 输出。
func parseChainRules(stdout []byte, wantChain string) ([]ChainRule, error) {
	var payload struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(stdout, &payload); err != nil {
		return nil, NewOpError(OpFailed, "解析 nft JSON 失败: "+err.Error())
	}
	rules := []ChainRule{}
	ruleObjects := 0
	seenAnyComment := false
	for _, object := range payload.Nftables {
		rawRule, ok := object["rule"]
		if !ok {
			continue
		}
		ruleObjects++
		var rule struct {
			Chain   string            `json:"chain"`
			Handle  int               `json:"handle"`
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(rawRule, &rule); err != nil {
			continue
		}
		if wantChain != "" && rule.Chain != "" && rule.Chain != wantChain {
			continue
		}
		comment, verdict := rule.Comment, ""
		seenComment := rule.Comment != ""
		if seenComment {
			seenAnyComment = true
		}
		for _, exprRaw := range rule.Expr {
			var expr map[string]json.RawMessage
			if err := json.Unmarshal(exprRaw, &expr); err != nil {
				continue
			}
			// nft 1.1.x 用 null 表示动作：只要键存在就是该动作（不能靠 *bool 非 nil 判断）。
			if _, ok := expr["drop"]; ok {
				verdict = "drop"
			}
			if _, ok := expr["accept"]; ok {
				verdict = "accept"
			}
			if raw, ok := expr["comment"]; ok {
				seenComment = true
				seenAnyComment = true
				var text string
				if json.Unmarshal(raw, &text) == nil && text != "" && comment == "" {
					comment = text
				}
			}
		}
		if strings.HasPrefix(comment, ruleCommentPrefix) {
			name := strings.TrimPrefix(comment, ruleCommentPrefix)
			builtin := false
			for _, candidate := range allBuiltinRules() {
				if candidate.Name == name {
					builtin = true
				}
			}
			// 自定义规则必须还原出可读 expr（如 `tcp dport 8443`）：0.4.3 只填 name/action，
			// 回读链里自定义规则的 expr 为空串，前端显示空白行（P3，0.4.4 修）。
			expr := renderRuleExpr(rule.Expr)
			if builtin {
				if candidate, ok := builtinByName(name); ok {
					expr = candidate.Expr
				}
			}
			if strings.TrimSpace(expr) == "" {
				expr = "（无匹配条件，" + strconv.Itoa(len(rule.Expr)) + " 个 nft token）"
			}
			rules = append(rules, ChainRule{Name: name, Expr: expr, Action: verdict, Enabled: true,
				Builtin: builtin, Handle: rule.Handle, ExprTokens: len(rule.Expr)})
			continue
		}
		// 内置规则没有 comment：按 expr 里的特征 token 识别，保证 chain 能列出内置规则
		// （标准 4 条 + strict 等级追加的 2 条）。
		if name, ok := builtinByTokens(rule.Expr); ok {
			if _, known := builtinTemplateByName(name); !known {
				continue
			}
			// 限速类与 strict 追加项在观察模式下没有 drop 动作：按实际 verdict 报，
			// 不硬编码成 drop（否则观察模式的链会被显示成「拦截」）。
			if verdict == "" {
				verdict = "observe"
			}
			candidate, _ := builtinTemplateByName(name)
			rules = append(rules, ChainRule{Name: name, Expr: candidate.Expr, Action: verdict,
				Enabled: true, Builtin: true, Handle: rule.Handle})
		}
	}
	// 兜底：JSON 里明明有规则对象、却一条 kore 规则都没解析出来 → 显式 E_UPSTREAM（不静默当空）。
	if ruleObjects > 0 && len(rules) == 0 && !seenAnyComment {
		snippet := string(stdout)
		if len(snippet) > 400 {
			snippet = snippet[:400] + "…"
		}
		return nil, NewOpError(OpFailed, "nft 回读解析不到任何 kore 规则（规则对象 "+strconv.Itoa(ruleObjects)+
			" 条）；原始输出片段："+snippet)
	}
	return rules, nil
}

// builtinByTokens 用特征 token 识别没有 comment 的内置规则。
func builtinByTokens(exprs []json.RawMessage) (string, bool) {
	joined := ""
	for _, exprRaw := range exprs {
		joined += string(exprRaw)
	}
	switch {
	case strings.Contains(joined, "@banned4"):
		return "ban-ipv4", true
	case strings.Contains(joined, "@banned6"):
		return "ban-ipv6", true
	case strings.Contains(joined, "kore_syn4"):
		return "syn-rate", true
	case strings.Contains(joined, "kore_ssh4"):
		return "ssh-rate", true
	case strings.Contains(joined, `"ct count"`),
		strings.Contains(joined, "ct") && strings.Contains(joined, "count"):
		// 老 nft 把 ct count 摊平成 ct / count 两个 token，新版是 `"ct count"` 对象：
		// 两种形态都要认（只作用于无 comment 的内置规则，自定义规则走 comment 分支）。
		return "conn-rate", true
	case strings.Contains(joined, "ct state invalid"):
		return "invalid-state", true
	case strings.Contains(joined, `"ct":`) && strings.Contains(joined, "invalid"):
		return "invalid-state", true
	}
	return "", false
}

// renderRuleExpr 把 nft `-j` 的 expr[] 反解成可读表达式（如 `tcp dport 8443`）。
//
// 只还原「匹配条件」：payload 匹配、ct count、set/prefix 字面量；
// counter / log / comment / drop / accept 不进 expr（动作由 Action 字段单独报）。
// 认不出的结构以 `raw:{...}` 形式保留原文，**绝不返回空串**——空 expr 会让前端显示空白行，
// 比给不完整信息更糟。返回的 token 数由调用方按 len(exprs) 记入 ChainRule.ExprTokens。
func renderRuleExpr(exprs []json.RawMessage) string {
	parts := make([]string, 0, len(exprs))
	for _, raw := range exprs {
		var piece map[string]json.RawMessage
		if err := json.Unmarshal(raw, &piece); err != nil {
			parts = append(parts, "raw:"+compactJSON(raw))
			continue
		}
		switch {
		case hasAnyKey(piece, "counter", "log", "comment", "drop", "accept"):
			continue // 计数/日志/注释/动作不属于匹配条件
		case hasAnyKey(piece, "match"):
			if text, ok := renderMatch(piece["match"]); ok {
				parts = append(parts, text)
				continue
			}
			parts = append(parts, "raw:"+compactJSON(raw))
		case hasAnyKey(piece, "ct count"):
			parts = append(parts, renderCtCount(piece["ct count"]))
		default:
			parts = append(parts, "raw:"+compactJSON(raw))
		}
	}
	return strings.Join(parts, " ")
}

// renderMatch 还原一条 `match` 语句：`<left> [op] <right>`（== / in 不写操作符）。
func renderMatch(raw json.RawMessage) (string, bool) {
	var match struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(raw, &match); err != nil {
		return "", false
	}
	left, ok := renderPayload(match.Left)
	if !ok {
		return "", false
	}
	right, ok := renderValue(match.Right)
	if !ok {
		return "", false
	}
	switch match.Op {
	case "==", "in":
		return left + " " + right, true
	case "!=", ">", ">=", "<", "<=":
		return left + " " + match.Op + " " + right, true
	}
	return "", false
}

// renderPayload 还原 `payload` 左值：`ip saddr` / `tcp dport` / `tcp flags`。
// nft 的左值是嵌套的 `{"payload":{"protocol":…,"field":…}}`（不是平铺）。
func renderPayload(raw json.RawMessage) (string, bool) {
	var left struct {
		Payload struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &left); err != nil {
		return "", false
	}
	if left.Payload.Protocol == "" || left.Payload.Field == "" {
		return "", false
	}
	return left.Payload.Protocol + " " + left.Payload.Field, true
}

// renderValue 还原右值：标量 / 集合 `{ 80, 443 }` / CIDR `10.20.0.0/16`。
func renderValue(raw json.RawMessage) (string, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if text == "" {
			return "", false
		}
		return text, true
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String(), true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return "", false
	}
	if setRaw, ok := object["set"]; ok {
		var elems []json.RawMessage
		if json.Unmarshal(setRaw, &elems) == nil {
			items := make([]string, 0, len(elems))
			for _, elem := range elems {
				value, ok := renderValue(elem)
				if !ok {
					return "", false
				}
				items = append(items, value)
			}
			if len(items) > 0 {
				return "{ " + strings.Join(items, ", ") + " }", true
			}
		}
	}
	if prefixRaw, ok := object["prefix"]; ok {
		var prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(prefixRaw, &prefix) == nil && prefix.Addr != "" {
			return prefix.Addr + "/" + strconv.Itoa(prefix.Len), true
		}
	}
	return "", false
}

// renderCtCount 还原 `ct count over 200`。
func renderCtCount(raw json.RawMessage) string {
	var count struct {
		Val int  `json:"val"`
		Inv bool `json:"inv"`
	}
	if err := json.Unmarshal(raw, &count); err != nil {
		return "ct count"
	}
	if count.Inv {
		return "ct count over " + strconv.Itoa(count.Val)
	}
	return "ct count " + strconv.Itoa(count.Val)
}

// hasAnyKey 判断对象里是否存在任一给定键（nft 用 null 表示动作，不能靠值判断）。
func hasAnyKey(fields map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		if _, ok := fields[key]; ok {
			return true
		}
	}
	return false
}

// compactJSON 压缩原始 JSON；压缩失败时退回原文（只用于 raw: 兜底展示）。
func compactJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err == nil && buf.Len() > 0 {
		return buf.String()
	}
	return string(raw)
}
