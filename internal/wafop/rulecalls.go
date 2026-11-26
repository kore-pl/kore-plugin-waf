package wafop

// rule.* 的方法面：参数校验 → 拼 token → 走 root-action → 回读比对 → 失败回滚。

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

const (
	// ActionNftAddRule / ActionNftDeleteRule 是 rule.* 使用的两个 root_actions。
	ActionNftAddRule    = "nft-add-rule"
	ActionNftDeleteRule = "nft-delete-rule"
)

// ruleRegistry 记录本次进程内增删过的自定义规则（用于 toggle 重建与回滚）。
type ruleRegistry struct {
	custom map[string]ruleParams
	order  []string
}

// disabledBuiltins 记录被停用的内置规则（进程内状态；nft 重启后按默认全开）。
var disabledBuiltins = map[string]bool{}

func (r *Runtime) ensureRegistry() {
	if r.registry == nil {
		r.registry = &ruleRegistry{custom: map[string]ruleParams{}}
	}
}

// nftBackend 构造执行面。
func (r *Runtime) nftBackend() *NftBackend { return NewNftBackend(r.env, r.root) }

// requireRuleChannel 要求 root 通道可用（rule.* 全部是写操作）。
func (r *Runtime) requireRuleChannel() *pluginapi.Error {
	backend := r.nftBackend()
	availability := backend.Availability()
	if !availability.Available || r.root == nil {
		return needRoot("规则增删/启停需要 root-action 通道", availability.Hint)
	}
	return nil
}

func (r *Runtime) callRuleAdd(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p ruleParams
	if perr := decodeStrict(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := r.ruleWritePrecheck(&p, true); perr != nil {
		return nil, perr
	}
	return r.applyRuleAdd(p, false)
}

func (r *Runtime) callRuleRemove(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p ruleParams
	if perr := decodeStrict(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := ValidateRuleName(p.Name); perr != nil {
		return nil, perr
	}
	if _, builtin := builtinByName(p.Name); builtin {
		return nil, invalid("内置规则只能停用不能删除：" + p.Name + "（用 rule.toggle enabled=false）")
	}
	if perr := r.requireRuleChannel(); perr != nil {
		return nil, perr
	}
	return r.applyRuleRemove(p.Name, false)
}

func (r *Runtime) callRuleToggle(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p ruleParams
	if perr := decodeStrict(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := ValidateRuleName(p.Name); perr != nil {
		return nil, perr
	}
	if p.Enabled == nil {
		return nil, invalid("rule.toggle 需要 enabled 字段（true|false）")
	}
	if perr := r.requireRuleChannel(); perr != nil {
		return nil, perr
	}
	if builtin, ok := builtinByName(p.Name); ok {
		return r.toggleBuiltin(builtin, *p.Enabled)
	}
	if *p.Enabled {
		param, known := r.registryCustom(p.Name)
		if !known {
			return nil, invalid("未知自定义规则：" + p.Name + "（先 rule.add 提供 expr/action）")
		}
		return r.applyRuleAdd(param, true)
	}
	return r.applyRuleRemove(p.Name, true)
}

// ruleWritePrecheck 校验 name/expr/action 与重复。
func (r *Runtime) ruleWritePrecheck(p *ruleParams, requireExpr bool) *pluginapi.Error {
	if perr := ValidateRuleName(p.Name); perr != nil {
		return perr
	}
	if _, builtin := builtinByName(p.Name); builtin {
		return invalid("内置规则已存在，不能重复添加：" + p.Name + "（需要调整用 rule.toggle）")
	}
	if requireExpr {
		if strings.TrimSpace(p.Expr) == "" {
			return invalid("rule.add 需要 expr（受控匹配器，如 ip saddr 1.2.3.4）")
		}
		if perr := checkAction(p.Action); perr != nil {
			return perr
		}
		if _, perr := ruleTokens(p.Name, p.Expr, p.Action); perr != nil {
			return perr
		}
	}
	if perr := r.requireRuleChannel(); perr != nil {
		return perr
	}
	return nil
}

// applyRuleAdd 幂等添加：已存在则直接回读返回。
func (r *Runtime) applyRuleAdd(p ruleParams, fromToggle bool) (json.RawMessage, *pluginapi.Error) {
	chain, err := r.nftBackend().nftChainRules()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	for _, existing := range chain {
		if existing.Name == p.Name {
			return r.ruleResult(p.Name, "add", false, chain)
		}
	}
	tokens, perr := ruleTokens(p.Name, p.Expr, p.Action)
	if perr != nil {
		return nil, perr
	}
	output, err := r.root(ActionNftAddRule, tokens)
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	if output.ExitCode != 0 {
		return nil, upstream("nft 添加规则失败（退出码 " + fmt.Sprint(output.ExitCode) + "）：" + trimLine(output.Stderr, 300))
	}
	after, err := r.nftBackend().nftChainRules()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	if !chainHas(after, p.Name) {
		// 回读不到 ⇒ 回滚：按 comment 找不到就按 handle 兜底查一次再删。
		return nil, r.rollbackAdd(p.Name, "写后回读不到规则 "+p.Name)
	}
	r.rememberCustom(p)
	return r.ruleResult(p.Name, "add", true, after)
}

// applyRuleRemove 幂等删除：不存在则返回 applied=false。
func (r *Runtime) applyRuleRemove(name string, fromToggle bool) (json.RawMessage, *pluginapi.Error) {
	chain, err := r.nftBackend().nftChainRules()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	target, found := findChainRule(chain, name)
	if !found {
		return r.ruleResult(name, "remove", false, chain)
	}
	output, err := r.root(ActionNftDeleteRule, []string{fmt.Sprint(target.Handle)})
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	if output.ExitCode != 0 {
		return nil, upstream("nft 删除规则失败（退出码 " + fmt.Sprint(output.ExitCode) + "）：" + trimLine(output.Stderr, 300))
	}
	after, err := r.nftBackend().nftChainRules()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	if _, still := findChainRule(after, name); still {
		return nil, upstream("删除后回读规则仍存在：" + name)
	}
	// 内置规则的启停状态单独记：重建链时按它跳过。
	if _, builtin := builtinByName(name); builtin {
		disabledBuiltins[name] = true
	}
	// 显式 remove 真删 registry：后续 toggle 内置规则触发 rebuildChain 时不会重放复活；
	// toggle off 保留 registry，便于随后 toggle on 恢复同一 expr。
	if !fromToggle {
		r.forgetCustom(name)
	}
	return r.ruleResult(name, "remove", true, after)
}

// toggleBuiltin 用重建链的方式启停内置规则（内置规则的表达式来自模板）。
func (r *Runtime) toggleBuiltin(rule builtinRule, enabled bool) (json.RawMessage, *pluginapi.Error) {
	if disabledBuiltins[rule.Name] == !enabled {
		chain, err := r.nftBackend().nftChainRules()
		if err != nil {
			return nil, classifyToggleChannel(err)
		}
		return r.ruleResult(rule.Name, "toggle", false, chain)
	}
	chain, err := r.nftBackend().nftChainRules()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	before := append([]ChainRule(nil), chain...)
	disabledBuiltins[rule.Name] = !enabled
	if err := r.rebuildChain(); err != nil {
		// 回滚：还原内置启停标记，再按重建前快照重放一次。
		disabledBuiltins[rule.Name] = enabled
		if rollbackErr := r.rebuildChain(); rollbackErr != nil {
			return nil, upstream("重建链失败且回滚失败：" + err.Error() + "；回滚：" + rollbackErr.Error())
		}
		return nil, upstream("重建链失败，已回滚到重放前规则集：" + err.Error())
	}
	after, err := r.nftBackend().nftChainRules()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	_ = before
	return r.ruleResult(rule.Name, "toggle", true, after)
}

// rebuildChain 清空并按「已启用内置 + 已登记自定义」重装规则。
//
// 重建必须保持**当前模式与等级**：内置规则在拦截模式是 counter drop、观察模式是
// counter log；strict 等级还要补回追加项。老实现固定用观察模式的 token 重装，
// 导致「在拦截模式下停用一条规则」会把整链悄悄降级成只记录（0.5.0 修）。
func (r *Runtime) rebuildChain() error {
	mode, level := r.dataState()
	if mode == "" || level == "" {
		if chain, err := r.nftBackend().nftChainRules(); err == nil {
			if mode == "" {
				mode = modeFromChain(chain)
			}
			if level == "" {
				level = LevelFromChain(chain)
				if level == "" {
					level = LevelStandard
				}
			}
		}
	}
	if mode == "" {
		mode = ModeObserve
	}
	if level == "" {
		level = LevelStandard
	}
	if _, err := r.root(ActionNftFlush, nil); err != nil {
		return err
	}
	for _, builtin := range builtinRules {
		if disabledBuiltins[builtin.Name] {
			continue
		}
		if level == LevelLoose && (builtin.Name == "syn-rate" || builtin.Name == "conn-rate") {
			continue
		}
		if output, err := r.root(ActionNftAddRule, builtinTokensFor(builtin, mode)); err != nil {
			return err
		} else if output.ExitCode != 0 {
			return fmt.Errorf("重装内置规则 %s 失败（退出码 %d）", builtin.Name, output.ExitCode)
		}
	}
	if level == LevelStrict {
		for _, extra := range strictExtraRules {
			if disabledBuiltins[extra.Name] {
				continue
			}
			if output, err := r.root(ActionNftAddRule, builtinTokensFor(extra, mode)); err != nil {
				return err
			} else if output.ExitCode != 0 {
				return fmt.Errorf("重装内置规则 %s 失败（退出码 %d）", extra.Name, output.ExitCode)
			}
		}
	}
	for _, name := range r.registryOrder() {
		param := r.registry.custom[name]
		tokens, perr := ruleTokens(param.Name, param.Expr, param.Action)
		if perr != nil {
			continue
		}
		if output, err := r.root(ActionNftAddRule, tokens); err != nil {
			return err
		} else if output.ExitCode != 0 {
			return fmt.Errorf("重装自定义规则 %s 失败（退出码 %d）", name, output.ExitCode)
		}
	}
	return nil
}

// rollbackAdd 在回读失败时清理可能已落地的规则。
func (r *Runtime) rollbackAdd(name, reason string) *pluginapi.Error {
	chain, err := r.nftBackend().nftChainRules()
	if err == nil {
		if target, found := findChainRule(chain, name); found {
			_, _ = r.root(ActionNftDeleteRule, []string{fmt.Sprint(target.Handle)})
		}
	}
	return upstream(reason + "；已回滚该规则")
}

// ruleResult 组装结果（含写后回读链）。
func (r *Runtime) ruleResult(name, op string, applied bool, chain []ChainRule) (json.RawMessage, *pluginapi.Error) {
	rule := ChainRule{Name: name, Enabled: false}
	for _, candidate := range chain {
		if candidate.Name == name {
			rule = candidate
		}
	}
	if _, builtin := builtinByName(name); builtin {
		rule.Builtin = true
		if disabledBuiltins[name] {
			rule.Enabled = false
		} else {
			rule.Enabled = true
		}
	} else if param, ok := r.registryCustom(name); ok {
		rule.Expr = param.Expr
		rule.Action = param.Action
	}
	result := RuleChangeResult{Applied: applied, Action: op, Rule: rule, Chain: chain}
	return encode(result)
}

func chainHas(chain []ChainRule, name string) bool {
	_, found := findChainRule(chain, name)
	return found
}

func findChainRule(chain []ChainRule, name string) (ChainRule, bool) {
	for _, rule := range chain {
		if rule.Name == name {
			return rule, true
		}
	}
	return ChainRule{}, false
}

func (r *Runtime) rememberCustom(p ruleParams) {
	r.ensureRegistry()
	if _, ok := r.registry.custom[p.Name]; !ok {
		r.registry.order = append(r.registry.order, p.Name)
	}
	r.registry.custom[p.Name] = p
}

func (r *Runtime) forgetCustom(name string) {
	r.ensureRegistry()
	delete(r.registry.custom, name)
	for index, existing := range r.registry.order {
		if existing == name {
			r.registry.order = append(r.registry.order[:index], r.registry.order[index+1:]...)
			break
		}
	}
}

func (r *Runtime) registryCustom(name string) (ruleParams, bool) {
	if r.registry == nil {
		return ruleParams{}, false
	}
	param, ok := r.registry.custom[name]
	return param, ok
}

func (r *Runtime) registryOrder() []string {
	if r.registry == nil {
		return nil
	}
	return append([]string(nil), r.registry.order...)
}
