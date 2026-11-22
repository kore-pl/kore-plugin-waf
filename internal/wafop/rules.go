package wafop

import (
	"encoding/json"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callRules 处理 waf.rules：校验 rule_id 格式与 limit 上限后返回规则集占位。
func callRules(raw json.RawMessage, root string, exec Executor) (json.RawMessage, *pluginapi.Error) {
	var p rulesParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := checkRuleID(p.RuleID); perr != nil {
		return nil, perr
	}
	limit, perr := checkLimit(p.Limit)
	if perr != nil {
		return nil, perr
	}
	rules, err := exec.Rules(root, p.RuleID, limit)
	if err != nil {
		return nil, classify(err)
	}
	if rules == nil {
		rules = []Rule{}
	}
	return encode(RulesResult{
		Root:       root,
		Rules:      rules,
		Count:      len(rules),
		Limit:      limit,
		FilterRule: p.RuleID,
		Applied:    false,
	})
}

// noopExecutor 是骨架默认执行面：不接真实 WAF 引擎，只返回空结果。
// 基础故障注入测试提供自己的 exec，让 Call 走错误映射路径。
type noopExecutor struct{}

func (noopExecutor) Rules(root, ruleID string, limit int) ([]Rule, error) { return nil, nil }
func (noopExecutor) BlockLog(root, ruleID string, limit int) ([]BlockLogEntry, error) {
	return nil, nil
}
