package wafop

import (
	"encoding/json"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callBlockLog 处理 waf.blockLog：校验 rule_id 格式与 limit 上限后返回拦截日志占位。
func callBlockLog(raw json.RawMessage, root string, exec Executor) (json.RawMessage, *pluginapi.Error) {
	var p blockLogParams
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
	entries, err := exec.BlockLog(root, p.RuleID, limit)
	if err != nil {
		return nil, classify(err)
	}
	if entries == nil {
		entries = []BlockLogEntry{}
	}
	return encode(BlockLogResult{
		Root:       root,
		Entries:    entries,
		Count:      len(entries),
		Limit:      limit,
		FilterRule: p.RuleID,
		Applied:    false,
	})
}
