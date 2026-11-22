package wafop

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// ruleIDPattern 约束规则 ID 为 WAF- 加四位数字（如 WAF-0001）。
var ruleIDPattern = regexp.MustCompile(`^WAF-[0-9]{4}$`)

// checkRuleID 校验可选 rule_id：空表示不过滤，非空必须匹配 WAF-0000 格式。
func checkRuleID(raw string) *pluginapi.Error {
	if raw == "" {
		return nil
	}
	if !ruleIDPattern.MatchString(raw) {
		return invalid(fmt.Sprintf("rule_id %q 格式非法，期望 WAF-0000", raw))
	}
	return nil
}

// checkLimit 校验 limit：0 取缺省值；1..1000 合法；负数或超上限返回 E_INVALID。
func checkLimit(limit int) (int, *pluginapi.Error) {
	if limit == 0 {
		return defaultLimit, nil
	}
	if limit < 0 {
		return 0, invalid("limit 不能为负数")
	}
	if limit > maxLimit {
		return 0, invalid(fmt.Sprintf("limit=%d 超过 %d 上限，防止 DoS", limit, maxLimit))
	}
	return limit, nil
}

// decodeParams 校验 params 是 JSON 对象并反序列化到目标形状。
func decodeParams(raw json.RawMessage, target any) *pluginapi.Error {
	if len(raw) == 0 || string(raw) == "null" {
		return invalid("缺少必填参数对象")
	}
	if raw[0] != '{' {
		return invalid("params 必须是 JSON 对象")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return invalid("params 解析失败: " + err.Error())
	}
	return nil
}

// encode 把结果编码为 json.RawMessage；序列化失败归 E_INTERNAL。
func encode(v any) (json.RawMessage, *pluginapi.Error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, internalErr("序列化结果失败: " + err.Error())
	}
	return data, nil
}

func invalid(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: msg}
}

func errNotFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法: " + method}
}

func upstream(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_UPSTREAM, Message: msg}
}

func internalErr(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: msg}
}
