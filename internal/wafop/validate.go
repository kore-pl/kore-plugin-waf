package wafop

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// allowedEngines 是 engine 参数的合法取值。
var allowedEngines = map[string]bool{
	"auto":            true,
	EngineModSecurity: true,
	EngineNaxsi:       true,
	EngineCoraza:      true,
	EngineCrowdSec:    true,
}

// allowedModes 是 toggle 的合法模式。
var allowedModes = map[string]bool{
	ModeOn:        true,
	ModeDetection: true,
	ModeOff:       true,
}

// checkEngine 校验可选的 engine 参数：空与 auto 等价；非法值给可操作提示。
func checkEngine(raw string) (string, *pluginapi.Error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "auto", nil
	}
	if !allowedEngines[value] {
		return "", invalid(fmt.Sprintf("engine=%q 非法，可选：auto / modsecurity / naxsi / coraza / crowdsec", raw))
	}
	return value, nil
}

// checkMode 校验 toggle 的 mode 参数（必填）。
func checkMode(raw string) (string, *pluginapi.Error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", invalid("缺少必填参数 mode，可选：on / detection / off")
	}
	if !allowedModes[value] {
		return "", invalid(fmt.Sprintf("mode=%q 非法，可选：on / detection / off", raw))
	}
	return value, nil
}

// checkLogLimit 校验 limit：0 取缺省值；负数或超过 200 返回 E_INVALID。
func checkLogLimit(limit int) (int, *pluginapi.Error) {
	if limit == 0 {
		return DefaultLogLimit, nil
	}
	if limit < 0 {
		return 0, invalid("limit 不能为负数")
	}
	if limit > MaxLogLimit {
		return 0, invalid(fmt.Sprintf("limit=%d 超过 %d 上限，防止一次返回过多日志", limit, MaxLogLimit))
	}
	return limit, nil
}

// checkRuleIDFilter 校验 rule_id 过滤参数：长度上限 + 禁止控制字符。
func checkRuleIDFilter(raw string) *pluginapi.Error {
	if raw == "" {
		return nil
	}
	if utf8.RuneCountInString(raw) > MaxRuleIDRunes {
		return invalid(fmt.Sprintf("rule_id 超过 %d 个字符", MaxRuleIDRunes))
	}
	if strings.IndexFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return invalid("rule_id 不得包含控制字符")
	}
	return nil
}

// checkSince 校验 since：相对时长或绝对时间，长度上限 64。
func checkSince(raw string) *pluginapi.Error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	if utf8.RuneCountInString(value) > MaxSinceRunes {
		return invalid(fmt.Sprintf("since 超过 %d 个字符", MaxSinceRunes))
	}
	if _, _, err := parseSince(value, time.Now()); err != nil {
		return invalid("since 只接受相对时长（如 1h / 30m / 7d）或 RFC3339 时间")
	}
	return nil
}

// decodeOptional 解码可选参数：缺省、null、空对象都合法。
func decodeOptional(raw json.RawMessage, target any) *pluginapi.Error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return decodeStrict(raw, target)
}

// decodeStrict 解码参数对象并拒绝未知字段（拼错字段会立刻暴露，而不是静默忽略）。
func decodeStrict(raw json.RawMessage, target any) *pluginapi.Error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return invalid("请传入参数对象 params（不能为空或 null）")
	}
	if trimmed[0] != '{' {
		return invalid("params 必须是 JSON 对象")
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalid("params 解析失败: " + err.Error())
	}
	if err := ensureNoTrailing(decoder); err != nil {
		return invalid(err.Error())
	}
	return nil
}

// ensureNoTrailing 拒绝 JSON 对象后的多余内容（`{} garbage` 不能当合法参数）。
func ensureNoTrailing(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("params 对象后存在多余内容")
	}
	return nil
}

// encode 把结果编码为 json.RawMessage；序列化失败归 E_INTERNAL。
func encode(value any) (json.RawMessage, *pluginapi.Error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, internalErr("序列化结果失败: " + err.Error())
	}
	return data, nil
}

// invalid 构造 E_INVALID。
func invalid(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: message}
}

// errNotFound 构造 E_NOTFOUND。
func errNotFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法: " + method}
}

// upstream 构造 E_UPSTREAM。
func upstream(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_UPSTREAM, Message: message}
}

// unsupported 构造 E_UNSUPPORTED。
func unsupported(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_UNSUPPORTED, Message: message}
}

// internalErr 构造 E_INTERNAL。
func internalErr(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: message}
}
