package main

import (
	"encoding/json"

	"github.com/pengtang1024/kore-plugin-waf/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// handleConfigGet 实现 <id>.config.get：返回 schema + 当前值 + 来源。
func handleConfigGet(cfg *config) (json.RawMessage, *pluginapi.Error) {
	values, err := json.Marshal(cfg.values)
	if err != nil {
		return nil, internalError("序列化配置值失败: " + err.Error())
	}
	result := plugincfg.GetResult{
		Schema: wafConfigSchema(),
		Values: values,
		Source: cfg.source,
	}
	return encodeResult(result)
}

// handleConfigSet 实现 <id>.config.set：校验 → 原子写 → 更新内存 → 返回 applied。
//
// 契约要求顺序固定；任一失败都不改内存、不写半份文件。
func handleConfigSet(raw json.RawMessage, cfg *config) (json.RawMessage, *pluginapi.Error) {
	var params plugincfg.SetParams
	if perr := decodeObject(raw, &params); perr != nil {
		return nil, perr
	}
	var optional optionalValues
	if err := decodeStrictJSON(params.Values, &optional); err != nil {
		return nil, invalidError("values 解析失败: " + err.Error())
	}
	merged := cfg.values
	applyOptional(&merged, optional)
	if err := validateValues(merged); err != nil {
		return nil, invalidError(err.Error())
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return nil, internalError("序列化配置值失败: " + err.Error())
	}
	if err := cfg.store.Write(data); err != nil {
		return nil, internalError("保存插件配置失败: " + err.Error())
	}
	settings, err := settingsFromValues(merged)
	if err != nil {
		return nil, invalidError(err.Error())
	}
	cfg.values = merged
	cfg.source = plugincfg.SourceFile
	cfg.runtime.SetSettings(settings)
	return encodeResult(plugincfg.SetResult{
		Saved:           true,
		Applied:         true,
		RestartRequired: false,
		Warnings:        []string{},
	})
}

// reloadConfig 处理 kore.reload：重新解析配置契约并热替换运行期参数。
func reloadConfig(cfg *config) (json.RawMessage, *pluginapi.Error) {
	values, source, err := resolveValues(cfg.store)
	if err != nil {
		return nil, internalError("重载配置失败: " + err.Error())
	}
	settings, err := settingsFromValues(values)
	if err != nil {
		return nil, internalError("重载配置失败: " + err.Error())
	}
	cfg.values = values
	cfg.source = source
	cfg.runtime.SetSettings(settings)
	return json.RawMessage(`{"ok":true,"config_digest":""}`), nil
}

// decodeObject 解码必填 JSON 对象参数（拒绝未知字段）。
func decodeObject(raw json.RawMessage, target any) *pluginapi.Error {
	if err := decodeStrictJSON(raw, target); err != nil {
		return invalidError("params 解析失败: " + err.Error())
	}
	return nil
}

// encodeResult 把结果编码为 json.RawMessage。
func encodeResult(value any) (json.RawMessage, *pluginapi.Error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, internalError("序列化结果失败: " + err.Error())
	}
	return data, nil
}

// invalidError 构造 E_INVALID。
func invalidError(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: message}
}

// internalError 构造 E_INTERNAL。
func internalError(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: message}
}
