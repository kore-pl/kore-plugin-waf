package wafop

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// kore 数据面的模式切换（0.3.0 起）。历史实现经 `sed -i` 改 ModSecurity 的模式包含
// 文件——那等于以 root 执行「任意表达式 + 任意文件」，审计里也看不出改了什么；
// 见 ADR-0022。现在模式 = **nft 规则集形态**：
//
//	observe：命中规则只 counter log，不阻断（看日志验证规则是否误伤）
//	enforce：命中规则 counter drop（真正阻断）
//	off    ：清空链（不删表/集合，封禁名单保留，重新 enforce 立即生效）

// ToggleParams 是 waf.toggle 的入参。confirm 只对「关闭防护」强制要求。
type ToggleParams struct {
	// Mode 目标模式：observe | enforce | off。
	Mode string `json:"mode"`
	// Level 目标等级：loose | standard | strict；不传按当前链上的实际等级，
	// 无法推断时按 standard（老客户端不带该字段时行为不变）。
	Level string `json:"level"`
	// Confirm 关闭防护（mode=off）时必须为 true。
	Confirm bool `json:"confirm"`
}

// Toggle 切换数据面模式：observe / enforce 重装规则集，off 清空链。
//
// 顺序：参数/确认 → 工具与通道可用性 → 幂等短路 → 下发 → **回读校验**。
// 任一步失败都如实返回 applied=false，不把「命令退出 0」当成「模式已生效」。
func Toggle(env Environment, params ToggleParams, root RootActionFunc) (ModeResult, *pluginapi.Error) {
	mode, perr := checkDataPlaneMode(params.Mode)
	if perr != nil {
		return ModeResult{}, perr
	}
	if mode == ModeOff && !params.Confirm {
		return ModeResult{}, unauthorized("关闭防护会放开全部流量（封禁名单保留但不生效）",
			"确认关闭请带 confirm=true 重试；只想观察不阻断请用 mode=observe")
	}
	level, perr := NormalizeLevel(params.Level)
	if perr != nil {
		return ModeResult{}, perr
	}
	backend := NewNftBackend(env, root)
	availability := backend.Availability()
	if !availability.Available {
		// 工具缺失属于「环境不支持」，返回结构化不可用（不报协议错误）。
		return ModeResult{Mode: mode, Level: level, Rules: []NftRule{}, Steps: []NftStep{},
			Hint: availability.Hint}, nil
	}
	// 不传 level 时沿用当前链上的实际等级：模式切换不该悄悄改掉用户选的等级。
	if strings.TrimSpace(params.Level) == "" {
		if chain, chainErr := backend.nftChainRules(); chainErr == nil {
			if derived := LevelFromChain(chain); derived != "" {
				level = derived
			}
		}
	}
	result, err := backend.ApplyLevel(mode, level)
	if err != nil {
		return result, classifyToggleChannel(err)
	}
	return result, nil
}

// checkDataPlaneMode 校验 mode 取值。
func checkDataPlaneMode(raw string) (string, *pluginapi.Error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "":
		return "", invalid("缺少必填参数 mode，可选：observe / enforce / off")
	case ModeObserve, ModeEnforce, ModeOff:
		return value, nil
	}
	return "", invalid("mode=" + raw + " 非法，可选：observe / enforce / off")
}

// Status 汇总数据面状态：nft 可用性 + 表状态 + 模式 + 封禁数 + 规则数。
func Status(env Environment, root RootActionFunc) StatusBackend {
	backend := NewNftBackend(env, root)
	availability := backend.Availability()
	status := StatusBackend{
		Tool: availability.Tool, Available: availability.Available, Channel: availability.Channel,
		Table: NftTable, Chain: NftChain, Mode: ModeOff,
	}
	status.Reason, status.Hint = availability.Reason, availability.Hint
	if !availability.Available || root == nil {
		return status
	}
	state, err := backend.State()
	if err != nil {
		var protocolErr *pluginapi.Error
		if errors.As(err, &protocolErr) {
			status.Reason = protocolErr.Message
			status.Hint = string(protocolErr.Detail)
			return status
		}
		status.Reason = err.Error()
		return status
	}
	status.Present = state.Present
	status.Mode = state.Mode
	status.Banned = len(state.Bans)
	status.RulesCount = len(state.Rules)
	status.Level = backend.currentLevel(state)
	if !state.Present {
		status.Hint = "数据面尚未初始化：调用 waf.toggle（mode=observe|enforce）或 waf.ban 会自动建表"
	}
	return status
}

// RootActionHint 是「下一步怎么做」的可操作提示（ADR-0018 降级硬要求）。
func rootActionHint(scope string) string {
	hint := "需 root 权限：请用 sudo/systemd 启动 kored（或在 systemd unit 里配置提权），" +
		"由内核经 ADR-0018 的 root-action 通道执行 nft 动作"
	if scope != "" {
		hint += "（当前：" + scope + "）"
	}
	return hint
}

// needRoot 构造 E_NEED_ROOT 协议错误，hint 同时进 message 与 detail。
func needRoot(message, hint string) *pluginapi.Error {
	return &pluginapi.Error{
		Code:    CodeNeedRoot,
		Message: message + "：" + hint,
		Detail:  detailHint(hint),
	}
}

// unauthorized 构造 E_UNAUTHORIZED 协议错误。
func unauthorized(message, hint string) *pluginapi.Error {
	return &pluginapi.Error{
		Code:    pluginapi.E_UNAUTHORIZED,
		Message: message + "（" + hint + "）",
		Detail:  detailHint(hint),
	}
}

// detailHint 把 hint 编成结构化 detail，前端可直接展示。
func detailHint(hint string) json.RawMessage {
	data, err := json.Marshal(struct {
		Hint string `json:"hint"`
	}{Hint: hint})
	if err != nil {
		return nil
	}
	return data
}

// classifyToggleChannel 把通道/命令错误映射为协议错误：内核明确拒绝的码原样透传，
// 其余归 E_UPSTREAM；注入故障走统一 classify。
func classifyToggleChannel(err error) *pluginapi.Error {
	var channel *ChannelError
	if errors.As(err, &channel) {
		switch channel.Code {
		case CodeNeedRoot, CodeNoSystemd, pluginapi.E_UNAUTHORIZED,
			pluginapi.E_UNSUPPORTED, pluginapi.E_INVALID, pluginapi.E_CONFLICT:
			return &pluginapi.Error{
				Code:    channel.Code,
				Message: channel.Message + hintSuffix(channel.Hint),
				Detail:  detailHint(channel.Hint),
			}
		}
		return upstream("root-action 通道失败: " + channel.Message + hintSuffix(channel.Hint))
	}
	var commandErr *NftCommandError
	if errors.As(err, &commandErr) {
		return upstream(commandErr.Error())
	}
	return classify(err)
}

// hintSuffix 把 hint 拼成 message 后缀（空 hint 不产生空括号）。
func hintSuffix(hint string) string {
	if strings.TrimSpace(hint) == "" {
		return ""
	}
	return "（" + hint + "）"
}
