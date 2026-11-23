package wafop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 模式切换用到的 root_actions（info.json 里声明的 id 必须与这里一致）。
const (
	// ActionSetMode 写入 kore 管理的模式包含文件（固定 argv + 追加 sed 参数）。
	ActionSetMode = "modsec-set-mode"
	// ActionReloadNginx 重载 nginx 让模式变更生效。
	ActionReloadNginx = "nginx-reload"
)

// Toggle 切换 WAF 运行模式。
//
// 决策顺序（每一步都可解释）：
//  1. 未检测到引擎 → 结构化 E_UNSUPPORTED（不是协议错误，UI 仍能展示原因）；
//  2. 目标模式与当前一致 → applied=true，不执行任何提权动作；
//  3. 引擎不支持运行时切换（naxsi / crowdsec）→ 结构化 E_UNSUPPORTED + hint；
//  4. 关闭拦截（mode=off）必须显式 confirm，否则 E_UNAUTHORIZED；
//  5. 没有 root-action 通道 → E_NEED_ROOT + hint（ADR-0018 降级硬要求）；
//  6. 模式包含文件不存在/不含 SecRuleEngine → 结构化 E_UNSUPPORTED + 怎么修；
//  7. 经通道写入并回读校验，再 reload nginx；任何一步失败都如实 applied=false。
func Toggle(env Environment, settings Settings, params ToggleParams, root RootActionFunc) (ToggleResult, *pluginapi.Error) {
	env = defaultEnvironment(env)
	s := settings.normalized()
	detection, err := Detect(env, s)
	if err != nil {
		return ToggleResult{}, classify(err)
	}
	result := ToggleResult{
		Engine: detection.Engine, Mode: detection.Mode, PreviousMode: detection.Mode,
		Available: detection.Found, Steps: []ToggleStep{},
	}
	if !detection.Found {
		result.ErrorCode = pluginapi.E_UNSUPPORTED
		result.Hint = installHint()
		return result, nil
	}
	if params.Mode == detection.Mode {
		result.Applied = true
		result.Hint = "当前已是 " + params.Mode + " 模式，未执行任何提权动作"
		return result, nil
	}
	if detection.Engine != EngineModSecurity && detection.Engine != EngineCoraza {
		result.ErrorCode = pluginapi.E_UNSUPPORTED
		result.Hint = detection.Engine + " 不支持运行时模式切换；请在引擎自身配置中修改（naxsi: SecRulesEnabled / LearningMode，crowdsec: 启停 bouncer）"
		return result, nil
	}
	if params.Mode == ModeOff && !params.Confirm {
		return ToggleResult{}, unauthorized("关闭拦截会放开全部流量，需要显式确认",
			"确认关闭请带 confirm=true 重试；建议先用 mode=detection 观察")
	}
	if root == nil {
		return ToggleResult{}, needRoot("切换 WAF 模式需要 root 权限，但插件没有可用的 root-action 通道",
			rootActionHint(detection.Engine))
	}
	modePath := modeConfigPath(s, detection.Engine)
	if problem, err := modeFileProblem(env, modePath); err != nil {
		return ToggleResult{}, classify(err)
	} else if problem != "" {
		result.ErrorCode = pluginapi.E_UNSUPPORTED
		result.Hint = problem
		return result, nil
	}
	expression := sedExpression(params.Mode)
	stdout, exitCode, err := root(ActionSetMode, []string{"-e", expression, modePath})
	if err != nil {
		return ToggleResult{}, classifyToggleChannel(err)
	}
	step := ToggleStep{Action: ActionSetMode, ExitCode: exitCode, OK: exitCode == 0}
	if exitCode != 0 {
		step.Error = trimLine(stdout, 200)
		result.Steps = append(result.Steps, step)
		result.ErrorCode = pluginapi.E_UPSTREAM
		result.Hint = "写入模式文件失败（退出码 " + fmt.Sprint(exitCode) + "）：" + step.Error
		return result, nil
	}
	result.Steps = append(result.Steps, step)
	// 回读校验：不把「命令退出 0」当成「模式已改」，以文件实际内容为准。
	if actual, _, err := scanSecRuleEngine(env, []string{modePath}); err != nil {
		return ToggleResult{}, classify(err)
	} else if actual != params.Mode {
		result.ErrorCode = pluginapi.E_UPSTREAM
		result.Hint = "模式文件写入后回读为 " + actual + "，期望 " + params.Mode + "；未完成切换"
		return result, nil
	}
	if _, ok := env.LookPath("nginx"); !ok {
		result.Mode = params.Mode
		result.Applied = true
		result.Hint = "模式文件已写入；未检测到 nginx，跳过 reload（Apache 部署请手动 graceful）"
		return result, nil
	}
	stdout, exitCode, err = root(ActionReloadNginx, nil)
	if err != nil {
		return ToggleResult{}, classifyToggleChannel(err)
	}
	reloadStep := ToggleStep{Action: ActionReloadNginx, ExitCode: exitCode, OK: exitCode == 0}
	if exitCode != 0 {
		reloadStep.Error = trimLine(stdout, 200)
		result.Steps = append(result.Steps, reloadStep)
		result.ErrorCode = pluginapi.E_UPSTREAM
		result.Hint = "模式文件已写入，但 nginx reload 失败（退出码 " + fmt.Sprint(exitCode) + "）：" +
			reloadStep.Error + "；变更尚未生效"
		return result, nil
	}
	result.Steps = append(result.Steps, reloadStep)
	result.Mode = params.Mode
	result.Applied = true
	result.Reloaded = true
	return result, nil
}

// modeFileProblem 检查模式包含文件是否可安全改写；返回非空提示表示不可用。
//
// 安全护栏：只允许改写「内容里已经有 SecRuleEngine 指令」的普通文件，
// 防止配置被误指到 /etc/passwd 之类无关文件后被 sed 覆盖。
func modeFileProblem(env Environment, path string) (string, error) {
	meta, err := env.Stat(path)
	if err != nil {
		if isFault(err) {
			return "", err
		}
		if isNotExist(err) {
			return "模式包含文件 " + path + " 不存在。请创建该文件并写入 `SecRuleEngine Off`，" +
				"再在引擎主配置里加 `Include " + path + "`（该 Include 需在其它 SecRuleEngine 之后）", nil
		}
		if isPermission(err) {
			return "无权访问模式包含文件 " + path + "：" + rootActionHint(""), nil
		}
		return "无法访问模式包含文件 " + path + "：" + err.Error(), nil
	}
	if meta.IsDir {
		return "模式包含文件 " + path + " 是目录，不是文件", nil
	}
	if meta.Size > 64<<10 {
		return "模式包含文件 " + path + " 超过 64 KiB，拒绝改写（防止误指到日志/数据库文件）", nil
	}
	data, err := env.ReadFile(path)
	if err != nil {
		if isFault(err) {
			return "", err
		}
		return "无法读取模式包含文件 " + path + "：" + err.Error(), nil
	}
	if !secRuleEngineRe.Match(data) {
		return "模式包含文件 " + path + " 不含 SecRuleEngine 指令，拒绝改写（防止误覆盖无关文件）；" +
			"请先写入一行 `SecRuleEngine Off` 并在引擎配置里 Include 它", nil
	}
	return "", nil
}

// sedExpression 生成幂等的模式写入表达式：把文件内所有 SecRuleEngine 行改成目标值。
func sedExpression(mode string) string {
	value := "Off"
	switch mode {
	case ModeOn:
		value = "On"
	case ModeDetection:
		value = "DetectionOnly"
	}
	return "s/^[[:space:]]*SecRuleEngine[[:space:]].*/SecRuleEngine " + value + "/"
}

// rootActionHint 是「下一步怎么做」的可操作提示（ADR-0018 降级硬要求）。
func rootActionHint(engine string) string {
	hint := "需 root 权限：请用 sudo/systemd 启动 kored（或在 systemd unit 里配置提权），" +
		"由内核经 ADR-0018 的 root-action 通道执行 " + ActionSetMode + " / " + ActionReloadNginx
	if engine != "" {
		hint += "；当前引擎=" + engine
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

// classifyToggleChannel 把通道错误映射为协议错误：内核明确拒绝的码原样透传，
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
	return classify(err)
}

// hintSuffix 把 hint 拼成 message 后缀（空 hint 不产生空括号）。
func hintSuffix(hint string) string {
	if strings.TrimSpace(hint) == "" {
		return ""
	}
	return "（" + hint + "）"
}
