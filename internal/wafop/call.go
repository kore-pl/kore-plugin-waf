package wafop

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// Options 构造方法面所需的依赖；Env 为空时用真实宿主环境。
type Options struct {
	// Env 是宿主环境访问入口（探测/读取/命令执行）。
	Env Environment
	// Settings 是配置契约解析出的运行期参数。
	Settings Settings
	// RootAction 是内核 root-action 通道；nil 表示通道不可用（非 root 且无内核注入）。
	RootAction RootActionFunc
}

// Runtime 是 waf 方法面的执行体：方法分发 + 参数校验 + 引擎操作。
type Runtime struct {
	env      Environment
	settings Settings
	root     RootActionFunc
}

// New 构造 Runtime；Env 缺省字段补真实实现，Settings 补齐缺省值。
func New(opts Options) *Runtime {
	settings := opts.Settings.normalized()
	if len(settings.RulesDirs) == 0 {
		settings.RulesDirs = nil
	}
	return &Runtime{env: defaultEnvironment(opts.Env), settings: settings, root: opts.RootAction}
}

// SetSettings 替换运行期配置（config.set 后立即生效，无需重启进程）。
func (r *Runtime) SetSettings(settings Settings) {
	r.settings = settings.normalized()
}

// Settings 返回当前运行期配置（副本）。
func (r *Runtime) Settings() Settings { return r.settings }

// Call 执行一个 waf 方法：归一方法名 → 参数校验 → 引擎操作 → 结构化结果。
// 同时接受 `waf.<verb>` 与裸 `<verb>`；`waf.blockLog` 是 `waf.logs` 的兼容别名。
func (r *Runtime) Call(method string, params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	verb, ok := businessVerb(method)
	if !ok {
		return nil, errNotFound(method)
	}
	switch verb {
	case "status":
		return r.callStatus(params)
	case "rules":
		return r.callRules(params)
	case "logs":
		return r.callLogs(params)
	case "toggle":
		return r.callToggle(params)
	}
	return nil, errNotFound(method)
}

// businessVerb 把 waf.<verb> 或裸 <verb> 归一为动词名；blockLog 兼容到 logs。
func businessVerb(method string) (string, bool) {
	verb := strings.TrimPrefix(method, "waf.")
	switch verb {
	case "status", "rules", "logs", "blockLog", "toggle":
		if verb == "blockLog" {
			return "logs", true
		}
		return verb, true
	}
	return "", false
}

// statusParams 是 waf.status 的入参（当前无字段，显式空结构体便于未来扩展）。
type statusParams struct{}

// rulesParams 是 waf.rules 的入参；engine 可临时覆盖配置里的首选引擎。
type rulesParams struct {
	Engine string `json:"engine"`
}

// logsParams 是 waf.logs 的入参。
type logsParams struct {
	Limit  int    `json:"limit"`
	Since  string `json:"since"`
	RuleID string `json:"rule_id"`
	Engine string `json:"engine"`
}

// toggleParams 是 waf.toggle 的入参。
type toggleParams struct {
	Mode    string `json:"mode"`
	Confirm bool   `json:"confirm"`
}

// callStatus 组装状态：引擎 + 版本 + 模式 + 规则条数 + 降级提示。
func (r *Runtime) callStatus(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p statusParams
	if perr := decodeOptional(raw, &p); perr != nil {
		return nil, perr
	}
	detection, err := Detect(r.env, r.settings)
	if err != nil {
		return nil, classify(err)
	}
	rules, err := ListRules(r.env, r.settings, detection)
	if err != nil {
		return nil, classify(err)
	}
	result := StatusResult{
		Available:     detection.Found,
		Engine:        detection.Engine,
		Version:       detection.Version,
		VersionSource: detection.VersionSource,
		RulesCount:    rules.Total,
		Mode:          detection.Mode,
		ModeSource:    detection.ModeSource,
		CRSVersion:    detection.CRSVersion,
		RequiresRoot:  true,
		Probed:        detection.Probed,
	}
	if !detection.Found {
		result.ErrorCode = pluginapi.E_UNSUPPORTED
		result.Hint = installHint()
	}
	return encode(result)
}

// callRules 列出规则集；未检测到引擎时返回 available=false + hint。
func (r *Runtime) callRules(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p rulesParams
	if perr := decodeOptional(raw, &p); perr != nil {
		return nil, perr
	}
	engine, perr := checkEngine(p.Engine)
	if perr != nil {
		return nil, perr
	}
	settings := r.settingsFor(p.Engine, engine)
	detection, err := Detect(r.env, settings)
	if err != nil {
		return nil, classify(err)
	}
	result, err := ListRules(r.env, settings, detection)
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// callLogs 读取拦截日志；未检测到引擎或日志不可读时返回结构化信息，不报错。
func (r *Runtime) callLogs(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p logsParams
	if perr := decodeOptional(raw, &p); perr != nil {
		return nil, perr
	}
	limit, perr := checkLogLimit(p.Limit)
	if perr != nil {
		return nil, perr
	}
	if perr := checkSince(p.Since); perr != nil {
		return nil, perr
	}
	if perr := checkRuleIDFilter(p.RuleID); perr != nil {
		return nil, perr
	}
	engine, perr := checkEngine(p.Engine)
	if perr != nil {
		return nil, perr
	}
	settings := r.settingsFor(p.Engine, engine)
	result, err := Logs(r.env, settings, LogsParams{Limit: limit, Since: p.Since, RuleID: p.RuleID})
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// callToggle 切换模式；无 root 通道时返回 E_NEED_ROOT。
func (r *Runtime) callToggle(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p toggleParams
	if perr := decodeOptional(raw, &p); perr != nil {
		return nil, perr
	}
	mode, perr := checkMode(p.Mode)
	if perr != nil {
		return nil, perr
	}
	result, perr := Toggle(r.env, r.settings, ToggleParams{Mode: mode, Confirm: p.Confirm}, r.root)
	if perr != nil {
		return nil, perr
	}
	return encode(result)
}

// settingsFor 仅在请求显式指定 engine 时覆盖配置里的首选引擎。
func (r *Runtime) settingsFor(requested, normalized string) Settings {
	if strings.TrimSpace(requested) == "" {
		return r.settings
	}
	return withEngine(r.settings, normalized)
}

// withEngine 返回覆盖首选引擎的配置副本。
func withEngine(settings Settings, engine string) Settings {
	clone := settings
	clone.Engine = engine
	return clone
}

// classify 把执行面错误映射为协议错误码：
//
//	注入故障：kill/timeout → E_UPSTREAM、disk → E_INTERNAL、cgroup → E_UNSUPPORTED；
//	运行期错误：权限 → E_NEED_ROOT、超时 → E_UPSTREAM、缺失 → E_UNSUPPORTED。
func classify(err error) *pluginapi.Error {
	var fault *FaultError
	if errors.As(err, &fault) {
		switch fault.Kind {
		case FaultKill:
			return upstream("进程被信号 9 终止: " + fault.Message)
		case FaultTimeout:
			return upstream("调用超时: " + fault.Message)
		case FaultDisk:
			return internalErr("磁盘满: " + fault.Message)
		case FaultCgroup:
			return unsupported("cgroup 限额: " + fault.Message)
		}
		return internalErr("执行面失败: " + err.Error())
	}
	var opErr *OpError
	if errors.As(err, &opErr) {
		switch opErr.Kind {
		case OpPermission:
			return needRoot("权限不足: "+opErr.Message, rootActionHint(""))
		case OpTimeout:
			return upstream("外部命令超时: " + opErr.Message)
		case OpNotFound:
			return unsupported("外部依赖缺失: " + opErr.Message)
		case OpDisk:
			return internalErr("磁盘错误: " + opErr.Message)
		case OpCgroup:
			return unsupported("cgroup 限制: " + opErr.Message)
		default:
			return upstream("外部操作失败: " + opErr.Message)
		}
	}
	return internalErr("执行面失败: " + err.Error())
}
