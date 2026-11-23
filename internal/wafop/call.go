package wafop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

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
	registry *ruleRegistry
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
	case "ban":
		return r.callBan(params)
	case "unban":
		return r.callUnban(params)
	case "bans":
		return r.callBans(params)
	case "rule.add":
		return r.callRuleAdd(params)
	case "rule.remove":
		return r.callRuleRemove(params)
	case "rule.toggle":
		return r.callRuleToggle(params)
	}
	return nil, errNotFound(method)
}

// businessVerb 把 waf.<verb> 或裸 <verb> 归一为动词名；blockLog 兼容到 logs。
func businessVerb(method string) (string, bool) {
	verb := strings.TrimPrefix(method, "waf.")
	switch verb {
	case "status", "rules", "logs", "blockLog", "toggle", "ban", "unban", "bans", "rule.add", "rule.remove", "rule.toggle":
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

// banParams 是 waf.ban 的入参。
type banParams struct {
	IP     string `json:"ip"`
	TTLS   int    `json:"ttl_s"`
	Reason string `json:"reason"`
}

// unbanParams 是 waf.unban 的入参。
type unbanParams struct {
	IP string `json:"ip"`
}

// bansParams 是 waf.bans 的入参。
type bansParams struct {
	Limit int `json:"limit"`
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
		Backend:       Status(r.env, r.root),
	}
	if !detection.Found {
		result.ErrorCode = pluginapi.E_UNSUPPORTED
		result.Hint = installHint()
		if result.Backend.Present || result.Backend.Channel {
			result.Hint += "；IP 封禁与基础防护走 kore 自有 nft 数据面（backend），不依赖该引擎"
		}
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
	result.Nft = nftRuleset(r.env, r.root)
	return encode(result)
}

// nftRuleset 汇总 kore 自有 nft 数据面（封禁集合 + 基础防护规则）。
func nftRuleset(env Environment, root RootActionFunc) NftRuleset {
	backend := NewNftBackend(env, root)
	availability := backend.Availability()
	ruleset := NftRuleset{Table: NftTable, Chain: NftChain, Mode: ModeOff,
		Rules: []NftRule{}, Bans: []NftElement{}}
	if !availability.Available || root == nil {
		return ruleset
	}
	state, err := backend.State()
	if err != nil {
		return ruleset
	}
	ruleset.Present = state.Present
	ruleset.Mode = state.Mode
	ruleset.Rules = state.Rules
	ruleset.RulesCount = len(state.Rules)
	ruleset.Bans = state.Bans
	ruleset.BansCount = len(state.Bans)
	return ruleset
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

// callToggle 切换数据面模式（observe / enforce / off）。
func (r *Runtime) callToggle(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p ToggleParams
	if perr := decodeOptional(raw, &p); perr != nil {
		return nil, perr
	}
	result, perr := Toggle(r.env, p, r.root)
	if perr != nil {
		return nil, perr
	}
	return encode(result)
}

// callBan 封禁一个 IP/CIDR（写进 nft 集合，经 root-action 通道）。
func (r *Runtime) callBan(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p banParams
	if perr := decodeStrict(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := checkBanReason(p.Reason); perr != nil {
		return nil, perr
	}
	ip, perr := checkBanIP(p.IP)
	if perr != nil {
		return nil, perr
	}
	backend := NewNftBackend(r.env, r.root)
	availability := backend.Availability()
	if !availability.Available || r.root == nil {
		return nil, needRoot("封禁 IP 需要 root-action 通道", availability.Hint)
	}
	if p.TTLS != 0 && (p.TTLS < MinBanTTLS || p.TTLS > MaxBanTTLS) {
		return nil, invalid(fmt.Sprintf("ttl_s=%d 超出 %d–%d 秒（0 表示永久）", p.TTLS, MinBanTTLS, MaxBanTTLS))
	}
	result, err := backend.Ban(ip, p.TTLS)
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	result.Reason = p.Reason
	return encode(result)
}

// callUnban 解封一个 IP/CIDR；不在集合里也算成功（幂等）。
func (r *Runtime) callUnban(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p unbanParams
	if perr := decodeStrict(raw, &p); perr != nil {
		return nil, perr
	}
	ip, perr := checkBanIP(p.IP)
	if perr != nil {
		return nil, perr
	}
	backend := NewNftBackend(r.env, r.root)
	availability := backend.Availability()
	if !availability.Available || r.root == nil {
		return nil, needRoot("解封 IP 需要 root-action 通道", availability.Hint)
	}
	result, err := backend.Unban(ip)
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	return encode(result)
}

// callBans 列出封禁集合。
func (r *Runtime) callBans(raw json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p bansParams
	if perr := decodeOptional(raw, &p); perr != nil {
		return nil, perr
	}
	limit, perr := checkBansLimit(p.Limit)
	if perr != nil {
		return nil, perr
	}
	backend := NewNftBackend(r.env, r.root)
	result, err := backend.Bans()
	if err != nil {
		return nil, classifyToggleChannel(err)
	}
	if limit > 0 && len(result.Bans) > limit {
		result.Bans = result.Bans[:limit]
	}
	return encode(result)
}

// checkBansLimit 校验 bans 的 limit：0 取缺省，负数或超上限拒绝。
func checkBansLimit(limit int) (int, *pluginapi.Error) {
	if limit == 0 {
		return 0, nil
	}
	if limit < 0 {
		return 0, invalid("limit 不能为负数")
	}
	if limit > 1000 {
		return 0, invalid("limit 最多 1000，防止一次返回过多封禁项")
	}
	return limit, nil
}

// checkBanIP 校验并规范化封禁目标；非法地址是**参数错误**（E_INVALID），
// 而不是执行面失败——参数错不该写进上游错误。
func checkBanIP(raw string) (string, *pluginapi.Error) {
	if strings.TrimSpace(raw) == "" {
		return "", invalid("缺少必填参数 ip")
	}
	normalized, _, err := normalizeIP(raw)
	if err != nil {
		return "", invalid(err.Error())
	}
	return normalized, nil
}

// checkBanReason 校验封禁原因：≤200 字符、无控制字符（只进结果，不进 argv）。
func checkBanReason(raw string) *pluginapi.Error {
	if raw == "" {
		return nil
	}
	if utf8.RuneCountInString(raw) > 200 {
		return invalid("reason 超过 200 个字符")
	}
	if strings.IndexFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return invalid("reason 不得包含控制字符")
	}
	return nil
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
