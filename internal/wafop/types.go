// Package wafop 实现 waf 插件的方法面：WAF 引擎检测、规则集统计、拦截日志解析
// 与观察/拦截模式切换。
//
// 设计约束（引擎无关 + 可降级）：
//   - 不内置任何 WAF 引擎，只管理宿主已安装的 modsecurity / naxsi / coraza / crowdsec；
//   - 没有引擎时读方法返回 available=false + error_code=E_UNSUPPORTED + hint，
//     不返回协议错误（UI 仍能展示「为什么不可用、下一步装什么」）；
//   - 模式切换需要 root 权限，走 ADR-0018 的 root-action 通道，插件自身永不提权。
package wafop

import (
	"fmt"
	"time"
)

// 引擎枚举。EngineNone 是「什么都没检测到」的显式值，不用空串冒充。
const (
	EngineNone        = "none"
	EngineModSecurity = "modsecurity"
	EngineNaxsi       = "naxsi"
	EngineCoraza      = "coraza"
	EngineCrowdSec    = "crowdsec"
)

// 模式枚举：on=拦截、detection=只记录不拦截、off=关闭。
const (
	ModeOn        = "on"
	ModeDetection = "detection"
	ModeOff       = "off"
)

// SDK v0.1.1 尚未包含 ADR-0018 的两个错误码常量，插件侧按协议字面量声明。
const (
	// CodeNeedRoot 需要宿主 root 权限但当前没有可用提权通道。
	CodeNeedRoot = "E_NEED_ROOT"
	// CodeNoSystemd 提权依赖 systemd-run，当前环境没有 systemd。
	CodeNoSystemd = "E_NO_SYSTEMD"
)

// 预算与缺省值。日志只读尾部，避免把 10 GiB 审计日志读进内存。
const (
	// DefaultMaxLogBytes 是单日志文件缺省读取上限（1 MiB）。
	DefaultMaxLogBytes = int64(1 << 20)
	// MinMaxLogBytes / MaxMaxLogBytes 是可配置的读取上限区间。
	MinMaxLogBytes = int64(64 << 10)
	MaxMaxLogBytes = int64(8 << 20)
	// DefaultLogLimit 是 waf.logs 缺省返回条数；MaxLogLimit 是硬上限。
	DefaultLogLimit = 50
	MaxLogLimit     = 200
	// DefaultModeConfigPath 是 kore 管理的 ModSecurity 模式包含文件。
	DefaultModeConfigPath = "/etc/modsecurity/kore-mode.conf"
	// DefaultCorazaModeConfigPath 是 coraza 引擎下的同类文件。
	DefaultCorazaModeConfigPath = "/etc/coraza/kore-mode.conf"
	// MaxRuleFileBytes 是单个规则文件读取上限，超限跳过并如实记录。
	MaxRuleFileBytes = int64(8 << 20)
	// MaxSinceRunes 限制 since 参数长度，避免超长字符串进入解析器。
	MaxSinceRunes = 64
	// MaxRuleIDRunes 限制 rule_id 过滤参数长度。
	MaxRuleIDRunes = 64
)

// Settings 是运行期可配参数（来自 config.json / 环境变量 / 缺省值）。
type Settings struct {
	// Engine 是首选引擎：auto|modsecurity|naxsi|coraza|crowdsec。
	Engine string
	// RulesDirs 覆盖缺省规则目录；空表示按引擎用内置缺省目录。
	RulesDirs []string
	// LogPaths 覆盖缺省日志路径；空表示按引擎用内置缺省路径。
	LogPaths []string
	// ModeConfigPath 是 kore 管理的模式包含文件（modsecurity/coraza）。
	ModeConfigPath string
	// MaxLogBytes 是单日志文件读取上限。
	MaxLogBytes int64
}

// normalized 补齐缺省值并收敛越界值（配置层已校验，这里兜底）。
func (s Settings) normalized() Settings {
	if s.Engine == "" {
		s.Engine = "auto"
	}
	if s.MaxLogBytes <= 0 {
		s.MaxLogBytes = DefaultMaxLogBytes
	}
	if s.MaxLogBytes < MinMaxLogBytes {
		s.MaxLogBytes = MinMaxLogBytes
	}
	if s.MaxLogBytes > MaxMaxLogBytes {
		s.MaxLogBytes = MaxMaxLogBytes
	}
	return s
}

// Probe 是一次引擎探测的证据：found 由哪个文件/命令得出。
type Probe struct {
	Engine   string `json:"engine"`
	Found    bool   `json:"found"`
	Evidence string `json:"evidence"`
}

// Detection 是引擎检测结果（不含规则计数，规则计数在 rules.go 里扫）。
type Detection struct {
	Engine        string
	Found         bool
	Version       string
	VersionSource string // command|file|unknown
	Mode          string
	ModeSource    string // config|default|heuristic
	CRSVersion    string
	Probed        []Probe
}

// StatusResult 是 waf.status 的结果。
type StatusResult struct {
	Available     bool    `json:"available"`
	Engine        string  `json:"engine"`
	Version       string  `json:"version,omitempty"`
	VersionSource string  `json:"version_source,omitempty"`
	RulesCount    int     `json:"rules_count"`
	Mode          string  `json:"mode"`
	ModeSource    string  `json:"mode_source,omitempty"`
	CRSVersion    string  `json:"crs_version,omitempty"`
	ErrorCode     string  `json:"error_code,omitempty"`
	Hint          string  `json:"hint,omitempty"`
	RequiresRoot  bool    `json:"requires_root"`
	Probed        []Probe `json:"probed,omitempty"`
}

// RuleSet 是一个规则集（通常对应一个 .conf / .rules 文件，crowdsec 下对应一个场景）。
type RuleSet struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	RuleCount int    `json:"rule_count"`
	Enabled   bool   `json:"enabled"`
}

// RulesResult 是 waf.rules 的结果。
type RulesResult struct {
	Engine    string    `json:"engine"`
	Available bool      `json:"available"`
	ErrorCode string    `json:"error_code,omitempty"`
	Hint      string    `json:"hint,omitempty"`
	RuleSets  []RuleSet `json:"rulesets"`
	Total     int       `json:"total"`
}

// LogSource 是一份日志文件的读取情况（只读尾部）。
type LogSource struct {
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	Readable  bool   `json:"readable"`
	Bytes     int    `json:"bytes_scanned"`
	Truncated bool   `json:"truncated"`
	Lines     int    `json:"lines"`
	Matched   int    `json:"matched"`
	Error     string `json:"error,omitempty"`
}

// LogEntry 是一条解析出的拦截/检测记录。
type LogEntry struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	URI    string `json:"uri"`
	RuleID string `json:"rule_id"`
	Action string `json:"action"` // blocked|detected
	Source string `json:"source,omitempty"`

	// at 是解析成功的时间戳；未解析成功时为零值，仅用于排序与 since 过滤。
	at time.Time
}

// LogsResult 是 waf.logs 的结果。
type LogsResult struct {
	Engine          string      `json:"engine"`
	Available       bool        `json:"available"`
	ErrorCode       string      `json:"error_code,omitempty"`
	Hint            string      `json:"hint,omitempty"`
	Sources         []LogSource `json:"sources"`
	Entries         []LogEntry  `json:"entries"`
	Count           int         `json:"count"`
	Limit           int         `json:"limit"`
	Since           string      `json:"since,omitempty"`
	ScannedLines    int         `json:"scanned_lines"`
	MatchedLines    int         `json:"matched_lines"`
	SkippedUnparsed int         `json:"skipped_unparsed"`
}

// ToggleParams 是 waf.toggle 的入参。confirm 只对「关闭拦截」强制要求。
type ToggleParams struct {
	Mode    string `json:"mode"`
	Confirm bool   `json:"confirm"`
}

// ToggleStep 是一步 root-action 的执行结果。
type ToggleStep struct {
	Action   string `json:"action"`
	ExitCode int    `json:"exit_code"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

// ToggleResult 是 waf.toggle 的结果；applied 表示模式文件已写入且已完成 reload。
type ToggleResult struct {
	Engine       string       `json:"engine"`
	Mode         string       `json:"mode"`
	PreviousMode string       `json:"previous_mode"`
	Applied      bool         `json:"applied"`
	Reloaded     bool         `json:"reloaded"`
	Available    bool         `json:"available"`
	ErrorCode    string       `json:"error_code,omitempty"`
	Hint         string       `json:"hint,omitempty"`
	Steps        []ToggleStep `json:"steps"`
}

// RootActionFunc 是插件→内核 root-action 通道的调用面（ADR-0018）。
// 返回 stdout、退出码与错误；错误可为 *ChannelError 或注入的 *FaultError。
type RootActionFunc func(actionID string, args []string) (stdout []byte, exitCode int, err error)

// ChannelError 是内核 root-action 通道返回的结构化拒绝（错误码 + 可操作提示）。
type ChannelError struct {
	Code    string
	Message string
	Hint    string
}

// Error 实现 error 接口。
func (e *ChannelError) Error() string {
	if e.Hint != "" {
		return e.Code + ": " + e.Message + "（" + e.Hint + "）"
	}
	return e.Code + ": " + e.Message
}

// FaultKind 标识一次故障注入的类别；v0.2.0 覆盖生产级四类。
type FaultKind string

// 四类故障注入：kill / timeout / disk / cgroup。
const (
	FaultNone    FaultKind = ""
	FaultKill    FaultKind = "kill"
	FaultTimeout FaultKind = "timeout"
	FaultDisk    FaultKind = "disk"
	FaultCgroup  FaultKind = "cgroup"
)

// FaultError 是测试注入的故障错误，Call 将其映射为协议错误码。
type FaultError struct {
	Kind    FaultKind
	Message string
}

// Error 实现 error 接口，输出 "<类别>: <说明>"。
func (e *FaultError) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Message) }

// NewFaultError 构造给定类别的故障错误。
func NewFaultError(kind FaultKind, message string) *FaultError {
	return &FaultError{Kind: kind, Message: message}
}

// OpErrorKind 是运行期外部操作失败类别（与注入故障分开，避免把真实错误伪装成注入）。
type OpErrorKind string

// 运行期操作失败类别。
const (
	OpPermission OpErrorKind = "permission"
	OpNotFound   OpErrorKind = "notfound"
	OpTimeout    OpErrorKind = "timeout"
	OpDisk       OpErrorKind = "disk"
	OpCgroup     OpErrorKind = "cgroup"
	OpFailed     OpErrorKind = "failed"
)

// OpError 是外部命令/文件操作失败的结构化错误。
type OpError struct {
	Kind    OpErrorKind
	Message string
}

// Error 实现 error 接口。
func (e *OpError) Error() string { return string(e.Kind) + ": " + e.Message }

// NewOpError 构造外部操作错误。
func NewOpError(kind OpErrorKind, message string) *OpError {
	return &OpError{Kind: kind, Message: message}
}
