// Package wafop 实现 waf 插件的方法面：参数校验与结构化占位结果。
// 本包只做逻辑校验，不接 ModSecurity/nginx 模块、不内置任何 WAF 二进制（骨架口径）。
package wafop

import "fmt"

// defaultLimit 是 limit 未指定（0）时的缺省条数。
const defaultLimit = 20

// maxLimit 是单次返回条数硬上限，防止恶意 limit 造成 DoS。
const maxLimit = 1000

// FaultKind 标识一次故障注入的类别；基础级只覆盖 kill 与 timeout。
type FaultKind string

const (
	FaultNone    FaultKind = ""
	FaultKill    FaultKind = "kill"
	FaultTimeout FaultKind = "timeout"
)

// FaultError 是执行面注入的故障错误，Call 将其映射为协议错误码。
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

// Rule 是规则集中的一条规则（结构化占位，不代表真实规则引擎内容）。
type Rule struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Category string `json:"category"`
	Enabled  bool   `json:"enabled"`
}

// BlockLogEntry 是一条拦截日志记录（结构化占位，不读真实日志）。
type BlockLogEntry struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	ClientIP string `json:"client_ip"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	At       string `json:"at"`
}

// Executor 是 WAF 执行面；骨架实现为 noop，测试可注入故障执行器。
type Executor interface {
	Rules(root, ruleID string, limit int) ([]Rule, error)
	BlockLog(root, ruleID string, limit int) ([]BlockLogEntry, error)
}

// rulesParams / blockLogParams 是两个方法的显式入参形状。
type rulesParams struct {
	RuleID string `json:"rule_id"`
	Limit  int    `json:"limit"`
}

type blockLogParams struct {
	RuleID string `json:"rule_id"`
	Limit  int    `json:"limit"`
}

// RulesResult / BlockLogResult 是两个方法的结构化结果。
// Applied=false 表示骨架口径：未接真实 WAF 引擎，条目为空但不伪装有数据。
type RulesResult struct {
	Root       string `json:"root"`
	Rules      []Rule `json:"rules"`
	Count      int    `json:"count"`
	Limit      int    `json:"limit"`
	FilterRule string `json:"filter_rule_id,omitempty"`
	Applied    bool   `json:"applied"`
}

type BlockLogResult struct {
	Root       string          `json:"root"`
	Entries    []BlockLogEntry `json:"entries"`
	Count      int             `json:"count"`
	Limit      int             `json:"limit"`
	FilterRule string          `json:"filter_rule_id,omitempty"`
	Applied    bool            `json:"applied"`
}
