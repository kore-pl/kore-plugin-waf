package wafop

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LogsParams 是 waf.logs 的入参。
type LogsParams struct {
	// Limit 返回条数上限；0 取缺省 50，超过 200 收敛到 200。
	Limit int
	// Since 只保留该时间之后的记录：相对时长（1h / 30m / 7d）或 RFC3339 / 日期。
	Since string
	// RuleID 按规则 ID 精确过滤（ModSecurity 的 942100、Naxsi 的 1007 等）。
	RuleID string
}

// 日志解析用的正则：ModSecurity 错误日志、Naxsi 行、nginx 时间前缀。
var (
	modsecClientRe = regexp.MustCompile(`\[client ([0-9a-fA-F:.]+)(?::[0-9]+)?\]`)
	modsecURIRe    = regexp.MustCompile(`\[uri "([^"]*)"\]`)
	modsecRuleRe   = regexp.MustCompile(`\[id "([^"]+)"\]`)
	nginxTimeRe    = regexp.MustCompile(`^([0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`)
	bracketRe      = regexp.MustCompile(`\[([^\]]{8,96})\]`)
)

// 时间格式候选：覆盖 nginx error.log、Apache error.log、ModSecurity 审计日志。
var logTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"02/Jan/2006:15:04:05 -0700",
	"02/Jan/2006:15:04:05",
	"Mon Jan _2 15:04:05.000000 2006",
	"Mon Jan _2 15:04:05 2006",
	"2006/01/02 15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
}

// Logs 读取并解析拦截日志。未检测到引擎时返回结构化不可用；引擎存在但日志
// 不可读（权限）时返回 E_NEED_ROOT + hint，不返回协议错误。
func Logs(env Environment, settings Settings, params LogsParams) (LogsResult, error) {
	env = defaultEnvironment(env)
	s := settings.normalized()
	limit := params.Limit
	if limit <= 0 {
		limit = DefaultLogLimit
	}
	if limit > MaxLogLimit {
		limit = MaxLogLimit
	}
	detection, err := Detect(env, s)
	if err != nil {
		return LogsResult{}, err
	}
	result := LogsResult{
		Engine: detection.Engine, Available: detection.Found,
		Sources: []LogSource{}, Entries: []LogEntry{}, Limit: limit, Since: params.Since,
	}
	if !detection.Found {
		result.ErrorCode = "E_UNSUPPORTED"
		result.Hint = installHint()
		return result, nil
	}
	if detection.Engine == EngineCrowdSec {
		result.ErrorCode = "E_UNSUPPORTED"
		result.Hint = "crowdsec 的告警不是 ModSecurity/NAXSI 行格式，v0.2.0 不解析；" +
			"请用 `cscli alerts list` 查看告警，或把 crowdsec 与 ModSecurity 一起部署后看后者日志"
		return result, nil
	}
	paths := s.LogPaths
	if len(paths) == 0 {
		paths = defaultLogPaths(detection.Engine)
	}
	cutoff, hasCutoff, err := parseSince(params.Since, env.Now())
	if err != nil {
		return LogsResult{}, NewOpError(OpFailed, "since 解析失败: "+err.Error())
	}
	permissionDenied := false
	readableSources := 0
	entries := make([]LogEntry, 0, limit*2)
	for _, path := range dedupe(paths) {
		source := LogSource{Path: path}
		meta, err := env.Stat(path)
		if err != nil {
			if isFault(err) {
				return LogsResult{}, err
			}
			source.Error = "文件不存在"
			result.Sources = append(result.Sources, source)
			continue
		}
		source.Exists = true
		if meta.IsDir {
			source.Error = "是目录，不是日志文件"
			result.Sources = append(result.Sources, source)
			continue
		}
		data, truncated, err := env.Tail(path, s.MaxLogBytes)
		if err != nil {
			if isFault(err) {
				return LogsResult{}, err
			}
			if isPermission(err) {
				permissionDenied = true
			}
			source.Error = "读取失败: " + err.Error()
			result.Sources = append(result.Sources, source)
			continue
		}
		source.Readable = true
		source.Truncated = truncated
		source.Bytes = len(data)
		parsed, stats := parseLogData(data)
		source.Lines = stats.lines
		source.Matched = len(parsed)
		result.ScannedLines += stats.lines
		result.MatchedLines += len(parsed)
		if len(parsed) > 0 {
			readableSources++
		}
		for _, entry := range parsed {
			if params.RuleID != "" && entry.RuleID != params.RuleID {
				continue
			}
			if hasCutoff {
				if entry.at.IsZero() {
					result.SkippedUnparsed++
					continue
				}
				if entry.at.Before(cutoff) {
					continue
				}
			}
			entry.Source = path
			entries = append(entries, entry)
		}
		result.Sources = append(result.Sources, source)
	}
	sortLogEntries(entries)
	if len(entries) > limit {
		entries = entries[:limit]
	}
	result.Entries = entries
	result.Count = len(entries)
	if result.Count == 0 {
		switch {
		case permissionDenied && readableSources == 0:
			result.ErrorCode = "E_NEED_ROOT"
			result.Hint = "日志文件存在但当前身份不可读：请用 sudo 启动 kored，或把 kored 用户加入 adm 组"
		case result.MatchedLines == 0:
			result.Hint = "已读取日志但未发现 ModSecurity/NAXSI 行；确认引擎已启用审计日志（SecAuditEngine RelevantOnly）且日志路径正确"
		default:
			result.Hint = "命中记录被 since/rule_id 过滤后为空"
		}
	}
	return result, nil
}

// defaultLogPaths 按引擎返回缺省日志路径。
func defaultLogPaths(engine string) []string {
	switch engine {
	case EngineNaxsi:
		return []string{"/var/log/nginx/error.log"}
	case EngineCoraza:
		return []string{"/var/log/nginx/error.log", "/var/log/coraza/audit.log"}
	default:
		return []string{
			"/var/log/modsec_audit.log",
			"/var/log/nginx/error.log",
			"/var/log/apache2/error.log",
		}
	}
}

// logStats 是一次解析的统计：扫描行数（matched 由调用方按返回条数得到）。
type logStats struct {
	lines int
}

// parseLogData 解析一个日志块：先按 ModSecurity 审计日志分节解析，再逐行解析
// ModSecurity / Naxsi 错误日志与 JSON 行。两种格式互不干扰。
func parseLogData(data []byte) ([]LogEntry, logStats) {
	lines := bytes.Split(data, []byte("\n"))
	stats := logStats{lines: len(lines)}
	entries := make([]LogEntry, 0, 8)
	entries = append(entries, parseAuditSections(lines)...)
	for _, line := range lines {
		if entry, ok := parseLogLine(line); ok {
			entries = append(entries, entry)
		}
	}
	return entries, stats
}

// parseLogLine 解析单行：JSON → Naxsi → ModSecurity → 放弃。
func parseLogLine(raw []byte) (LogEntry, bool) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return LogEntry{}, false
	}
	if strings.HasPrefix(text, "{") {
		if entry, ok := parseJSONLog(text); ok {
			return entry, true
		}
	}
	if strings.Contains(text, "NAXSI_FMT:") || strings.Contains(text, "NAXSI_EXLOG:") {
		return parseNaxsiLine(text)
	}
	if strings.Contains(text, "ModSecurity") {
		return parseModSecLine(text)
	}
	return LogEntry{}, false
}

// parseModSecLine 解析 ModSecurity 错误日志行：
//
//	[Wed Oct 11 14:32:00 2023] [error] [client 1.2.3.4] ModSecurity: Access denied
//	with code 403 ... [id "942100"] [uri "/x?a=1"] ...
func parseModSecLine(text string) (LogEntry, bool) {
	entry := LogEntry{}
	if at, raw, ok := parseAnyTimestamp(text); ok {
		entry.at = at
		entry.Time = at.Format(time.RFC3339)
		_ = raw
	}
	if matches := regexpGroups(modsecClientRe, text); len(matches) > 0 {
		entry.IP = matches[0]
	}
	if matches := regexpGroups(modsecURIRe, text); len(matches) > 0 {
		entry.URI = matches[0]
	}
	if matches := regexpGroups(modsecRuleRe, text); len(matches) > 0 {
		entry.RuleID = matches[0]
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "access denied"), strings.Contains(lower, "request blocked"),
		strings.Contains(lower, "blocked by"), strings.Contains(lower, "deny with code"):
		entry.Action = "blocked"
	case strings.Contains(lower, "warning"), strings.Contains(lower, "detected"),
		strings.Contains(lower, "access allowed"):
		entry.Action = "detected"
	default:
		entry.Action = "detected"
	}
	if entry.IP == "" && entry.URI == "" && entry.RuleID == "" {
		return LogEntry{}, false
	}
	return entry, true
}

// parseNaxsiLine 解析 Naxsi 的 NAXSI_FMT / NAXSI_EXLOG 行（key=value&...）。
func parseNaxsiLine(text string) (LogEntry, bool) {
	marker := "NAXSI_FMT:"
	if index := strings.Index(text, "NAXSI_EXLOG:"); index >= 0 {
		marker = "NAXSI_EXLOG:"
	}
	index := strings.Index(text, marker)
	if index < 0 {
		return LogEntry{}, false
	}
	payload := strings.TrimSpace(text[index+len(marker):])
	fields := map[string]string{}
	for _, pair := range strings.Split(payload, "&") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := fields[key]; !exists {
			fields[key] = strings.TrimSpace(value)
		}
	}
	entry := LogEntry{IP: fields["ip"], URI: unescapeQuery(fields["uri"])}
	for _, key := range []string{"id0", "id1", "id2", "id3", "id4"} {
		if id := fields[key]; id != "" {
			entry.RuleID = id
			break
		}
	}
	entry.Action = "detected"
	if fields["block"] == "1" && fields["learning"] != "1" {
		entry.Action = "blocked"
	}
	if at, _, ok := parseNginxTimestamp(text); ok {
		entry.at = at
		entry.Time = at.Format(time.RFC3339)
	}
	if entry.IP == "" && entry.URI == "" && entry.RuleID == "" {
		return LogEntry{}, false
	}
	return entry, true
}

// jsonLogLine 是 JSON 日志行的显式形状（兼容扁平字段与 ModSecurity JSON 审计结构）。
type jsonLogLine struct {
	Time        string          `json:"time"`
	Timestamp   string          `json:"timestamp"`
	IP          string          `json:"ip"`
	ClientIP    string          `json:"client_ip"`
	RemoteAddr  string          `json:"remote_addr"`
	URI         string          `json:"uri"`
	RequestURI  string          `json:"request_uri"`
	RuleID      string          `json:"rule_id"`
	RuleIDCamel string          `json:"ruleId"`
	ID          json.RawMessage `json:"id"`
	Action      string          `json:"action"`
	Request     *struct {
		URI string `json:"uri"`
	} `json:"request"`
	Transaction *struct {
		TimeStamp     string `json:"time_stamp"`
		ClientIP      string `json:"client_ip"`
		IsInterrupted bool   `json:"is_interrupted"`
		Request       *struct {
			URI string `json:"uri"`
		} `json:"request"`
	} `json:"transaction"`
	AuditData *struct {
		Messages []struct {
			Details *struct {
				RuleID string `json:"ruleId"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"audit_data"`
}

// parseJSONLog 解析扁平或 ModSecurity JSON 审计结构的日志行。
func parseJSONLog(text string) (LogEntry, bool) {
	var line jsonLogLine
	if err := json.Unmarshal([]byte(text), &line); err != nil {
		return LogEntry{}, false
	}
	entry := LogEntry{}
	entry.IP = firstNonEmpty(line.IP, line.ClientIP, line.RemoteAddr)
	entry.URI = firstNonEmpty(line.URI, line.RequestURI, nestedRequestURI(line.Request))
	entry.RuleID = firstNonEmpty(line.RuleID, line.RuleIDCamel, rawScalar(line.ID))
	if line.Transaction != nil {
		entry.IP = firstNonEmpty(entry.IP, line.Transaction.ClientIP)
		entry.URI = firstNonEmpty(entry.URI, nestedRequestURI(line.Transaction.Request))
		if line.Time == "" && line.Timestamp == "" {
			line.Timestamp = line.Transaction.TimeStamp
		}
		if entry.Action == "" && line.Transaction.IsInterrupted {
			entry.Action = "blocked"
		}
	}
	if entry.RuleID == "" && line.AuditData != nil {
		for _, message := range line.AuditData.Messages {
			if message.Details != nil && message.Details.RuleID != "" {
				entry.RuleID = message.Details.RuleID
				break
			}
		}
	}
	if entry.Action == "" {
		entry.Action = normalizeAction(line.Action)
	}
	if entry.Action == "" {
		entry.Action = "detected"
	}
	if at, ok := parseTimeValue(firstNonEmpty(line.Time, line.Timestamp)); ok {
		entry.at = at
		entry.Time = at.Format(time.RFC3339)
	}
	if entry.IP == "" && entry.URI == "" && entry.RuleID == "" {
		return LogEntry{}, false
	}
	return entry, true
}

// auditTx 是 ModSecurity 审计日志的一笔事务。
type auditTx struct {
	active    bool
	at        time.Time
	ip        string
	uri       string
	status    int
	hasStatus bool
}

// parseAuditSections 解析 ModSecurity 审计日志的分节结构（A/B/H/Z）。
//
// 审计日志本身不含 "ModSecurity" 字样，不能靠 grep；按 --<id>-<节>-- 分节解析，
// A 节取时间与客户端 IP、B 节取请求行、H 节取响应码。规则 ID 只在错误日志里有，
// 审计日志条目 rule_id 留空——不猜。
func parseAuditSections(lines [][]byte) []LogEntry {
	entries := make([]LogEntry, 0, 4)
	tx := auditTx{}
	section := byte(0)
	flush := func() {
		if !tx.active {
			return
		}
		if tx.ip == "" && tx.uri == "" {
			tx = auditTx{}
			section = 0
			return
		}
		entry := LogEntry{IP: tx.ip, URI: tx.uri, Action: "detected"}
		if tx.hasStatus {
			if tx.status >= 400 {
				entry.Action = "blocked"
			}
		}
		if !tx.at.IsZero() {
			entry.at = tx.at
			entry.Time = tx.at.Format(time.RFC3339)
		}
		entries = append(entries, entry)
		tx = auditTx{}
		section = 0
	}
	for _, raw := range lines {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if marker, ok := auditSection(line); ok {
			if marker == 'A' {
				flush()
				tx = auditTx{active: true}
				section = 'A'
				continue
			}
			section = marker
			continue
		}
		switch section {
		case 'A':
			if tx.at.IsZero() && tx.ip == "" {
				if at, rest, ok := parseAnyTimestamp(line); ok {
					tx.at = at
					line = rest
				}
				tx.ip = firstField(line)
			}
		case 'B':
			if tx.uri == "" {
				if fields := strings.Fields(line); len(fields) >= 2 {
					tx.uri = fields[1]
				}
			}
		case 'H':
			if !tx.hasStatus {
				if fields := strings.Fields(line); len(fields) >= 2 {
					if status, err := parseStatusCode(fields[1]); err == nil {
						tx.status = status
						tx.hasStatus = true
					}
				}
			}
		case 'Z':
			flush()
		}
	}
	flush()
	return entries
}

// auditSection 从 `--<id>-A--` 提取节字母。
func auditSection(line string) (byte, bool) {
	if len(line) < 7 || !strings.HasPrefix(line, "--") || !strings.HasSuffix(line, "--") {
		return 0, false
	}
	marker := line[len(line)-3]
	if marker < 'A' || marker > 'Z' {
		return 0, false
	}
	return marker, true
}

// parseAnyTimestamp 在文本中找第一个可解析的时间戳，返回时间与**去掉时间戳后的剩余文本**
// （审计日志 A 节需要从剩余文本里取客户端 IP）。
func parseAnyTimestamp(text string) (time.Time, string, bool) {
	if match := nginxTimeRe.FindStringSubmatchIndex(text); match != nil {
		if at, ok := parseTimeValue(text[match[2]:match[3]]); ok {
			return at, strings.TrimSpace(text[match[1]:]), true
		}
	}
	for _, match := range bracketRe.FindAllStringSubmatchIndex(text, -1) {
		if at, ok := parseTimeValue(text[match[2]:match[3]]); ok {
			return at, strings.TrimSpace(text[match[1]:]), true
		}
	}
	return time.Time{}, text, false
}

// parseNginxTimestamp 解析 nginx error.log 的 "2006/01/02 15:04:05" 前缀。
func parseNginxTimestamp(text string) (time.Time, string, bool) {
	matches := regexpGroups(nginxTimeRe, text)
	if len(matches) == 0 {
		return time.Time{}, text, false
	}
	if at, ok := parseTimeValue(matches[0]); ok {
		return at, text, true
	}
	return time.Time{}, text, false
}

// parseTimeValue 依次尝试已知时间格式（无时区按本地时区解析）。
func parseTimeValue(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range logTimeLayouts {
		if at, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return at, true
		}
	}
	return time.Time{}, false
}

// parseSince 解析 since 参数：相对时长或绝对时间。
func parseSince(raw string, now time.Time) (time.Time, bool, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false, nil
	}
	if duration, ok := parseRelativeDuration(value); ok {
		return now.Add(-duration), true, nil
	}
	if at, ok := parseTimeValue(value); ok {
		return at, true, nil
	}
	if at, err := time.ParseInLocation("2006-01-02", value, time.Local); err == nil {
		return at, true, nil
	}
	return time.Time{}, false, NewOpError(OpFailed, "since 只接受相对时长（如 1h / 30m / 7d）或 RFC3339 时间")
}

// parseRelativeDuration 解析单值相对时长（支持 d，其余走 time.ParseDuration）。
func parseRelativeDuration(value string) (time.Duration, bool) {
	if strings.HasSuffix(value, "d") {
		number := strings.TrimSuffix(value, "d")
		if number == "" {
			return 0, false
		}
		days, err := time.ParseDuration(number + "h")
		if err != nil {
			return 0, false
		}
		return days * 24, true
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, false
	}
	return duration, true
}

// sortLogEntries 按解析时间倒序；时间不可解析的条目排在后面并保持原顺序。
func sortLogEntries(entries []LogEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i].at, entries[j].at
		switch {
		case left.IsZero() && right.IsZero():
			return false
		case left.IsZero():
			return false
		case right.IsZero():
			return true
		default:
			return left.After(right)
		}
	})
}

// regexpGroups 取第一处匹配的分组 1。
func regexpGroups(re *regexp.Regexp, text string) []string {
	match := re.FindStringSubmatch(text)
	if len(match) < 2 {
		return nil
	}
	return match[1:]
}

// regexpGroupsAll 取所有匹配的分组 1。
func regexpGroupsAll(re *regexp.Regexp, text string) []string {
	matches := re.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) >= 2 {
			out = append(out, match[1])
		}
	}
	return out
}

// normalizeAction 把引擎/日志里的动作词归一为 blocked / detected。
func normalizeAction(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case lower == "":
		return ""
	case strings.Contains(lower, "block"), strings.Contains(lower, "deny"),
		strings.Contains(lower, "denied"), strings.Contains(lower, "drop"),
		lower == "403", lower == "406", lower == "429":
		return "blocked"
	case strings.Contains(lower, "detect"), strings.Contains(lower, "warn"),
		strings.Contains(lower, "alert"), strings.Contains(lower, "allow"),
		strings.Contains(lower, "pass"), lower == "200":
		return "detected"
	}
	return ""
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// nestedRequestURI 取 request.uri。
func nestedRequestURI(request *struct {
	URI string `json:"uri"`
}) string {
	if request == nil {
		return ""
	}
	return request.URI
}

// rawScalar 把 JSON 标量（字符串或数字）转成文本。
func rawScalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	text := strings.TrimSpace(string(raw))
	if text == "null" {
		return ""
	}
	if strings.HasPrefix(text, `"`) {
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			return value
		}
		return ""
	}
	return text
}

// firstField 返回空白分隔的第一个字段。
func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// parseStatusCode 解析 H 节的响应码。
func parseStatusCode(raw string) (int, error) {
	value := 0
	for _, char := range raw {
		if char < '0' || char > '9' {
			break
		}
		value = value*10 + int(char-'0')
	}
	if value < 100 || value > 599 {
		return 0, NewOpError(OpFailed, "非法状态码 "+raw)
	}
	return value, nil
}

// unescapeQuery 尽力还原 URL 编码（失败时保留原文，不丢信息）。
func unescapeQuery(raw string) string {
	if raw == "" || !strings.ContainsAny(raw, "%+") {
		return raw
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}
