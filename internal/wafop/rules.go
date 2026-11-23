package wafop

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// maxRuleScanDepth 是规则目录递归深度上限（CRS 是 rules/*.conf 一层，
// 允许一层子目录兼容分目录部署，不无界递归）。
const maxRuleScanDepth = 2

// ListRules 统计规则集。文件型引擎按目录扫描并统计指令行数；crowdsec 走
// `cscli scenarios list -o json`。未检测到引擎时返回结构化不可用，不报错。
func ListRules(env Environment, settings Settings, detection Detection) (RulesResult, error) {
	env = defaultEnvironment(env)
	s := settings.normalized()
	result := RulesResult{Engine: detection.Engine, RuleSets: []RuleSet{}}
	if detection.Engine == EngineNone || !detection.Found {
		result.Engine = EngineNone
		result.Available = false
		result.ErrorCode = "E_UNSUPPORTED"
		result.Hint = installHint()
		return result, nil
	}
	result.Available = true
	var ruleSets []RuleSet
	var err error
	switch detection.Engine {
	case EngineCrowdSec:
		ruleSets, err = crowdsecRuleSets(env)
	case EngineNaxsi:
		ruleSets, err = scanRuleDirs(env, naxsiRuleDirs(s), countNaxsiRules)
	default:
		ruleSets, err = scanRuleDirs(env, modsecRuleDirs(s, detection.Engine), countSecRules)
	}
	if err != nil {
		return RulesResult{}, err
	}
	if ruleSets == nil {
		ruleSets = []RuleSet{}
	}
	result.RuleSets = ruleSets
	result.Total = 0
	for _, ruleSet := range ruleSets {
		result.Total += ruleSet.RuleCount
	}
	if result.Total == 0 {
		result.Hint = "检测到 " + detection.Engine + "，但未在规则目录中找到可统计的规则文件；可在插件设置里补充「规则目录」"
	}
	return result, nil
}

// modsecRuleDirs 返回 ModSecurity / Coraza 的规则目录：配置优先，否则内置缺省。
func modsecRuleDirs(s Settings, engine string) []string {
	if len(s.RulesDirs) > 0 {
		return s.RulesDirs
	}
	if engine == EngineCoraza {
		return []string{"/etc/coraza", "/etc/modsecurity"}
	}
	return []string{"/etc/modsecurity", "/usr/share/modsecurity-crs/rules"}
}

// naxsiRuleDirs 返回 Naxsi 规则目录：配置优先，否则 /etc/nginx。
func naxsiRuleDirs(s Settings) []string {
	if len(s.RulesDirs) > 0 {
		return s.RulesDirs
	}
	return []string{"/etc/nginx"}
}

// scanRuleDirs 扫描多个根目录并合并规则集（按路径去重、排序）。
func scanRuleDirs(env Environment, roots []string, counter func([]byte) int) ([]RuleSet, error) {
	seen := make(map[string]struct{})
	ruleSets := make([]RuleSet, 0, 16)
	for _, root := range roots {
		if root == "" {
			continue
		}
		collected, err := scanRuleDir(env, root, maxRuleScanDepth, counter)
		if err != nil {
			return nil, err
		}
		for _, ruleSet := range collected {
			if _, ok := seen[ruleSet.Path]; ok {
				continue
			}
			seen[ruleSet.Path] = struct{}{}
			ruleSets = append(ruleSets, ruleSet)
		}
	}
	sort.Slice(ruleSets, func(i, j int) bool { return ruleSets[i].Path < ruleSets[j].Path })
	return ruleSets, nil
}

// scanRuleDir 递归扫描一个目录，返回含有效规则的文件（目录不存在视为无规则）。
func scanRuleDir(env Environment, dir string, depth int, counter func([]byte) int) ([]RuleSet, error) {
	meta, err := env.Stat(dir)
	if err != nil {
		if isFault(err) {
			return nil, err
		}
		if isNotExist(err) {
			return nil, nil
		}
		if isPermission(err) {
			return nil, nil // 无权限目录按「无规则」降级，具体原因由 status/logs 呈现
		}
		return nil, nil
	}
	if !meta.IsDir {
		return nil, nil
	}
	entries, err := env.ReadDir(dir)
	if err != nil {
		if isFault(err) {
			return nil, err
		}
		return nil, nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	out := make([]RuleSet, 0, 8)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, ".") {
			continue
		}
		path := filepath.Join(dir, entry.Name)
		if entry.IsDir {
			if depth <= 1 {
				continue
			}
			nested, err := scanRuleDir(env, path, depth-1, counter)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		if !isRuleFile(entry.Name) {
			continue
		}
		count, err := countRuleFile(env, path, counter)
		if err != nil {
			return nil, err
		}
		if count == 0 {
			continue
		}
		out = append(out, RuleSet{Name: entry.Name, Path: path, RuleCount: count, Enabled: true})
	}
	return out, nil
}

// isRuleFile 只把 .conf / .rules 视为规则文件（避免把 README、备份当规则）。
func isRuleFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".conf") || strings.HasSuffix(lower, ".rules")
}

// countRuleFile 读取规则文件并统计指令行；超大文件跳过（返回 0）。
func countRuleFile(env Environment, path string, counter func([]byte) int) (int, error) {
	meta, err := env.Stat(path)
	if err != nil {
		if isFault(err) {
			return 0, err
		}
		return 0, nil
	}
	if meta.IsDir || meta.Size > MaxRuleFileBytes {
		return 0, nil
	}
	data, err := env.ReadFile(path)
	if err != nil {
		if isFault(err) {
			return 0, err
		}
		if isPermission(err) {
			return 0, nil
		}
		return 0, nil
	}
	return counter(data), nil
}

// countSecRules 统计 ModSecurity / Coraza 的 SecRule 指令行（行首注释不算）。
func countSecRules(data []byte) int {
	return countDirectiveLines(data, "SecRule")
}

// countNaxsiRules 统计 Naxsi 的 MainRule / BasicRule 指令行。
func countNaxsiRules(data []byte) int {
	return countDirectiveLines(data, "MainRule") + countDirectiveLines(data, "BasicRule")
}

// countDirectiveLines 统计「行首（忽略缩进）为指令名且后接空白」的行数。
// 用字节扫描而不是整段正则，避免 CRS 上万行的正则回溯。
func countDirectiveLines(data []byte, directive string) int {
	count := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimLeft(line, " \t")
		if !bytes.HasPrefix(trimmed, []byte(directive)) {
			continue
		}
		rest := trimmed[len(directive):]
		if len(rest) == 0 || rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		count++
	}
	return count
}

// crowdsecRuleSets 用 `cscli scenarios list -o json` 列出场景。
//
// 诚实口径：crowdsec 的「规则集」是场景，一个场景的 rule_count 记为 1——
// 它没有 ModSecurity 的 SecRule 行级计数，不拿别的数字冒充。
func crowdsecRuleSets(env Environment) ([]RuleSet, error) {
	if _, ok := env.LookPath("cscli"); !ok {
		return nil, nil
	}
	result, err := env.Run("cscli", "scenarios", "list", "-o", "json")
	if err != nil {
		if isFault(err) {
			return nil, err
		}
		return nil, NewOpError(OpFailed, "执行 cscli scenarios list 失败: "+err.Error())
	}
	if result.ExitCode != 0 {
		return nil, NewOpError(OpFailed, "cscli scenarios list 退出码 "+strconv.Itoa(result.ExitCode)+"："+
			trimLine(result.Stderr, 200))
	}
	var items []json.RawMessage
	if err := json.Unmarshal(result.Stdout, &items); err != nil {
		return nil, NewOpError(OpFailed, "解析 cscli scenarios JSON 失败: "+err.Error())
	}
	ruleSets := make([]RuleSet, 0, len(items))
	for _, item := range items {
		fields, err := decodeFlexibleObject(item)
		if err != nil {
			continue // 单条格式异常不拖垮整表
		}
		name := fieldString(fields, "name")
		path := fieldString(fields, "file")
		if name == "" {
			name = path
		}
		if name == "" {
			continue
		}
		enabled := true
		if value, ok := fieldBool(fields, "enabled"); ok {
			enabled = value
		}
		ruleSets = append(ruleSets, RuleSet{Name: name, Path: path, RuleCount: 1, Enabled: enabled})
	}
	sort.Slice(ruleSets, func(i, j int) bool { return ruleSets[i].Name < ruleSets[j].Name })
	return ruleSets, nil
}

// decodeFlexibleObject 把 JSON 对象解成「键 → 原始值」，键大小写不敏感匹配。
// 这是 G-24 允许的内部收口：外部工具字段名大小写不稳定，先收成原始值再转显式类型。
func decodeFlexibleObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// fieldString 按键（大小写不敏感）取字符串值。
func fieldString(fields map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		for actual, raw := range fields {
			if !strings.EqualFold(actual, key) {
				continue
			}
			var text string
			if err := json.Unmarshal(raw, &text); err == nil {
				return text
			}
			break
		}
	}
	return ""
}

// fieldBool 按键（大小写不敏感）取布尔值；也接受 "true"/"false" 字符串。
func fieldBool(fields map[string]json.RawMessage, keys ...string) (bool, bool) {
	for _, key := range keys {
		for actual, raw := range fields {
			if !strings.EqualFold(actual, key) {
				continue
			}
			var value bool
			if err := json.Unmarshal(raw, &value); err == nil {
				return value, true
			}
			var text string
			if err := json.Unmarshal(raw, &text); err == nil {
				switch strings.ToLower(text) {
				case "true", "enabled":
					return true, true
				case "false", "disabled":
					return false, true
				}
			}
			return false, false
		}
	}
	return false, false
}

// installHint 是「没有引擎」时的可操作安装建议（ADR-0018 的 hint 要求）。
func installHint() string {
	return "未检测到 WAF 引擎。安装其一后重试（安装完保持 engine=auto 或手动选择）：" +
		"modsecurity（Debian/Ubuntu：apt install libmodsecurity3 + nginx modsecurity 模块）；" +
		"naxsi（apt install libnginx-mod-http-naxsi 并在 nginx.conf 加载）；" +
		"coraza（https://coraza.io 独立二进制或 Caddy 模块）；" +
		"crowdsec（https://install.crowdsec.net 一键脚本）。"
}
