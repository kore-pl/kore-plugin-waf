package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-waf/internal/plugincfg"
	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// embeddedInfo 是随二进制发布的内嵌清单：只含握手字段，字节稳定。
// 刻意不内嵌 info.json——其 size_bytes 会被打包脚本回填，若内嵌会使二进制
// 随清单自指震荡，破坏 make dist 的 sha 确定性（manifest.json 提交态固定）。
//
//go:embed manifest.json
var embeddedInfo []byte

// manifest 是 info.json 中插件运行期真正需要的字段，其余字段归内核校验。
type manifest struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	RequiresKore string   `json:"requires_kore"`
	Capabilities []string `json:"capabilities"`
}

// fileValues 是 <state_dir>/config.json 的显式形状（G-24：不引入 object/any）。
type fileValues struct {
	// Engine 是首选引擎：auto|modsecurity|naxsi|coraza|crowdsec。
	Engine string `json:"engine"`
	// RulesDirs 覆盖内置规则目录；空表示按引擎用缺省目录。
	RulesDirs []string `json:"rules_dirs"`
	// LogPaths 覆盖内置日志路径；空表示按引擎用缺省路径。
	LogPaths []string `json:"log_paths"`
	// ModeConfigPath 是 kore 管理的模式包含文件。
	ModeConfigPath string `json:"mode_config_path"`
	// MaxLogBytes 是单日志文件读取上限。
	MaxLogBytes int64 `json:"max_log_bytes"`
}

// optionalValues 用于「配置文件部分字段 + 环境变量 + 默认值」的逐字段合并。
type optionalValues struct {
	Engine         *string   `json:"engine"`
	RulesDirs      *[]string `json:"rules_dirs"`
	LogPaths       *[]string `json:"log_paths"`
	ModeConfigPath *string   `json:"mode_config_path"`
	MaxLogBytes    *int64    `json:"max_log_bytes"`
}

// config 是插件运行期配置：配置契约（config.json）+ 环境变量 + 内嵌清单。
type config struct {
	socket       string
	id           string
	token        string
	version      string
	requiresKore string
	capabilities []string
	startedAt    time.Time
	// stateDir 是插件状态目录（KORE_STATE_DIR），配置落盘为 <stateDir>/config.json。
	stateDir string
	// store 是配置文件的 0600 原子读写器。
	store *plugincfg.Store
	// values / source 是 config.get 的当前值与来源（file / env / default）。
	values fileValues
	source string
	// runtime 是方法面执行体；config.set 后热替换 settings。
	runtime *wafop.Runtime
}

// loadConfig 读取配置契约文件与环境变量，并按 file > env > default 解析运行期参数。
func loadConfig() (config, error) {
	var m manifest
	if err := json.Unmarshal(embeddedInfo, &m); err != nil {
		return config{}, fmt.Errorf("解析内嵌 manifest.json: %w", err)
	}
	if m.Protocol != pluginapi.Protocol {
		return config{}, fmt.Errorf("info.json.protocol=%q 与 SDK 协议 %q 不一致", m.Protocol, pluginapi.Protocol)
	}
	if err := plugincfg.ValidateSchema(wafConfigSchema()); err != nil {
		return config{}, fmt.Errorf("config schema 非法: %w", err)
	}
	stateDir := strings.TrimSpace(os.Getenv("KORE_STATE_DIR"))
	store := plugincfg.NewStore(stateDir)
	values, source, err := resolveValues(store)
	if err != nil {
		return config{}, err
	}
	settings, err := settingsFromValues(values)
	if err != nil {
		return config{}, err
	}
	cfg := config{
		socket:       os.Getenv("KORE_PLUGIN_SOCK"),
		id:           os.Getenv("KORE_PLUGIN_ID"),
		token:        os.Getenv("KORE_PLUGIN_TOKEN"),
		version:      m.Version,
		requiresKore: m.RequiresKore,
		capabilities: m.Capabilities,
		startedAt:    time.Now(),
		stateDir:     stateDir,
		store:        store,
		values:       values,
		source:       source,
	}
	if cfg.id == "" {
		cfg.id = m.ID
	}
	if cfg.socket == "" {
		return config{}, fmt.Errorf("缺少环境变量 KORE_PLUGIN_SOCK")
	}
	cfg.runtime = wafop.New(wafop.Options{
		Env:        wafop.OSEnvironment(),
		Settings:   settings,
		RootAction: rootActionFunc(),
	})
	return cfg, nil
}

// defaultValues 是代码默认值（source=default）。
func defaultValues() fileValues {
	return fileValues{
		Engine:         "auto",
		RulesDirs:      []string{},
		LogPaths:       []string{},
		ModeConfigPath: "",
		MaxLogBytes:    wafop.DefaultMaxLogBytes,
	}
}

// resolveValues 实现优先级 config.json > 环境变量 > 代码默认值。
// 配置文件损坏或非法时启动失败（不静默回退），避免用户以为保存生效了却跑着旧值。
func resolveValues(store *plugincfg.Store) (fileValues, string, error) {
	values := defaultValues()
	source := plugincfg.SourceDefault
	applied, err := applyEnv(&values)
	if err != nil {
		return fileValues{}, "", err
	}
	if applied {
		source = plugincfg.SourceEnv
	}
	if store.Exists() {
		raw, _, err := store.Read()
		if err != nil {
			return fileValues{}, "", err
		}
		var optional optionalValues
		if err := decodeStrictJSON(raw, &optional); err != nil {
			return fileValues{}, "", fmt.Errorf("解析插件配置 %s: %w", store.Path(), err)
		}
		applyOptional(&values, optional)
		source = plugincfg.SourceFile
	}
	if err := validateValues(values); err != nil {
		return fileValues{}, "", fmt.Errorf("插件配置非法: %w", err)
	}
	return values, source, nil
}

// applyEnv 把 KORE_WAF_* 环境变量叠加到 values；返回是否有任一变量生效。
// KORE_WAF_RULES_ROOT 是 0.1.x 的历史变量，映射为规则目录（仅当未显式配置规则目录）。
func applyEnv(values *fileValues) (bool, error) {
	applied := false
	if raw := strings.TrimSpace(os.Getenv("KORE_WAF_ENGINE")); raw != "" {
		values.Engine = strings.ToLower(raw)
		applied = true
	}
	if raw := strings.TrimSpace(os.Getenv("KORE_WAF_RULES_DIRS")); raw != "" {
		dirs, err := parseEnvList(raw)
		if err != nil {
			return false, fmt.Errorf("KORE_WAF_RULES_DIRS: %w", err)
		}
		values.RulesDirs = dirs
		applied = true
	}
	if raw := strings.TrimSpace(os.Getenv("KORE_WAF_LOG_PATHS")); raw != "" {
		paths, err := parseEnvList(raw)
		if err != nil {
			return false, fmt.Errorf("KORE_WAF_LOG_PATHS: %w", err)
		}
		values.LogPaths = paths
		applied = true
	}
	if raw := strings.TrimSpace(os.Getenv("KORE_WAF_MODE_CONFIG")); raw != "" {
		values.ModeConfigPath = raw
		applied = true
	}
	if raw := strings.TrimSpace(os.Getenv("KORE_WAF_MAX_LOG_BYTES")); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return false, fmt.Errorf("KORE_WAF_MAX_LOG_BYTES=%q 不是整数", raw)
		}
		values.MaxLogBytes = size
		applied = true
	}
	if legacy := strings.TrimSpace(os.Getenv("KORE_WAF_RULES_ROOT")); legacy != "" && len(values.RulesDirs) == 0 {
		values.RulesDirs = []string{legacy}
		applied = true
	}
	return applied, nil
}

// parseEnvList 解析环境变量里的列表：优先 JSON 数组，退回逗号分隔。
func parseEnvList(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "[") {
		var items []string
		if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
			return nil, fmt.Errorf("不是合法 JSON 数组: %w", err)
		}
		return items, nil
	}
	parts := strings.Split(trimmed, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			items = append(items, value)
		}
	}
	return items, nil
}

// applyOptional 用配置文件中出现的字段覆盖当前值（缺省字段保留环境变量/默认值）。
func applyOptional(values *fileValues, optional optionalValues) {
	if optional.Engine != nil {
		values.Engine = strings.ToLower(strings.TrimSpace(*optional.Engine))
	}
	if optional.RulesDirs != nil {
		values.RulesDirs = *optional.RulesDirs
	}
	if optional.LogPaths != nil {
		values.LogPaths = *optional.LogPaths
	}
	if optional.ModeConfigPath != nil {
		values.ModeConfigPath = strings.TrimSpace(*optional.ModeConfigPath)
	}
	if optional.MaxLogBytes != nil {
		values.MaxLogBytes = *optional.MaxLogBytes
	}
}

// validateValues 全量校验配置值；错误信息写「哪一项错 + 怎么改」。
func validateValues(values fileValues) error {
	switch values.Engine {
	case "auto", wafop.EngineModSecurity, wafop.EngineNaxsi, wafop.EngineCoraza, wafop.EngineCrowdSec:
	default:
		return fmt.Errorf("engine=%q 非法，可选：auto / modsecurity / naxsi / coraza / crowdsec", values.Engine)
	}
	if err := validatePathList(values.RulesDirs, "rules_dirs"); err != nil {
		return err
	}
	if err := validatePathList(values.LogPaths, "log_paths"); err != nil {
		return err
	}
	if values.ModeConfigPath != "" {
		if err := validateAbsolutePath(values.ModeConfigPath, "mode_config_path"); err != nil {
			return err
		}
	}
	if values.MaxLogBytes < wafop.MinMaxLogBytes || values.MaxLogBytes > wafop.MaxMaxLogBytes {
		return fmt.Errorf("max_log_bytes=%d 超出 %d–%d（字节）", values.MaxLogBytes, wafop.MinMaxLogBytes, wafop.MaxMaxLogBytes)
	}
	return nil
}

// validatePathList 校验路径列表：≤32 项、每项绝对路径。
func validatePathList(paths []string, label string) error {
	if len(paths) > 32 {
		return fmt.Errorf("%s 最多 32 项（当前 %d）", label, len(paths))
	}
	for index, path := range paths {
		if err := validateAbsolutePath(path, fmt.Sprintf("%s[%d]", label, index)); err != nil {
			return err
		}
	}
	return nil
}

// validateAbsolutePath 校验单个绝对路径（不要求存在：引擎可能稍后安装）。
func validateAbsolutePath(path, label string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s 不能为空", label)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%s 含 NUL 字符", label)
	}
	if len(path) > 4096 {
		return fmt.Errorf("%s 超过 4096 字节", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s=%q 必须是绝对路径", label, path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%s=%q 不是规范化的绝对路径（含 .. 或多余分隔符）", label, path)
	}
	return nil
}

// settingsFromValues 把配置值转成方法面的运行期参数。
func settingsFromValues(values fileValues) (wafop.Settings, error) {
	if err := validateValues(values); err != nil {
		return wafop.Settings{}, err
	}
	return wafop.Settings{
		Engine:         values.Engine,
		RulesDirs:      values.RulesDirs,
		LogPaths:       values.LogPaths,
		ModeConfigPath: values.ModeConfigPath,
		MaxLogBytes:    values.MaxLogBytes,
	}, nil
}

// wafConfigSchema 是 config.get 返回的表单描述（字段顺序即 UI 顺序）。
func wafConfigSchema() plugincfg.Schema {
	minBytes := int(wafop.MinMaxLogBytes)
	maxBytes := int(wafop.MaxMaxLogBytes)
	return plugincfg.Schema{
		Title: "WAF 管理",
		Fields: []plugincfg.Field{
			{
				Key: "engine", Label: "WAF 引擎", Type: plugincfg.TypeSelect,
				Options: []string{"auto", "modsecurity", "naxsi", "coraza", "crowdsec"},
				Default: json.RawMessage(`"auto"`), Required: false,
				Help: "auto 自动探测；也可指定优先管理的引擎（不会安装引擎）",
			},
			{
				Key: "rules_dirs", Label: "规则目录", Type: plugincfg.TypeList, Item: plugincfg.TypeString,
				Default: json.RawMessage(`[]`), Required: false,
				Help: "留空使用内置缺省目录；每项一条绝对路径，如 /usr/share/modsecurity-crs/rules",
			},
			{
				Key: "log_paths", Label: "日志路径", Type: plugincfg.TypeList, Item: plugincfg.TypeString,
				Default: json.RawMessage(`[]`), Required: false,
				Help: "留空使用内置缺省路径；每项一条绝对路径，只读文件尾部",
			},
			{
				Key: "mode_config_path", Label: "模式包含文件", Type: plugincfg.TypeString,
				Default: json.RawMessage(`""`), Required: false,
				Help: "留空按引擎选择（modsecurity: /etc/modsecurity/kore-mode.conf；coraza: /etc/coraza/kore-mode.conf）；需在引擎主配置里 Include 它",
			},
			{
				Key: "max_log_bytes", Label: "单日志读取上限（字节）", Type: plugincfg.TypeInt,
				Min: &minBytes, Max: &maxBytes,
				Default: json.RawMessage(`1048576`), Required: false,
				Help: "只读日志尾部，默认 1 MiB，范围 64 KiB–8 MiB",
			},
		},
	}
}

// decodeStrictJSON 严格解码（拒绝未知字段），用于配置文件与 config.set。
func decodeStrictJSON(raw json.RawMessage, target any) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return fmt.Errorf("必须是 JSON 对象")
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("必须是 JSON 对象")
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
