// Package plugincfg 实现 waf 插件的配置契约（kore docs/PLUGIN-CONFIG.md）：
// schema 描述、0600 原子存储、sensitive 掩码与统一的 get/set 响应形状。
//
// 本包只负责契约形状与存储，不替插件做业务校验：调用方必须先校验、
// 再调用 Store.Write，保证「校验 → 原子写 → 更新内存」的顺序。
package plugincfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// ConfigFileName 是插件状态目录下的配置文件名。
	ConfigFileName = "config.json"
	// SensitivePlaceholder 是敏感字段在 config.get 中的占位值；config.set 收到它表示不修改。
	SensitivePlaceholder = "***"
	// SourceFile / SourceEnv / SourceDefault 是 config.get 的 source 枚举。
	SourceFile    = "file"
	SourceEnv     = "env"
	SourceDefault = "default"
)

// 字段类型枚举（与契约文档 §2 一致，禁止扩展成 object）。
const (
	TypeString = "string"
	TypeInt    = "int"
	TypeBool   = "bool"
	TypeSelect = "select"
	TypeList   = "list"
)

// Field 是一个表单字段的显式描述。Default 与 Values 用 json.RawMessage 承载
// 异构标量/数组——这是 G-24 允许的「插件方法结果载荷」受控例外，形状由 Type 定形。
type Field struct {
	Key         string          `json:"key"`
	Label       string          `json:"label"`
	Type        string          `json:"type"`
	Item        string          `json:"item,omitempty"`
	Default     json.RawMessage `json:"default"`
	Required    bool            `json:"required"`
	Help        string          `json:"help"`
	Options     []string        `json:"options,omitempty"`
	Min         *int            `json:"min,omitempty"`
	Max         *int            `json:"max,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	Sensitive   bool            `json:"sensitive,omitempty"`
}

// Schema 是 config.get 返回的表单描述。
type Schema struct {
	Title  string  `json:"title"`
	Fields []Field `json:"fields"`
}

// GetResult 是 <id>.config.get 的结果。
type GetResult struct {
	Schema Schema          `json:"schema"`
	Values json.RawMessage `json:"values"`
	Source string          `json:"source"`
}

// SetParams 是 <id>.config.set 的入参。
type SetParams struct {
	Values json.RawMessage `json:"values"`
}

// SetResult 是 <id>.config.set 的结果。
type SetResult struct {
	Saved           bool     `json:"saved"`
	Applied         bool     `json:"applied"`
	RestartRequired bool     `json:"restart_required"`
	Warnings        []string `json:"warnings"`
}

// Store 是插件配置文件的 0600 原子读写器。
type Store struct {
	path string
}

// NewStore 以插件状态目录（KORE_STATE_DIR）构造存储；目录为空时路径为空，
// Read/Write 会返回明确错误而不是写到相对路径。
func NewStore(stateDir string) *Store {
	dir := strings.TrimSpace(stateDir)
	if dir == "" {
		return &Store{}
	}
	return &Store{path: filepath.Join(filepath.Clean(dir), ConfigFileName)}
}

// Path 返回配置文件绝对路径（未配置状态目录时为空）。
func (s *Store) Path() string { return s.path }

// Exists 报告配置文件是否存在。
func (s *Store) Exists() bool {
	if s.path == "" {
		return false
	}
	info, err := os.Stat(s.path)
	return err == nil && info.Mode().IsRegular()
}

// Read 读取配置原文；文件不存在返回 (nil, false, nil)，不把「未配置」当错误。
func (s *Store) Read() (json.RawMessage, bool, error) {
	if s.path == "" {
		return nil, false, errors.New("KORE_STATE_DIR 未设置，无法定位插件配置")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("读取插件配置 %s: %w", s.path, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || !json.Valid([]byte(trimmed)) {
		return nil, true, fmt.Errorf("插件配置 %s 不是合法 JSON 对象", s.path)
	}
	if trimmed[0] != '{' {
		return nil, true, fmt.Errorf("插件配置 %s 必须是 JSON 对象", s.path)
	}
	return json.RawMessage(trimmed), true, nil
}

// Write 原子写配置：同目录临时文件 → 0600 → fsync → rename → fsync 目录。
// 中途失败不会破坏旧文件。
func (s *Store) Write(values json.RawMessage) error {
	if s.path == "" {
		return errors.New("KORE_STATE_DIR 未设置，无法保存插件配置")
	}
	if len(values) == 0 || !json.Valid(values) || values[0] != '{' {
		return errors.New("配置值必须是合法 JSON 对象")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建插件状态目录 %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时配置文件: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // rename 成功后这里是无操作
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("设置临时配置文件权限: %w", err)
	}
	if _, err := tmp.Write(values); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写临时配置文件: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("同步临时配置文件: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时配置文件: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("替换插件配置 %s: %w", s.path, err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

// ValidateSchema 校验 schema 自身符合契约枚举；插件应在启动时自检一次。
func ValidateSchema(schema Schema) error {
	if strings.TrimSpace(schema.Title) == "" {
		return errors.New("schema.title 不能为空")
	}
	if len(schema.Fields) == 0 {
		return errors.New("schema.fields 不能为空")
	}
	seen := make(map[string]bool, len(schema.Fields))
	for i, field := range schema.Fields {
		if field.Key == "" || field.Label == "" || field.Help == "" {
			return fmt.Errorf("第 %d 个字段缺少 key/label/help", i)
		}
		if seen[field.Key] {
			return fmt.Errorf("字段 key 重复: %s", field.Key)
		}
		seen[field.Key] = true
		if len(field.Default) == 0 || !json.Valid(field.Default) {
			return fmt.Errorf("字段 %s 的 default 不是合法 JSON", field.Key)
		}
		switch field.Type {
		case TypeString, TypeInt, TypeBool:
		case TypeSelect:
			if len(field.Options) == 0 {
				return fmt.Errorf("select 字段 %s 缺少 options", field.Key)
			}
		case TypeList:
			if !scalarType(field.Item) {
				return fmt.Errorf("list 字段 %s 的 item=%q 不是标量类型", field.Key, field.Item)
			}
		default:
			return fmt.Errorf("字段 %s 的 type=%q 不在枚举内", field.Key, field.Type)
		}
		if field.Min != nil && field.Max != nil && *field.Min > *field.Max {
			return fmt.Errorf("字段 %s 的 min 大于 max", field.Key)
		}
	}
	return nil
}

// scalarType 判断 list 元素是否允许的标量类型。
func scalarType(t string) bool {
	switch t {
	case TypeString, TypeInt, TypeBool, TypeSelect:
		return true
	default:
		return false
	}
}

// MaskValues 按 schema 把 sensitive 字段替换为占位值；没有 sensitive 字段时原样返回。
// values 必须是 JSON 对象。
func MaskValues(schema Schema, values json.RawMessage) (json.RawMessage, error) {
	if len(values) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(values, &decoded); err != nil {
		return nil, fmt.Errorf("配置值不是 JSON 对象: %w", err)
	}
	for _, field := range schema.Fields {
		if !field.Sensitive {
			continue
		}
		if _, ok := decoded[field.Key]; ok {
			decoded[field.Key] = json.RawMessage(`"` + SensitivePlaceholder + `"`)
		}
	}
	out, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("序列化掩码配置: %w", err)
	}
	return out, nil
}

// IsSensitivePlaceholder 判断 config.set 收到的值是否为「不修改」占位。
func IsSensitivePlaceholder(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return false
	}
	return text == SensitivePlaceholder
}
