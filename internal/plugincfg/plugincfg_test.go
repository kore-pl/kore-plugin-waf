package plugincfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSchema 含一个敏感字段，用于验证 config.get 不回传原值。
func testSchema() Schema {
	return Schema{Title: "测试", Fields: []Field{
		{Key: "password", Label: "密码", Type: TypeString, Default: json.RawMessage(`""`), Help: "只写不回显", Sensitive: true},
		{Key: "name", Label: "名称", Type: TypeString, Default: json.RawMessage(`"kore"`), Help: "普通字段"},
		{Key: "sources", Label: "来源", Type: TypeList, Item: TypeString, Default: json.RawMessage(`[]`), Help: "列表"},
	}}
}

func TestValidateSchema(t *testing.T) {
	if err := ValidateSchema(testSchema()); err != nil {
		t.Fatalf("合法 schema 被拒绝: %v", err)
	}
	bad := testSchema()
	bad.Fields[1].Type = "object"
	if err := ValidateSchema(bad); err == nil || !strings.Contains(err.Error(), "不在枚举内") {
		t.Fatalf("object 类型应被拒绝，得到 %v", err)
	}
	nested := testSchema()
	nested.Fields[2].Item = TypeList
	if err := ValidateSchema(nested); err == nil || !strings.Contains(err.Error(), "不是标量") {
		t.Fatalf("嵌套 list 应被拒绝，得到 %v", err)
	}
}

func TestMaskValuesNeverReturnsSecret(t *testing.T) {
	raw := json.RawMessage(`{"password":"s3cr3t","name":"kore","sources":["a=/tmp/a"]}`)
	masked, err := MaskValues(testSchema(), raw)
	if err != nil {
		t.Fatalf("MaskValues: %v", err)
	}
	if strings.Contains(string(masked), "s3cr3t") {
		t.Fatalf("config.get 泄露了敏感原值: %s", masked)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(masked, &got); err != nil {
		t.Fatalf("解析掩码结果: %v", err)
	}
	if string(got["password"]) != `"`+SensitivePlaceholder+`"` {
		t.Fatalf("敏感字段占位=%s", got["password"])
	}
	if !IsSensitivePlaceholder(got["password"]) {
		t.Fatal("占位值应被识别为不修改")
	}
}

func TestStoreAtomicWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if store.Path() != filepath.Join(dir, ConfigFileName) {
		t.Fatalf("路径=%s", store.Path())
	}
	if _, ok, err := store.Read(); ok || err != nil {
		t.Fatalf("未创建时应返回 (nil,false,nil)，得到 ok=%v err=%v", ok, err)
	}
	if err := store.Write(json.RawMessage(`{"sources":["syslog=/var/log/syslog"]}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("配置权限=%o，期望 600", info.Mode().Perm())
	}
	raw, ok, err := store.Read()
	if err != nil || !ok || !strings.Contains(string(raw), "syslog=/var/log/syslog") {
		t.Fatalf("Read=%s ok=%v err=%v", raw, ok, err)
	}
	// 覆盖写失败不应留半份文件：写入非法 JSON 被拒绝，旧内容仍可读。
	if err := store.Write(json.RawMessage(`{"x":`)); err == nil {
		t.Fatal("非法 JSON 应被拒绝")
	}
	if raw, _, _ := store.Read(); !strings.Contains(string(raw), "syslog=/var/log/syslog") {
		t.Fatalf("失败写入破坏了旧配置: %s", raw)
	}
}
