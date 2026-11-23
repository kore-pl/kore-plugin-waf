package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/plugincfg"
	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// dispatchOnce 构造请求并走一次 dispatch。
func dispatchOnce(t *testing.T, cfg *config, method, params string) *pluginapi.Response {
	t.Helper()
	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: method, Params: json.RawMessage(params),
	}
	response, shutdown := dispatch(request, cfg, testLogger())
	if shutdown {
		t.Fatalf("%s 不应触发 shutdown", method)
	}
	return response
}

// TestDispatchMethodsNoEngine 无引擎时五个方法都可用：读方法返回 available=false，toggle 返回结构化不可用。
func TestDispatchMethodsNoEngine(t *testing.T) {
	cfg := testConfig(t)
	cases := []struct {
		method string
		params string
		want   []string
	}{
		{"waf.status", `{}`, []string{`"available":false`, `"engine":"none"`, `"error_code":"E_UNSUPPORTED"`, `"requires_root":true`}},
		{"waf.rules", `{}`, []string{`"available":false`, `"error_code":"E_UNSUPPORTED"`, `"rulesets":[]`}},
		{"waf.logs", `{"limit":7}`, []string{`"available":false`, `"error_code":"E_UNSUPPORTED"`, `"limit":7`}},
		{"waf.toggle", `{"mode":"on"}`, []string{`"available":false`, `"applied":false`, `"error_code":"E_UNSUPPORTED"`}},
	}
	for _, c := range cases {
		response := dispatchOnce(t, cfg, c.method, c.params)
		if response.Error != nil {
			t.Fatalf("%s 无引擎不应返回协议错误: %v", c.method, response.Error)
		}
		for _, want := range c.want {
			if !strings.Contains(string(response.Result), want) {
				t.Fatalf("%s 结果=%s，未含 %q", c.method, response.Result, want)
			}
		}
	}
}

// TestDispatchReject 非法参数与未知方法返回协议错误。
func TestDispatchReject(t *testing.T) {
	cfg := testConfig(t)
	cases := []struct {
		method string
		params string
		code   string
	}{
		{"waf.toggle", `{"mode":"banana"}`, pluginapi.E_INVALID},
		{"waf.toggle", `{"mode":"on","unknown":1}`, pluginapi.E_INVALID},
		{"waf.logs", `{"limit":201}`, pluginapi.E_INVALID},
		{"waf.logs", `{"since":"whenever"}`, pluginapi.E_INVALID},
		{"waf.rules", `{"engine":"squid"}`, pluginapi.E_INVALID},
		{"waf.exec", `{}`, pluginapi.E_NOTFOUND},
	}
	for _, c := range cases {
		response := dispatchOnce(t, cfg, c.method, c.params)
		if response.Error == nil || response.Error.Code != c.code {
			t.Fatalf("%s 错误=%v，期望 %q", c.method, response.Error, c.code)
		}
		if response.Result != nil {
			t.Fatalf("%s 出错时不应带结果", c.method)
		}
	}
}

// TestConfigGetDefault 配置契约：默认值 + source=default + schema 五个字段。
func TestConfigGetDefault(t *testing.T) {
	cfg := testConfig(t)
	response := dispatchOnce(t, cfg, "waf.config.get", `{}`)
	if response.Error != nil {
		t.Fatalf("config.get: %v", response.Error)
	}
	var result plugincfg.GetResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析 config.get: %v", err)
	}
	if result.Source != plugincfg.SourceDefault {
		t.Fatalf("source=%q，期望 default", result.Source)
	}
	if len(result.Schema.Fields) != 5 {
		t.Fatalf("schema 应有 5 个字段，实际 %d", len(result.Schema.Fields))
	}
	var values fileValues
	if err := json.Unmarshal(result.Values, &values); err != nil {
		t.Fatalf("解析 values: %v", err)
	}
	if values.Engine != "auto" || values.MaxLogBytes != wafop.DefaultMaxLogBytes || values.ModeConfigPath != "" {
		t.Fatalf("默认值不正确: %+v", values)
	}
}

// TestConfigSetHotApply 配置保存：0600 落盘、source 变 file、下一次业务调用立即生效。
func TestConfigSetHotApply(t *testing.T) {
	cfg := testConfig(t)
	rulesDir := t.TempDir()
	params := `{"values":{"engine":"modsecurity","rules_dirs":["` + rulesDir + `"],"max_log_bytes":131072}}`
	response := dispatchOnce(t, cfg, "waf.config.set", params)
	if response.Error != nil {
		t.Fatalf("config.set: %v", response.Error)
	}
	var setResult plugincfg.SetResult
	if err := json.Unmarshal(response.Result, &setResult); err != nil {
		t.Fatalf("解析 set: %v", err)
	}
	if !setResult.Saved || !setResult.Applied || setResult.RestartRequired {
		t.Fatalf("保存结果不正确: %+v", setResult)
	}
	// 文件权限 0600 + 内容完整。
	info, err := os.Stat(cfg.store.Path())
	if err != nil {
		t.Fatalf("配置文件未落盘: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("配置文件权限=%o，期望 600", perm)
	}
	raw, err := os.ReadFile(cfg.store.Path())
	if err != nil {
		t.Fatalf("读取配置文件: %v", err)
	}
	var stored fileValues
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("配置文件不是合法 JSON: %v", err)
	}
	if stored.Engine != "modsecurity" || len(stored.RulesDirs) != 1 || stored.MaxLogBytes != 131072 {
		t.Fatalf("落盘值不正确: %+v", stored)
	}
	getResponse := dispatchOnce(t, cfg, "waf.config.get", `{}`)
	var getResult plugincfg.GetResult
	if err := json.Unmarshal(getResponse.Result, &getResult); err != nil {
		t.Fatalf("解析 get: %v", err)
	}
	if getResult.Source != plugincfg.SourceFile {
		t.Fatalf("保存后 source=%q，期望 file", getResult.Source)
	}
	// 热生效：显式引擎 + 已存在的规则目录 → status 立即变为可用（对照 PID 不变语义）。
	statusResponse := dispatchOnce(t, cfg, "waf.status", `{}`)
	var status wafop.StatusResult
	if err := json.Unmarshal(statusResponse.Result, &status); err != nil {
		t.Fatalf("解析 status: %v", err)
	}
	if !status.Available || status.Engine != wafop.EngineModSecurity {
		t.Fatalf("配置未热生效: %+v", status)
	}
}

// TestConfigSetRejectsInvalid 非法值不落盘、不改内存。
func TestConfigSetRejectsInvalid(t *testing.T) {
	cfg := testConfig(t)
	cases := []string{
		`{"values":{"engine":"squid"}}`,
		`{"values":{"rules_dirs":["relative/path"]}}`,
		`{"values":{"log_paths":["/var/log/../etc/passwd"]}}`,
		`{"values":{"max_log_bytes":1024}}`,
		`{"values":{"mode_config_path":"relative.conf"}}`,
		`{"values":{"unknown":1}}`,
	}
	for _, params := range cases {
		response := dispatchOnce(t, cfg, "waf.config.set", params)
		if response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
			t.Fatalf("params=%s 错误=%v，期望 E_INVALID", params, response.Error)
		}
	}
	if cfg.store.Exists() {
		t.Fatal("非法配置不应落盘")
	}
	if cfg.values.Engine != "auto" {
		t.Fatalf("非法配置不应改内存: %+v", cfg.values)
	}
}

// TestConfigEnvPrecedence 环境变量优先于默认值；config.json 优先于环境变量。
func TestConfigEnvPrecedence(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("KORE_STATE_DIR", stateDir)
	t.Setenv("KORE_WAF_ENGINE", "naxsi")
	t.Setenv("KORE_WAF_RULES_DIRS", `["/opt/naxsi/rules"]`)
	t.Setenv("KORE_WAF_MAX_LOG_BYTES", "262144")
	t.Setenv("KORE_WAF_RULES_ROOT", "/legacy/root")
	store := plugincfg.NewStore(stateDir)
	values, source, err := resolveValues(store)
	if err != nil {
		t.Fatalf("resolveValues: %v", err)
	}
	if source != plugincfg.SourceEnv {
		t.Fatalf("source=%q，期望 env", source)
	}
	if values.Engine != "naxsi" || len(values.RulesDirs) != 1 || values.RulesDirs[0] != "/opt/naxsi/rules" {
		t.Fatalf("环境变量未生效: %+v", values)
	}
	if values.MaxLogBytes != 262144 {
		t.Fatalf("max_log_bytes 未生效: %d", values.MaxLogBytes)
	}
	// 配置文件覆盖环境变量（逐字段：只写 engine）。
	raw := json.RawMessage(`{"engine":"coraza"}`)
	if err := store.Write(raw); err != nil {
		t.Fatalf("写配置文件: %v", err)
	}
	values, source, err = resolveValues(store)
	if err != nil {
		t.Fatalf("resolveValues: %v", err)
	}
	if source != plugincfg.SourceFile {
		t.Fatalf("source=%q，期望 file", source)
	}
	if values.Engine != "coraza" {
		t.Fatalf("文件未覆盖 env: %+v", values)
	}
	if values.MaxLogBytes != 262144 || len(values.RulesDirs) != 1 {
		t.Fatalf("未写字段应保留 env 值: %+v", values)
	}
}

// TestConfigLegacyRulesRoot 历史 KORE_WAF_RULES_ROOT 映射为规则目录。
func TestConfigLegacyRulesRoot(t *testing.T) {
	t.Setenv("KORE_STATE_DIR", t.TempDir())
	t.Setenv("KORE_WAF_RULES_ROOT", "/srv/waf/rules")
	values, _, err := resolveValues(plugincfg.NewStore(os.Getenv("KORE_STATE_DIR")))
	if err != nil {
		t.Fatalf("resolveValues: %v", err)
	}
	if len(values.RulesDirs) != 1 || values.RulesDirs[0] != "/srv/waf/rules" {
		t.Fatalf("历史变量未映射: %+v", values)
	}
}

// TestReloadConfig kore.reload 重新解析配置。
func TestReloadConfig(t *testing.T) {
	cfg := testConfig(t)
	raw := json.RawMessage(`{"engine":"naxsi"}`)
	if err := cfg.store.Write(raw); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	result, perr := reloadConfig(cfg)
	if perr != nil {
		t.Fatalf("reload: %v", perr)
	}
	if !strings.Contains(string(result), `"ok":true`) {
		t.Fatalf("reload 结果=%s", result)
	}
	if cfg.values.Engine != "naxsi" || cfg.source != plugincfg.SourceFile {
		t.Fatalf("reload 未更新配置: %+v source=%q", cfg.values, cfg.source)
	}
}

// TestPingResult kore.ping 返回 ready 状态。
func TestPingResult(t *testing.T) {
	cfg := testConfig(t)
	response := dispatchOnce(t, cfg, "kore.ping", ``)
	if !strings.Contains(string(response.Result), `"status":"ready"`) {
		t.Fatalf("ping 结果=%s", response.Result)
	}
}

// TestDispatchShutdown kore.shutdown 回 ok 并标记 shutdown=true。
func TestDispatchShutdown(t *testing.T) {
	cfg := testConfig(t)
	request := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: "kore.shutdown"}
	response, shutdown := dispatch(request, cfg, testLogger())
	if !shutdown || !strings.Contains(string(response.Result), `"ok":true`) {
		t.Fatalf("shutdown 响应=%s shutdown=%v", response.Result, shutdown)
	}
}

// TestConfigSchemaDefaultsMatchDefaults 防止 schema 默认值与代码默认值漂移。
func TestConfigSchemaDefaultsMatchDefaults(t *testing.T) {
	defaults := defaultValues()
	expected := map[string]string{
		"engine":           `"` + defaults.Engine + `"`,
		"rules_dirs":       `[]`,
		"log_paths":        `[]`,
		"mode_config_path": `""`,
		"max_log_bytes":    "1048576",
	}
	for _, field := range wafConfigSchema().Fields {
		want, ok := expected[field.Key]
		if !ok {
			t.Fatalf("schema 出现未预期字段 %q", field.Key)
		}
		if strings.TrimSpace(string(field.Default)) != want {
			t.Fatalf("字段 %s 默认值=%s，期望 %s", field.Key, field.Default, want)
		}
		delete(expected, field.Key)
	}
	if len(expected) != 0 {
		t.Fatalf("schema 缺少字段: %v", expected)
	}
}

// TestConfigSetRequiresStateDir 无 KORE_STATE_DIR 时保存失败且不改内存。
func TestConfigSetRequiresStateDir(t *testing.T) {
	cfg := testConfig(t)
	cfg.store = plugincfg.NewStore("")
	response := dispatchOnce(t, cfg, "waf.config.set", `{"values":{"engine":"naxsi"}}`)
	if response.Error == nil || response.Error.Code != pluginapi.E_INTERNAL {
		t.Fatalf("无状态目录应 E_INTERNAL，实际 %v", response.Error)
	}
	if cfg.values.Engine != "auto" {
		t.Fatalf("失败不应改内存: %+v", cfg.values)
	}
}
