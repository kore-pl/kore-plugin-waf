package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/plugincfg"
	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// realRuleFileA / realRuleFileB 是 CRS 风格的规则文件内容（真实文件结构，非 mock 文件系统）：
// 统计口径 = 行首（允许缩进）SecRule 指令行，注释行不计。
const realRuleFileA = `# REQUEST-942-APPLICATION-ATTACK-SQLI
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:select.*from)" \
    "id:942100,phase:2,block,t:none,t:urlDecodeUni,msg:'SQL Injection'"
SecRule REQUEST_FILENAME "@rx \.php$" \
    "id:942101,phase:2,block,msg:'PHP'"
  SecRule ARGS "@rx union" "id:942102,phase:2,deny"
# SecRule ARGS "@rx commented" "id:942103,phase:2,deny"
`

const realRuleFileB = `SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=1"
SecRule REQUEST_URI "@rx /admin" "id:100001,phase:1,deny"
SecRule REQUEST_HEADERS:Host "@rx evil" "id:100002,phase:1,block"
`

// realLogContent 是 ModSecurity 错误日志（真实 nginx error.log 格式）。
const realLogContent = `2026/11/23 11:58:01 [error] 42#42: *7 ModSecurity: Access denied with code 403 (phase 2). Matches "union" [file "/rules/a.conf"] [line "5"] [id "942100"] [uri "/login?user=1"] [hostname "example.com"]
2026/11/23 11:58:30 [error] 42#42: *8 ModSecurity: Warning. detected [client 198.51.100.9] [id "920350"] [uri "/api/items"]
2026/11/23 11:59:00 [error] 42#42: *9 upstream timed out
`

// TestConstructedEngineLayout 用真实文件结构 + 环境变量指向验证解析逻辑（本机无引擎）。
//
// 覆盖：env → config 解析 → 引擎识别（配置目录证据）→ 模式识别 → 规则计数 → 日志解析
// → config.get 来源；这是「未对接真实运行引擎」下能做到的最强验证。
func TestConstructedEngineLayout(t *testing.T) {
	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("创建规则目录: %v", err)
	}
	ruleA := filepath.Join(rulesDir, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
	ruleB := filepath.Join(rulesDir, "REQUEST-100-CUSTOM.conf")
	if err := os.WriteFile(ruleA, []byte(realRuleFileA), 0o644); err != nil {
		t.Fatalf("写规则文件 A: %v", err)
	}
	if err := os.WriteFile(ruleB, []byte(realRuleFileB), 0o644); err != nil {
		t.Fatalf("写规则文件 B: %v", err)
	}
	logPath := filepath.Join(root, "nginx-error.log")
	if err := os.WriteFile(logPath, []byte(realLogContent), 0o644); err != nil {
		t.Fatalf("写日志: %v", err)
	}
	modePath := filepath.Join(root, "kore-mode.conf")
	if err := os.WriteFile(modePath, []byte("SecRuleEngine On\n"), 0o644); err != nil {
		t.Fatalf("写模式文件: %v", err)
	}
	stateDir := filepath.Join(root, "state")
	rulesJSON, _ := json.Marshal([]string{rulesDir})
	logsJSON, _ := json.Marshal([]string{logPath})

	t.Setenv("KORE_PLUGIN_SOCK", filepath.Join(root, "fake.sock")) // 只做配置解析，不建连
	t.Setenv("KORE_STATE_DIR", stateDir)
	t.Setenv("KORE_WAF_ENGINE", "modsecurity")
	t.Setenv("KORE_WAF_RULES_DIRS", string(rulesJSON))
	t.Setenv("KORE_WAF_LOG_PATHS", string(logsJSON))
	t.Setenv("KORE_WAF_MODE_CONFIG", modePath)
	t.Setenv("KORE_KERNEL_SOCK", "")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.source != plugincfg.SourceEnv {
		t.Fatalf("source=%q，期望 env", cfg.source)
	}

	// 1) status：引擎识别 + 模式 + 规则条数（3 + 2 = 5）。
	statusRaw, perr := cfg.runtime.Call("waf.status", nil)
	if perr != nil {
		t.Fatalf("status: %v", perr)
	}
	var status wafop.StatusResult
	if err := json.Unmarshal(statusRaw, &status); err != nil {
		t.Fatalf("解析 status: %v", err)
	}
	if !status.Available || status.Engine != wafop.EngineModSecurity {
		t.Fatalf("构造布局未被识别: %+v", status)
	}
	if status.Mode != wafop.ModeOn || !strings.HasSuffix(status.ModeSource, "kore-mode.conf") {
		t.Fatalf("模式识别不正确: %+v", status)
	}
	if status.RulesCount != 5 {
		t.Fatalf("规则条数=%d，期望 5（规则文件中的 SecRule 行）", status.RulesCount)
	}
	if !status.RequiresRoot {
		t.Fatalf("应声明 requires_root: %+v", status)
	}
	if len(status.Probed) != 1 || !strings.Contains(status.Probed[0].Evidence, rulesDir) {
		t.Fatalf("探测证据应指向配置目录: %+v", status.Probed)
	}

	// 2) rules：两个规则集，路径与计数正确。
	rulesRaw, perr := cfg.runtime.Call("waf.rules", []byte(`{}`))
	if perr != nil {
		t.Fatalf("rules: %v", perr)
	}
	var rules wafop.RulesResult
	if err := json.Unmarshal(rulesRaw, &rules); err != nil {
		t.Fatalf("解析 rules: %v", err)
	}
	if rules.Total != 5 || len(rules.RuleSets) != 2 {
		t.Fatalf("规则集统计不正确: %+v", rules)
	}
	countByFile := map[string]int{}
	for _, ruleSet := range rules.RuleSets {
		countByFile[filepath.Base(ruleSet.Path)] = ruleSet.RuleCount
	}
	if countByFile["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] != 3 || countByFile["REQUEST-100-CUSTOM.conf"] != 2 {
		t.Fatalf("单文件计数不正确: %+v", countByFile)
	}

	// 3) logs：两条 ModSecurity 行被解析，无关行忽略。
	logsRaw, perr := cfg.runtime.Call("waf.logs", []byte(`{"limit":200}`))
	if perr != nil {
		t.Fatalf("logs: %v", perr)
	}
	var logs wafop.LogsResult
	if err := json.Unmarshal(logsRaw, &logs); err != nil {
		t.Fatalf("解析 logs: %v", err)
	}
	if logs.Count != 2 || len(logs.Sources) != 1 || !logs.Sources[0].Readable {
		t.Fatalf("日志解析不正确: %+v", logs)
	}
	if logs.Entries[0].URI == "" || logs.Entries[1].URI == "" {
		t.Fatalf("URI 未解析: %+v", logs.Entries)
	}
	if !strings.Contains(logs.Entries[0].URI+logs.Entries[1].URI, "/login?user=1") {
		t.Fatalf("应保留原始查询串: %+v", logs.Entries)
	}
	if logs.ScannedLines == 0 || logs.MatchedLines != 2 {
		t.Fatalf("行统计不正确: %+v", logs)
	}

	// 4) toggle：无 root-action 通道 → E_NEED_ROOT（不是静默成功）。
	if _, perr := cfg.runtime.Call("waf.toggle", []byte(`{"mode":"detection"}`)); perr == nil || perr.Code != "E_NEED_ROOT" {
		t.Fatalf("无通道应 E_NEED_ROOT，实际 %v", perr)
	}
	if _, perr := cfg.runtime.Call("waf.toggle", []byte(`{"mode":"off"}`)); perr == nil || perr.Code != pluginapi.E_UNAUTHORIZED {
		t.Fatalf("关闭拦截缺 confirm 应 E_UNAUTHORIZED，实际 %v", perr)
	}

	// 5) config.get：来源 env，值与环境变量一致。
	getRaw, perr := handleConfigGet(&cfg)
	if perr != nil {
		t.Fatalf("config.get: %v", perr)
	}
	var getResult plugincfg.GetResult
	if err := json.Unmarshal(getRaw, &getResult); err != nil {
		t.Fatalf("解析 config.get: %v", err)
	}
	var values fileValues
	if err := json.Unmarshal(getResult.Values, &values); err != nil {
		t.Fatalf("解析 values: %v", err)
	}
	if getResult.Source != plugincfg.SourceEnv || values.Engine != "modsecurity" {
		t.Fatalf("config.get 来源/值不正确: %+v", getResult)
	}
	if len(values.RulesDirs) != 1 || values.RulesDirs[0] != rulesDir {
		t.Fatalf("rules_dirs 未从环境变量解析: %+v", values)
	}
}
