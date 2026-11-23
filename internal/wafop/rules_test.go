package wafop

import (
	"strings"
	"testing"
)

// modsecDetection 返回「已检测到 modsecurity」的判定结果，供规则/日志测试复用。
func modsecDetection() Detection {
	return Detection{Engine: EngineModSecurity, Found: true, Mode: ModeOn, ModeSource: "config"}
}

// TestListRulesModSecurity 统计 SecRule 行：注释行与缩进行分别处理。
func TestListRulesModSecurity(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", strings.Join([]string{
		"SecRuleEngine On",
		"SecRule ARGS \"@rx union\" \"id:942100,phase:2,deny\"",
		"  SecRule REQUEST_URI \"@rx x\" \"id:1\"",
		"# SecRule ARGS \"@rx comment\" \"id:2\"",
		"SecAction \"id:900000,pass\"",
	}, "\n"))
	env.addFile("/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", strings.Join([]string{
		`# 942100`,
		`SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/ "@rx (?i:select.*from)" "id:942100,phase:2,deny"`,
		`SecRule REQUEST_FILENAME "@rx \.php$" "id:942101,phase:2,deny"`,
		`SecRule ARGS "@rx a" "id:942102,phase:2,block"`,
	}, "\n"))
	settings := Settings{Engine: EngineModSecurity}
	result, err := ListRules(env.env(), settings, modsecDetection())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if !result.Available || result.Engine != EngineModSecurity {
		t.Fatalf("应可用，实际 %+v", result)
	}
	if result.Total != 5 {
		t.Fatalf("规则总数应为 5（modsecurity.conf 3 + CRS 3 - 注释 1），实际 %d（%+v）", result.Total, result.RuleSets)
	}
	if len(result.RuleSets) != 2 {
		t.Fatalf("应有两个规则集，实际 %d", len(result.RuleSets))
	}
	for _, ruleSet := range result.RuleSets {
		if !ruleSet.Enabled || ruleSet.RuleCount == 0 || ruleSet.Path == "" {
			t.Fatalf("规则集字段不完整: %+v", ruleSet)
		}
	}
}

// TestListRulesRespectsConfiguredDirs 配置目录优先于内置目录。
func TestListRulesRespectsConfiguredDirs(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/opt/waf/rules/a.conf", "SecRule ARGS \"@rx a\" \"id:1\"\n")
	env.addFile("/etc/modsecurity/default.conf", "SecRule ARGS \"@rx b\" \"id:2\"\n")
	settings := Settings{Engine: EngineModSecurity, RulesDirs: []string{"/opt/waf/rules"}}
	result, err := ListRules(env.env(), settings, modsecDetection())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if result.Total != 1 || result.RuleSets[0].Path != "/opt/waf/rules/a.conf" {
		t.Fatalf("应只统计配置目录，实际 %+v", result.RuleSets)
	}
}

// TestListRulesNaxsi 统计 MainRule / BasicRule。
func TestListRulesNaxsi(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/nginx/naxsi.rules", strings.Join([]string{
		`MainRule "str:select" "msg:sqli" "mz:ARGS" "s:$SQL:8" id:1007;`,
		`BasicRule "str:union" "msg:sqli" "mz:ARGS" "s:$SQL:8" id:1008;`,
		`# MainRule "str:comment" id:1009;`,
	}, "\n"))
	detection := Detection{Engine: EngineNaxsi, Found: true, Mode: ModeOn}
	result, err := ListRules(env.env(), Settings{Engine: EngineNaxsi}, detection)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if result.Total != 2 {
		t.Fatalf("Naxsi 规则数应为 2，实际 %d（%+v）", result.Total, result.RuleSets)
	}
}

// TestListRulesCrowdSec 解析 cscli scenarios JSON（键大小写不敏感）。
func TestListRulesCrowdSec(t *testing.T) {
	env := newFakeEnv()
	env.setCommand("cscli", func(args ...string) (CommandResult, error) {
		return CommandResult{Stdout: []byte(`[
			{"Name":"crowdsecurity/ssh-bf","File":"/etc/crowdsec/scenarios/ssh-bf.yaml","Enabled":true},
			{"name":"crowdsecurity/http-bf","file":"/etc/crowdsec/scenarios/http-bf.yaml","enabled":false}
		]`)}, nil
	})
	detection := Detection{Engine: EngineCrowdSec, Found: true, Mode: ModeOn}
	result, err := ListRules(env.env(), Settings{Engine: EngineCrowdSec}, detection)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if result.Total != 2 || len(result.RuleSets) != 2 {
		t.Fatalf("应有两个场景，实际 %+v", result.RuleSets)
	}
	if result.RuleSets[0].Name != "crowdsecurity/http-bf" && result.RuleSets[0].Name != "crowdsecurity/ssh-bf" {
		t.Fatalf("场景名解析异常: %+v", result.RuleSets)
	}
	for _, ruleSet := range result.RuleSets {
		if ruleSet.RuleCount != 1 {
			t.Fatalf("crowdsec 场景按 1 条计，实际 %+v", ruleSet)
		}
	}
}

// TestListRulesNoEngine 无引擎：结构化不可用，不报错。
func TestListRulesNoEngine(t *testing.T) {
	env := newFakeEnv()
	result, err := ListRules(env.env(), Settings{Engine: "auto"}, Detection{Engine: EngineNone, Mode: ModeOff})
	if err != nil {
		t.Fatalf("无引擎不应报错: %v", err)
	}
	if result.Available || result.ErrorCode != "E_UNSUPPORTED" || result.Hint == "" {
		t.Fatalf("应 available=false + E_UNSUPPORTED + hint，实际 %+v", result)
	}
	if result.RuleSets == nil {
		t.Fatal("rulesets 应为空数组而不是 null")
	}
}

// TestCountDirectiveLinesEdge 边界：指令名后缀、空行、行首注释。
func TestCountDirectiveLinesEdge(t *testing.T) {
	if count := countDirectiveLines([]byte("SecRuleX a\nSecRule \n\tSecRule b\n#SecRule c\n"), "SecRule"); count != 2 {
		t.Fatalf("应计 2 条，实际 %d", count)
	}
}
