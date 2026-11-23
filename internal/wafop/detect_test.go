package wafop

import (
	"strings"
	"testing"
)

// detectSettings 返回 auto 探测的缺省配置。
func detectSettings() Settings { return Settings{Engine: "auto"} }

// TestDetectModSecurityFromFiles modsecurity 配置目录 + SecRuleEngine On + 包版本。
func TestDetectModSecurityFromFiles(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine On\nSecRule ARGS \"@rx x\" \"id:1\"\n")
	env.addFile("/usr/share/modsecurity-crs/VERSION", "4.3.0\n")
	env.setCommand("dpkg-query", func(args ...string) (CommandResult, error) {
		return CommandResult{Stdout: []byte("3.0.12")}, nil
	})
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detection.Found || detection.Engine != EngineModSecurity {
		t.Fatalf("应检测到 modsecurity，实际 %+v", detection)
	}
	if detection.Mode != ModeOn || detection.ModeSource != "/etc/modsecurity/modsecurity.conf" {
		t.Fatalf("模式应为 on 且来源可追溯，实际 mode=%q source=%q", detection.Mode, detection.ModeSource)
	}
	if detection.Version != "3.0.12" || detection.VersionSource != "command" {
		t.Fatalf("版本应为 dpkg 查询值，实际 %q/%q", detection.Version, detection.VersionSource)
	}
	if detection.CRSVersion != "4.3.0" {
		t.Fatalf("CRS 版本应为 4.3.0，实际 %q", detection.CRSVersion)
	}
}

// TestDetectModSecurityFromNginx -V 输出（stderr）含 modsecurity 模块。
func TestDetectModSecurityFromNginx(t *testing.T) {
	env := newFakeEnv()
	env.setCommand("nginx", func(args ...string) (CommandResult, error) {
		return CommandResult{Stderr: []byte("nginx version: nginx/1.24.0\nconfigure arguments: --add-dynamic-module=/build/nginx-modsecurity\n")}, nil
	})
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detection.Found || detection.Engine != EngineModSecurity {
		t.Fatalf("nginx -V 含 modsecurity 应被识别，实际 %+v", detection)
	}
	if detection.Mode != ModeOff {
		t.Fatalf("无 SecRuleEngine 指令时缺省应为 off，实际 %q", detection.Mode)
	}
	if !strings.Contains(detection.Probed[0].Evidence, "nginx -V") {
		t.Fatalf("证据应包含 nginx -V，实际 %q", detection.Probed[0].Evidence)
	}
}

// TestDetectNaxsi naxsi 模块 + LearningMode → detection。
func TestDetectNaxsi(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/usr/lib/nginx/modules/ngx_http_naxsi_module.so", "")
	env.addFile("/etc/nginx/nginx.conf", "load_module modules/ngx_http_naxsi_module.so;\nhttp {\n  LearningMode;\n}\n")
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detection.Found || detection.Engine != EngineNaxsi {
		t.Fatalf("应检测到 naxsi，实际 %+v", detection)
	}
	if detection.Mode != ModeDetection {
		t.Fatalf("LearningMode 应映射为 detection，实际 %q", detection.Mode)
	}
}

// TestDetectCorazaBinaryAndMode coraza 二进制版本 + 配置里的 DetectionOnly。
func TestDetectCorazaBinaryAndMode(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/coraza/coraza.conf", "SecRuleEngine DetectionOnly\n")
	env.setCommand("coraza", func(args ...string) (CommandResult, error) {
		return CommandResult{Stdout: []byte("coraza 3.0.1")}, nil
	})
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detection.Found || detection.Engine != EngineCoraza {
		t.Fatalf("应检测到 coraza，实际 %+v", detection)
	}
	if detection.Mode != ModeDetection {
		t.Fatalf("DetectionOnly 应映射为 detection，实际 %q", detection.Mode)
	}
	if detection.Version != "coraza 3.0.1" || detection.VersionSource != "command" {
		t.Fatalf("版本应来自二进制，实际 %q/%q", detection.Version, detection.VersionSource)
	}
}

// TestDetectCrowdSec cscli 可用 + 有 bouncer → on。
func TestDetectCrowdSec(t *testing.T) {
	env := newFakeEnv()
	env.setCommand("cscli", func(args ...string) (CommandResult, error) {
		joined := strings.Join(args, " ")
		switch {
		case joined == "version":
			return CommandResult{Stdout: []byte("version: v1.6.3\n")}, nil
		case strings.HasPrefix(joined, "bouncers list"):
			return CommandResult{Stdout: []byte(`[{"name":"nginx-bouncer"}]`)}, nil
		}
		return CommandResult{ExitCode: 1}, nil
	})
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detection.Found || detection.Engine != EngineCrowdSec {
		t.Fatalf("应检测到 crowdsec，实际 %+v", detection)
	}
	if detection.Version != "1.6.3" || detection.Mode != ModeOn {
		t.Fatalf("版本/模式不符：%q/%q", detection.Version, detection.Mode)
	}
}

// TestDetectCrowdSecNoBouncer 没有 bouncer 时只告警不拦截 → detection。
func TestDetectCrowdSecNoBouncer(t *testing.T) {
	env := newFakeEnv()
	env.setCommand("cscli", func(args ...string) (CommandResult, error) {
		joined := strings.Join(args, " ")
		if joined == "version" {
			return CommandResult{Stdout: []byte("version: v1.6.3\n")}, nil
		}
		return CommandResult{Stdout: []byte(`[]`)}, nil
	})
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if detection.Mode != ModeDetection {
		t.Fatalf("无 bouncer 应为 detection，实际 %q", detection.Mode)
	}
}

// TestDetectNone 空环境：不报错、返回 EngineNone 与四条探测证据。
func TestDetectNone(t *testing.T) {
	env := newFakeEnv()
	detection, err := Detect(env.env(), detectSettings())
	if err != nil {
		t.Fatalf("空环境不应报错: %v", err)
	}
	if detection.Found || detection.Engine != EngineNone {
		t.Fatalf("空环境应 none，实际 %+v", detection)
	}
	if len(detection.Probed) != 4 {
		t.Fatalf("auto 应探测 4 个引擎，实际 %d", len(detection.Probed))
	}
	for _, probe := range detection.Probed {
		if probe.Found || probe.Evidence == "" {
			t.Fatalf("未命中的探测也要有证据，实际 %+v", probe)
		}
	}
}

// TestDetectExplicitEngineWithConfiguredDirs 非标准安装：显式引擎 + 配置目录存在。
func TestDetectExplicitEngineWithConfiguredDirs(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/opt/waf/rules/app.conf", "SecRule ARGS \"@rx x\" \"id:1\"\n")
	settings := Settings{Engine: EngineModSecurity, RulesDirs: []string{"/opt/waf/rules"}}
	detection, err := Detect(env.env(), settings)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !detection.Found || detection.Engine != EngineModSecurity {
		t.Fatalf("配置目录存在时显式引擎应认定可用，实际 %+v", detection)
	}
	if !strings.Contains(detection.Probed[0].Evidence, "/opt/waf/rules") {
		t.Fatalf("证据应指向配置目录，实际 %q", detection.Probed[0].Evidence)
	}
}

// TestDetectExplicitEngineWithoutEvidence 显式引擎但无任何证据 → 仍不可用。
func TestDetectExplicitEngineWithoutEvidence(t *testing.T) {
	env := newFakeEnv()
	settings := Settings{Engine: EngineModSecurity}
	detection, err := Detect(env.env(), settings)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if detection.Found || detection.Engine != EngineNone {
		t.Fatalf("无证据时不应认定可用，实际 %+v", detection)
	}
}
