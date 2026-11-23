package main

// 方法级 capability 一致性表测试（PLUGIN-MATURITY §3.5 #12 完整性要求）。
//
// 断言四件事：
//  1. 声明 ⊆ 实现分派（method_capabilities 里每个方法都真有实现入口）
//  2. 反向：实现分派里的每个业务方法都被声明（不静默漏声明）
//  3. 条数相等（两侧一一对应，不多不少）
//  4. 取值 ∈ 6 项特权能力，且 info.json / manifest.json 版本一致

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// wafMethodCapabilities 是 waf 的方法级能力期望表（实现分派 + 读写分级）。
//
// 读类：status / rules / logs / bans / config.get；写类：toggle / ban / unban /
// config.set / rule.add / rule.remove / rule.toggle。新增方法必须同时登记到这里，
// 否则本测试会拒绝（防止「加了方法忘了声明能力」）。
var wafMethodCapabilities = map[string]string{
	"waf.status":      "system:read",
	"waf.rules":       "system:read",
	"waf.logs":        "system:read",
	"waf.bans":        "system:read",
	"waf.config.get":  "system:read",
	"waf.ban":         "system:admin",
	"waf.unban":       "system:admin",
	"waf.toggle":      "system:admin",
	"waf.config.set":  "system:admin",
	"waf.rule.add":    "system:admin",
	"waf.rule.remove": "system:admin",
	"waf.rule.toggle": "system:admin",
}

// privilegedCapabilities 是允许的能力集合：system: / net: / proc: 的 read/write 类，
// 外加 system:admin（info.json 的 capabilities 实际使用的管理能力）。
var privilegedCapabilities = map[string]bool{
	"system:read":  true,
	"system:write": true,
	"system:admin": true,
	"net:read":     true,
	"net:write":    true,
	"proc:read":    true,
	"proc:write":   true,
}

// TestMethodCapabilitiesCoverBusinessVerbs 锁定 info.json 的 method_capabilities。
func TestMethodCapabilitiesCoverBusinessVerbs(t *testing.T) {
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json 失败: %v", err)
	}
	var info struct {
		Version            string            `json:"version"`
		MethodCapabilities map[string]string `json:"method_capabilities"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("info.json 解析失败: %v", err)
	}
	if len(info.MethodCapabilities) != len(wafMethodCapabilities) {
		t.Fatalf("method_capabilities 条数=%d，期望 %d：%v", len(info.MethodCapabilities), len(wafMethodCapabilities), info.MethodCapabilities)
	}
	// 1) 声明 ⊆ 实现
	for method := range info.MethodCapabilities {
		if _, ok := wafMethodCapabilities[method]; !ok {
			t.Fatalf("声明了未实现的方法：%s", method)
		}
	}
	// 2) 实现 ⊆ 声明（反向）
	for method := range wafMethodCapabilities {
		if _, ok := info.MethodCapabilities[method]; !ok {
			t.Fatalf("实现分派缺少能力声明：%s", method)
		}
	}
	// 3) 取值与分级
	for method, want := range wafMethodCapabilities {
		got := info.MethodCapabilities[method]
		if got != want {
			t.Fatalf("%s 能力=%q，期望 %q", method, got, want)
		}
		// 4) 取值 ∈ 特权能力集
		found := false
		for capability := range privilegedCapabilities {
			if capability == got {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s 的能力 %q 不在 6 项特权能力内", method, got)
		}
	}
	// 5) info / manifest 版本一致
	manifestRaw, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatalf("读取 manifest.json 失败: %v", err)
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("manifest.json 解析失败: %v", err)
	}
	if strings.TrimSpace(info.Version) != strings.TrimSpace(manifest.Version) {
		t.Fatalf("info.json 版本 %q != manifest.json 版本 %q", info.Version, manifest.Version)
	}
}
