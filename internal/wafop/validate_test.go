package wafop

import (
	"strings"
	"testing"
)

// TestCheckEngine 校验 engine 参数：空/auto 等价，非法值给可操作提示。
func TestCheckEngine(t *testing.T) {
	for _, raw := range []string{"", "auto", "AUTO", "modsecurity", "naxsi", "coraza", "crowdsec", " ModSecurity "} {
		if _, perr := checkEngine(raw); perr != nil {
			t.Fatalf("checkEngine(%q) 意外拒绝: %v", raw, perr)
		}
	}
	for _, raw := range []string{"squid", "mod_security", "none"} {
		if _, perr := checkEngine(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("checkEngine(%q) 未返回 E_INVALID: %v", raw, perr)
		}
	}
}

// TestCheckMode 校验 mode 必填与枚举。
func TestCheckMode(t *testing.T) {
	for _, raw := range []string{"on", "detection", "off", "ON"} {
		if _, perr := checkMode(raw); perr != nil {
			t.Fatalf("checkMode(%q) 意外拒绝: %v", raw, perr)
		}
	}
	for _, raw := range []string{"", "block", "true", "on;off"} {
		if _, perr := checkMode(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("checkMode(%q) 未返回 E_INVALID: %v", raw, perr)
		}
	}
}

// TestCheckLogLimit 校验 limit 边界：0 取缺省 50，1..200 合法，负数/201 拒绝。
func TestCheckLogLimit(t *testing.T) {
	cases := map[int]int{0: DefaultLogLimit, 1: 1, 50: 50, 200: 200}
	for in, want := range cases {
		got, perr := checkLogLimit(in)
		if perr != nil || got != want {
			t.Fatalf("checkLogLimit(%d)=(%d,%v)，期望 (%d,nil)", in, got, perr, want)
		}
	}
	for _, in := range []int{-1, 201, 10000} {
		got, perr := checkLogLimit(in)
		if perr == nil || perr.Code != "E_INVALID" || got != 0 {
			t.Fatalf("checkLogLimit(%d)=(%d,%v)，期望 (0,E_INVALID)", in, got, perr)
		}
	}
}

// TestCheckSince 校验 since：合法时长/时间放行，非法与超长拒绝。
func TestCheckSince(t *testing.T) {
	for _, raw := range []string{"", "1h", "30m", "7d", "2026-11-23T10:00:00Z", "2026-11-23"} {
		if perr := checkSince(raw); perr != nil {
			t.Fatalf("checkSince(%q) 意外拒绝: %v", raw, perr)
		}
	}
	for _, raw := range []string{"yesterday", "1 hour", strings.Repeat("1", MaxSinceRunes+1)} {
		if perr := checkSince(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("checkSince(%q) 未返回 E_INVALID: %v", raw, perr)
		}
	}
}

// TestCheckRuleIDFilter 规则 ID 过滤参数：长度与控制字符限制。
func TestCheckRuleIDFilter(t *testing.T) {
	for _, raw := range []string{"", "942100", "WAF-0001", strings.Repeat("a", MaxRuleIDRunes)} {
		if perr := checkRuleIDFilter(raw); perr != nil {
			t.Fatalf("checkRuleIDFilter(%q) 意外拒绝: %v", raw, perr)
		}
	}
	for _, raw := range []string{"a\nb", strings.Repeat("a", MaxRuleIDRunes+1)} {
		if perr := checkRuleIDFilter(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("checkRuleIDFilter(%q) 未返回 E_INVALID: %v", raw, perr)
		}
	}
}
