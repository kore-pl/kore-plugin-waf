package wafop

import "testing"

// testRoot 是方法测试共用的逻辑规则根目录（骨架口径不访问真实文件系统）。
const testRoot = "/var/lib/kore/waf"

// TestCheckRuleID 校验 WAF-0000 格式：空放行、合法匹配、非法拒绝。
func TestCheckRuleID(t *testing.T) {
	for _, raw := range []string{"", "WAF-0000", "WAF-9999", "WAF-0123"} {
		if perr := checkRuleID(raw); perr != nil {
			t.Fatalf("checkRuleID(%q) 意外拒绝: %v", raw, perr)
		}
	}
	for _, raw := range []string{"waf-0001", "WAF-001", "WAF-00001", "WAF-ABCD", "RULE-0001", "WAF-0001 ", "abc"} {
		if perr := checkRuleID(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("checkRuleID(%q) 未返回 E_INVALID: %v", raw, perr)
		}
	}
}

// TestCheckLimit 校验 limit 边界：0 取缺省，1..1000 合法，负数/1001 拒绝。
func TestCheckLimit(t *testing.T) {
	cases := map[int]int{0: defaultLimit, 1: 1, 20: 20, 1000: 1000}
	for in, want := range cases {
		got, perr := checkLimit(in)
		if perr != nil || got != want {
			t.Fatalf("checkLimit(%d)=(%d,%v)，期望 (%d,nil)", in, got, perr, want)
		}
	}
	for _, in := range []int{-1, 1001, 10000} {
		got, perr := checkLimit(in)
		if perr == nil || perr.Code != "E_INVALID" || got != 0 {
			t.Fatalf("checkLimit(%d)=(%d,%v)，期望 (0,E_INVALID)", in, got, perr)
		}
	}
}
