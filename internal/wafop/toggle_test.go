package wafop

import (
	"encoding/json"
	"testing"
)

// TestToggleRuntimeContract waf.toggle 的方法面契约（0.3.0 起模式=数据面规则形态）。
func TestToggleRuntimeContract(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	runtime := New(Options{Env: env.env(), RootAction: root.Call})

	// 缺 mode → E_INVALID。
	if _, perr := runtime.Call("waf.toggle", json.RawMessage(`{}`)); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("缺 mode 应 E_INVALID: %v", perr)
	}
	// 未知字段 → E_INVALID（严格解码）。
	if _, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"enforce","bogus":1}`)); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("未知字段应 E_INVALID: %v", perr)
	}
	// enforce 成功。
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"enforce"}`))
	if perr != nil {
		t.Fatalf("enforce 失败: %v", perr)
	}
	var result ModeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析结果: %v", err)
	}
	if !result.Applied || !result.Verified || result.Mode != ModeEnforce || len(result.Rules) != ModeRuleCount {
		t.Fatalf("enforce 结果不符: %+v", result)
	}
	// off 缺 confirm → E_UNAUTHORIZED，且不执行。
	callsBefore := len(root.calls)
	if _, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"off"}`)); perr == nil || perr.Code != "E_UNAUTHORIZED" {
		t.Fatalf("off 缺 confirm 应 E_UNAUTHORIZED: %v", perr)
	}
	if len(root.calls) != callsBefore {
		t.Fatalf("未确认时不应执行动作: %v", root.calls[callsBefore:])
	}
	// off + confirm 成功并清链。
	raw, perr = runtime.Call("waf.toggle", json.RawMessage(`{"mode":"off","confirm":true}`))
	if perr != nil {
		t.Fatalf("off 失败: %v", perr)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析结果: %v", err)
	}
	if !result.Applied || result.Mode != ModeOff || len(result.Rules) != 0 {
		t.Fatalf("off 结果不符: %+v", result)
	}
}

// TestBanRuntimeContract waf.ban/unban/bans 的方法面契约。
func TestBanRuntimeContract(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	runtime := New(Options{Env: env.env(), RootAction: root.Call})

	raw, perr := runtime.Call("waf.ban", json.RawMessage(`{"ip":"203.0.113.7","ttl_s":600,"reason":"扫描"}`))
	if perr != nil {
		t.Fatalf("ban 失败: %v", perr)
	}
	var banned BanResult
	if err := json.Unmarshal(raw, &banned); err != nil {
		t.Fatalf("解析 ban: %v", err)
	}
	if !banned.Banned || banned.Set != NftSetV4 || banned.Reason != "扫描" || banned.TTL != 600 {
		t.Fatalf("ban 结果不符: %+v", banned)
	}

	// 参数校验。
	if _, perr := runtime.Call("waf.ban", json.RawMessage(`{}`)); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("缺 ip 应 E_INVALID: %v", perr)
	}
	if _, perr := runtime.Call("waf.ban", json.RawMessage(`{"ip":"1.2.3.4","reason":"a\nb"}`)); perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("含控制字符的 reason 应 E_INVALID: %v", perr)
	}

	raw, perr = runtime.Call("waf.bans", json.RawMessage(`{}`))
	if perr != nil {
		t.Fatalf("bans 失败: %v", perr)
	}
	var listed BansResult
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatalf("解析 bans: %v", err)
	}
	if listed.Count != 1 || listed.Bans[0].IP != "203.0.113.7" {
		t.Fatalf("bans 结果不符: %+v", listed)
	}

	raw, perr = runtime.Call("waf.unban", json.RawMessage(`{"ip":"203.0.113.7"}`))
	if perr != nil {
		t.Fatalf("unban 失败: %v", perr)
	}
	var removed UnbanResult
	if err := json.Unmarshal(raw, &removed); err != nil {
		t.Fatalf("解析 unban: %v", err)
	}
	if !removed.Removed {
		t.Fatalf("unban 应移除: %+v", removed)
	}
}
