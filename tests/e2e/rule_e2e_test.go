//go:build linux

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chainRuleView 是 waf.rules.chain[] / rule.*.rule 的形状（独立声明，不复用内部包类型：
// e2e 断言的是对外契约，内部改名不应让 e2e 静默跟随）。
type chainRuleView struct {
	Name       string `json:"name"`
	Expr       string `json:"expr"`
	Action     string `json:"action"`
	Enabled    bool   `json:"enabled"`
	Builtin    bool   `json:"builtin"`
	Handle     int    `json:"handle"`
	ExprTokens int    `json:"expr_tokens"`
}

// rulesView 是 waf.rules 的对外结果。
type rulesView struct {
	Engine string          `json:"engine"`
	Nft    json.RawMessage `json:"nft"`
	Chain  []chainRuleView `json:"chain"`
}

// ruleChangeView 是 waf.rule.* 的对外结果。
type ruleChangeView struct {
	Applied bool            `json:"applied"`
	DryRun  bool            `json:"dry_run"`
	Op      string          `json:"op"`
	Rule    chainRuleView   `json:"rule"`
	Chain   []chainRuleView `json:"chain"`
}

// callOK 调一个方法并要求成功。
func callOK[T any](t *testing.T, h *harness, method string, params string) T {
	t.Helper()
	result, perr := h.Call(method, json.RawMessage(params))
	if perr != nil {
		t.Fatalf("%s 应成功，实际错误 code=%s message=%s detail=%s",
			method, perr.Code, perr.Message, perr.Detail)
	}
	var decoded T
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatalf("%s 结果解码失败: %v（原文 %s）", method, err, result)
	}
	return decoded
}

// findRule 在链里按名字找规则。
func findRule(chain []chainRuleView, name string) (chainRuleView, bool) {
	for _, rule := range chain {
		if rule.Name == name {
			return rule, true
		}
	}
	return chainRuleView{}, false
}

// TestPluginLoadsAndDeclaredMethodsDispatch 是 0.4.5 的端到端基线。
//
// 0.4.5 的变更只有元数据（depth_level production→basic + 版本 bump，见 CHANGELOG「零代码变更」），
// 所以这里断言的不是「新功能」，而是「这次元数据变更没有让插件加载/方法面退化」：
//   - 真实二进制能起、kore.hello 能被接受、内嵌 manifest 版本与 info.json 一致；
//   - info.json 声明的 12 个方法全部落到实现上（不是 E_NOTFOUND）；
//   - 未声明的方法必须是 E_NOTFOUND（证明分发表是白名单，不是「什么都放行」）。
//
// 不断言业务语义——那是下面 rule.* 用例的事；也不为凑数构造断言。
func TestPluginLoadsAndDeclaredMethodsDispatch(t *testing.T) {
	requireNft(t)
	h := newHarness(t)

	raw, err := readInfoJSON(t)
	if err != nil {
		t.Fatalf("读 info.json: %v", err)
	}
	if len(raw.MethodCapabilities) != 12 {
		t.Fatalf("info.json 声明方法数 = %d，期望 12", len(raw.MethodCapabilities))
	}

	// 每个声明方法都要落到实现：用最小合法参数调用，只断言「不是未知方法」。
	// 写方法用只读/空参数触发参数校验，不制造副作用。
	paramsFor := map[string]string{
		"waf.status":      `{}`,
		"waf.rules":       `{}`,
		"waf.logs":        `{}`,
		"waf.bans":        `{}`,
		"waf.config.get":  `{}`,
		"waf.ban":         `{}`,
		"waf.unban":       `{}`,
		"waf.toggle":      `{"mode":"off","confirm":true}`,
		"waf.config.set":  `{}`,
		"waf.rule.add":    `{}`,
		"waf.rule.remove": `{}`,
		"waf.rule.toggle": `{}`,
	}
	for method := range raw.MethodCapabilities {
		params, ok := paramsFor[method]
		if !ok {
			t.Fatalf("info.json 声明了未在用例中覆盖的方法 %q（新增方法必须补 e2e）", method)
		}
		_, perr := h.Call(method, json.RawMessage(params))
		if perr != nil && perr.Code == "E_NOTFOUND" {
			t.Fatalf("声明的方法 %s 未落到实现（E_NOTFOUND）", method)
		}
		if perr != nil && strings.Contains(perr.Message, "未知方法") {
			t.Fatalf("声明的方法 %s 返回「未知方法」", method)
		}
	}

	// 反向断言：未声明方法必须被拒（白名单证明）。
	if _, perr := h.Call("waf.not-a-real-method", json.RawMessage(`{}`)); perr == nil || perr.Code != "E_NOTFOUND" {
		t.Fatalf("未声明方法应返回 E_NOTFOUND，实际 %+v", perr)
	}
}

// TestRuleAddToggleRemoveAgainstRealNft 是 basic 等级的核心路径：
// waf.rule.add / remove / toggle 在真实 nftables 上可用（README 声称 0.4.2–0.4.4 已补，
// 但 0.4.4 真机 e2e 因无 root 通道被 BLOCKED，从未拿到正向证据）。
//
// 断言全部用「独立读 nft」核对，不看插件自己的回读：
//   - add 后 nft 里真有带 kore-rule-<name> 注释的规则，handle 与返回一致；
//   - toggle off 后 nft 里规则真的消失、toggle on 后真的回来；
//   - remove 后真的消失；重复 remove 幂等 applied=false；
//   - 内置 4 条不可删（E_INVALID），但可 toggle。
func TestRuleAddToggleRemoveAgainstRealNft(t *testing.T) {
	requireNft(t)
	h := newHarness(t)

	// 1) 下发观察模式：建表 + 集合 + 链 + 4 条内置规则（全走 root-action 通道）。
	toggle := callOK[struct {
		Mode    string `json:"mode"`
		Applied bool   `json:"applied"`
	}](t, h, "waf.toggle", `{"mode":"observe"}`)
	if toggle.Mode != "observe" {
		t.Fatalf("toggle 后 mode=%q，期望 observe", toggle.Mode)
	}
	if !nftTableExists(t) {
		t.Fatal("独立核对：nft 表 inet kore_waf 不存在，说明 toggle 没有真正下发")
	}

	// 2) 内置 4 条规则可见、builtin=true、expr 非空（0.4.4 的 P3 修复：回读 expr 不能是空串）。
	rules := callOK[rulesView](t, h, "waf.rules", `{}`)
	if len(rules.Chain) != 4 {
		t.Fatalf("内置链长度 = %d，期望 4（chain=%+v）", len(rules.Chain), rules.Chain)
	}
	for _, rule := range rules.Chain {
		if !rule.Builtin {
			t.Fatalf("内置规则 %s 的 builtin=false", rule.Name)
		}
		if strings.TrimSpace(rule.Expr) == "" {
			t.Fatalf("内置规则 %s 的 expr 为空串（0.4.4 已修，回退即回归）", rule.Name)
		}
	}

	// 3) 新增自定义规则。
	added := callOK[ruleChangeView](t, h, "waf.rule.add",
		`{"name":"block-e2e","expr":"ip saddr 203.0.113.0/24","action":"drop"}`)
	if !added.Applied {
		t.Fatalf("rule.add applied=false（op=%s）", added.Op)
	}
	if added.Rule.Builtin {
		t.Fatal("自定义规则被标成 builtin=true")
	}
	if strings.TrimSpace(added.Rule.Expr) == "" {
		t.Fatal("rule.add 回读的 expr 为空串")
	}
	if !strings.Contains(added.Rule.Expr, "203.0.113.0/24") {
		t.Fatalf("回读 expr=%q 不含 203.0.113.0/24", added.Rule.Expr)
	}

	// 4) 独立核对数据面：nft 里确实有这条规则，且 handle 与插件返回一致。
	handles := nftRuleHandles(t, "block-e2e")
	if len(handles) != 1 {
		t.Fatalf("独立核对：nft 中 block-e2e 规则数 = %d，期望 1（说明 applied=true 但数据面没写进去）", len(handles))
	}
	if handles[0] != added.Rule.Handle {
		t.Fatalf("nft handle=%d 与插件回读 handle=%d 不一致", handles[0], added.Rule.Handle)
	}

	// 5) 通道确实执行了 nft-add-rule（不是插件内部假装成功）。
	if !h.sawAction("nft-add-rule") {
		t.Fatal("root-action 通道未收到 nft-add-rule，rule.add 可能没真正落数据面")
	}

	// 6) 幂等：重复 add 不再写第二条。
	again := callOK[ruleChangeView](t, h, "waf.rule.add",
		`{"name":"block-e2e","expr":"ip saddr 203.0.113.0/24","action":"drop"}`)
	if again.Applied {
		t.Fatal("重复 rule.add 应 applied=false（幂等），实际 true")
	}
	if got := nftRuleHandles(t, "block-e2e"); len(got) != 1 {
		t.Fatalf("重复 add 后 nft 规则数 = %d，期望 1", len(got))
	}

	// 7) toggle off：规则从数据面消失。
	off := callOK[ruleChangeView](t, h, "waf.rule.toggle", `{"name":"block-e2e","enabled":false}`)
	if !off.Applied {
		t.Fatal("rule.toggle enabled=false 应 applied=true")
	}
	if got := nftRuleHandles(t, "block-e2e"); len(got) != 0 {
		t.Fatalf("toggle off 后 nft 仍有 %d 条 block-e2e", len(got))
	}
	if _, present := findRule(off.Chain, "block-e2e"); present {
		t.Fatal("toggle off 后返回的 chain 仍含 block-e2e")
	}

	// 8) toggle on：规则回到数据面，expr 不变。
	on := callOK[ruleChangeView](t, h, "waf.rule.toggle", `{"name":"block-e2e","enabled":true}`)
	if !on.Applied {
		t.Fatal("rule.toggle enabled=true 应 applied=true")
	}
	if got := nftRuleHandles(t, "block-e2e"); len(got) != 1 {
		t.Fatalf("toggle on 后 nft 规则数 = %d，期望 1", len(got))
	}
	if restored, present := findRule(on.Chain, "block-e2e"); !present || !strings.Contains(restored.Expr, "203.0.113.0/24") {
		t.Fatalf("toggle on 后规则未按原 expr 恢复：%+v", restored)
	}

	// 9) remove：从数据面删除。
	removed := callOK[ruleChangeView](t, h, "waf.rule.remove", `{"name":"block-e2e"}`)
	if !removed.Applied {
		t.Fatal("rule.remove 应 applied=true")
	}
	if got := nftRuleHandles(t, "block-e2e"); len(got) != 0 {
		t.Fatalf("remove 后 nft 仍有 %d 条 block-e2e", len(got))
	}

	// 10) 幂等：再删一次 applied=false。
	if second := callOK[ruleChangeView](t, h, "waf.rule.remove", `{"name":"block-e2e"}`); second.Applied {
		t.Fatal("重复 rule.remove 应 applied=false")
	}

	// 11) 内置规则不可删，只能 toggle。
	_, perr := h.Call("waf.rule.remove", json.RawMessage(`{"name":"ban-ipv4"}`))
	if perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("删除内置规则应 E_INVALID，实际 %+v", perr)
	}
	builtinOff := callOK[ruleChangeView](t, h, "waf.rule.toggle", `{"name":"ban-ipv4","enabled":false}`)
	if !builtinOff.Applied {
		t.Fatal("内置规则 toggle 应 applied=true")
	}
	if _, present := findRule(builtinOff.Chain, "ban-ipv4"); present {
		t.Fatal("内置规则 toggle off 后仍在 chain 里")
	}
	builtinOn := callOK[ruleChangeView](t, h, "waf.rule.toggle", `{"name":"ban-ipv4","enabled":true}`)
	if _, present := findRule(builtinOn.Chain, "ban-ipv4"); !present {
		t.Fatal("内置规则 toggle on 后未恢复")
	}
}

// TestRuleAddRejectsInjectionOnRealNft 证明「受控匹配器白名单」在真实通道上生效：
// 注入式 expr 必须在插件侧就被拒，且 nft 表一个字节都没被改动。
func TestRuleAddRejectsInjectionOnRealNft(t *testing.T) {
	requireNft(t)
	h := newHarness(t)
	if toggle := callOK[struct {
		Mode string `json:"mode"`
	}](t, h, "waf.toggle", `{"mode":"observe"}`); toggle.Mode != "observe" {
		t.Fatalf("前置 toggle 失败：mode=%q", toggle.Mode)
	}
	before := callOK[rulesView](t, h, "waf.rules", `{}`)

	cases := []struct{ name, params, wantCode string }{
		{"语句注入", `{"name":"inj-a","expr":"; flush ruleset","action":"drop"}`, "E_UNSUPPORTED"},
		{"文件包含", `{"name":"inj-b","expr":"include /etc/nftables.conf","action":"drop"}`, "E_UNSUPPORTED"},
		{"表达式夹带动作", `{"name":"inj-c","expr":"ip saddr 1.2.3.4 drop","action":"drop"}`, "E_UNSUPPORTED"},
		{"非法 IP", `{"name":"inj-d","expr":"ip saddr 999.1.1.1","action":"drop"}`, "E_INVALID"},
	}
	for _, tc := range cases {
		if _, perr := h.Call("waf.rule.add", json.RawMessage(tc.params)); perr == nil || perr.Code != tc.wantCode {
			t.Fatalf("%s：期望 %s，实际 %+v", tc.name, tc.wantCode, perr)
		}
	}

	after := callOK[rulesView](t, h, "waf.rules", `{}`)
	if len(after.Chain) != len(before.Chain) {
		t.Fatalf("注入尝试改变了链长度：before=%d after=%d", len(before.Chain), len(after.Chain))
	}
	if !nftTableExists(t) {
		t.Fatal("注入尝试把 nft 表打没了（flush 生效）")
	}
	for _, bad := range []string{"inj-a", "inj-b", "inj-c", "inj-d"} {
		if got := nftRuleHandles(t, bad); len(got) != 0 {
			t.Fatalf("独立核对：被拒的规则 %s 却出现在 nft 里", bad)
		}
	}
}

// sawAction 判断通道是否执行过某个动作。
func (h *harness) sawAction(actionID string) bool {
	h.callsMu.Lock()
	defer h.callsMu.Unlock()
	for _, call := range h.calls {
		if call.ActionID == actionID {
			return true
		}
	}
	return false
}

// infoManifest 是 e2e 需要读的 info.json 字段。
type infoManifest struct {
	Version            string            `json:"version"`
	DepthLevel         string            `json:"depth_level"`
	MethodCapabilities map[string]string `json:"method_capabilities"`
}

// readInfoJSON 读 info.json（版本/深度等级/方法声明的唯一真源）。
func readInfoJSON(t *testing.T) (infoManifest, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "info.json"))
	if err != nil {
		return infoManifest{}, err
	}
	var manifest infoManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return infoManifest{}, err
	}
	return manifest, nil
}
