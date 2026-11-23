package wafop

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeNft 是 nft root-action 的**有状态**模拟：维护表/集合/规则，覆盖初始化、
// 模式下发、封禁/解封与回读校验。它只模拟内核通道的行为（argv 形状由内核校验，
// 这里不重复实现），因此断言的是「插件有没有按声明的动作与追加参数调用」。
type fakeNft struct {
	calls   []string
	args    [][]string
	actions []string

	present bool
	chain   bool
	sets    map[string][]NftElement
	rules   []NftRule

	// exitFor / stderrFor 让指定动作失败（模拟权限、语法不支持、对象缺失）。
	exitFor   map[string]int
	stderrFor map[string]string
	// freeze 让动作「成功」但不改状态（模拟回读不一致的中间态）。
	freeze bool
}

// newFakeNft 返回初始为空的 nft 后端（表不存在）。
func newFakeNft() *fakeNft {
	return &fakeNft{sets: map[string][]NftElement{}, exitFor: map[string]int{}, stderrFor: map[string]string{}}
}

// nftEnv 返回「装了 nft」的假环境（backend 只用 LookPath 判断工具是否存在）。
func nftEnv() *fakeEnv {
	env := newFakeEnv()
	env.lookPath["nft"] = "/usr/sbin/nft"
	return env
}

// Call 实现 RootActionFunc。
func (f *fakeNft) Call(action string, args []string) (RootActionOutput, error) {
	f.calls = append(f.calls, action+" "+strings.Join(args, " "))
	f.actions = append(f.actions, action)
	f.args = append(f.args, append([]string{}, args...))
	if code, ok := f.exitFor[action]; ok {
		return RootActionOutput{ExitCode: code, Stderr: []byte(f.stderrFor[action])}, nil
	}
	if f.freeze && action != ActionNftList {
		return RootActionOutput{ExitCode: 0}, nil
	}
	switch action {
	case ActionNftInitTable:
		if f.present {
			return alreadyExists(), nil
		}
		f.present = true
	case ActionNftInitSet4, ActionNftInitSet6:
		name := NftSetV4
		if action == ActionNftInitSet6 {
			name = NftSetV6
		}
		if _, ok := f.sets[name]; ok {
			return alreadyExists(), nil
		}
		if !f.present {
			return RootActionOutput{ExitCode: 1, Stderr: []byte("Error: No such file or directory")}, nil
		}
		f.sets[name] = []NftElement{}
	case ActionNftInitChain:
		if f.chain {
			return alreadyExists(), nil
		}
		f.chain = true
	case ActionNftModeEnforce:
		f.rules = fakeRules("drop")
	case ActionNftModeObserve:
		f.rules = fakeRules("observe")
	case ActionNftFlush:
		f.rules = nil
	case ActionNftBan4, ActionNftBan6:
		set := NftSetV4
		if action == ActionNftBan6 {
			set = NftSetV6
		}
		element, ok := elementFromArgs(set, args)
		if !ok {
			return RootActionOutput{ExitCode: 1, Stderr: []byte("Error: invalid element")}, nil
		}
		for _, existing := range f.sets[set] {
			if existing.IP == element.IP {
				return RootActionOutput{ExitCode: 0}, nil
			}
		}
		f.sets[set] = append(f.sets[set], element)
	case ActionNftUnban4, ActionNftUnban6:
		set := NftSetV4
		if action == ActionNftUnban6 {
			set = NftSetV6
		}
		ip := ""
		for _, arg := range args {
			if arg != "{" && arg != "}" {
				ip = arg
			}
		}
		kept := make([]NftElement, 0, len(f.sets[set]))
		removed := false
		for _, existing := range f.sets[set] {
			if existing.IP == ip {
				removed = true
				continue
			}
			kept = append(kept, existing)
		}
		if !removed {
			return RootActionOutput{ExitCode: 1, Stderr: []byte("Error: element does not exist")}, nil
		}
		f.sets[set] = kept
	case ActionNftList:
		if !f.present {
			return RootActionOutput{ExitCode: 1, Stderr: []byte("Error: No such file or directory")}, nil
		}
		return RootActionOutput{Stdout: f.stateJSON()}, nil
	default:
		return RootActionOutput{ExitCode: 1, Stderr: []byte("Error: unknown action " + action)}, nil
	}
	return RootActionOutput{ExitCode: 0}, nil
}

// alreadyExists 模拟 nft 对已存在对象的报错（幂等路径）。
func alreadyExists() RootActionOutput {
	return RootActionOutput{ExitCode: 1, Stderr: []byte("Error: File exists")}
}

// fakeRules 构造一个模式的四条规则（verdict 为 drop 或 observe）。
func fakeRules(verdict string) []NftRule {
	summaries := []string{
		"ip saddr == @banned4 → counter → " + verdict,
		"ip6 saddr == @banned6 → counter → " + verdict,
		"tcp flags == syn → tcp dport == {80, 443} → @kore_syn4 limit rate over 60/second → counter → " + verdict,
		"tcp dport == {80, 443} → ct count over 200 → counter → " + verdict,
	}
	rules := make([]NftRule, 0, len(summaries))
	for index, summary := range summaries {
		rules = append(rules, NftRule{Handle: index + 1, Summary: summary, Verdict: verdict, HasCount: true})
	}
	return rules
}

// elementFromArgs 从追加参数里解出集合元素（`{ <ip> [timeout <ttl>] }`）。
func elementFromArgs(set string, args []string) (NftElement, bool) {
	values := make([]string, 0, len(args))
	for _, arg := range args {
		values = append(values, arg)
	}
	element := NftElement{Set: set}
	for index := 0; index < len(values); index++ {
		switch values[index] {
		case "{", "}":
			continue
		case "timeout":
			continue
		default:
			if element.IP == "" {
				element.IP = values[index]
				continue
			}
			var seconds int
			if _, err := fmt.Sscanf(values[index], "%d", &seconds); err == nil {
				element.TimeoutS = seconds
			}
		}
	}
	return element, element.IP != ""
}

// stateJSON 把内存状态编码成 `nft -j` 形状的 JSON。
func (f *fakeNft) stateJSON() []byte {
	objects := []map[string]any{{"table": map[string]any{"family": "inet", "name": NftTable}}}
	for name, elements := range f.sets {
		entry := map[string]any{"family": "inet", "table": NftTable, "name": name, "type": "ipv4_addr"}
		items := make([]any, 0, len(elements))
		for _, element := range elements {
			if element.TimeoutS > 0 {
				items = append(items, map[string]any{"elem": map[string]any{
					"val": element.IP, "timeout": element.TimeoutS, "expires": element.TimeoutS - 1}})
				continue
			}
			items = append(items, element.IP)
		}
		entry["elem"] = items
		objects = append(objects, map[string]any{"set": entry})
	}
	for index, rule := range f.rules {
		expr := []any{map[string]any{"counter": map[string]any{
			"packets": rule.Packets, "bytes": rule.Bytes}}}
		switch rule.Verdict {
		case "drop":
			expr = append(expr, map[string]any{"drop": nil})
		case "accept":
			expr = append(expr, map[string]any{"accept": nil})
		}
		objects = append(objects, map[string]any{"rule": map[string]any{
			"family": "inet", "table": NftTable, "chain": NftChain, "handle": index + 1,
			"expr": expr,
		}})
	}
	data, _ := json.Marshal(map[string]any{"nftables": objects})
	return data
}

// ---- 测试 ----

// TestNftEnsureIdempotent 初始化幂等：首次建四件套，再次容忍 File exists 并回读成功。
func TestNftEnsureIdempotent(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	backend := NewNftBackend(env.env(), root.Call)

	steps, err := backend.Ensure()
	if err != nil {
		t.Fatalf("首次初始化失败：%v", err)
	}
	if len(steps) != 4 || !allOK(steps) {
		t.Fatalf("首次初始化应有四步全成功：%+v", steps)
	}
	if !root.present || !root.chain {
		t.Fatalf("表/链未建立：present=%v chain=%v", root.present, root.chain)
	}
	if len(root.sets[NftSetV4]) != 0 || len(root.sets[NftSetV6]) != 0 {
		t.Fatalf("集合应为空：%+v", root.sets)
	}

	steps, err = backend.Ensure()
	if err != nil {
		t.Fatalf("重复初始化应幂等成功：%v", err)
	}
	if !allOK(steps) {
		t.Fatalf("重复初始化应全部标记 ok（File exists 被容忍）：%+v", steps)
	}
	if steps[0].Detail != "已存在，跳过" {
		t.Fatalf("应记录「已存在」：%+v", steps[0])
	}
}

// TestNftApplyModeEnforceObserveOff 模式下发 + 幂等短路 + 回读校验。
func TestNftApplyModeEnforceObserveOff(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	backend := NewNftBackend(env.env(), root.Call)

	result, err := backend.ApplyMode(ModeEnforce)
	if err != nil {
		t.Fatalf("enforce 下发失败：%v", err)
	}
	if !result.Applied || !result.Verified || result.Mode != ModeEnforce || len(result.Rules) != ModeRuleCount {
		t.Fatalf("enforce 结果不符：%+v", result)
	}
	if result.PreviousMode != ModeOff {
		t.Fatalf("前态应为 off：%+v", result.PreviousMode)
	}
	// 表不存在时应先初始化（init 四个动作 + 模式动作）。
	if !containsAction(root.actions, ActionNftInitTable) || !containsAction(root.actions, ActionNftModeEnforce) {
		t.Fatalf("应先初始化再下发规则：%v", root.actions)
	}

	callsBefore := len(root.calls)
	again, err := backend.ApplyMode(ModeEnforce)
	if err != nil {
		t.Fatalf("重复下发应成功：%v", err)
	}
	if len(root.calls) != callsBefore+1 {
		t.Fatalf("同模式应短路（只多一次回读），实际多 %d 次：%v", len(root.calls)-callsBefore, root.calls[callsBefore:])
	}
	if !again.Applied || !again.Verified {
		t.Fatalf("幂等短路结果不符：%+v", again)
	}

	observe, err := backend.ApplyMode(ModeObserve)
	if err != nil {
		t.Fatalf("observe 下发失败：%v", err)
	}
	if !observe.Applied || observe.Mode != ModeObserve || len(observe.Rules) != ModeRuleCount {
		t.Fatalf("observe 结果不符：%+v", observe)
	}
	for _, rule := range observe.Rules {
		if rule.Verdict == "drop" {
			t.Fatalf("observe 模式不应有 drop 规则：+%v", rule)
		}
	}

	off, err := backend.ApplyMode(ModeOff)
	if err != nil {
		t.Fatalf("off 下发失败：%v", err)
	}
	if !off.Applied || off.Mode != ModeOff || len(off.Rules) != 0 {
		t.Fatalf("off 结果不符：%+v", off)
	}
	if !containsAction(root.actions, ActionNftFlush) {
		t.Fatalf("off 应走清链动作：%v", root.actions)
	}
	if len(root.sets[NftSetV4]) != 0 {
		t.Fatalf("off 不应删集合：%+v", root.sets)
	}
}

// TestNftApplyModeVerifyMismatch 动作退出 0 但状态没变 → applied=false（不谎报）。
func TestNftApplyModeVerifyMismatch(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	backend := NewNftBackend(env.env(), root.Call)
	if _, err := backend.Ensure(); err != nil {
		t.Fatalf("初始化失败：%v", err)
	}
	root.freeze = true // 动作成功但不改状态
	result, err := backend.ApplyMode(ModeEnforce)
	if err != nil {
		t.Fatalf("不应返回协议错误：%v", err)
	}
	if result.Applied || result.Verified {
		t.Fatalf("回读不一致必须 applied=false：%+v", result)
	}
	if !strings.Contains(result.Hint, "回读不一致") {
		t.Fatalf("应给出回读失败提示：%q", result.Hint)
	}
}

// TestNftBanUnban IPv4/IPv6 封禁与解封、超时参数、幂等。
func TestNftBanUnban(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	backend := NewNftBackend(env.env(), root.Call)

	banned, err := backend.Ban("203.0.113.7", 3600)
	if err != nil {
		t.Fatalf("ban v4 失败：%v", err)
	}
	if !banned.Banned || banned.Set != NftSetV4 || banned.Family != "ipv4" || banned.TTL != 3600 {
		t.Fatalf("ban v4 结果不符：%+v", banned)
	}
	lastArgs := lastArgsFor(t, root, ActionNftBan4)
	if strings.Join(lastArgs, " ") != "{ 203.0.113.7 timeout 3600s }" {
		t.Fatalf("ban 追加参数形状不符：%v", lastArgs)
	}

	bannedV6, err := backend.Ban("2001:db8::7", 0)
	if err != nil {
		t.Fatalf("ban v6 失败：%v", err)
	}
	if !bannedV6.Banned || bannedV6.Set != NftSetV6 || bannedV6.Family != "ipv6" {
		t.Fatalf("ban v6 结果不符：%+v", bannedV6)
	}

	// 重复封禁幂等（nft add element 对已存在元素退出 0）。
	repeat, err := backend.Ban("203.0.113.7", 0)
	if err != nil || !repeat.Banned {
		t.Fatalf("重复封禁应幂等成功：%+v err=%v", repeat, err)
	}

	bans, err := backend.Bans()
	if err != nil {
		t.Fatalf("bans 失败：%v", err)
	}
	if bans.Count != 2 || len(bans.Bans) != 2 {
		t.Fatalf("封禁数应为 2：%+v", bans)
	}

	removed, err := backend.Unban("203.0.113.7")
	if err != nil {
		t.Fatalf("unban 失败：%v", err)
	}
	if !removed.Removed {
		t.Fatalf("应移除成功：%+v", removed)
	}
	missing, err := backend.Unban("198.51.100.9")
	if err != nil {
		t.Fatalf("解封不存在的 IP 应幂等成功：%v", err)
	}
	if missing.Removed || missing.Hint == "" {
		t.Fatalf("不存在的 IP 应 removed=false + hint：%+v", missing)
	}
}

// TestNftBanValidation 参数校验：非法 IP、越界 TTL。
func TestNftBanValidation(t *testing.T) {
	backend := NewNftBackend(nftEnv().env(), newFakeNft().Call)
	if _, err := backend.Ban("not-an-ip", 0); err == nil {
		t.Fatal("非法 IP 应被拒绝")
	}
	if _, err := backend.Ban("203.0.113.7", 1); err == nil {
		t.Fatal("过短 TTL 应被拒绝")
	}
	if _, err := backend.Ban("203.0.113.7", MaxBanTTLS+1); err == nil {
		t.Fatal("过长 TTL 应被拒绝")
	}
	if _, err := backend.Ban("203.0.113.7/33", 0); err == nil {
		t.Fatal("越界掩码应被拒绝")
	}
}

// TestNftStateParseRealFixture 解析真实 `nft -j` 输出（fixture 由隔离 netns 采集）。
func TestNftStateParseRealFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/nft-state-enforce.json")
	if err != nil {
		t.Fatalf("读取 fixture：%v", err)
	}
	state, err := parseNftTableJSON(raw)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if !state.Present || state.Mode != ModeEnforce {
		t.Fatalf("状态不符：present=%v mode=%s", state.Present, state.Mode)
	}
	if len(state.Rules) != 4 {
		t.Fatalf("应解析出 4 条规则，实际 %d", len(state.Rules))
	}
	for _, rule := range state.Rules {
		if rule.Verdict != "drop" || !rule.HasCount || rule.Summary == "" {
			t.Fatalf("规则摘要不完整：%+v", rule)
		}
	}
	if !strings.Contains(state.Rules[0].Summary, "@banned4") {
		t.Fatalf("首条规则应引用 @banned4：%+v", state.Rules[0])
	}
	if len(state.Bans) != 2 {
		t.Fatalf("应解析出 2 个封禁元素，实际 %d：%+v", len(state.Bans), state.Bans)
	}
	var v4, v6 *NftElement
	for index := range state.Bans {
		switch state.Bans[index].Set {
		case NftSetV4:
			v4 = &state.Bans[index]
		case NftSetV6:
			v6 = &state.Bans[index]
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("v4/v6 元素都应存在：%+v", state.Bans)
	}
	if v4.TimeoutS != 3600 || v4.ExpiresS <= 0 {
		t.Fatalf("v4 超时未解析：+%v", *v4)
	}
	if v6.IP != "2001:db8::7" || v6.TimeoutS != 0 {
		t.Fatalf("v6 永久封禁解析不符：+%v", *v6)
	}
}

// TestNftToggleChannelErrors 通道缺失/内核拒绝 → E_NEED_ROOT；nft 缺失 → 结构化不可用。
func TestNftToggleChannelErrors(t *testing.T) {
	env := nftEnv()
	// 通道未注入。
	result, perr := Toggle(env.env(), ToggleParams{Mode: ModeObserve}, nil)
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("无通道应 E_NEED_ROOT：%+v %v", result, perr)
	}
	// 内核对动作形状/权限的拒绝原样透传。
	root := func(string, []string) (RootActionOutput, error) {
		return RootActionOutput{}, &ChannelError{Code: CodeNeedRoot, Message: "内核拒绝"}
	}
	if _, perr := Toggle(env.env(), ToggleParams{Mode: ModeEnforce}, root); perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("内核拒绝应透传 E_NEED_ROOT：%v", perr)
	}
	// nft 不存在 → 结构化不可用（不是协议错误）。
	noNft := newFakeEnv()
	noNftRoot := newFakeNft()
	result, perr = Toggle(noNft.env(), ToggleParams{Mode: ModeEnforce}, noNftRoot.Call)
	if perr != nil {
		t.Fatalf("nft 缺失不应报协议错误：%v", perr)
	}
	if result.Applied || result.Hint == "" || !strings.Contains(result.Hint, "nftables") {
		t.Fatalf("应给出安装提示：+%v", result)
	}
}

// TestNftToggleOffRequiresConfirm 关闭防护必须显式 confirm，且不执行任何动作。
func TestNftToggleOffRequiresConfirm(t *testing.T) {
	root := newFakeNft()
	_, perr := Toggle(nftEnv().env(), ToggleParams{Mode: ModeOff}, root.Call)
	if perr == nil || perr.Code != "E_UNAUTHORIZED" {
		t.Fatalf("缺 confirm 应 E_UNAUTHORIZED：%v", perr)
	}
	if len(root.calls) != 0 {
		t.Fatalf("未确认时不应执行任何 root 动作：%v", root.calls)
	}
}

// TestNftToggleModeValues 非法模式值给可操作提示。
func TestNftToggleModeValues(t *testing.T) {
	_, perr := Toggle(nftEnv().env(), ToggleParams{Mode: "on"}, newFakeNft().Call)
	if perr == nil || perr.Code != "E_INVALID" || !strings.Contains(perr.Message, "observe") {
		t.Fatalf("旧模式值 on 应被拒绝并给出新取值：%v", perr)
	}
}

// TestNftUnsupportedSyntax nft 版本不支持 meter/ct count → E_UNSUPPORTED + 原始 stderr。
func TestNftUnsupportedSyntax(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	root.exitFor[ActionNftModeEnforce] = 1
	root.stderrFor[ActionNftModeEnforce] = "Error: syntax error, unexpected meter"
	_, perr := Toggle(env.env(), ToggleParams{Mode: ModeEnforce}, root.Call)
	if perr == nil || perr.Code != "E_UNSUPPORTED" {
		t.Fatalf("语法不支持应 E_UNSUPPORTED：%v", perr)
	}
	if !strings.Contains(perr.Message, "meter") {
		t.Fatalf("应保留原始错误：%q", perr.Message)
	}
}

// TestNftStatusSummary status/bans 的汇总字段。
func TestNftStatusSummary(t *testing.T) {
	env := nftEnv()
	root := newFakeNft()
	backend := NewNftBackend(env.env(), root.Call)
	if _, err := backend.Ensure(); err != nil {
		t.Fatalf("初始化失败：%v", err)
	}
	if _, err := backend.Ban("203.0.113.7", 0); err != nil {
		t.Fatalf("封禁失败：%v", err)
	}
	if _, err := backend.ApplyMode(ModeEnforce); err != nil {
		t.Fatalf("下发失败：%v", err)
	}
	status := Status(env.env(), root.Call)
	if !status.Available || !status.Channel || !status.Present || status.Mode != ModeEnforce {
		t.Fatalf("status 不符：+%v", status)
	}
	if status.Banned != 1 || status.RulesCount != ModeRuleCount {
		t.Fatalf("status 计数不符：+%v", status)
	}
	ruleset := nftRuleset(env.env(), root.Call)
	if !ruleset.Present || ruleset.RulesCount != ModeRuleCount || ruleset.BansCount != 1 {
		t.Fatalf("ruleset 不符：+%v", ruleset)
	}
}

// lastArgsFor 返回某动作最后一次调用的追加参数（跳过其后的回读动作）。
func lastArgsFor(t *testing.T, root *fakeNft, action string) []string {
	t.Helper()
	for index := len(root.actions) - 1; index >= 0; index-- {
		if root.actions[index] == action {
			return root.args[index]
		}
	}
	t.Fatalf("没有调用过 %s：%v", action, root.actions)
	return nil
}

// allOK 报告所有步骤都成功。
func allOK(steps []NftStep) bool {
	for _, step := range steps {
		if !step.OK {
			return false
		}
	}
	return true
}

// containsAction 报告动作序列里是否出现过某动作。
func containsAction(actions []string, want string) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}
