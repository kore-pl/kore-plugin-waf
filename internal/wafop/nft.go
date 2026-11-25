package wafop

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// nft 数据面。设计要点（ADR-0022 / 插件 0.3.0）：
//
//   - **插件自身不 exec nft**：所有 nft 命令都经内核 root-action 通道（ADR-0018），
//     argv 与 info.json 声明的固定形状逐字一致，追加参数只有集合元素（IP/CIDR）
//     与超时秒数；
//   - **kore 自有命名空间**：表 `kore_waf`、集合 `banned4`/`banned6`、链 `input`
//     （内核形状校验要求 nft 表名 `kore_` 前缀，插件不可能写到宿主的 filter/nat）；
//   - **观察 / 拦截两种规则集**：observe 只 `counter log`（不 verdict），enforce 用
//     `counter drop`；两者都是同一组四条规则，切换 = 清链 + 重装（幂等）；
//   - **基础防护**：集合封禁（v4/v6）、SYN 高频扫描限速、单 IP 并发连接数上限。

// kore 自有 nft 对象名（与 info.json 的 argv 逐字一致，改动必须同步内核 ADR-0022）。
const (
	// NftTable 是 kore 自有 nft 表名。
	NftTable = "kore_waf"
	// NftChain 是挂钩 input 的 base chain 名。
	NftChain = "input"
	// NftSetV4 / NftSetV6 是封禁集合名（分别承载 IPv4 / IPv6 与 CIDR）。
	NftSetV4 = "banned4"
	NftSetV6 = "banned6"
)

// 数据面模式：observe 只记录，enforce 阻断，off 清空规则（不删表/集合）。
const (
	// ModeObserve 只记录不阻断。
	ModeObserve = "observe"
	// ModeEnforce 阻断命中规则。
	ModeEnforce = "enforce"
)

// 基础防护阈值：写进 info.json 的规则 argv（固定形状），因此不是运行期配置项。
// 改阈值等于改插件版本（argv 变了 → dist sha 变 → 必须 bump）。
const (
	// BaseProtectPorts 是基础防护作用的端口集合（HTTP/HTTPS）。
	BaseProtectPorts = "80, 443"
	// SynRate / SynBurst 是 SYN 扫描限速（每源 IP）。
	SynRate  = "60/second"
	SynBurst = "120 packets"
	// ConnLimit 是单 IP 到 80/443 的并发连接上限。
	ConnLimit = 200
	// ModeRuleCount 是一个模式的规则条数（回读校验用）。
	ModeRuleCount = 4
)

// 封禁超时区间（秒）。0 表示永久。
const (
	// MinBanTTLS 是最短封禁时长。
	MinBanTTLS = 60
	// MaxBanTTLS 是最长封禁时长（30 天）。
	MaxBanTTLS = 30 * 24 * 60 * 60
)

// 封禁/解封动作 id（info.json 必须逐字一致；v4/v6 分成不同动作是因为
// argv 是**固定数组**，集合名不能作为运行时参数替换）。
const (
	// ActionNftInitTable 建 kore_waf 表。
	ActionNftInitTable = "nft-init-table"
	// ActionNftInitSet4 / ActionNftInitSet6 建封禁集合。
	ActionNftInitSet4 = "nft-init-set4"
	ActionNftInitSet6 = "nft-init-set6"
	// ActionNftInitChain 建 input base chain。
	ActionNftInitChain = "nft-init-chain"
	// ActionNftModeObserve / ActionNftModeEnforce 重装规则集。
	ActionNftModeObserve = "nft-mode-observe"
	ActionNftModeEnforce = "nft-mode-enforce"
	// ActionNftFlush 清空链（mode=off）。
	ActionNftFlush = "nft-flush"
	// ActionNftBan4 / ActionNftBan6 加封禁元素。
	ActionNftBan4 = "nft-ban4"
	ActionNftBan6 = "nft-ban6"
	// ActionNftUnban4 / ActionNftUnban6 删封禁元素。
	ActionNftUnban4 = "nft-unban4"
	ActionNftUnban6 = "nft-unban6"
	// ActionNftList 只读列出 kore 表（JSON）。
	ActionNftList = "nft-list"
)

// initActions 是建表/集合/链的顺序清单（建链依赖表存在）。
var initActions = []string{ActionNftInitTable, ActionNftInitSet4, ActionNftInitSet6, ActionNftInitChain}

// NftStep 是一步 root-action 的执行结果（对用户可见，便于定位失败在哪一步）。
type NftStep struct {
	Action   string `json:"action"`
	ExitCode int    `json:"exit_code"`
	OK       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
}

// NftElement 是一个封禁元素。
type NftElement struct {
	IP string `json:"ip"`
	// TimeoutS / ExpiresS 是集合里记录的超时与剩余秒数（0 表示永久）。
	TimeoutS int `json:"timeout_s,omitempty"`
	ExpiresS int `json:"expires_s,omitempty"`
	// Set 是元素所在集合（banned4 / banned6）。
	Set string `json:"set"`
}

// NftRule 是一条已装载的规则（从 `nft -j` 输出解析）。
type NftRule struct {
	Handle   int    `json:"handle"`
	Summary  string `json:"summary"`
	Verdict  string `json:"verdict"` // drop|accept|observe
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
	HasCount bool   `json:"has_counter"`
}

// NftState 是 kore 自有 nft 表的当前状态。
type NftState struct {
	// Present 表示 kore_waf 表存在。
	Present bool `json:"present"`
	// Mode 由规则判定：无规则=off，含 drop=enforce，否则 observe。
	Mode string `json:"mode"`
	// Rules 是链上的规则（按 handle 排序）。
	Rules []NftRule `json:"rules"`
	// Bans 是封禁集合里的元素（v4 + v6）。
	Bans []NftElement `json:"bans"`
}

// NftCommandError 是一次 root-action 执行失败（退出码非 0），保留 stderr 便于归因。
type NftCommandError struct {
	Action   string
	ExitCode int
	Stderr   string
}

// Error 实现 error 接口。
func (e *NftCommandError) Error() string {
	detail := strings.TrimSpace(e.Stderr)
	if detail == "" {
		detail = "无 stderr 输出"
	}
	return fmt.Sprintf("root 动作 %s 退出码 %d：%s", e.Action, e.ExitCode, trimLine([]byte(detail), 300))
}

// NftBackend 是 nft 数据面的执行面；所有命令都经内核通道。
type NftBackend struct {
	env  Environment
	root RootActionFunc
}

// NewNftBackend 构造执行面；root 为 nil 表示内核未注入通道。
func NewNftBackend(env Environment, root RootActionFunc) *NftBackend {
	return &NftBackend{env: defaultEnvironment(env), root: root}
}

// Availability 报告 nft 是否可用（工具存在 + 通道可用）；不可用时给出下一步。
type Availability struct {
	Tool      string `json:"tool"`
	Available bool   `json:"available"`
	// Channel 表示 root-action 通道是否注入（false → 只读探测也不能做）。
	Channel bool   `json:"channel"`
	Reason  string `json:"reason,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

// Availability 探测 nft 工具与通道。
func (b *NftBackend) Availability() Availability {
	info := Availability{Tool: "nft", Channel: b.root != nil}
	if _, ok := b.env.LookPath("nft"); !ok {
		info.Reason = "未找到 nft 可执行文件"
		info.Hint = "安装 nftables（Debian/Ubuntu：apt install nftables；RHEL：dnf install nftables）；" +
			"kore 只用 nft 管理自己的 kore_waf 表，不改动宿主既有规则"
		return info
	}
	if b.root == nil {
		info.Available = true
		info.Reason = "缺少 root-action 通道，无法读写规则"
		info.Hint = rootActionHint("nft")
		return info
	}
	info.Available = true
	return info
}

// call 执行一次 root 动作：通道错误结构化透传，退出码非 0 返回 *NftCommandError。
func (b *NftBackend) call(action string, args []string) (RootActionOutput, error) {
	if b.root == nil {
		// 用 ChannelError 表达「内核未提供通道」，这样所有调用方都能统一映射成
		// E_NEED_ROOT + hint（ADR-0018 的降级硬要求）。
		return RootActionOutput{}, &ChannelError{
			Code:    CodeNeedRoot,
			Message: "nft 数据面需要 root 权限，但插件没有可用的 root-action 通道",
			Hint:    rootActionHint("nft"),
		}
	}
	output, err := b.root(action, args)
	if err != nil {
		// 通道拒绝（*ChannelError）、注入故障（*FaultError）与传输错误都原样上抛，
		// 由方法面统一映射一次——这里再映射会导致 E_NEED_ROOT 被包成 E_INTERNAL。
		return output, err
	}
	if output.ExitCode != 0 {
		return output, &NftCommandError{Action: action, ExitCode: output.ExitCode,
			Stderr: string(output.Stderr) + string(output.Stdout)}
	}
	return output, nil
}

// Ensure 建立表 / 集合 / 链。
//
// 幂等策略：nft 1.1.x 的 `add table/set/chain` 在同定义下幂等（退出 0），但旧版本或
// 「对象已存在但定义不同」会报 `File exists` 并退出 1——该错误被容忍，最后**回读**确认
// 三件套真的齐备，不把「退出码被容忍」当成「状态正确」。
func (b *NftBackend) Ensure() ([]NftStep, error) {
	steps := make([]NftStep, 0, len(initActions))
	for _, action := range initActions {
		output, err := b.call(action, nil)
		step := NftStep{Action: action, ExitCode: output.ExitCode, OK: err == nil}
		if err != nil {
			commandErr, isCommand := err.(*NftCommandError)
			if !isCommand {
				return steps, err
			}
			if !isNftAlreadyExists(commandErr.Stderr) {
				step.Detail = trimLine([]byte(commandErr.Stderr), 200)
				steps = append(steps, step)
				return steps, commandErr
			}
			step.OK = true
			step.Detail = "已存在，跳过"
		}
		steps = append(steps, step)
	}
	state, err := b.State()
	if err != nil {
		return steps, err
	}
	if !state.Present {
		return steps, NewOpError(OpFailed, "nft 初始化后仍读不到表 "+NftTable+"（检查 root-action 审计与 nft 权限）")
	}
	return steps, nil
}

// isNftAlreadyExists 报告 nft 的「对象已存在」错误（幂等路径，不是失败）。
func isNftAlreadyExists(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "file exists") || strings.Contains(lower, "already exists")
}

// State 读取 kore 自有表的状态；表不存在时 Present=false，不报错。
func (b *NftBackend) State() (NftState, error) {
	output, err := b.call(ActionNftList, nil)
	if err != nil {
		commandErr, isCommand := err.(*NftCommandError)
		if !isCommand {
			return NftState{}, err
		}
		// 表不存在：nft list 退出 1 且 stderr 带 "No such file or directory"。
		if isNftMissing(commandErr.Stderr) {
			return NftState{Present: false, Mode: ModeOff, Rules: []NftRule{}, Bans: []NftElement{}}, nil
		}
		return NftState{}, commandErr
	}
	return parseNftTableJSON(output.Stdout)
}

// isNftMissing 报告「表/对象不存在」（属于正常未初始化状态）。
func isNftMissing(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "no such file") || strings.Contains(lower, "does not exist")
}

// ModeRuleCountFor 返回给定模式的规则条数（回读校验用）。
func ModeRuleCountFor(mode string) int {
	switch mode {
	case ModeObserve, ModeEnforce:
		return ModeRuleCount
	}
	return 0
}

// ApplyMode 切换数据面模式（标准等级）：等价于 ApplyLevel(mode, LevelStandard)。
func (b *NftBackend) ApplyMode(mode string) (ModeResult, error) {
	return b.ApplyLevel(mode, LevelStandard)
}

// ApplyLevel 切换数据面「模式 + 防护等级」。
//
//	observe / enforce：清链后重装该模式的 4 条基础规则；等级再调整覆盖面
//	  - standard：就是这 4 条
//	  - loose   ：删掉扫描限速与并发上限，只留封禁名单
//	  - strict  ：再追加「无效连接状态丢弃」与「SSH 暴力破解限速」两条
//	off：清空链（不删表/集合）
//
// 不把「动作退出 0」当成「已生效」：执行后回读模式、等级与规则条数，任一不符都
// 如实返回 applied=false 并附原因（规则集可能处于「已清链但未装完」的中间态）。
func (b *NftBackend) ApplyLevel(mode, level string) (ModeResult, error) {
	if level == "" {
		level = LevelStandard
	}
	result := ModeResult{Mode: mode, Level: level, Rules: []NftRule{}, Steps: []NftStep{}}
	state, err := b.State()
	if err != nil {
		return result, err
	}
	result.PreviousMode = state.Mode
	currentLevel := b.currentLevel(state)
	result.PreviousLevel = currentLevel

	if mode == ModeOff {
		return b.applyOff(state, result)
	}
	switch mode {
	case ModeObserve, ModeEnforce:
	default:
		return result, NewOpError(OpFailed, "未知模式 "+mode)
	}
	wantRules := LevelRuleCountFor(level)
	if state.Mode == mode && currentLevel == level && len(state.Rules) == wantRules {
		result.Applied = true
		result.Verified = true
		result.Rules = state.Rules
		result.Hint = "当前已是「" + modeText(mode) + " / " + LevelText(level) + "」，未执行任何提权动作"
		return result, nil
	}
	if !state.Present {
		steps, err := b.Ensure()
		result.Steps = append(result.Steps, steps...)
		if err != nil {
			return result, err
		}
	}
	action := ActionNftModeObserve
	if mode == ModeEnforce {
		action = ActionNftModeEnforce
	}
	if err := b.runStep(&result, action, nil); err != nil {
		return result, err
	}
	if err := b.adjustLevel(&result, mode, level); err != nil {
		// 等级调整失败时链仍处在该模式的基础规则上：如实报未验证 + 可操作提示。
		result.Hint = "基础防护已下发，但等级调整未完成（" + err.Error() + "）；可重试切换到该等级"
		return result, nil
	}
	after, err := b.State()
	if err != nil {
		return result, err
	}
	actualLevel := b.currentLevel(after)
	result.Rules = after.Rules
	result.Verified = after.Mode == mode && actualLevel == level && len(after.Rules) == wantRules
	if !result.Verified {
		result.Hint = fmt.Sprintf("规则已下发但回读不一致（期望 %s / %s / %d 条，实际 %s / %s / %d 条）；"+
			"链可能处于中间态，请重试或检查 nft 版本", mode, level, wantRules,
			after.Mode, levelLabel(actualLevel), len(after.Rules))
		return result, nil
	}
	result.Applied = true
	return result, nil
}

// applyOff 关闭防护：清空链（表与封禁集合保留，重新开启立即生效）。
func (b *NftBackend) applyOff(state NftState, result ModeResult) (ModeResult, error) {
	result.Level = ""
	if !state.Present || (state.Mode == ModeOff && len(state.Rules) == 0) {
		result.Applied = true
		result.Verified = true
		result.Rules = state.Rules
		result.Hint = "当前已是关闭状态，未执行任何提权动作"
		return result, nil
	}
	if err := b.runStep(&result, ActionNftFlush, nil); err != nil {
		return result, err
	}
	after, err := b.State()
	if err != nil {
		return result, err
	}
	result.Rules = after.Rules
	result.Verified = after.Mode == ModeOff && len(after.Rules) == 0
	if !result.Verified {
		result.Hint = "清链已执行但回读仍有规则；链可能处于中间态，请重试"
		return result, nil
	}
	result.Hint = "防护已关闭（封禁名单保留但不生效）；重新开启时按标准等级下发"
	result.Applied = true
	return result, nil
}

// runStep 执行一条 root 动作并记入 steps；失败按 nft 错误类别归一。
func (b *NftBackend) runStep(result *ModeResult, action string, args []string) error {
	output, err := b.call(action, args)
	step := NftStep{Action: action, ExitCode: output.ExitCode, OK: err == nil}
	if err != nil {
		commandErr, ok := err.(*NftCommandError)
		if !ok {
			return err
		}
		step.Detail = trimLine([]byte(commandErr.Stderr), 300)
		result.Steps = append(result.Steps, step)
		if looksLikeNftUnsupported(commandErr.Stderr) {
			return NewOpError(OpCgroup,
				"当前 nft 版本不支持规则集里的语法（meter / ct count / log level）："+step.Detail)
		}
		return commandErr
	}
	result.Steps = append(result.Steps, step)
	return nil
}

// adjustLevel 在已下发的基础规则上把链调整到目标等级。
func (b *NftBackend) adjustLevel(result *ModeResult, mode, level string) error {
	switch level {
	case LevelStrict:
		for _, extra := range strictExtraRules {
			if err := b.runStep(result, ActionNftAddRule, builtinTokensFor(extra, mode)); err != nil {
				return err
			}
		}
		return nil
	case LevelLoose:
		chain, err := b.nftChainRules()
		if err != nil {
			return err
		}
		for _, name := range []string{"syn-rate", "conn-rate"} {
			target, found := findChainRule(chain, name)
			if !found || target.Handle <= 0 {
				continue
			}
			if err := b.runStep(result, ActionNftDeleteRule, []string{fmt.Sprint(target.Handle)}); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

// modeText / LevelText / levelLabel 是给用户看的中文短名（不暴露内部枚举）。
func modeText(mode string) string {
	switch mode {
	case ModeObserve:
		return "只记录不拦截"
	case ModeEnforce:
		return "直接拦截"
	case ModeOff:
		return "已关闭"
	}
	return "未知模式"
}

// LevelText 是等级的中文名。
func LevelText(level string) string {
	switch level {
	case LevelLoose:
		return "宽松"
	case LevelStandard:
		return "标准"
	case LevelStrict:
		return "严格"
	}
	return "未启用"
}

// levelLabel 把空串显示成「未启用」，其余同 LevelText。
func levelLabel(level string) string {
	if level == "" {
		return "未启用"
	}
	return LevelText(level)
}

// looksLikeNftUnsupported 报告「nft 版本不支持该语法」类错误。
func looksLikeNftUnsupported(stderr string) bool {
	lower := strings.ToLower(stderr)
	for _, marker := range []string{"syntax error", "unknown identifier", "not supported", "could not parse"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// Ban 封禁一个 IP/CIDR：写进对应地址族的封禁集合，可选超时（秒）。
func (b *NftBackend) Ban(ip string, ttlS int) (BanResult, error) {
	normalized, family, err := normalizeIP(ip)
	if err != nil {
		return BanResult{}, err
	}
	if ttlS != 0 && (ttlS < MinBanTTLS || ttlS > MaxBanTTLS) {
		return BanResult{}, NewOpError(OpFailed,
			fmt.Sprintf("ttl_s=%d 超出 %d–%d 秒（0 表示永久）", ttlS, MinBanTTLS, MaxBanTTLS))
	}
	result := BanResult{IP: normalized, Family: family, TTL: ttlS, Steps: []NftStep{}}
	state, err := b.State()
	if err != nil {
		return result, err
	}
	if !state.Present {
		steps, err := b.Ensure()
		result.Steps = append(result.Steps, steps...)
		if err != nil {
			return result, err
		}
	}
	action := ActionNftBan4
	set := NftSetV4
	if family == "ipv6" {
		action = ActionNftBan6
		set = NftSetV6
	}
	args := []string{"{", normalized}
	if ttlS > 0 {
		args = append(args, "timeout", strconv.Itoa(ttlS)+"s")
	}
	args = append(args, "}")
	output, err := b.call(action, args)
	step := NftStep{Action: action, ExitCode: output.ExitCode, OK: err == nil}
	if err != nil {
		if commandErr, ok := err.(*NftCommandError); ok {
			step.Detail = trimLine([]byte(commandErr.Stderr), 300)
			result.Steps = append(result.Steps, step)
			return result, commandErr
		}
		return result, err
	}
	result.Steps = append(result.Steps, step)
	// 回读：元素真的在集合里才算成功。
	after, err := b.State()
	if err != nil {
		return result, err
	}
	result.Banned = containsBan(after.Bans, normalized, set)
	if result.Banned {
		result.Set = set
		return result, nil
	}
	result.Hint = "集合写入后回读不到该元素；检查 nft 集合类型（" + set + "）与地址族是否匹配"
	return result, nil
}

// Unban 解封一个 IP/CIDR；元素本不存在时 existed=false（幂等，不报错）。
func (b *NftBackend) Unban(ip string) (UnbanResult, error) {
	normalized, family, err := normalizeIP(ip)
	if err != nil {
		return UnbanResult{}, err
	}
	result := UnbanResult{IP: normalized, Family: family, Steps: []NftStep{}}
	action := ActionNftUnban4
	set := NftSetV4
	if family == "ipv6" {
		action = ActionNftUnban6
		set = NftSetV6
	}
	result.Set = set
	output, err := b.call(action, []string{"{", normalized, "}"})
	step := NftStep{Action: action, ExitCode: output.ExitCode, OK: err == nil}
	if err != nil {
		if commandErr, ok := err.(*NftCommandError); ok {
			step.Detail = trimLine([]byte(commandErr.Stderr), 300)
			result.Steps = append(result.Steps, step)
			if isNftMissing(commandErr.Stderr) || strings.Contains(strings.ToLower(commandErr.Stderr), "element") {
				// 元素不存在：幂等成功（没有可解封的）。
				step.OK = true
				result.Removed = false
				result.Hint = "该 IP 不在封禁集合中（无需解封）"
				return result, nil
			}
			return result, commandErr
		}
		return result, err
	}
	result.Steps = append(result.Steps, step)
	after, err := b.State()
	if err != nil {
		return result, err
	}
	result.Removed = !containsBan(after.Bans, normalized, set)
	return result, nil
}

// Bans 列出封禁元素（按 IP 排序）。
func (b *NftBackend) Bans() (BansResult, error) {
	state, err := b.State()
	if err != nil {
		return BansResult{}, err
	}
	bans := state.Bans
	if bans == nil {
		bans = []NftElement{}
	}
	return BansResult{Present: state.Present, Mode: state.Mode, Count: len(bans), Bans: bans}, nil
}

// containsBan 判断集合里是否有该元素（CIDR 与单地址都按规范化字符串比较）。
func containsBan(bans []NftElement, ip, set string) bool {
	for _, element := range bans {
		if element.Set == set && element.IP == ip {
			return true
		}
	}
	return false
}

// normalizeIP 校验并规范化 IP/CIDR，返回 (规范化字符串, ipv4|ipv6)。
func normalizeIP(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", NewOpError(OpFailed, "ip 不能为空")
	}
	address, bits, hasBits := strings.Cut(value, "/")
	parsed := net.ParseIP(address)
	if parsed == nil {
		return "", "", NewOpError(OpFailed, "ip="+raw+" 不是合法 IPv4/IPv6 地址")
	}
	family := "ipv4"
	width := 32
	normalizedAddress := parsed.To4().String()
	if parsed.To4() == nil {
		family = "ipv6"
		width = 128
		normalizedAddress = parsed.String()
	}
	if !hasBits {
		return normalizedAddress, family, nil
	}
	prefix, err := strconv.Atoi(bits)
	if err != nil || prefix < 0 || prefix > width {
		return "", "", NewOpError(OpFailed,
			fmt.Sprintf("ip=%s 的掩码长度必须 0–%d", raw, width))
	}
	if prefix == width {
		return normalizedAddress, family, nil
	}
	return normalizedAddress + "/" + strconv.Itoa(prefix), family, nil
}

// ---- nft JSON 解析（`nft -j list table inet kore_waf`）----

// nftObject 是 nft JSON 里的一个对象：键名即对象类型（table/chain/set/rule/…）。
type nftObject map[string]json.RawMessage

// nftSetJSON 是 set 对象的形状。
type nftSetJSON struct {
	Name string            `json:"name"`
	Type string            `json:"type"`
	Elem []json.RawMessage `json:"elem"`
}

// nftElemJSON 是集合元素的两种编码：纯字符串，或 {elem:{val,timeout,expires}}。
type nftElemJSON struct {
	Elem *struct {
		Val     string `json:"val"`
		Timeout int    `json:"timeout"`
		Expires int    `json:"expires"`
	} `json:"elem"`
}

// nftRuleJSON 是 rule 对象的形状。
type nftRuleJSON struct {
	Handle int               `json:"handle"`
	Expr   []json.RawMessage `json:"expr"`
}

// parseNftTableJSON 解析 kore 表的 JSON 输出。
func parseNftTableJSON(raw []byte) (NftState, error) {
	state := NftState{Present: false, Mode: ModeOff, Rules: []NftRule{}, Bans: []NftElement{}}
	var payload struct {
		Nftables []nftObject `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return state, NewOpError(OpFailed, "解析 nft JSON 失败: "+err.Error())
	}
	tableFound := false
	for _, object := range payload.Nftables {
		switch {
		case object["table"] != nil:
			var table struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(object["table"], &table); err == nil && table.Name == NftTable {
				tableFound = true
			}
		case object["set"] != nil:
			var set nftSetJSON
			if err := json.Unmarshal(object["set"], &set); err != nil {
				continue
			}
			if set.Name != NftSetV4 && set.Name != NftSetV6 {
				continue
			}
			for _, elementRaw := range set.Elem {
				element, ok := parseNftElement(elementRaw, set.Name)
				if ok {
					state.Bans = append(state.Bans, element)
				}
			}
		case object["rule"] != nil:
			var rule nftRuleJSON
			if err := json.Unmarshal(object["rule"], &rule); err != nil {
				continue
			}
			state.Rules = append(state.Rules, summarizeNftRule(rule))
		}
	}
	state.Present = tableFound
	state.Mode = modeFromRules(state.Rules)
	return state, nil
}

// parseNftElement 解析单个集合元素（容忍两种编码）。
func parseNftElement(raw json.RawMessage, set string) (NftElement, bool) {
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil && plain != "" {
		return NftElement{IP: plain, Set: set}, true
	}
	var wrapped nftElemJSON
	if err := json.Unmarshal(raw, &wrapped); err != nil || wrapped.Elem == nil {
		return NftElement{}, false
	}
	return NftElement{
		IP:       wrapped.Elem.Val,
		TimeoutS: wrapped.Elem.Timeout,
		ExpiresS: wrapped.Elem.Expires,
		Set:      set,
	}, true
}

// modeFromRules 由规则 verdict 判定当前数据面模式。
func modeFromRules(rules []NftRule) string {
	if len(rules) == 0 {
		return ModeOff
	}
	for _, rule := range rules {
		if rule.Verdict == "drop" {
			return ModeEnforce
		}
	}
	return ModeObserve
}

// summarizeNftRule 把 nft 的表达式 JSON 压成一条可读摘要（含计数）。
func summarizeNftRule(rule nftRuleJSON) NftRule {
	summary := NftRule{Handle: rule.Handle, Verdict: "observe"}
	parts := make([]string, 0, 6)
	for _, exprRaw := range rule.Expr {
		var expr nftObject
		if err := json.Unmarshal(exprRaw, &expr); err != nil {
			continue
		}
		switch {
		case expr["match"] != nil:
			if text := describeNftMatch(expr["match"]); text != "" {
				parts = append(parts, text)
			}
		case expr["ct count"] != nil:
			var count struct {
				Val int  `json:"val"`
				Inv bool `json:"inv"`
			}
			if err := json.Unmarshal(expr["ct count"], &count); err == nil {
				op := "over"
				if !count.Inv {
					op = "under"
				}
				parts = append(parts, fmt.Sprintf("ct count %s %d", op, count.Val))
			}
		case expr["set"] != nil:
			if text := describeNftSetStatement(expr["set"]); text != "" {
				parts = append(parts, text)
			}
		case expr["counter"] != nil:
			var counter struct {
				Packets int64 `json:"packets"`
				Bytes   int64 `json:"bytes"`
			}
			if err := json.Unmarshal(expr["counter"], &counter); err == nil {
				summary.Packets, summary.Bytes, summary.HasCount = counter.Packets, counter.Bytes, true
			}
			parts = append(parts, "counter")
		case expr["log"] != nil:
			var log struct {
				Prefix string `json:"prefix"`
			}
			_ = json.Unmarshal(expr["log"], &log)
			parts = append(parts, "log prefix "+log.Prefix)
		case expr["drop"] != nil:
			summary.Verdict = "drop"
			parts = append(parts, "drop")
		case expr["accept"] != nil:
			summary.Verdict = "accept"
			parts = append(parts, "accept")
		default:
			for key := range expr {
				parts = append(parts, key)
			}
		}
	}
	summary.Summary = strings.Join(parts, " → ")
	return summary
}

// describeNftMatch 描述一条 match 表达式（payload 匹配或集合成员匹配）。
func describeNftMatch(raw json.RawMessage) string {
	var match struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(raw, &match); err != nil {
		return ""
	}
	left := describeNftExpr(match.Left)
	right := describeNftExpr(match.Right)
	if left == "" {
		return ""
	}
	if right == "" {
		return left
	}
	return left + " " + match.Op + " " + right
}

// describeNftExpr 描述表达式左/右值的常见形状（payload / 字符串 / 集合）。
func describeNftExpr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var payload struct {
		Payload *struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
		Set json.RawMessage `json:"set"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil {
		if payload.Payload != nil {
			return strings.TrimSpace(payload.Payload.Protocol + " " + payload.Payload.Field)
		}
		if len(payload.Set) > 0 {
			var items []json.RawMessage
			if err := json.Unmarshal(payload.Set, &items); err == nil {
				values := make([]string, 0, len(items))
				for _, item := range items {
					var text string
					if err := json.Unmarshal(item, &text); err == nil {
						values = append(values, text)
						continue
					}
					values = append(values, string(item))
				}
				return "{" + strings.Join(values, ", ") + "}"
			}
		}
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String()
	}
	return ""
}

// describeNftSetStatement 描述 meter/动态集合语句（`limit rate over …`）。
func describeNftSetStatement(raw json.RawMessage) string {
	var statement struct {
		Op   string            `json:"op"`
		Set  string            `json:"set"`
		Stmt []json.RawMessage `json:"stmt"`
	}
	if err := json.Unmarshal(raw, &statement); err != nil {
		return ""
	}
	parts := make([]string, 0, 2)
	if statement.Set != "" {
		parts = append(parts, statement.Set)
	}
	for _, stmtRaw := range statement.Stmt {
		var stmt nftObject
		if err := json.Unmarshal(stmtRaw, &stmt); err != nil {
			continue
		}
		if limitRaw := stmt["limit"]; limitRaw != nil {
			var limit struct {
				Rate  int    `json:"rate"`
				Burst int    `json:"burst"`
				Per   string `json:"per"`
				Inv   bool   `json:"inv"`
			}
			if err := json.Unmarshal(limitRaw, &limit); err == nil {
				op := "over"
				if !limit.Inv {
					op = "under"
				}
				text := fmt.Sprintf("limit %s %d/%s", op, limit.Rate, limit.Per)
				if limit.Burst > 0 {
					text += fmt.Sprintf(" burst %d", limit.Burst)
				}
				parts = append(parts, text)
			}
		}
	}
	return strings.Join(parts, " ")
}

// BanParams 是 waf.ban 的入参。
type BanParams struct {
	IP     string `json:"ip"`
	TTLS   int    `json:"ttl_s"`
	Reason string `json:"reason"`
}

// BanResult 是 waf.ban 的结果。
type BanResult struct {
	IP     string    `json:"ip"`
	Family string    `json:"family"`
	Set    string    `json:"set,omitempty"`
	TTL    int       `json:"ttl_s,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Banned bool      `json:"banned"`
	Hint   string    `json:"hint,omitempty"`
	Steps  []NftStep `json:"steps"`
}

// UnbanResult 是 waf.unban 的结果。
type UnbanResult struct {
	IP      string    `json:"ip"`
	Family  string    `json:"family"`
	Set     string    `json:"set"`
	Removed bool      `json:"removed"`
	Hint    string    `json:"hint,omitempty"`
	Steps   []NftStep `json:"steps"`
}

// BansResult 是 waf.bans 的结果。
type BansResult struct {
	Present bool         `json:"present"`
	Mode    string       `json:"mode"`
	Count   int          `json:"count"`
	Bans    []NftElement `json:"bans"`
}

// ModeResult 是 waf.toggle 的结果。
type ModeResult struct {
	Mode          string    `json:"mode"`
	PreviousMode  string    `json:"previous_mode"`
	Level         string    `json:"level"`
	PreviousLevel string    `json:"previous_level"`
	Applied       bool      `json:"applied"`
	Verified      bool      `json:"verified"`
	Hint          string    `json:"hint,omitempty"`
	Rules         []NftRule `json:"rules"`
	Steps         []NftStep `json:"steps"`
}

// StatusBackend 是 waf.status 里的数据面子对象。
type StatusBackend struct {
	Tool       string `json:"tool"`
	Available  bool   `json:"available"`
	Channel    bool   `json:"channel"`
	Table      string `json:"table"`
	Chain      string `json:"chain"`
	Present    bool   `json:"present"`
	Mode       string `json:"mode"`
	Level      string `json:"level"`
	Banned     int    `json:"banned_count"`
	RulesCount int    `json:"rules_count"`
	Reason     string `json:"reason,omitempty"`
	Hint       string `json:"hint,omitempty"`
}

// NftRuleset 是 waf.rules 里的数据面片段。
type NftRuleset struct {
	Table      string       `json:"table"`
	Chain      string       `json:"chain"`
	Present    bool         `json:"present"`
	Mode       string       `json:"mode"`
	RulesCount int          `json:"rules_count"`
	Rules      []NftRule    `json:"rules"`
	BansCount  int          `json:"bans_count"`
	Bans       []NftElement `json:"bans"`
}
