package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// infoJSONSnapshot 只取本测试关心的字段；root_actions 的元素类型直接用公开 SDK。
type infoJSONSnapshot struct {
	RequiresRoot bool                   `json:"requires_root"`
	RootActions  []pluginapi.RootAction `json:"root_actions"`
}

// localRootActionIDPattern 是协议 §3.1.3 的 id 语法（本地结构校验用）。
var localRootActionIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// readInfoJSON 读取并解析 info.json 的 requires_root / root_actions。
func readInfoJSON(t *testing.T) infoJSONSnapshot {
	t.Helper()
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json: %v", err)
	}
	var snapshot infoJSONSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	return snapshot
}

// TestInfoJSONRootActionsLocalSchema 是本仓**自足**的 schema 校验：
// 字段/长度/语法/不可回滚语义，全部按协议 §3.1.3 逐条断言。
//
// 它不依赖 SDK 是否已发布新的命令白名单（见下一个测试的版本说明），因此任何一次
// 改清单都会在这里被检查，不会因为 SDK 滞后而裸奔。
func TestInfoJSONRootActionsLocalSchema(t *testing.T) {
	snapshot := readInfoJSON(t)
	if len(snapshot.RootActions) == 0 {
		t.Fatal("本仓声明了 requires_root，root_actions 不能为空")
	}
	if !snapshot.RequiresRoot {
		t.Fatal("root_actions 非空时 requires_root 必须为 true（协议 §3.1.3 / ADR-0018）")
	}
	if len(snapshot.RootActions) > 16 {
		t.Fatalf("root_actions 最多 16 条，当前 %d", len(snapshot.RootActions))
	}
	seen := make(map[string]struct{}, len(snapshot.RootActions))
	for _, action := range snapshot.RootActions {
		prefix := "root_actions[" + action.ID + "]"
		if !localRootActionIDPattern.MatchString(action.ID) {
			t.Errorf("%s id 不匹配 ^[a-z][a-z0-9-]*$", prefix)
		}
		if _, ok := seen[action.ID]; ok {
			t.Errorf("%s id 重复", prefix)
		}
		seen[action.ID] = struct{}{}
		if len(action.Argv) == 0 || len(action.Argv) > 32 {
			t.Errorf("%s argv 元素数=%d，必须 1–32", prefix, len(action.Argv))
		}
		total := 0
		for argIndex, arg := range action.Argv {
			if arg == "" {
				t.Errorf("%s argv[%d] 为空", prefix, argIndex)
			}
			if utf8.RuneCountInString(arg) > 256 {
				t.Errorf("%s argv[%d] 超过 256 字符", prefix, argIndex)
			}
			if strings.ContainsRune(arg, 0) || strings.ContainsAny(arg, "\n\r\t") {
				t.Errorf("%s argv[%d] 含 NUL/控制字符", prefix, argIndex)
			}
			total += utf8.RuneCountInString(arg)
		}
		if total > 4096 {
			t.Errorf("%s argv 总长 %d 超过 4096", prefix, total)
		}
		if action.TimeoutS < 1 || action.TimeoutS > 300 {
			t.Errorf("%s timeout_s=%d 超出 1–300", prefix, action.TimeoutS)
		}
		if utf8.RuneCountInString(action.Description) > 200 {
			t.Errorf("%s description 超过 200 字符", prefix)
		}
		if strings.TrimSpace(action.Description) == "" {
			t.Errorf("%s description 不能为空（启用时展示给用户确认）", prefix)
		}
		// 语义不变量：本插件的 nft 动作都能反向操作（enforce↔observe/off、ban↔unban、
		// 建表/集合/链可 flush/删除），因此一律不得声明 irreversible——否则插件
		// 自己无法签发 confirm 令牌，动作会永远执行不了。
		if action.Irreversible {
			t.Errorf("%s 声明了 irreversible，但本插件没有可自签 confirm 令牌的路径", prefix)
		}
	}
}

// TestInfoJSONRootActionsSchema 用公开 SDK 校验本仓 info.json 的 root_actions。
//
// **SDK 版本门槛**：形状表（ADR-0022）在 `pkg/pluginapi` 里，需要 SDK ≥ v0.1.3 才会认识
// `nft` / `ipset` / DNS 组命令。钉在 v0.1.2 时 SDK 只认识旧的 8 个命令名——这时显式
// skip 并写明需要的版本，而不是把校验放宽或手写一份本地白名单副本（那样会掩盖漂移）。
// 内核侧 `pkg/pluginapi` 的 `TestWafPluginRootActionsCrossRepo` 会在同一工作区里按最新
// 形状表再校验一遍（含追加参数样本），所以漂移不会漏网。
func TestInfoJSONRootActionsSchema(t *testing.T) {
	snapshot := readInfoJSON(t)
	if len(snapshot.RootActions) == 0 {
		t.Fatal("本仓声明了 requires_root，root_actions 不能为空")
	}
	for index, action := range snapshot.RootActions {
		err := pluginapi.ValidateRootAction(action)
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "不在命令白名单内") || strings.Contains(err.Error(), "受控命令白名单") {
			t.Skipf("SDK %s 尚未包含 ADR-0022 的受控命令形状表（首个不允许的命令：%q）。"+
				"需要 pluginapi ≥ v0.1.3 才能在这里做完整形状校验；"+
				"本测试已由 TestInfoJSONRootActionsLocalSchema 兜住字段级约束，"+
				"内核侧跨仓测试 TestWafPluginRootActionsCrossRepo 负责形状校验。",
				moduleVersion(t), action.Argv[0])
		}
		t.Errorf("root_actions[%d] id=%q 未通过 SDK schema 校验: %v", index, action.ID, err)
	}
}

// moduleVersion 读取本仓 go.mod 里钉的 pluginapi 版本（仅用于 skip 提示）。
func moduleVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "pengtang1024/kore/pkg/pluginapi") {
			fields := strings.Fields(line)
			return fields[len(fields)-1]
		}
	}
	return "unknown"
}
