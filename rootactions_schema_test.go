package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// infoJSONSnapshot 只取本测试关心的字段；root_actions 的元素类型直接用公开 SDK。
type infoJSONSnapshot struct {
	RequiresRoot bool                   `json:"requires_root"`
	RootActions  []pluginapi.RootAction `json:"root_actions"`
}

// TestInfoJSONRootActionsSchema 用公开 SDK（pluginapi v0.1.2+）校验本仓 info.json
// 的 root_actions：清单与协议 schema 的漂移在这里失败，而不是等用户启用插件时才报
// E_INVALID。对应协议 §3.1.3 与 ADR-0018。
func TestInfoJSONRootActionsSchema(t *testing.T) {
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json: %v", err)
	}
	var snapshot infoJSONSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}

	if len(snapshot.RootActions) == 0 {
		if snapshot.RequiresRoot {
			t.Fatal("requires_root=true 但 root_actions 为空（协议 §3.1.3）")
		}
		t.Log("本仓未声明 root_actions，跳过 schema 校验")
		return
	}
	if !snapshot.RequiresRoot {
		t.Fatal("root_actions 非空时 requires_root 必须为 true（协议 §3.1.3 / ADR-0018）")
	}

	seen := make(map[string]int, len(snapshot.RootActions))
	for i, action := range snapshot.RootActions {
		if prev, ok := seen[action.ID]; ok {
			t.Errorf("root_actions[%d] id=%q 与 root_actions[%d] 重复", i, action.ID, prev)
		}
		seen[action.ID] = i
		if err := pluginapi.ValidateRootAction(action); err != nil {
			t.Errorf("root_actions[%d] id=%q 未通过 SDK schema 校验: %v", i, action.ID, err)
		}
	}
}
