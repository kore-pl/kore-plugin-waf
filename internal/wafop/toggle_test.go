package wafop

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// toggleEnv 构造带模式包含文件的 modsecurity 环境。
func toggleEnv(t *testing.T, mode string) *fakeEnv {
	t.Helper()
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine "+mode+"\n")
	env.addFile("/etc/modsecurity/kore-mode.conf", "SecRuleEngine "+mode+"\n")
	return env
}

// TestToggleNoRootChannel 无 root-action 通道 → E_NEED_ROOT + hint。
func TestToggleNoRootChannel(t *testing.T) {
	env := toggleEnv(t, "Off")
	runtime := New(Options{Env: env.env()})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr == nil {
		t.Fatalf("无通道应 E_NEED_ROOT，实际成功: %s", raw)
	}
	if perr.Code != CodeNeedRoot {
		t.Fatalf("错误码=%q，期望 %q（message=%q）", perr.Code, CodeNeedRoot, perr.Message)
	}
	if !strings.Contains(string(perr.Detail), "hint") {
		t.Fatalf("detail 应含可操作 hint，实际 %s", perr.Detail)
	}
}

// TestToggleOffRequiresConfirm 关闭拦截必须显式 confirm。
func TestToggleOffRequiresConfirm(t *testing.T) {
	env := toggleEnv(t, "On")
	root := &fakeRoot{}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	_, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"off"}`))
	if perr == nil || perr.Code != pluginapi.E_UNAUTHORIZED {
		t.Fatalf("缺 confirm 应 E_UNAUTHORIZED，实际 %v", perr)
	}
	if len(root.calls) != 0 {
		t.Fatalf("未确认时不应执行任何 root 动作: %v", root.calls)
	}
}

// TestToggleNoChangeShortCircuits 目标模式与当前一致时不提权。
func TestToggleNoChangeShortCircuits(t *testing.T) {
	env := toggleEnv(t, "On")
	root := &fakeRoot{}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr != nil {
		t.Fatalf("toggle: %v", perr)
	}
	var result ToggleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if !result.Applied || result.Mode != ModeOn {
		t.Fatalf("同模式应 applied=true，实际 %+v", result)
	}
	if len(root.calls) != 0 {
		t.Fatalf("同模式不应执行 root 动作: %v", root.calls)
	}
}

// TestToggleSuccess root 动作写文件并 reload，回读校验通过。
func TestToggleSuccess(t *testing.T) {
	env := toggleEnv(t, "Off")
	env.setCommand("nginx", func(args ...string) (CommandResult, error) { return CommandResult{}, nil })
	modePath := "/etc/modsecurity/kore-mode.conf"
	root := &fakeRoot{handle: func(actionID string, args []string) ([]byte, int, error) {
		switch actionID {
		case ActionSetMode:
			env.files[modePath] = []byte("SecRuleEngine On\n")
			return nil, 0, nil
		case ActionReloadNginx:
			return nil, 0, nil
		}
		return []byte("unexpected"), 1, nil
	}}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr != nil {
		t.Fatalf("toggle: %v", perr)
	}
	var result ToggleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if !result.Applied || !result.Reloaded || result.Mode != ModeOn || result.PreviousMode != ModeOff {
		t.Fatalf("切换结果不正确: %+v", result)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("应记录写文件与 reload 两步，实际 %+v", result.Steps)
	}
	if len(root.calls) != 2 {
		t.Fatalf("应调用两次 root 动作，实际 %v", root.calls)
	}
	if !strings.Contains(root.calls[0], "SecRuleEngine On") {
		t.Fatalf("sed 表达式未携带目标模式: %s", root.calls[0])
	}
}

// TestToggleWriteFailure 写入退出码非零 → 结构化 E_UPSTREAM，不谎报 applied。
func TestToggleWriteFailure(t *testing.T) {
	env := toggleEnv(t, "Off")
	root := &fakeRoot{handle: func(actionID string, args []string) ([]byte, int, error) {
		return []byte("sed: permission denied"), 4, nil
	}}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr != nil {
		t.Fatalf("写入失败应为结构化结果: %v", perr)
	}
	var result ToggleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if result.Applied || result.ErrorCode != pluginapi.E_UPSTREAM || result.Hint == "" {
		t.Fatalf("失败应 applied=false + E_UPSTREAM + hint，实际 %+v", result)
	}
}

// TestToggleChannelRejects 通道返回 E_NEED_ROOT 时原样透传并带 hint。
func TestToggleChannelRejects(t *testing.T) {
	env := toggleEnv(t, "Off")
	root := &fakeRoot{handle: func(actionID string, args []string) ([]byte, int, error) {
		return nil, -1, &ChannelError{Code: CodeNeedRoot, Message: "需要 root", Hint: "用 sudo 启动 kored"}
	}}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	_, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("应透传 E_NEED_ROOT，实际 %v", perr)
	}
	if !strings.Contains(perr.Message, "sudo") {
		t.Fatalf("message 应带 hint，实际 %q", perr.Message)
	}
}

// TestToggleModeFileMissing 模式包含文件不存在 → 结构化 E_UNSUPPORTED + 怎么修。
func TestToggleModeFileMissing(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/etc/modsecurity/modsecurity.conf", "SecRuleEngine Off\n")
	root := &fakeRoot{}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr != nil {
		t.Fatalf("缺文件应为结构化结果: %v", perr)
	}
	var result ToggleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if result.ErrorCode != pluginapi.E_UNSUPPORTED || !strings.Contains(result.Hint, "Include") {
		t.Fatalf("应给 Include 提示，实际 %+v", result)
	}
}

// TestToggleRefusesUnrelatedFile 模式文件不含 SecRuleEngine → 拒绝改写（安全护栏）。
func TestToggleRefusesUnrelatedFile(t *testing.T) {
	env := toggleEnv(t, "Off")
	env.files["/etc/modsecurity/kore-mode.conf"] = []byte("root:x:0:0:root:/root:/bin/bash\n")
	root := &fakeRoot{}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"on"}`))
	if perr != nil {
		t.Fatalf("应为结构化结果: %v", perr)
	}
	var result ToggleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if result.ErrorCode != pluginapi.E_UNSUPPORTED || len(root.calls) != 0 {
		t.Fatalf("应拒绝改写无关文件: %+v calls=%v", result, root.calls)
	}
}

// TestToggleUnsupportedEngine naxsi 不支持运行时切换 → 结构化 E_UNSUPPORTED。
func TestToggleUnsupportedEngine(t *testing.T) {
	env := newFakeEnv()
	env.addFile("/usr/lib/nginx/modules/ngx_http_naxsi_module.so", "")
	env.addFile("/etc/nginx/nginx.conf", "SecRulesEnabled;\n")
	root := &fakeRoot{}
	runtime := New(Options{Env: env.env(), RootAction: root.Call})
	raw, perr := runtime.Call("waf.toggle", json.RawMessage(`{"mode":"off","confirm":true}`))
	if perr != nil {
		t.Fatalf("应为结构化结果: %v", perr)
	}
	var result ToggleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("解析 toggle: %v", err)
	}
	if result.ErrorCode != pluginapi.E_UNSUPPORTED || !strings.Contains(result.Hint, "naxsi") {
		t.Fatalf("应说明 naxsi 不支持切换，实际 %+v", result)
	}
	if len(root.calls) != 0 {
		t.Fatalf("不应执行 root 动作: %v", root.calls)
	}
}
