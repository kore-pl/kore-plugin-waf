package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-waf/internal/plugincfg"
	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// testConfig 构造握手与会话循环共用的一致配置（不依赖环境变量）。
func testConfig(t *testing.T) *config {
	t.Helper()
	stateDir := t.TempDir()
	values := defaultValues()
	settings, err := settingsFromValues(values)
	if err != nil {
		t.Fatalf("构造 settings: %v", err)
	}
	return &config{
		id:           "waf",
		version:      "0.2.0",
		requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:read", "system:admin"},
		startedAt:    time.Now(),
		stateDir:     stateDir,
		store:        plugincfg.NewStore(stateDir),
		values:       values,
		source:       plugincfg.SourceDefault,
		runtime:      wafop.New(wafop.Options{Settings: settings}),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func readFrame(t *testing.T, conn net.Conn) any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码帧失败: %v", err)
	}
	return env
}

func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	request, ok := readFrame(t, conn).(*pluginapi.Request)
	if !ok {
		t.Fatal("帧类型不是 request")
	}
	return request
}

func writeResponse(t *testing.T, conn net.Conn, id, reqID string, result json.RawMessage) {
	t.Helper()
	if err := pluginapi.WriteJSON(conn, &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: id, ReqID: reqID, Result: result,
	}); err != nil {
		t.Fatalf("写响应失败: %v", err)
	}
}

// TestHandshake 校验 hello 首帧字段与三步握手。
func TestHandshake(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- handshake(pluginConn, testConfig(t)); _ = pluginConn.Close() }()

	request := readRequest(t, kernelConn)
	if request.Method != helloMethod {
		t.Fatalf("首帧方法=%q，期望 %q", request.Method, helloMethod)
	}
	var params helloParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("解析 hello 参数失败: %v", err)
	}
	if params.PluginID != "waf" || params.ID != "waf" {
		t.Fatalf("plugin_id/id=%q/%q，期望 waf", params.PluginID, params.ID)
	}
	if params.Protocol != pluginapi.Protocol || params.Version != "0.2.0" {
		t.Fatalf("protocol/version=%q/%q 不符合 §5", params.Protocol, params.Version)
	}
	if params.PID != os.Getpid() {
		t.Fatalf("pid=%d，期望 %d", params.PID, os.Getpid())
	}
	result, err := json.Marshal(helloResult{OK: true, Protocol: pluginapi.Protocol})
	if err != nil {
		t.Fatalf("序列化握手响应失败: %v", err)
	}
	writeResponse(t, kernelConn, request.ID, request.ReqID, result)
	if err := <-done; err != nil {
		t.Fatalf("握手返回错误: %v", err)
	}
}

// TestServeShutdown 会话循环收到 kore.shutdown 后回响应帧再优雅退出。
// 硬约束：每个 shutdown 请求都配对读取一次响应帧，不靠"写完就算"。
func TestServeShutdown(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- serve(pluginConn, testConfig(t), testLogger()); _ = pluginConn.Close() }()

	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-shutdown", ReqID: "r-shutdown", Method: "kore.shutdown",
	}
	if err := pluginapi.WriteJSON(kernelConn, request); err != nil {
		t.Fatalf("写 shutdown 请求失败: %v", err)
	}
	// 配对读：请求 ID 必须与响应帧一一对齐。
	env := readFrame(t, kernelConn)
	response, ok := env.(*pluginapi.Response)
	if !ok || response.ID != request.ID || response.ReqID != request.ReqID {
		t.Fatalf("shutdown 配对响应帧异常: %+v", env)
	}
	if response.Error != nil {
		t.Fatalf("shutdown 响应带错误: %v", response.Error)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
}

// TestServeMethodThenShutdown 先跑业务方法再发 shutdown，两次请求各配对读一次响应帧。
func TestServeMethodThenShutdown(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- serve(pluginConn, testConfig(t), testLogger()); _ = pluginConn.Close() }()

	requests := []*pluginapi.Request{
		{Type: pluginapi.TypeRequest, ID: "id-status", ReqID: "r-status", Method: "waf.status", Params: json.RawMessage(`{}`)},
		{Type: pluginapi.TypeRequest, ID: "id-rules", ReqID: "r-rules", Method: "waf.rules", Params: json.RawMessage(`{}`)},
		{Type: pluginapi.TypeRequest, ID: "id-log", ReqID: "r-log", Method: "waf.logs", Params: json.RawMessage(`{"limit":3}`)},
		{Type: pluginapi.TypeRequest, ID: "id-cfg", ReqID: "r-cfg", Method: "waf.config.get", Params: json.RawMessage(`{}`)},
		{Type: pluginapi.TypeRequest, ID: "id-shutdown", ReqID: "r-shutdown", Method: "kore.shutdown"},
	}
	for _, request := range requests {
		if err := pluginapi.WriteJSON(kernelConn, request); err != nil {
			t.Fatalf("写 %s 请求失败: %v", request.Method, err)
		}
		env := readFrame(t, kernelConn)
		response, ok := env.(*pluginapi.Response)
		if !ok || response.ID != request.ID || response.ReqID != request.ReqID {
			t.Fatalf("%s 配对响应帧异常: %+v", request.Method, env)
		}
		if response.Error != nil {
			t.Fatalf("%s 响应带错误: %v", request.Method, response.Error)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
}
