package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

const helloMethod = "kore.hello"

// helloTimeout 是插件侧等待握手响应的上限，与内核 2s hello 预算一致。
const helloTimeout = 2 * time.Second

// helloParams 是 kore.hello 请求参数：§5 全字段 + id/token 别名。
type helloParams struct {
	PluginID     string   `json:"plugin_id"`
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	RequiresKore string   `json:"requires_kore"`
	PID          int      `json:"pid"`
	Capabilities []string `json:"capabilities"`
	StartedAt    string   `json:"started_at"`
	Token        string   `json:"token,omitempty"`
}

// helloResult 是内核握手响应中本插件需要校验的字段。
type helloResult struct {
	OK       bool   `json:"ok"`
	Protocol string `json:"protocol"`
}

// handshake 完成三步握手：发 kore.hello → 读响应帧 → 校验 ok/协议。
func handshake(conn net.Conn, cfg *config) error {
	requestID, err := randomID()
	if err != nil {
		return fmt.Errorf("生成握手请求 id: %w", err)
	}
	params, err := json.Marshal(newHelloParams(cfg))
	if err != nil {
		return fmt.Errorf("序列化 hello 参数: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(helloTimeout)); err != nil {
		return fmt.Errorf("设置握手超时: %w", err)
	}
	request := &pluginapi.Request{
		Type:   pluginapi.TypeRequest,
		ID:     requestID,
		ReqID:  "r-" + requestID[:8],
		Method: helloMethod,
		Params: params,
	}
	if err := pluginapi.WriteJSON(conn, request); err != nil {
		return fmt.Errorf("发送 kore.hello: %w", err)
	}
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		return fmt.Errorf("读取 kore.hello 响应: %w", err)
	}
	response, err := decodeHelloResponse(payload, requestID)
	if err != nil {
		return err
	}
	if err := checkHelloResult(response); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

// newHelloParams 用运行期配置组装 §5 握手参数。
func newHelloParams(cfg *config) helloParams {
	return helloParams{
		PluginID:     cfg.id,
		ID:           cfg.id,
		Version:      cfg.version,
		Protocol:     pluginapi.Protocol,
		RequiresKore: cfg.requiresKore,
		PID:          os.Getpid(),
		Capabilities: cfg.capabilities,
		StartedAt:    time.Now().Format(time.RFC3339Nano),
		Token:        cfg.token,
	}
}

// decodeHelloResponse 解码握手响应并校验 id 回显与 error 分支。
func decodeHelloResponse(payload []byte, requestID string) (*pluginapi.Response, error) {
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		return nil, fmt.Errorf("解码 kore.hello 响应: %w", err)
	}
	response, ok := env.(*pluginapi.Response)
	if !ok {
		return nil, fmt.Errorf("kore.hello 响应帧类型是 %T，不是 response", env)
	}
	if response.ID != requestID {
		return nil, fmt.Errorf("kore.hello 响应 id=%q 与请求 %q 不一致", response.ID, requestID)
	}
	if response.Error != nil {
		return nil, fmt.Errorf("内核拒绝握手: %w", response.Error)
	}
	return response, nil
}

// checkHelloResult 校验 result.ok 与协议主版本，防止内核降级兼容。
func checkHelloResult(response *pluginapi.Response) error {
	var result helloResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		return fmt.Errorf("解析 kore.hello 结果: %w", err)
	}
	if !result.OK {
		return errors.New("内核握手结果 ok=false")
	}
	if result.Protocol != "" && result.Protocol != pluginapi.Protocol {
		return fmt.Errorf("内核握手协议 %q 与 %q 不匹配", result.Protocol, pluginapi.Protocol)
	}
	return nil
}

// randomID 生成 32 位小写 hex 的连接内请求 id（§7.2）。
func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
