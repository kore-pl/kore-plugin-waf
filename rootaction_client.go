package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
)

// rootActionTimeout 是插件经内核 root-action 通道执行动作的上限。
// 通道侧由动作声明的 timeout_s 兜底，这里只防 HTTP 层永久挂住。
const rootActionTimeout = 60 * time.Second

// rootActionClient 是插件→内核提权通道的客户端（ADR-0018）。
//
// 传输：内核 UDS 上的 HTTP（KORE_KERNEL_SOCK 由 supervisor 注入）；
// 身份：KORE_PLUGIN_TOKEN bearer，内核只允许插件调用自己的 root_actions，
// 且要求该插件已获 system:admin。插件自身永不 exec sudo/setuid。
type rootActionClient struct {
	pluginID string
	token    string
	client   *http.Client
}

// newRootActionClient 在三个环境变量齐备时构造客户端；缺一返回 nil（通道不可用）。
func newRootActionClient() *rootActionClient {
	socket := os.Getenv("KORE_KERNEL_SOCK")
	token := os.Getenv("KORE_PLUGIN_TOKEN")
	pluginID := os.Getenv("KORE_PLUGIN_ID")
	if socket == "" || token == "" || pluginID == "" {
		return nil
	}
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}
	return &rootActionClient{
		pluginID: pluginID, token: token,
		client: &http.Client{Transport: transport, Timeout: rootActionTimeout},
	}
}

// rootActionRequest / rootActionResponse / rootActionError 是通道的 JSON 契约。
type rootActionRequest struct {
	ActionID string   `json:"action_id"`
	Args     []string `json:"args,omitempty"`
}

type rootActionResponse struct {
	Executed bool   `json:"executed"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	DurMS    int64  `json:"dur_ms"`
	Unit     string `json:"unit"`
}

type rootActionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

// Call 经内核执行一个声明过的 root 动作，返回 stdout/stderr/退出码。
//
// 退出码非 0 不是 error：那是命令自己的结果（nft 在对象不存在时退出 1），由方法面
// 按语义判断；只有「内核拒绝」「传输失败」才返回 error。
func (c *rootActionClient) Call(actionID string, args []string) (wafop.RootActionOutput, error) {
	body, err := json.Marshal(rootActionRequest{ActionID: actionID, Args: args})
	if err != nil {
		return wafop.RootActionOutput{}, fmt.Errorf("序列化 root-action 请求失败：%w", err)
	}
	req, err := http.NewRequest(http.MethodPost,
		"http://kore/api/v1/plugins/"+c.pluginID+"/root-action", strings.NewReader(string(body)))
	if err != nil {
		return wafop.RootActionOutput{}, fmt.Errorf("构造 root-action 请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return wafop.RootActionOutput{}, fmt.Errorf("调用内核 root-action 失败：%w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return wafop.RootActionOutput{}, fmt.Errorf("读取 root-action 响应失败：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var protocolErr rootActionError
		if json.Unmarshal(raw, &protocolErr) == nil && protocolErr.Code != "" {
			return wafop.RootActionOutput{}, &wafop.ChannelError{
				Code: protocolErr.Code, Message: protocolErr.Message, Hint: protocolErr.Detail,
			}
		}
		return wafop.RootActionOutput{}, fmt.Errorf("内核 root-action 返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var result rootActionResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return wafop.RootActionOutput{}, fmt.Errorf("解析 root-action 响应失败：%w", err)
	}
	return wafop.RootActionOutput{
		Stdout: []byte(result.Stdout), Stderr: []byte(result.Stderr), ExitCode: result.ExitCode,
	}, nil
}

// rootActionFunc 在客户端可用时返回方法面的调用面；nil 表示内核未注入通道。
func rootActionFunc() wafop.RootActionFunc {
	client := newRootActionClient()
	if client == nil {
		return nil
	}
	return client.Call
}
