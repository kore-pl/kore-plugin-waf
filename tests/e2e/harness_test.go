//go:build linux

// Package e2e 是 waf 插件的端到端验证：真实二进制 + 真实协议帧 + 真实 nftables。
//
// 与 internal/wafop 的单测区别：这里不构造 Runtime、不 mock 通道。
//   - 插件按发布形态编译成二进制，用 KORE_PLUGIN_SOCK 连「假内核」，
//     走完整的 kore.hello 握手 + 会话帧循环（serve.go 的真实路径）；
//   - root-action 通道用 KORE_KERNEL_SOCK 上的 HTTP 服务替代（ADR-0018 契约不变：
//     POST /api/v1/plugins/<id>/root-action + Bearer），服务端按 info.json 的
//     root_actions 声明执行真实 nft 命令——只把 systemd-run 换成直接 exec，
//     因为 nft 与插件在同一个私有 netns 里已是 uid 0。
//   - 数据面断言不看插件自己的回读，另起 `nft -j list` 独立核对，
//     避免「插件回读自证」的循环论证。
//
// 权限来源（本机实测）：普通用户无 cap_net_admin、polkit 拒绝 systemd-run --uid=0。
// 因此用 `unshare -rn` 进入「私有 user+net namespace」拿 uid 0 与独立 nftables：
// 不写宿主 netns、不需要 root、不改任何宿主配置。TestMain 会自动探测并 re-exec。
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

const (
	// envInNetNS 标记「当前进程已在私有 netns 内」，由 TestMain 的 re-exec 注入。
	envInNetNS = "WAF_E2E_PRIVATE_NETNS"
	// envPluginBin 把父进程构建好的插件二进制路径传给 netns 内的子进程。
	envPluginBin = "WAF_E2E_PLUGIN_BIN"
	// pluginID 与被测插件 id 一致。
	pluginID = "waf"
	// ruleCommentPrefix 与 internal/wafop/ruleadmin.go 的常量一致（独立断言用，故意不引用内部包）。
	ruleCommentPrefix = "kore-rule-"
	// maxAddRuleArgs 与 info.json 中 nft-add-rule 的声明一致：受控 token 最多 28 个。
	maxAddRuleArgs = 28
)

// repoRoot 返回插件仓根目录（本测试位于 tests/e2e/）。
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("解析仓库根目录: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "info.json")); err != nil {
		t.Fatalf("仓库根目录 %s 下没有 info.json: %v", root, err)
	}
	return root
}

// rootAction 是 info.json 里声明的提权动作。
type rootAction struct {
	ID   string   `json:"id"`
	Argv []string `json:"argv"`
}

// loadRootActions 从 info.json 读声明，作为假内核的允许清单（与内核同一份声明来源）。
func loadRootActions(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "info.json"))
	if err != nil {
		t.Fatalf("读 info.json: %v", err)
	}
	var manifest struct {
		RootActions []rootAction `json:"root_actions"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	if len(manifest.RootActions) == 0 {
		t.Fatal("info.json 未声明 root_actions，无法构造 root 通道")
	}
	actions := make(map[string][]string, len(manifest.RootActions))
	for _, action := range manifest.RootActions {
		actions[action.ID] = action.Argv
	}
	return actions
}

// nftUsable 探测当前进程能否真正操作用 nft（决定是否要进私有 netns）。
func nftUsable() bool {
	cmd := exec.Command("nft", "list", "tables")
	cmd.Stdout, cmd.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	return cmd.Run() == nil
}

// TestMain 负责「让测试跑在有 nft 权限的环境里」。
//
// 顺序：已在 netns 内 → 直接跑；宿主已能 nft（root）→ 直接跑；
// 否则 unshare -rn 进私有 netns 重跑自己；两者都不行 → 交给测试自己 skip 并说明原因。
func TestMain(m *testing.M) {
	if os.Getenv(envInNetNS) == "1" {
		os.Exit(m.Run())
	}

	buildDir, err := os.MkdirTemp("", "waf-e2e-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[e2e] 创建构建目录失败: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(buildDir)

	binary, err := buildPluginBinary(buildDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[e2e] 构建插件二进制失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv(envPluginBin, binary); err != nil {
		fmt.Fprintf(os.Stderr, "[e2e] 设置 %s 失败: %v\n", envPluginBin, err)
		os.Exit(1)
	}

	if nftUsable() {
		os.Exit(m.Run())
	}

	unshare, err := exec.LookPath("unshare")
	if err != nil {
		// 没有 unshare：让测试跑起来并自行 skip，报出「环境缺失」而不是静默通过。
		os.Exit(m.Run())
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[e2e] 定位测试二进制失败: %v\n", err)
		os.Exit(1)
	}
	cmd := exec.Command(unshare, append([]string{"-rn", self}, os.Args[1:]...)...)
	cmd.Env = append(os.Environ(), envInNetNS+"=1", envPluginBin+"="+binary)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[e2e] unshare -rn 重跑失败: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// buildPluginBinary 按发布基线编译插件（CGO_ENABLED=0 + trimpath）。
func buildPluginBinary(dir string) (string, error) {
	binary := filepath.Join(dir, "waf")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, ".")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, output.String())
	}
	return binary, nil
}

// harness 是「假内核 + 真插件进程」的组合。
type harness struct {
	t          *testing.T
	binary     string
	pluginSock string
	kernelSock string
	token      string
	stateDir   string
	actions    map[string][]string

	pluginCmd *exec.Cmd
	conn      net.Conn

	// connMu 串行化协议帧读写；callsMu 只保护 calls，两者分开。
	// 不能合并：插件在响应当前请求期间会回打 root-action 通道，
	// 若 Call 全程持锁、handler 又要锁，就会自锁。
	connMu  sync.Mutex
	callsMu sync.Mutex
	calls   []rootActionCall
	server  *http.Server
}

// rootActionCall 记录一次经通道执行的动作，供断言「确实走了 nft」。
type rootActionCall struct {
	ActionID string
	Args     []string
	ExitCode int
}

// newHarness 启动假内核并拉起真实插件二进制。
func newHarness(t *testing.T) *harness {
	t.Helper()

	binary := os.Getenv(envPluginBin)
	if binary == "" {
		t.Fatalf("%s 为空：TestMain 未构建插件二进制", envPluginBin)
	}

	dir := t.TempDir()
	// UDS 路径长度上限 108 字节，用短目录。
	sockDir, err := os.MkdirTemp("", "waf-e2e-")
	if err != nil {
		t.Fatalf("创建 socket 目录: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	h := &harness{
		t:          t,
		binary:     binary,
		pluginSock: filepath.Join(sockDir, "p.sock"),
		kernelSock: filepath.Join(sockDir, "k.sock"),
		token:      "e2e-token-" + strings.ReplaceAll(dir, "/", "_"),
		stateDir:   filepath.Join(dir, "state"),
		actions:    loadRootActions(t),
	}
	if err := os.MkdirAll(h.stateDir, 0o755); err != nil {
		t.Fatalf("创建 state 目录: %v", err)
	}

	// 1) 插件要连的会话 socket（插件是 dial 方）。
	listener, err := net.Listen("unix", h.pluginSock)
	if err != nil {
		t.Fatalf("监听插件 socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// 2) root-action 通道（HTTP over UDS，契约同 ADR-0018）。
	kernelListener, err := net.Listen("unix", h.kernelSock)
	if err != nil {
		t.Fatalf("监听内核 socket: %v", err)
	}
	h.server = &http.Server{Handler: h.rootActionHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = h.server.Serve(kernelListener) }()
	t.Cleanup(func() { _ = h.server.Close() })

	// 3) 拉起插件进程（真实发布形态）。
	cmd := exec.Command(h.binary)
	cmd.Env = append(os.Environ(),
		"KORE_PLUGIN_SOCK="+h.pluginSock,
		"KORE_PLUGIN_ID="+pluginID,
		"KORE_PLUGIN_TOKEN="+h.token,
		"KORE_STATE_DIR="+h.stateDir,
		"KORE_KERNEL_SOCK="+h.kernelSock,
		"KORE_LOG_LEVEL=error",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动插件进程: %v", err)
	}
	h.pluginCmd = cmd
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// 4) 接受连接并完成 hello 握手。
	if unixListener, ok := listener.(*net.UnixListener); ok {
		_ = unixListener.SetDeadline(time.Now().Add(20 * time.Second))
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("接受插件连接（stderr: %s）: %v", stderr.String(), err)
	}
	h.conn = conn
	t.Cleanup(func() { _ = conn.Close() })

	if err := h.completeHello(); err != nil {
		t.Fatalf("kore.hello 握手失败（stderr: %s）: %v", stderr.String(), err)
	}
	return h
}

// completeHello 读插件的 hello 帧、校验声明并回 ok。
func (h *harness) completeHello() error {
	h.t.Helper()
	payload, err := pluginapi.ReadFrame(h.conn, 0)
	if err != nil {
		return fmt.Errorf("读 hello 帧: %w", err)
	}
	envelope, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		return fmt.Errorf("解码 hello 帧: %w", err)
	}
	request, ok := envelope.(*pluginapi.Request)
	if !ok {
		return fmt.Errorf("首帧不是 request: %T", envelope)
	}
	if request.Method != "kore.hello" {
		return fmt.Errorf("首帧方法 %q，期望 kore.hello", request.Method)
	}

	var hello struct {
		PluginID     string   `json:"plugin_id"`
		Version      string   `json:"version"`
		Protocol     string   `json:"protocol"`
		RequiresKore string   `json:"requires_kore"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(request.Params, &hello); err != nil {
		return fmt.Errorf("解析 hello 参数: %w", err)
	}
	if hello.PluginID != pluginID {
		return fmt.Errorf("hello.plugin_id=%q，期望 %q", hello.PluginID, pluginID)
	}
	if hello.Protocol != pluginapi.Protocol {
		return fmt.Errorf("hello.protocol=%q，期望 %q", hello.Protocol, pluginapi.Protocol)
	}
	// 版本必须与 info.json 一致：0.4.5 是纯元数据变更，若二进制内嵌 manifest 漂移这里就会红。
	if want := manifestVersion(h.t); hello.Version != want {
		return fmt.Errorf("hello.version=%q，info.json=%q", hello.Version, want)
	}

	result, err := json.Marshal(map[string]any{"ok": true, "protocol": pluginapi.Protocol})
	if err != nil {
		return err
	}
	return pluginapi.WriteJSON(h.conn, &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID, Result: result,
	})
}

// manifestVersion 读 info.json 的 version（作为唯一真源）。
func manifestVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "info.json"))
	if err != nil {
		t.Fatalf("读 info.json: %v", err)
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	return manifest.Version
}

// Call 通过真实协议帧调用一个方法。
func (h *harness) Call(method string, params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	h.t.Helper()
	if params == nil {
		params = json.RawMessage(`{}`)
	}
	h.connMu.Lock()
	defer h.connMu.Unlock()

	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: randomHex(h.t), ReqID: "r-e2e",
		Method: method, Params: params, TimeoutMS: 15000,
	}
	if err := pluginapi.WriteJSON(h.conn, request); err != nil {
		h.t.Fatalf("写请求帧 %s: %v", method, err)
	}
	payload, err := pluginapi.ReadFrame(h.conn, 0)
	if err != nil {
		h.t.Fatalf("读响应帧 %s: %v", method, err)
	}
	envelope, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		h.t.Fatalf("解码响应帧 %s: %v", method, err)
	}
	response, ok := envelope.(*pluginapi.Response)
	if !ok {
		h.t.Fatalf("响应不是 response 帧: %T", envelope)
	}
	if response.ID != request.ID {
		h.t.Fatalf("响应 id=%q 未回显请求 id=%q", response.ID, request.ID)
	}
	return response.Result, response.Error
}

// randomHex 生成 32 位小写 hex（协议要求）。
func randomHex(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	for index := range raw {
		raw[index] = byte(time.Now().UnixNano() >> (index % 8))
	}
	return fmt.Sprintf("%032x", raw)
}

// rootActionHandler 实现内核侧契约：鉴权 → 查声明 → 形状复核 → 执行真实 nft。
func (h *harness) rootActionHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins/"+pluginID+"/root-action", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"code":"E_INVALID","message":"只接受 POST"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+h.token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"E_BAD_TOKEN","message":"token 不匹配"}`))
			return
		}
		var request struct {
			ActionID string   `json:"action_id"`
			Args     []string `json:"args"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"E_INVALID","message":"请求体不是合法 JSON"}`))
			return
		}
		argv, declared := h.actions[request.ActionID]
		if !declared {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"E_DENIED","message":"未声明的动作"}`))
			return
		}
		if perr := checkArgShape(request.ActionID, request.Args); perr != "" {
			w.WriteHeader(http.StatusForbidden)
			body, _ := json.Marshal(map[string]string{"code": "E_DENIED", "message": perr})
			_, _ = w.Write(body)
			return
		}

		full := append(append([]string{}, argv...), request.Args...)
		cmd := exec.Command(full[0], full[1:]...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()

		exitCode := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				body, _ := json.Marshal(map[string]string{"code": "E_EXEC", "message": runErr.Error()})
				_, _ = w.Write(body)
				return
			}
		}

		h.callsMu.Lock()
		h.calls = append(h.calls, rootActionCall{ActionID: request.ActionID, Args: request.Args, ExitCode: exitCode})
		h.callsMu.Unlock()

		body, _ := json.Marshal(map[string]any{
			"executed": true, "exit_code": exitCode,
			"stdout": stdout.String(), "stderr": stderr.String(),
			"dur_ms": 0, "unit": "e2e-test",
		})
		_, _ = w.Write(body)
	})
	return mux
}

// checkArgShape 复核追加参数：只有可追加动作能带参，且不得含 shell/nft 语句分隔符。
// 这是内核侧策略的最小投影——假内核故意不比真内核更宽松。
func checkArgShape(actionID string, args []string) string {
	allowed := map[string]bool{"nft-ban4": true, "nft-ban6": true, "nft-unban4": true, "nft-unban6": true,
		"nft-add-rule": true, "nft-delete-rule": true}
	if len(args) == 0 {
		return ""
	}
	if !allowed[actionID] {
		return "动作 " + actionID + " 不接受追加参数"
	}
	if actionID == "nft-add-rule" && len(args) > maxAddRuleArgs {
		return fmt.Sprintf("nft-add-rule 追加参数 %d 个，超过声明上限 %d", len(args), maxAddRuleArgs)
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, ";\n\r|&`$<>") {
			return "追加参数含非法字符: " + arg
		}
	}
	return ""
}

// nftRuleHandles 用独立进程读 nft 真实状态，返回指定规则名的 handle 列表。
// 故意不经插件、不经 internal 包：数据面断言不能由被测代码自证。
func nftRuleHandles(t *testing.T, name string) []int {
	t.Helper()
	output, err := exec.Command("nft", "-j", "list", "table", "inet", "kore_waf").Output()
	if err != nil {
		return nil // 表不存在视为空
	}
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("解析 nft -j 输出: %v（原文 %s）", err, output)
	}
	want := ruleCommentPrefix + name
	var handles []int
	for _, entry := range document.Nftables {
		rawRule, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Handle  int                          `json:"handle"`
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(rawRule, &rule); err != nil {
			continue
		}
		comment := rule.Comment
		if comment == "" {
			for _, item := range rule.Expr {
				var value string
				if raw, ok := item["comment"]; ok && json.Unmarshal(raw, &value) == nil {
					comment = value
					break
				}
			}
		}
		if comment == want {
			handles = append(handles, rule.Handle)
		}
	}
	return handles
}

// nftTableExists 判断 kore_waf 表是否真实存在。
func nftTableExists(t *testing.T) bool {
	t.Helper()
	return exec.Command("nft", "list", "table", "inet", "kore_waf").Run() == nil
}

// requireNft 在环境确实缺能力时 skip，并写明替代验证手段。
func requireNft(t *testing.T) {
	t.Helper()
	if !nftUsable() {
		t.Skip("环境缺失：当前进程无 nft 权限且 unshare -rn 不可用（无 cap_net_admin / 无 userns）。" +
			"已尝试的替代路径：unshare -rn 私有 netns（uid 0 + 独立 nftables）。" +
			"本用例不做假数据顶替；请在有 root 或 userns 的宿主上重跑。")
	}
}
