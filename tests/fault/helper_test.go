// Package fault 对 waf 插件做四类故障注入（kill / timeout / disk / cgroup），
// 验证方法级错误码映射。故障环境是内存文件系统 + 注入故障的宿主操作，
// 不依赖本机是否装了 WAF 引擎。
package fault

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 内存布局：一个可被识别的 ModSecurity 安装 + 一个日志文件。
const (
	confPath = "/etc/modsecurity/modsecurity.conf"
	modePath = "/etc/modsecurity/kore-mode.conf"
	rulesDir = "/usr/share/modsecurity-crs/rules"
	rulePath = rulesDir + "/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
	logPath  = "/var/log/modsec_audit.log"
)

// modsecLogLine 是一条可解析的 ModSecurity 日志行（用于确认故障不是"永远失败"）。
const modsecLogLine = `[Wed Oct 11 14:32:00 2023] [error] [client 203.0.113.7] ModSecurity: Access denied with code 403 [id "942100"] [uri "/login"]` + "\n"

// faultEnv 按方法注入不同故障：status 注入命令故障、rules 注入读文件故障、
// logs 注入读日志故障；toggle 的故障在 root-action 上注入。
type faultEnv struct {
	kind      wafop.FaultKind
	faultRun  bool
	faultRead bool
	faultTail bool
}

// environment 返回接入类型环境的视图。
func (f faultEnv) environment() wafop.Environment {
	fault := func() error { return wafop.NewFaultError(f.kind, "执行面故障") }
	isDir := func(path string) bool { return path == "/etc/modsecurity" || path == rulesDir }
	sizes := map[string]int64{confPath: 32, modePath: 32, rulePath: 64, logPath: int64(len(modsecLogLine))}
	return wafop.Environment{
		Stat: func(path string) (wafop.FileMeta, error) {
			if isDir(path) {
				return wafop.FileMeta{Path: path, IsDir: true}, nil
			}
			if size, ok := sizes[path]; ok {
				return wafop.FileMeta{Path: path, Size: size}, nil
			}
			return wafop.FileMeta{}, fs.ErrNotExist
		},
		ReadDir: func(dir string) ([]wafop.DirEntry, error) {
			switch dir {
			case "/etc/modsecurity":
				return []wafop.DirEntry{{Name: "modsecurity.conf"}, {Name: "kore-mode.conf"}}, nil
			case rulesDir:
				return []wafop.DirEntry{{Name: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"}}, nil
			}
			return nil, fs.ErrNotExist
		},
		ReadFile: func(path string) ([]byte, error) {
			if f.faultRead && strings.HasPrefix(path, rulesDir) {
				return nil, fault()
			}
			switch path {
			case confPath, modePath:
				return []byte("SecRuleEngine On\n"), nil
			case rulePath:
				return []byte(`SecRule ARGS "@rx union" "id:942100,phase:2,deny"` + "\n"), nil
			case logPath:
				return []byte(modsecLogLine), nil
			}
			return nil, fs.ErrNotExist
		},
		Tail: func(path string, maxBytes int64) ([]byte, bool, error) {
			if f.faultTail {
				return nil, false, fault()
			}
			return []byte(modsecLogLine), false, nil
		},
		LookPath: func(name string) (string, bool) {
			switch name {
			case "dpkg-query":
				return "/usr/bin/dpkg-query", true
			case "nginx":
				return "/usr/sbin/nginx", true
			}
			return "", false
		},
		Run: func(name string, args ...string) (wafop.CommandResult, error) {
			if f.faultRun && name == "dpkg-query" {
				return wafop.CommandResult{}, fault()
			}
			if name == "dpkg-query" {
				return wafop.CommandResult{Stdout: []byte("3.0.12")}, nil
			}
			return wafop.CommandResult{}, nil
		},
		Euid: func() int { return 1000 },
		Now:  func() time.Time { return time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC) },
	}
}

// methods 是故障注入覆盖的方法：每个方法对应一种故障注入方式。
var methods = []struct {
	name   string
	method string
	params string
}{
	{"status", "waf.status", `{}`},
	{"rules", "waf.rules", `{}`},
	{"logs", "waf.logs", `{"limit":5}`},
	{"toggle", "waf.toggle", `{"mode":"detection"}`},
}

// runtimeFor 为指定方法构造注入给定故障的执行面。
func runtimeFor(name string, kind wafop.FaultKind) *wafop.Runtime {
	env := faultEnv{kind: kind}
	var root wafop.RootActionFunc
	switch name {
	case "status":
		env.faultRun = true
	case "rules":
		env.faultRead = true
	case "logs":
		env.faultTail = true
	case "toggle":
		root = func(string, []string) ([]byte, int, error) {
			return nil, -1, wafop.NewFaultError(kind, "root-action 执行面故障")
		}
	}
	return wafop.New(wafop.Options{
		Env:        env.environment(),
		Settings:   wafop.Settings{Engine: wafop.EngineModSecurity},
		RootAction: root,
	})
}

// assertFault 对每个方法注入故障，断言返回 nil 结果 + 预期协议错误码与类别关键词。
func assertFault(t *testing.T, kind wafop.FaultKind, wantCode, wantHint string) {
	t.Helper()
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			result, perr := runtimeFor(m.name, kind).Call(m.method, []byte(m.params))
			if perr == nil {
				t.Fatalf("%s 注入 %s 后未返回错误（结果=%s）", m.method, kind, result)
			}
			if result != nil {
				t.Fatalf("%s 出错时不应带结果: %s", m.method, result)
			}
			if perr.Code != wantCode {
				t.Fatalf("%s 错误码=%q，期望 %q（message=%q）", m.method, perr.Code, wantCode, perr.Message)
			}
			if !strings.Contains(perr.Message, wantHint) {
				t.Fatalf("%s 错误信息 %q 未含类别关键词 %q", m.method, perr.Message, wantHint)
			}
		})
	}
}

// sanityNoFault 验证无故障时三个读方法正常返回，证明故障断言不是"永远失败"的假通过。
func sanityNoFault(t *testing.T) {
	t.Helper()
	for _, m := range methods[:3] {
		env := faultEnv{}
		runtime := wafop.New(wafop.Options{
			Env:      env.environment(),
			Settings: wafop.Settings{Engine: wafop.EngineModSecurity},
		})
		result, perr := runtime.Call(m.method, []byte(m.params))
		if perr != nil {
			t.Fatalf("无故障时 %s 意外返回错误: %v", m.method, perr)
		}
		if len(result) == 0 {
			t.Fatalf("无故障时 %s 返回空结果", m.method)
		}
	}
	// toggle 无故障的完整成功路径在 wafop 单测覆盖；这里只反证通道存在时不是必定失败。
	env := faultEnv{}
	runtime := wafop.New(wafop.Options{
		Env:        env.environment(),
		Settings:   wafop.Settings{Engine: wafop.EngineModSecurity},
		RootAction: func(string, []string) ([]byte, int, error) { return nil, 0, nil },
	})
	if _, perr := runtime.Call("waf.toggle", []byte(`{"mode":"detection"}`)); perr != nil {
		t.Fatalf("无故障时 toggle 不应返回协议错误: %v", perr)
	}
}

// verifyErrorContract 断言错误体是标准协议结构（含 code 与 message）。
func verifyErrorContract(t *testing.T, perr *pluginapi.Error) {
	t.Helper()
	if perr == nil {
		t.Fatal("错误体为 nil")
	}
	if perr.Code == "" || perr.Message == "" {
		t.Fatalf("错误体字段不完整: %+v", perr)
	}
}
