package fault

import (
	"encoding/json"
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
)

// TestKillFault 注入 kill -9（进程被信号终止），期望两方法返回 E_UPSTREAM。
func TestKillFault(t *testing.T) {
	assertFault(t, wafop.FaultKill, "E_UPSTREAM", "信号 9")
}

// TestKillFaultContract 单独验证 kill 故障的错误体结构完整（真实调用，非空壳）。
func TestKillFaultContract(t *testing.T) {
	_, perr := wafop.Call("waf.rules", json.RawMessage(`{"rule_id":"WAF-0001"}`), testRoot, faultExecutor{kind: wafop.FaultKill})
	verifyErrorContract(t, perr)
}
