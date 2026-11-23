package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
)

// TestKillFault 注入 kill -9（进程被信号终止），期望四方法返回 E_UPSTREAM。
func TestKillFault(t *testing.T) {
	assertFault(t, wafop.FaultKill, "E_UPSTREAM", "信号 9")
}

// TestKillFaultContract 单独验证 kill 故障的错误体结构完整（真实调用，非空壳）。
func TestKillFaultContract(t *testing.T) {
	_, perr := runtimeFor("status", wafop.FaultKill).Call("waf.status", []byte(`{}`))
	verifyErrorContract(t, perr)
}

// TestSanityNoFault 反证：无故障时方法正常返回，避免"永远失败"的假通过。
func TestSanityNoFault(t *testing.T) {
	sanityNoFault(t)
}
