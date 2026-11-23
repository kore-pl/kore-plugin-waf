package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
)

// TestCgroupLimitFault 注入 cgroup 超限，期望四方法返回 E_UNSUPPORTED。
func TestCgroupLimitFault(t *testing.T) {
	assertFault(t, wafop.FaultCgroup, "E_UNSUPPORTED", "cgroup")
}
