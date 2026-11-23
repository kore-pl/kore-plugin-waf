package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
)

// TestTimeoutFault 注入调用超时，期望四方法返回 E_UPSTREAM。
func TestTimeoutFault(t *testing.T) {
	assertFault(t, wafop.FaultTimeout, "E_UPSTREAM", "超时")
}
