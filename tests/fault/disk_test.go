package fault

import (
	"testing"

	"github.com/pengtang1024/kore-plugin-waf/internal/wafop"
)

// TestDiskFullFault 注入磁盘满，期望四方法返回 E_INTERNAL。
func TestDiskFullFault(t *testing.T) {
	assertFault(t, wafop.FaultDisk, "E_INTERNAL", "磁盘满")
}
