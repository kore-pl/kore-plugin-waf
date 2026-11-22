package wafop

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// Call 执行一个 waf 方法：先校验方法名，再校验参数，最后调用执行面并结构化结果。
// exec 为 nil 时使用 noopExecutor（骨架口径，不接真实 WAF 引擎）。
func Call(method string, params json.RawMessage, root string, exec Executor) (json.RawMessage, *pluginapi.Error) {
	verb, ok := businessVerb(method)
	if !ok {
		return nil, errNotFound(method)
	}
	if exec == nil {
		exec = noopExecutor{}
	}
	switch verb {
	case "rules":
		return callRules(params, root, exec)
	case "blockLog":
		return callBlockLog(params, root, exec)
	}
	return nil, errNotFound(method)
}

// businessVerb 把 waf.<verb> 或裸 <verb> 归一为动词名。
func businessVerb(method string) (string, bool) {
	verb := method
	if strings.HasPrefix(method, "waf.") {
		verb = strings.TrimPrefix(method, "waf.")
	}
	switch verb {
	case "rules", "blockLog":
		return verb, true
	}
	return "", false
}

// classify 把执行面错误映射为协议错误码：基础级两类故障各有对应，其余归 E_INTERNAL。
func classify(err error) *pluginapi.Error {
	var fe *FaultError
	if errors.As(err, &fe) {
		switch fe.Kind {
		case FaultKill:
			return upstream("进程被信号 9 终止: " + fe.Message)
		case FaultTimeout:
			return upstream("调用超时: " + fe.Message)
		}
	}
	return internalErr("执行面失败: " + err.Error())
}
