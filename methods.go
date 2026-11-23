package main

import (
	"encoding/json"
	"log/slog"
	"runtime"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// statusResult 是 kore.ping 的结果（PLUGIN-PROTOCOL §7.1）。
type statusResult struct {
	Status     string `json:"status"`
	UptimeS    int64  `json:"uptime_s"`
	Goroutines int    `json:"goroutines"`
	RSSKB      int64  `json:"rss_kb"`
}

// dispatch 把请求分发为响应帧；第二个返回值表示收到 kore.shutdown。
func dispatch(request *pluginapi.Request, cfg *config, logger *slog.Logger) (*pluginapi.Response, bool) {
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID}
	switch request.Method {
	case "kore.shutdown":
		response.Result = json.RawMessage(`{"ok":true}`)
		logger.Info("收到 kore.shutdown，优雅退出")
		return response, true
	case "kore.ping":
		response.Result = pingResult(cfg)
		return response, false
	case "kore.reload":
		result, perr := reloadConfig(cfg)
		response.Result = result
		response.Error = perr
		return response, false
	case cfg.id + ".config.get", "config.get":
		result, perr := handleConfigGet(cfg)
		response.Result = result
		response.Error = perr
		return response, false
	case cfg.id + ".config.set", "config.set":
		result, perr := handleConfigSet(request.Params, cfg)
		response.Result = result
		response.Error = perr
		return response, false
	}
	result, perr := cfg.runtime.Call(request.Method, request.Params)
	if perr != nil {
		response.Error = perr
		response.Result = nil
		return response, false
	}
	response.Result = result
	return response, false
}

// pingResult 组装 kore.ping 结果。
func pingResult(cfg *config) json.RawMessage {
	data, _ := json.Marshal(statusResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
		RSSKB:      rssKB(),
	})
	return data
}
