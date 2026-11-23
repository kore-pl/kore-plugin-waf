package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// serve 执行会话循环：读帧 → 分发 → 写 response；收到 kore.shutdown 后返回 nil。
func serve(conn net.Conn, cfg *config, logger *slog.Logger) error {
	for {
		payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // 帧边界上的干净关闭
			}
			return fmt.Errorf("读帧失败: %w", err)
		}
		request, err := decodeRequest(payload)
		if err != nil {
			return err
		}
		if request == nil {
			logger.Debug("忽略非 request 帧")
			continue
		}
		response, shutdown := dispatch(request, cfg, logger)
		if err := pluginapi.WriteJSON(conn, response); err != nil {
			if shutdown {
				return nil // 内核已关闭连接，退出码仍按优雅退出
			}
			return fmt.Errorf("写响应失败: %w", err)
		}
		if shutdown {
			return nil
		}
	}
}

// decodeRequest 解码一帧并返回 request；非 request 帧返回 (nil, nil) 继续循环。
func decodeRequest(payload []byte) (*pluginapi.Request, error) {
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		return nil, fmt.Errorf("解码帧失败: %w", err)
	}
	request, ok := env.(*pluginapi.Request)
	if !ok {
		return nil, nil
	}
	return request, nil
}
