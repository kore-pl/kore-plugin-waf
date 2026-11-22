package main

import (
	"log/slog"
	"os"
	"strings"
)

// logLevels 是 KORE_LOG_LEVEL 的合法取值，未设置或非法时取 warn。
var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// newLogger 构造写 stderr 的日志器；stdout 留给协议帧，不得写日志。
func newLogger(raw string) *slog.Logger {
	level := slog.LevelWarn
	if parsed, ok := logLevels[strings.ToLower(strings.TrimSpace(raw))]; ok {
		level = parsed
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
