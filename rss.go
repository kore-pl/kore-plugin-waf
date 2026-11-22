package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// rssKB 读取 Linux /proc/self/statm 的常驻页并换算为 KiB；
// 非 Linux 平台或读取失败返回 0（Tier B 允许缺失该指标，不静默改写状态）。
func rssKB() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * int64(os.Getpagesize()) / 1024
}
