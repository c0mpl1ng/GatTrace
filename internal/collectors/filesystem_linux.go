//go:build linux

package collectors

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// getFileAccessTime 获取文件访问时间 (Linux)
func getFileAccessTime(info os.FileInfo) time.Time {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
	}
	return info.ModTime()
}

// getFileOwnership 获取文件所有者和组 (Linux)
func getFileOwnership(info os.FileInfo) (owner, group string) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d", stat.Uid), fmt.Sprintf("%d", stat.Gid)
	}
	return "unknown", "unknown"
}
