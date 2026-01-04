//go:build darwin

package collectors

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// getFileAccessTime 获取文件访问时间 (macOS)
func getFileAccessTime(info os.FileInfo) time.Time {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
	}
	return info.ModTime()
}

// getFileOwnership 获取文件所有者和组 (macOS)
func getFileOwnership(info os.FileInfo) (owner, group string) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d", stat.Uid), fmt.Sprintf("%d", stat.Gid)
	}
	return "unknown", "unknown"
}
