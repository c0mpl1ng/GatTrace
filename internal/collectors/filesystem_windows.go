//go:build windows

package collectors

import (
	"os"
	"syscall"
	"time"
)

// getFileAccessTime 获取文件访问时间 (Windows)
func getFileAccessTime(info os.FileInfo) time.Time {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return time.Unix(0, data.LastAccessTime.Nanoseconds())
	}
	return info.ModTime()
}

// getFileOwnership 获取文件所有者和组 (Windows)
// Windows 使用不同的权限模型，这里返回默认值
// 实际的所有者信息会在 getWindowsFileSystemStat 中通过 PowerShell 获取
func getFileOwnership(info os.FileInfo) (owner, group string) {
	return "unknown", "unknown"
}
