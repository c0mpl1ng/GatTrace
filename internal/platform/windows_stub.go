//go:build !windows

package platform

import "GatTrace/internal/core"

// WindowsAdapter Windows 平台适配器存根
type WindowsAdapter struct {
	*core.BasePlatformAdapter
}

// NewWindowsAdapter 创建 Windows 平台适配器存根
func NewWindowsAdapter() *WindowsAdapter {
	return &WindowsAdapter{
		BasePlatformAdapter: core.NewBasePlatformAdapter(),
	}
}

// GetNetworkInfo 获取网络信息（存根）
func (w *WindowsAdapter) GetNetworkInfo() (*core.NetworkInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetNetworkInfo")
}

// GetProcessInfo 获取进程信息（存根）
func (w *WindowsAdapter) GetProcessInfo() (*core.ProcessInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetProcessInfo")
}

// GetUserInfo 获取用户信息（存根）
func (w *WindowsAdapter) GetUserInfo() (*core.UserInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetUserInfo")
}

// GetPersistenceInfo 获取持久化信息（存根）
func (w *WindowsAdapter) GetPersistenceInfo() (*core.PersistenceInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetPersistenceInfo")
}

// GetFileSystemInfo 获取文件系统信息（存根）
func (w *WindowsAdapter) GetFileSystemInfo() (*core.FileSystemInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetFileSystemInfo")
}

// GetSecurityLogs 获取安全日志（存根）
func (w *WindowsAdapter) GetSecurityLogs() (*core.SecurityLogs, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetSecurityLogs")
}

// GetSystemInfo 获取系统信息（存根）
func (w *WindowsAdapter) GetSystemInfo() (*core.SystemInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetSystemInfo")
}

// GetSystemStatus 获取系统状态（存根）
func (w *WindowsAdapter) GetSystemStatus() (*core.SystemStatus, error) {
	return nil, core.NewUnsupportedPlatformError("Windows adapter", "GetSystemStatus")
}

// 存根方法
func (w *WindowsAdapter) isCurrentUserAdmin() bool {
	return false
}

func (w *WindowsAdapter) checkDigitalSignature(filePath string) (string, error) {
	return "", nil
}

func (w *WindowsAdapter) getRegistryStartupItems() ([]core.PersistenceItem, error) {
	return []core.PersistenceItem{}, nil
}