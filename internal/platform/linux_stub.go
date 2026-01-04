//go:build !linux

package platform

import "GatTrace/internal/core"

// LinuxAdapter Linux 平台适配器存根
type LinuxAdapter struct {
	*core.BasePlatformAdapter
}

// NewLinuxAdapter 创建 Linux 平台适配器存根
func NewLinuxAdapter() *LinuxAdapter {
	return &LinuxAdapter{
		BasePlatformAdapter: core.NewBasePlatformAdapter(),
	}
}

// GetNetworkInfo 获取网络信息（存根）
func (l *LinuxAdapter) GetNetworkInfo() (*core.NetworkInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetNetworkInfo")
}

// GetProcessInfo 获取进程信息（存根）
func (l *LinuxAdapter) GetProcessInfo() (*core.ProcessInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetProcessInfo")
}

// GetUserInfo 获取用户信息（存根）
func (l *LinuxAdapter) GetUserInfo() (*core.UserInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetUserInfo")
}

// GetPersistenceInfo 获取持久化信息（存根）
func (l *LinuxAdapter) GetPersistenceInfo() (*core.PersistenceInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetPersistenceInfo")
}

// GetFileSystemInfo 获取文件系统信息（存根）
func (l *LinuxAdapter) GetFileSystemInfo() (*core.FileSystemInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetFileSystemInfo")
}

// GetSecurityLogs 获取安全日志（存根）
func (l *LinuxAdapter) GetSecurityLogs() (*core.SecurityLogs, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetSecurityLogs")
}

// GetSystemInfo 获取系统信息（存根）
func (l *LinuxAdapter) GetSystemInfo() (*core.SystemInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetSystemInfo")
}

// GetSystemStatus 获取系统状态（存根）
func (l *LinuxAdapter) GetSystemStatus() (*core.SystemStatus, error) {
	return nil, core.NewUnsupportedPlatformError("Linux adapter", "GetSystemStatus")
}

// 存根方法
func (l *LinuxAdapter) checkSudoAccess() bool {
	return false
}

func (l *LinuxAdapter) getUserGroups(username string) ([]string, error) {
	return []string{}, nil
}

func (l *LinuxAdapter) getDNSConfig() (core.DNSConfig, error) {
	return core.DNSConfig{}, nil
}

func (l *LinuxAdapter) getRoutes() ([]core.Route, error) {
	return []core.Route{}, nil
}

func (l *LinuxAdapter) hexToIP(hexStr string) string {
	return "0.0.0.0"
}

func (l *LinuxAdapter) calculateStringHash(data string) string {
	return ""
}