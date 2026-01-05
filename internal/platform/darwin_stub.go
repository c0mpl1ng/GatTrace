//go:build !darwin

package platform

import "GatTrace/internal/core"

// DarwinAdapter macOS 平台适配器存根
type DarwinAdapter struct {
	*core.BasePlatformAdapter
}

// NewDarwinAdapter 创建 macOS 平台适配器存根
func NewDarwinAdapter() *DarwinAdapter {
	return &DarwinAdapter{
		BasePlatformAdapter: core.NewBasePlatformAdapter(),
	}
}

// GetNetworkInfo 获取网络信息（存根）
func (d *DarwinAdapter) GetNetworkInfo() (*core.NetworkInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetNetworkInfo")
}

// GetProcessInfo 获取进程信息（存根）
func (d *DarwinAdapter) GetProcessInfo() (*core.ProcessInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetProcessInfo")
}

// GetUserInfo 获取用户信息（存根）
func (d *DarwinAdapter) GetUserInfo() (*core.UserInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetUserInfo")
}

// GetPersistenceInfo 获取持久化信息（存根）
func (d *DarwinAdapter) GetPersistenceInfo() (*core.PersistenceInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetPersistenceInfo")
}

// GetFileSystemInfo 获取文件系统信息（存根）
func (d *DarwinAdapter) GetFileSystemInfo() (*core.FileSystemInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetFileSystemInfo")
}

// GetSecurityLogs 获取安全日志（存根）
func (d *DarwinAdapter) GetSecurityLogs() (*core.SecurityLogs, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetSecurityLogs")
}

// GetSystemInfo 获取系统信息（存根）
func (d *DarwinAdapter) GetSystemInfo() (*core.SystemInfo, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetSystemInfo")
}

// GetSystemStatus 获取系统状态（存根）
func (d *DarwinAdapter) GetSystemStatus() (*core.SystemStatus, error) {
	return nil, core.NewUnsupportedPlatformError("Darwin adapter", "GetSystemStatus")
}

// 存根方法
func (d *DarwinAdapter) checkSudoAccess() bool {
	return false
}

func (d *DarwinAdapter) isCurrentUserAdmin() bool {
	return false
}

func (d *DarwinAdapter) getUserGroups(username string) ([]string, error) {
	return []string{}, nil
}

func (d *DarwinAdapter) getUserUID(username string) string {
	return "0"
}

func (d *DarwinAdapter) getUserGID(username string) string {
	return "0"
}

func (d *DarwinAdapter) getUserHomeDir(username string) string {
	return "/Users/" + username
}

func (d *DarwinAdapter) getUserShell(username string) string {
	return "/bin/bash"
}

func (d *DarwinAdapter) calculateStringHash(data string) string {
	return ""
}
