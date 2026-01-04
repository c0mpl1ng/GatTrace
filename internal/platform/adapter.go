package platform

import (
	"fmt"
	"runtime"

	"GatTrace/internal/core"
)

// NewPlatformAdapter 创建平台特定的适配器
func NewPlatformAdapter() (core.PlatformAdapter, error) {
	switch runtime.GOOS {
	case "windows":
		return NewWindowsAdapter(), nil
	case "linux":
		return NewLinuxAdapter(), nil
	case "darwin":
		return NewDarwinAdapter(), nil
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// 为了编译通过，创建占位符适配器
type PlaceholderAdapter struct {
	*core.BasePlatformAdapter
}

func NewPlaceholderAdapter() *PlaceholderAdapter {
	return &PlaceholderAdapter{
		BasePlatformAdapter: core.NewBasePlatformAdapter(),
	}
}

func (p *PlaceholderAdapter) GetNetworkInfo() (*core.NetworkInfo, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetProcessInfo() (*core.ProcessInfo, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetUserInfo() (*core.UserInfo, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetPersistenceInfo() (*core.PersistenceInfo, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetFileSystemInfo() (*core.FileSystemInfo, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetSecurityLogs() (*core.SecurityLogs, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetSystemInfo() (*core.SystemInfo, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}

func (p *PlaceholderAdapter) GetSystemStatus() (*core.SystemStatus, error) {
	return nil, fmt.Errorf("not implemented for this platform")
}