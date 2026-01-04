package core

import (
	"fmt"
	"os"
	"runtime"
)

// Platform 平台类型枚举
type Platform int

const (
	PlatformUnknown Platform = iota
	PlatformWindows
	PlatformLinux
	PlatformDarwin
)

// String 返回平台名称
func (p Platform) String() string {
	switch p {
	case PlatformWindows:
		return "windows"
	case PlatformLinux:
		return "linux"
	case PlatformDarwin:
		return "darwin"
	default:
		return "unknown"
	}
}

// PlatformCapability 平台功能枚举
type PlatformCapability int

const (
	CapabilityEventLogs PlatformCapability = iota
	CapabilityRegistry
	CapabilityServices
	CapabilityDigitalSignatures
	CapabilitySystemdLogs
	CapabilityCrontab
	CapabilityAuditLogs
	CapabilityUnifiedLogs
	CapabilityLaunchAgents
	CapabilityPrivilegeEscalation
)

// PlatformInfo 平台信息结构
type PlatformInfo struct {
	Platform     Platform
	Architecture string
	Version      string
	Capabilities map[PlatformCapability]bool
}

// PlatformDetector 平台检测器接口
type PlatformDetector interface {
	DetectPlatform() Platform
	GetPlatformInfo() (*PlatformInfo, error)
	HasCapability(cap PlatformCapability) bool
	CheckPrivileges() (bool, error)
}

// RuntimePlatformDetector 运行时平台检测器
type RuntimePlatformDetector struct {
	info *PlatformInfo
}

// NewPlatformDetector 创建新的平台检测器
func NewPlatformDetector() PlatformDetector {
	detector := &RuntimePlatformDetector{}
	detector.initialize()
	return detector
}

// initialize 初始化平台检测器
func (d *RuntimePlatformDetector) initialize() {
	platform := d.DetectPlatform()
	d.info = &PlatformInfo{
		Platform:     platform,
		Architecture: runtime.GOARCH,
		Version:      runtime.Version(),
		Capabilities: d.detectCapabilities(platform),
	}
}

// DetectPlatform 检测当前平台
func (d *RuntimePlatformDetector) DetectPlatform() Platform {
	switch runtime.GOOS {
	case "windows":
		return PlatformWindows
	case "linux":
		return PlatformLinux
	case "darwin":
		return PlatformDarwin
	default:
		return PlatformUnknown
	}
}

// GetPlatformInfo 获取平台信息
func (d *RuntimePlatformDetector) GetPlatformInfo() (*PlatformInfo, error) {
	if d.info == nil {
		return nil, fmt.Errorf("platform detector not initialized")
	}
	return d.info, nil
}

// HasCapability 检查是否具有特定功能
func (d *RuntimePlatformDetector) HasCapability(cap PlatformCapability) bool {
	if d.info == nil {
		return false
	}
	return d.info.Capabilities[cap]
}

// CheckPrivileges 检查当前权限级别
func (d *RuntimePlatformDetector) CheckPrivileges() (bool, error) {
	switch d.info.Platform {
	case PlatformWindows:
		return d.checkWindowsPrivileges()
	case PlatformLinux, PlatformDarwin:
		return d.checkUnixPrivileges()
	default:
		return false, fmt.Errorf("unsupported platform: %s", d.info.Platform)
	}
}

// detectCapabilities 检测平台功能
func (d *RuntimePlatformDetector) detectCapabilities(platform Platform) map[PlatformCapability]bool {
	capabilities := make(map[PlatformCapability]bool)
	
	switch platform {
	case PlatformWindows:
		capabilities[CapabilityEventLogs] = true
		capabilities[CapabilityRegistry] = true
		capabilities[CapabilityServices] = true
		capabilities[CapabilityDigitalSignatures] = true
		capabilities[CapabilityPrivilegeEscalation] = true
	case PlatformLinux:
		capabilities[CapabilitySystemdLogs] = d.checkSystemdAvailability()
		capabilities[CapabilityCrontab] = true
		capabilities[CapabilityAuditLogs] = d.checkAuditdAvailability()
		capabilities[CapabilityPrivilegeEscalation] = true
	case PlatformDarwin:
		capabilities[CapabilityUnifiedLogs] = true
		capabilities[CapabilityLaunchAgents] = true
		capabilities[CapabilityPrivilegeEscalation] = true
	}
	
	return capabilities
}

// checkWindowsPrivileges 检查 Windows 权限
func (d *RuntimePlatformDetector) checkWindowsPrivileges() (bool, error) {
	// 简化实现：检查是否能访问系统目录
	_, err := os.Stat("C:\\Windows\\System32\\config")
	return err == nil, nil
}

// checkUnixPrivileges 检查 Unix 权限
func (d *RuntimePlatformDetector) checkUnixPrivileges() (bool, error) {
	return os.Geteuid() == 0, nil
}

// checkSystemdAvailability 检查 systemd 可用性
func (d *RuntimePlatformDetector) checkSystemdAvailability() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// checkAuditdAvailability 检查 auditd 可用性
func (d *RuntimePlatformDetector) checkAuditdAvailability() bool {
	_, err := os.Stat("/var/log/audit")
	return err == nil
}

// Legacy functions for backward compatibility
// isWindows 检查是否为 Windows 平台
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// isLinux 检查是否为 Linux 平台
func isLinux() bool {
	return runtime.GOOS == "linux"
}

// isDarwin 检查是否为 macOS 平台
func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

// getPlatform 获取当前平台字符串
func getPlatform() string {
	detector := NewPlatformDetector()
	return detector.DetectPlatform().String()
}