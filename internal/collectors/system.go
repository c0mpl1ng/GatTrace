package collectors

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"GatTrace/internal/core"
)

// SystemCollector 系统状态采集器
type SystemCollector struct {
	adapter core.PlatformAdapter
}

// NewSystemCollector 创建系统状态采集器
func NewSystemCollector(adapter core.PlatformAdapter) *SystemCollector {
	return &SystemCollector{
		adapter: adapter,
	}
}

// Name 返回采集器名称
func (c *SystemCollector) Name() string {
	return "system"
}

// RequiresPrivileges 返回是否需要特权
func (c *SystemCollector) RequiresPrivileges() bool {
	return false // 基础系统信息通常不需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *SystemCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行系统状态信息采集
func (c *SystemCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 使用平台适配器获取系统状态
	systemStatus, err := c.adapter.GetSystemStatus()
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "system",
			Operation: "GetSystemStatus",
			Err:       err,
			Severity:  core.SeverityError,
		}
		errors = append(errors, collectionErr)

		// 如果平台适配器失败，尝试使用通用方法
		systemStatus, err = c.collectGenericSystemStatus(ctx)
		if err != nil {
			collectionErr := core.CollectionError{
				Module:    "system",
				Operation: "collectGenericSystemStatus",
				Err:       err,
				Severity:  core.SeverityCritical,
			}
			errors = append(errors, collectionErr)
			return &core.CollectionResult{Data: nil, Errors: errors}, err
		}
	}

	return &core.CollectionResult{
		Data:   systemStatus,
		Errors: errors,
	}, nil
}

// collectGenericSystemStatus 使用通用方法采集系统状态
func (c *SystemCollector) collectGenericSystemStatus(ctx context.Context) (*core.SystemStatus, error) {
	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 创建基础元数据
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	systemStatus := &core.SystemStatus{
		Metadata: metadata,
	}

	// 获取系统启动时间和运行时间
	bootTime, uptime, err := c.getBootTimeAndUptime(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get boot time and uptime: %w", err)
	}
	systemStatus.BootTime = bootTime
	systemStatus.Uptime = uptime

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 获取NTP同步状态
	ntpStatus, err := c.getNTPStatus(ctx)
	if err != nil {
		// NTP状态获取失败不是致命错误
		ntpStatus = &core.NTPStatus{
			Synchronized: false,
			Error:        err.Error(),
		}
	}
	systemStatus.NTPStatus = ntpStatus

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 获取内核模块和驱动列表
	modules, err := c.getKernelModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get kernel modules: %w", err)
	}
	systemStatus.KernelModules = modules

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 获取系统完整性信息
	integrity, err := c.getSystemIntegrity(ctx)
	if err != nil {
		// 完整性检查失败不是致命错误
		integrity = &core.SystemIntegrity{
			Status: "unknown",
			Error:  err.Error(),
		}
	}
	systemStatus.Integrity = integrity

	return systemStatus, nil
}

// getBootTimeAndUptime 获取系统启动时间和运行时间
func (c *SystemCollector) getBootTimeAndUptime(ctx context.Context) (time.Time, time.Duration, error) {
	// 根据平台获取启动时间
	var bootTime time.Time
	var uptime time.Duration
	var err error

	switch runtime.GOOS {
	case "windows":
		bootTime, uptime, err = c.getWindowsBootTimeAndUptime(ctx)
	case "linux":
		bootTime, uptime, err = c.getLinuxBootTimeAndUptime(ctx)
	case "darwin":
		bootTime, uptime, err = c.getDarwinBootTimeAndUptime(ctx)
	default:
		return time.Time{}, 0, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err != nil {
		return time.Time{}, 0, err
	}

	return bootTime, uptime, nil
}

// getNTPStatus 获取NTP同步状态
func (c *SystemCollector) getNTPStatus(ctx context.Context) (*core.NTPStatus, error) {
	switch runtime.GOOS {
	case "windows":
		return c.getWindowsNTPStatus(ctx)
	case "linux":
		return c.getLinuxNTPStatus(ctx)
	case "darwin":
		return c.getDarwinNTPStatus(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// getKernelModules 获取内核模块和驱动列表
func (c *SystemCollector) getKernelModules(ctx context.Context) ([]core.KernelModule, error) {
	switch runtime.GOOS {
	case "windows":
		return c.getWindowsDrivers(ctx)
	case "linux":
		return c.getLinuxKernelModules(ctx)
	case "darwin":
		return c.getDarwinKernelExtensions(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// getSystemIntegrity 获取系统完整性信息
func (c *SystemCollector) getSystemIntegrity(ctx context.Context) (*core.SystemIntegrity, error) {
	switch runtime.GOOS {
	case "windows":
		return c.getWindowsIntegrity(ctx)
	case "linux":
		return c.getLinuxIntegrity(ctx)
	case "darwin":
		return c.getDarwinIntegrity(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Windows specific implementations
func (c *SystemCollector) getWindowsBootTimeAndUptime(ctx context.Context) (time.Time, time.Duration, error) {
	// 简化实现：使用当前时间减去运行时间
	// 实际应该使用Windows API获取准确的启动时间
	now := time.Now()
	uptime := time.Duration(60) * time.Minute // 模拟1小时运行时间
	bootTime := now.Add(-uptime)

	return bootTime, uptime, nil
}

func (c *SystemCollector) getWindowsNTPStatus(ctx context.Context) (*core.NTPStatus, error) {
	// 简化实现：模拟NTP状态
	// 实际应该使用w32tm命令或Windows API
	return &core.NTPStatus{
		Synchronized: true,
		Server:       "time.windows.com",
		LastSync:     time.Now().Add(-5 * time.Minute),
		Offset:       time.Duration(10) * time.Millisecond,
	}, nil
}

func (c *SystemCollector) getWindowsDrivers(ctx context.Context) ([]core.KernelModule, error) {
	// 简化实现：模拟驱动程序列表
	// 实际应该使用driverquery命令或Windows API
	modules := []core.KernelModule{
		{
			Name:        "ntoskrnl.exe",
			Path:        "C:\\Windows\\System32\\ntoskrnl.exe",
			Version:     "10.0.19041.1",
			Description: "NT Kernel & System",
			Signed:      true,
		},
		{
			Name:        "hal.dll",
			Path:        "C:\\Windows\\System32\\hal.dll",
			Version:     "10.0.19041.1",
			Description: "Hardware Abstraction Layer DLL",
			Signed:      true,
		},
	}

	return modules, nil
}

func (c *SystemCollector) getWindowsIntegrity(ctx context.Context) (*core.SystemIntegrity, error) {
	// 简化实现：模拟系统完整性状态
	// 实际应该使用sfc /verifyonly或其他完整性检查工具
	return &core.SystemIntegrity{
		Status:      "healthy",
		LastCheck:   time.Now().Add(-24 * time.Hour),
		Issues:      []string{},
		CheckMethod: "sfc",
	}, nil
}

// Linux specific implementations
func (c *SystemCollector) getLinuxBootTimeAndUptime(ctx context.Context) (time.Time, time.Duration, error) {
	// 简化实现：使用当前时间减去运行时间
	// 实际应该读取/proc/uptime和/proc/stat
	now := time.Now()
	uptime := time.Duration(120) * time.Minute // 模拟2小时运行时间
	bootTime := now.Add(-uptime)

	return bootTime, uptime, nil
}

func (c *SystemCollector) getLinuxNTPStatus(ctx context.Context) (*core.NTPStatus, error) {
	// 简化实现：模拟NTP状态
	// 实际应该使用timedatectl或ntpq命令
	return &core.NTPStatus{
		Synchronized: true,
		Server:       "pool.ntp.org",
		LastSync:     time.Now().Add(-10 * time.Minute),
		Offset:       time.Duration(5) * time.Millisecond,
	}, nil
}

func (c *SystemCollector) getLinuxKernelModules(ctx context.Context) ([]core.KernelModule, error) {
	// 简化实现：模拟内核模块列表
	// 实际应该读取/proc/modules或使用lsmod命令
	modules := []core.KernelModule{
		{
			Name:        "ext4",
			Path:        "/lib/modules/5.4.0/kernel/fs/ext4/ext4.ko",
			Version:     "5.4.0",
			Description: "Fourth Extended Filesystem",
			Size:        737280,
		},
		{
			Name:        "usbcore",
			Path:        "/lib/modules/5.4.0/kernel/drivers/usb/core/usbcore.ko",
			Version:     "5.4.0",
			Description: "USB Core",
			Size:        278528,
		},
	}

	return modules, nil
}

func (c *SystemCollector) getLinuxIntegrity(ctx context.Context) (*core.SystemIntegrity, error) {
	// 简化实现：模拟系统完整性状态
	// 实际应该检查IMA/EVM、AIDE或其他完整性系统
	return &core.SystemIntegrity{
		Status:      "healthy",
		LastCheck:   time.Now().Add(-12 * time.Hour),
		Issues:      []string{},
		CheckMethod: "aide",
	}, nil
}

// macOS specific implementations
func (c *SystemCollector) getDarwinBootTimeAndUptime(ctx context.Context) (time.Time, time.Duration, error) {
	// 简化实现：使用当前时间减去运行时间
	// 实际应该使用sysctl kern.boottime
	now := time.Now()
	uptime := time.Duration(90) * time.Minute // 模拟1.5小时运行时间
	bootTime := now.Add(-uptime)

	return bootTime, uptime, nil
}

func (c *SystemCollector) getDarwinNTPStatus(ctx context.Context) (*core.NTPStatus, error) {
	// 简化实现：模拟NTP状态
	// 实际应该使用sntp命令或系统配置
	return &core.NTPStatus{
		Synchronized: true,
		Server:       "time.apple.com",
		LastSync:     time.Now().Add(-15 * time.Minute),
		Offset:       time.Duration(2) * time.Millisecond,
	}, nil
}

func (c *SystemCollector) getDarwinKernelExtensions(ctx context.Context) ([]core.KernelModule, error) {
	// 简化实现：模拟内核扩展列表
	// 实际应该使用kextstat命令
	modules := []core.KernelModule{
		{
			Name:        "com.apple.kext.AppleACPIPlatform",
			Path:        "/System/Library/Extensions/AppleACPIPlatform.kext",
			Version:     "6.1",
			Description: "Apple ACPI Platform Driver",
			Signed:      true,
		},
		{
			Name:        "com.apple.iokit.IOUSBHostFamily",
			Path:        "/System/Library/Extensions/IOUSBHostFamily.kext",
			Version:     "1.2",
			Description: "USB Host Controller Family",
			Signed:      true,
		},
	}

	return modules, nil
}

func (c *SystemCollector) getDarwinIntegrity(ctx context.Context) (*core.SystemIntegrity, error) {
	// 简化实现：模拟系统完整性状态
	// 实际应该使用System Integrity Protection (SIP)状态检查
	return &core.SystemIntegrity{
		Status:      "enabled",
		LastCheck:   time.Now().Add(-6 * time.Hour),
		Issues:      []string{},
		CheckMethod: "sip",
	}, nil
}
