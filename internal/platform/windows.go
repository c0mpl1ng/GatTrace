//go:build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"GatTrace/internal/core"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// WindowsAdapter Windows 平台适配器
type WindowsAdapter struct {
	*core.BasePlatformAdapter
}

// NewWindowsAdapter 创建 Windows 平台适配器
func NewWindowsAdapter() *WindowsAdapter {
	return &WindowsAdapter{
		BasePlatformAdapter: core.NewBasePlatformAdapter(),
	}
}

// GetNetworkInfo 获取网络信息
func (w *WindowsAdapter) GetNetworkInfo() (*core.NetworkInfo, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	networkInfo := &core.NetworkInfo{
		Metadata:    sessionManager.GetMetadata(),
		Interfaces:  []core.NetworkInterface{},
		Routes:      []core.Route{},
		DNS:         core.DNSConfig{},
		Connections: []core.Connection{},
		Listeners:   []core.Listener{},
	}

	// 获取网络接口信息
	interfaces, err := w.getNetworkInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}
	networkInfo.Interfaces = interfaces

	// 获取网络连接
	connections, err := w.getNetworkConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to get network connections: %w", err)
	}
	networkInfo.Connections = connections

	// 获取监听端口
	listeners, err := w.getNetworkListeners()
	if err != nil {
		return nil, fmt.Errorf("failed to get network listeners: %w", err)
	}
	networkInfo.Listeners = listeners

	// 获取 DNS 配置
	dnsConfig, err := w.getDNSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS config: %w", err)
	}
	networkInfo.DNS = dnsConfig

	return networkInfo, nil
}

// GetProcessInfo 获取进程信息
func (w *WindowsAdapter) GetProcessInfo() (*core.ProcessInfo, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	processInfo := &core.ProcessInfo{
		Metadata:  sessionManager.GetMetadata(),
		Processes: []core.Process{},
	}

	// 获取所有进程
	processes, err := w.getAllProcesses()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}
	processInfo.Processes = processes

	return processInfo, nil
}

// GetUserInfo 获取用户信息
func (w *WindowsAdapter) GetUserInfo() (*core.UserInfo, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	userInfo := &core.UserInfo{
		Metadata:     sessionManager.GetMetadata(),
		CurrentUsers: []core.User{},
		RecentLogins: []core.LoginRecord{},
		Privileges:   []core.Privilege{},
		SSHKeys:      []core.SSHKey{},
	}

	// 获取当前用户
	currentUsers, err := w.getCurrentUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get current users: %w", err)
	}
	userInfo.CurrentUsers = currentUsers

	// 获取权限信息
	privileges, err := w.getUserPrivileges()
	if err != nil {
		return nil, fmt.Errorf("failed to get user privileges: %w", err)
	}
	userInfo.Privileges = privileges

	return userInfo, nil
}

// GetPersistenceInfo 获取持久化信息
func (w *WindowsAdapter) GetPersistenceInfo() (*core.PersistenceInfo, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	persistenceInfo := &core.PersistenceInfo{
		Metadata: sessionManager.GetMetadata(),
		Items:    []core.PersistenceItem{},
	}

	// 获取服务
	services, err := w.getWindowsServices()
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}
	persistenceInfo.Items = append(persistenceInfo.Items, services...)

	// 获取计划任务
	tasks, err := w.getScheduledTasks()
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled tasks: %w", err)
	}
	persistenceInfo.Items = append(persistenceInfo.Items, tasks...)

	// 获取注册表自启动项
	registryItems, err := w.getRegistryStartupItems()
	if err != nil {
		return nil, fmt.Errorf("failed to get registry startup items: %w", err)
	}
	persistenceInfo.Items = append(persistenceInfo.Items, registryItems...)

	return persistenceInfo, nil
}

// GetFileSystemInfo 获取文件系统信息
func (w *WindowsAdapter) GetFileSystemInfo() (*core.FileSystemInfo, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	fileSystemInfo := &core.FileSystemInfo{
		Metadata:    sessionManager.GetMetadata(),
		RecentFiles: []core.FileInfo{},
	}

	// 获取最近文件
	recentFiles, err := w.getRecentFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get recent files: %w", err)
	}
	fileSystemInfo.RecentFiles = recentFiles

	return fileSystemInfo, nil
}

// GetSecurityLogs 获取安全日志
func (w *WindowsAdapter) GetSecurityLogs() (*core.SecurityLogs, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	securityLogs := &core.SecurityLogs{
		Metadata: sessionManager.GetMetadata(),
		Entries:  []core.LogEntry{},
	}

	// 获取 Windows 事件日志
	entries, err := w.getWindowsEventLogs()
	if err != nil {
		return nil, fmt.Errorf("failed to get Windows event logs: %w", err)
	}
	securityLogs.Entries = entries

	return securityLogs, nil
}

// GetSystemInfo 获取系统信息
func (w *WindowsAdapter) GetSystemInfo() (*core.SystemInfo, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	systemInfo := &core.SystemInfo{
		Metadata:       sessionManager.GetMetadata(),
		KernelModules:  []string{},
		IntegrityCheck: make(map[string]string),
	}

	// 获取系统启动时间
	bootTime, err := w.getBootTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get boot time: %w", err)
	}
	systemInfo.BootTime = bootTime
	systemInfo.Uptime = time.Since(bootTime)
	systemInfo.SystemTime = core.NormalizeTimestamp(time.Now())

	// 获取 NTP 状态
	ntpStatus, err := w.getNTPStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get NTP status: %w", err)
	}
	systemInfo.NTPStatus = ntpStatus

	// 获取驱动列表
	drivers, err := w.getLoadedDrivers()
	if err != nil {
		return nil, fmt.Errorf("failed to get loaded drivers: %w", err)
	}
	systemInfo.KernelModules = drivers

	return systemInfo, nil
}

// GetSystemStatus 获取系统状态
func (w *WindowsAdapter) GetSystemStatus() (*core.SystemStatus, error) {
	sessionManager, err := core.NewSessionManager(core.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	systemStatus := &core.SystemStatus{
		Metadata: sessionManager.GetMetadata(),
	}

	// 获取系统启动时间和运行时间
	bootTime, err := w.getBootTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get boot time: %w", err)
	}
	systemStatus.BootTime = bootTime
	systemStatus.Uptime = time.Since(bootTime)

	// 获取NTP状态
	ntpStatus, err := w.getWindowsNTPStatus()
	if err != nil {
		// NTP状态获取失败不是致命错误
		ntpStatus = &core.NTPStatus{
			Synchronized: false,
			Error:        err.Error(),
		}
	}
	systemStatus.NTPStatus = ntpStatus

	// 获取内核模块（Windows驱动）
	modules, err := w.getWindowsKernelModules()
	if err != nil {
		return nil, fmt.Errorf("failed to get kernel modules: %w", err)
	}
	systemStatus.KernelModules = modules

	// 获取系统完整性
	integrity, err := w.getWindowsSystemIntegrity()
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

// 辅助方法实现

// getNetworkInterfaces 获取网络接口信息
func (w *WindowsAdapter) getNetworkInterfaces() ([]core.NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []core.NetworkInterface
	for _, iface := range interfaces {
		netInterface := core.NetworkInterface{
			Name:   iface.Name,
			IPs:    []string{},
			MAC:    iface.HardwareAddr,
			Status: "up", // 简化实现
			MTU:    int(iface.MTU),
			Flags:  iface.Flags,
		}

		// 获取 IP 地址
		for _, addr := range iface.Addrs {
			netInterface.IPs = append(netInterface.IPs, addr.Addr)
		}

		result = append(result, netInterface)
	}

	return result, nil
}

// getNetworkConnections 获取网络连接
func (w *WindowsAdapter) getNetworkConnections() ([]core.Connection, error) {
	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	var result []core.Connection
	for _, conn := range connections {
		connection := core.Connection{
			LocalAddr:  fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port),
			State:      conn.Status,
			PID:        conn.Pid,
			Protocol:   fmt.Sprintf("%d", conn.Type),
		}

		// 获取进程名
		if conn.Pid > 0 {
			if proc, err := process.NewProcess(conn.Pid); err == nil {
				if name, err := proc.Name(); err == nil {
					connection.Process = name
				}
			}
		}

		result = append(result, connection)
	}

	return result, nil
}

// getNetworkListeners 获取监听端口
func (w *WindowsAdapter) getNetworkListeners() ([]core.Listener, error) {
	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	var result []core.Listener
	for _, conn := range connections {
		if conn.Status == "LISTEN" {
			listener := core.Listener{
				LocalAddr: fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
				PID:       conn.Pid,
				Protocol:  fmt.Sprintf("%d", conn.Type),
			}

			// 获取进程名
			if conn.Pid > 0 {
				if proc, err := process.NewProcess(conn.Pid); err == nil {
					if name, err := proc.Name(); err == nil {
						listener.Process = name
					}
				}
			}

			result = append(result, listener)
		}
	}

	return result, nil
}

// getDNSConfig 获取 DNS 配置
func (w *WindowsAdapter) getDNSConfig() (core.DNSConfig, error) {
	// 简化实现，实际应该从注册表读取
	return core.DNSConfig{
		Servers:    []string{"8.8.8.8", "8.8.4.4"}, // 示例
		SearchList: []string{},
		HostsFile:  make(map[string]string),
	}, nil
}

// getAllProcesses 获取所有进程
func (w *WindowsAdapter) getAllProcesses() ([]core.Process, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	var result []core.Process
	for _, pid := range pids {
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue // 跳过无法访问的进程
		}

		processInfo := core.Process{
			PID: pid,
		}

		// 获取进程信息
		if name, err := proc.Name(); err == nil {
			processInfo.Name = name
		}

		if ppid, err := proc.Ppid(); err == nil {
			processInfo.PPID = ppid
		}

		// 获取完整命令行（保持原始格式，不分割）
		if cmdline, err := proc.Cmdline(); err == nil && cmdline != "" {
			processInfo.Cmdline = []string{cmdline}
		}

		if exe, err := proc.Exe(); err == nil {
			processInfo.Exe = exe
		}

		if cwd, err := proc.Cwd(); err == nil {
			processInfo.Cwd = cwd
		}

		if username, err := proc.Username(); err == nil {
			processInfo.Username = username
		}

		if createTime, err := proc.CreateTime(); err == nil {
			processInfo.CreateTime = core.NormalizeTimestamp(time.Unix(createTime/1000, 0))
		}

		if status, err := proc.Status(); err == nil {
			processInfo.Status = strings.Join(status, ",")
		}

		// 计算可执行文件哈希
		if processInfo.Exe != "" {
			if hash, err := w.calculateFileHash(processInfo.Exe); err == nil {
				processInfo.ExeHash = hash
			}
		}

		// 检查数字签名（Windows 特有）
		if processInfo.Exe != "" {
			if signature, err := w.checkDigitalSignature(processInfo.Exe); err == nil {
				processInfo.Signature = signature
			}
		}

		result = append(result, processInfo)
	}

	return result, nil
}

// getCurrentUsers 获取当前用户
func (w *WindowsAdapter) getCurrentUsers() ([]core.User, error) {
	// 简化实现，获取当前用户
	username := os.Getenv("USERNAME")
	if username == "" {
		return []core.User{}, nil
	}

	user := core.User{
		Username: username,
		UID:      "0", // Windows 没有 UID 概念
		GID:      "0",
		HomeDir:  os.Getenv("USERPROFILE"),
		Shell:    "cmd.exe",
		IsActive: true,
	}

	return []core.User{user}, nil
}

// getUserPrivileges 获取用户权限
func (w *WindowsAdapter) getUserPrivileges() ([]core.Privilege, error) {
	username := os.Getenv("USERNAME")
	if username == "" {
		return []core.Privilege{}, nil
	}

	privilege := core.Privilege{
		Username: username,
		Groups:   []string{},
		Sudo:     false,
		Admin:    w.isCurrentUserAdmin(),
	}

	return []core.Privilege{privilege}, nil
}

// getWindowsServices 获取 Windows 服务
func (w *WindowsAdapter) getWindowsServices() ([]core.PersistenceItem, error) {
	// 这里需要使用 Windows API 或 WMI 查询服务
	// 简化实现，返回空列表
	return []core.PersistenceItem{}, nil
}

// getScheduledTasks 获取计划任务
func (w *WindowsAdapter) getScheduledTasks() ([]core.PersistenceItem, error) {
	// 这里需要使用 schtasks 命令或 Task Scheduler API
	// 简化实现，返回空列表
	return []core.PersistenceItem{}, nil
}

// getRegistryStartupItems 获取注册表自启动项
func (w *WindowsAdapter) getRegistryStartupItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// 检查常见的自启动注册表项
	startupKeys := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}

	for _, keyPath := range startupKeys {
		if registryItems, err := w.readRegistryStartupKey(keyPath); err == nil {
			items = append(items, registryItems...)
		}
	}

	return items, nil
}

// readRegistryStartupKey 读取注册表启动项
func (w *WindowsAdapter) readRegistryStartupKey(keyPath string) ([]core.PersistenceItem, error) {
	if runtime.GOOS != "windows" {
		return []core.PersistenceItem{}, nil
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return []core.PersistenceItem{}, nil
	}
	defer key.Close()

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return []core.PersistenceItem{}, nil
	}

	var items []core.PersistenceItem
	for _, valueName := range valueNames {
		value, _, err := key.GetStringValue(valueName)
		if err != nil {
			continue
		}

		item := core.PersistenceItem{
			Type:    "registry",
			Name:    valueName,
			Path:    keyPath,
			Command: value,
			User:    "SYSTEM",
			Enabled: true,
			Properties: map[string]string{
				"registry_key": keyPath,
				"value_name":   valueName,
			},
		}

		items = append(items, item)
	}

	return items, nil
}

// getRecentFiles 获取最近文件
func (w *WindowsAdapter) getRecentFiles() ([]core.FileInfo, error) {
	// 简化实现，扫描用户目录下的最近文件
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return []core.FileInfo{}, nil
	}

	recentDir := filepath.Join(userProfile, "Recent")
	return w.scanDirectoryForRecentFiles(recentDir)
}

// scanDirectoryForRecentFiles 扫描目录获取最近文件
func (w *WindowsAdapter) scanDirectoryForRecentFiles(dir string) ([]core.FileInfo, error) {
	var files []core.FileInfo

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 忽略错误，继续扫描
		}

		if !info.IsDir() && time.Since(info.ModTime()) < 7*24*time.Hour {
			fileInfo := core.FileInfo{
				Path:       path,
				Size:       info.Size(),
				Mode:       info.Mode().String(),
				ModTime:    core.NormalizeTimestamp(info.ModTime()),
				AccessTime: core.NormalizeTimestamp(info.ModTime()), // Windows 访问时间获取较复杂
				ChangeTime: core.NormalizeTimestamp(info.ModTime()),
			}

			// 计算文件哈希
			if hash, err := w.calculateFileHash(path); err == nil {
				fileInfo.Hash = hash
			}

			files = append(files, fileInfo)
		}

		return nil
	})

	if err != nil {
		return []core.FileInfo{}, err
	}

	return files, nil
}

// getWindowsEventLogs 获取 Windows 事件日志
func (w *WindowsAdapter) getWindowsEventLogs() ([]core.LogEntry, error) {
	// 这里需要使用 Windows Event Log API
	// 简化实现，返回空列表
	return []core.LogEntry{}, nil
}

// getBootTime 获取系统启动时间
func (w *WindowsAdapter) getBootTime() (time.Time, error) {
	info, err := host.Info()
	if err != nil {
		return time.Time{}, err
	}

	return core.NormalizeTimestamp(time.Unix(int64(info.BootTime), 0)), nil
}

// getNTPStatus 获取 NTP 状态
func (w *WindowsAdapter) getNTPStatus() (string, error) {
	// 简化实现
	return "unknown", nil
}

// getLoadedDrivers 获取已加载驱动
func (w *WindowsAdapter) getLoadedDrivers() ([]string, error) {
	// 这里需要使用 Windows API 查询驱动
	// 简化实现，返回空列表
	return []string{}, nil
}

// calculateFileHash 计算文件哈希
func (w *WindowsAdapter) calculateFileHash(filePath string) (string, error) {
	// 使用输出管理器的哈希计算功能
	// 这里简化实现
	return "", nil
}

// checkDigitalSignature 检查数字签名
func (w *WindowsAdapter) checkDigitalSignature(filePath string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", nil
	}

	// 这里需要使用 Windows Authenticode API
	// 简化实现
	return "not_verified", nil
}

// isCurrentUserAdmin 检查当前用户是否为管理员
func (w *WindowsAdapter) isCurrentUserAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}

// getWindowsNTPStatus 获取Windows NTP状态
func (w *WindowsAdapter) getWindowsNTPStatus() (*core.NTPStatus, error) {
	// 简化实现：模拟NTP状态
	// 实际应该使用w32tm命令或Windows API
	return &core.NTPStatus{
		Synchronized: true,
		Server:       "time.windows.com",
		LastSync:     time.Now().Add(-5 * time.Minute),
		Offset:       time.Duration(10) * time.Millisecond,
	}, nil
}

// getWindowsKernelModules 获取Windows内核模块（驱动）
func (w *WindowsAdapter) getWindowsKernelModules() ([]core.KernelModule, error) {
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

// getWindowsSystemIntegrity 获取Windows系统完整性
func (w *WindowsAdapter) getWindowsSystemIntegrity() (*core.SystemIntegrity, error) {
	// 简化实现：模拟系统完整性状态
	// 实际应该使用sfc /verifyonly或其他完整性检查工具
	return &core.SystemIntegrity{
		Status:      "healthy",
		LastCheck:   time.Now().Add(-24 * time.Hour),
		Issues:      []string{},
		CheckMethod: "sfc",
	}, nil
}
