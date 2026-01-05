package collectors

import (
	"context"
	"fmt"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// MockPlatformAdapter 用于测试的模拟平台适配器
type MockPlatformAdapter struct {
	*core.BasePlatformAdapter
	networkInfo            *core.NetworkInfo
	processInfo            *core.ProcessInfo
	userInfo               *core.UserInfo
	persistenceInfo        *core.PersistenceInfo
	fileSystemInfo         *core.FileSystemInfo
	securityLogs           *core.SecurityLogs
	systemStatus           *core.SystemStatus
	shouldError            bool
	shouldFailSystemStatus bool
}

func NewMockPlatformAdapter() *MockPlatformAdapter {
	return &MockPlatformAdapter{
		BasePlatformAdapter: core.NewBasePlatformAdapter(),
		shouldError:         false,
	}
}

func (m *MockPlatformAdapter) SetNetworkInfo(info *core.NetworkInfo) {
	m.networkInfo = info
}

func (m *MockPlatformAdapter) SetProcessInfo(info *core.ProcessInfo) {
	m.processInfo = info
}

func (m *MockPlatformAdapter) SetUserInfo(info *core.UserInfo) {
	m.userInfo = info
}

func (m *MockPlatformAdapter) SetPersistenceInfo(info *core.PersistenceInfo) {
	m.persistenceInfo = info
}

func (m *MockPlatformAdapter) SetFileSystemInfo(info *core.FileSystemInfo) {
	m.fileSystemInfo = info
}

func (m *MockPlatformAdapter) SetSecurityLogs(logs *core.SecurityLogs) {
	m.securityLogs = logs
}

func (m *MockPlatformAdapter) SetShouldError(shouldError bool) {
	m.shouldError = shouldError
}

func (m *MockPlatformAdapter) GetNetworkInfo() (*core.NetworkInfo, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	if m.networkInfo != nil {
		return m.networkInfo, nil
	}

	// 返回默认的网络信息
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.NetworkInfo{
		Metadata: metadata,
		Interfaces: []core.NetworkInterface{
			{
				Name:   "eth0",
				IPs:    []string{"192.168.1.100"},
				MAC:    "00:11:22:33:44:55",
				Status: "up",
				MTU:    1500,
				Flags:  []string{"up", "broadcast", "multicast"},
			},
		},
		Routes: []core.Route{
			{
				Destination: "0.0.0.0/0",
				Gateway:     "192.168.1.1",
				Interface:   "eth0",
				Metric:      100,
			},
		},
		DNS: core.DNSConfig{
			Servers:    []string{"8.8.8.8", "8.8.4.4"},
			SearchList: []string{"local"},
			HostsFile:  map[string]string{"localhost": "127.0.0.1"},
		},
		Connections: []core.Connection{
			{
				LocalAddr:  "192.168.1.100:22",
				RemoteAddr: "192.168.1.1:54321",
				State:      "ESTABLISHED",
				PID:        1234,
				Process:    "sshd",
				Protocol:   "tcp",
			},
		},
		Listeners: []core.Listener{
			{
				LocalAddr: "0.0.0.0:22",
				PID:       1234,
				Process:   "sshd",
				Protocol:  "tcp",
			},
		},
	}, nil
}

func (m *MockPlatformAdapter) GetProcessInfo() (*core.ProcessInfo, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	if m.processInfo != nil {
		return m.processInfo, nil
	}

	// 返回默认的进程信息
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.ProcessInfo{
		Metadata: metadata,
		Processes: []core.Process{
			{
				PID:        1,
				PPID:       0,
				Name:       "init",
				Cmdline:    []string{"/sbin/init"},
				Exe:        "/sbin/init",
				Cwd:        "/",
				Username:   "root",
				CreateTime: time.Now().Add(-time.Hour).UTC(),
				Status:     "running",
				ExeHash:    "abc123def456789012345678901234567890123456789012345678901234abcd",
			},
			{
				PID:        1234,
				PPID:       1,
				Name:       "sshd",
				Cmdline:    []string{"/usr/sbin/sshd", "-D"},
				Exe:        "/usr/sbin/sshd",
				Cwd:        "/",
				Username:   "root",
				CreateTime: time.Now().Add(-30 * time.Minute).UTC(),
				Status:     "running",
				ExeHash:    "def456ghi78901234567890123456789012345678901234567890123456789ef",
			},
		},
	}, nil
}

func (m *MockPlatformAdapter) GetUserInfo() (*core.UserInfo, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	if m.userInfo != nil {
		return m.userInfo, nil
	}

	// 返回默认的用户信息
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.UserInfo{
		Metadata: metadata,
		CurrentUsers: []core.User{
			{
				Username:  "testuser",
				UID:       "1000",
				GID:       "1000",
				HomeDir:   "/home/testuser",
				Shell:     "/bin/bash",
				LastLogin: time.Now().Add(-time.Hour).UTC(),
				IsActive:  true,
			},
		},
		RecentLogins: []core.LoginRecord{
			{
				Username:  "testuser",
				Terminal:  "pts/0",
				Host:      "192.168.1.100",
				LoginTime: time.Now().Add(-2 * time.Hour).UTC(),
				Status:    "active",
			},
		},
		Privileges: []core.Privilege{
			{
				Username: "testuser",
				Groups:   []string{"users", "sudo", "admin"},
				Sudo:     true,
				Admin:    true,
			},
		},
		SSHKeys: []core.SSHKey{
			{
				Username: "testuser",
				KeyType:  "ssh-rsa",
				KeyHash:  "abc123def456",
				Comment:  "testuser@localhost",
				FilePath: "/home/testuser/.ssh/id_rsa.pub",
			},
		},
	}, nil
}

func (m *MockPlatformAdapter) GetPersistenceInfo() (*core.PersistenceInfo, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	if m.persistenceInfo != nil {
		return m.persistenceInfo, nil
	}

	// 返回默认的持久化信息
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.PersistenceInfo{
		Metadata: metadata,
		Items: []core.PersistenceItem{
			{
				Type:    "systemd_service",
				Name:    "sshd",
				Path:    "/lib/systemd/system/sshd.service",
				Command: "systemctl start sshd",
				User:    "root",
				Enabled: true,
				Properties: map[string]string{
					"location":     "systemd",
					"service_type": "system",
				},
			},
			{
				Type:    "cron",
				Name:    "user_backup",
				Path:    "/var/spool/cron/crontabs/testuser",
				Command: "0 2 * * * /home/testuser/backup.sh",
				User:    "current_user",
				Enabled: true,
				Properties: map[string]string{
					"location": "user_cron",
				},
			},
			{
				Type:    "startup",
				Name:    "autostart_app",
				Path:    "/home/testuser/.config/autostart/app.desktop",
				Command: "/usr/bin/myapp",
				User:    "current_user",
				Enabled: true,
				Properties: map[string]string{
					"location": "startup_folder",
				},
			},
		},
	}, nil
}

func (m *MockPlatformAdapter) GetFileSystemInfo() (*core.FileSystemInfo, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	if m.fileSystemInfo != nil {
		return m.fileSystemInfo, nil
	}

	// 返回默认的文件系统信息
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.FileSystemInfo{
		Metadata: metadata,
		RecentFiles: []core.FileInfo{
			{
				Path:       "/etc/passwd",
				Size:       1024,
				Mode:       "-rw-r--r--",
				ModTime:    time.Now().Add(-time.Hour).UTC(),
				AccessTime: time.Now().Add(-30 * time.Minute).UTC(),
				ChangeTime: time.Now().Add(-time.Hour).UTC(),
				Hash:       "abc123def456789012345678901234567890123456789012345678901234abcd",
				Owner:      "root",
				Group:      "root",
			},
			{
				Path:       "/usr/bin/bash",
				Size:       1048576,
				Mode:       "-rwxr-xr-x",
				ModTime:    time.Now().Add(-24 * time.Hour).UTC(),
				AccessTime: time.Now().Add(-time.Hour).UTC(),
				ChangeTime: time.Now().Add(-24 * time.Hour).UTC(),
				Hash:       "def456ghi78901234567890123456789012345678901234567890123456789ef",
				Owner:      "root",
				Group:      "root",
			},
		},
	}, nil
}

func (m *MockPlatformAdapter) GetSecurityLogs() (*core.SecurityLogs, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	if m.securityLogs != nil {
		return m.securityLogs, nil
	}

	// 返回默认的安全日志
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.SecurityLogs{
		Metadata: metadata,
		Entries: []core.LogEntry{
			{
				Timestamp: time.Now().Add(-time.Hour).UTC(),
				Level:     "Info",
				Source:    "auth.log",
				EventID:   "1001",
				Message:   "User login successful",
				Details: map[string]string{
					"user":    "testuser",
					"process": "sshd",
					"pid":     "1234",
				},
			},
			{
				Timestamp: time.Now().Add(-30 * time.Minute).UTC(),
				Level:     "Warning",
				Source:    "secure.log",
				EventID:   "1002",
				Message:   "Failed login attempt",
				Details: map[string]string{
					"user":       "admin",
					"ip_address": "192.168.1.100",
					"process":    "sshd",
				},
			},
		},
	}, nil
}

func (m *MockPlatformAdapter) GetSystemInfo() (*core.SystemInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockPlatformAdapter) GetSystemStatus() (*core.SystemStatus, error) {
	if m.shouldFailSystemStatus {
		return nil, fmt.Errorf("mock system status error")
	}
	if m.systemStatus != nil {
		return m.systemStatus, nil
	}

	// 返回默认的系统状态
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	return &core.SystemStatus{
		Metadata: metadata,
		BootTime: time.Now().Add(-2 * time.Hour),
		Uptime:   2 * time.Hour,
		NTPStatus: &core.NTPStatus{
			Synchronized: true,
			Server:       "pool.ntp.org",
			LastSync:     time.Now().Add(-10 * time.Minute),
			Offset:       5 * time.Millisecond,
		},
		KernelModules: []core.KernelModule{
			{
				Name:        "test_module",
				Path:        "/lib/modules/test_module.ko",
				Version:     "1.0.0",
				Description: "Test kernel module",
				Size:        1024,
			},
		},
		Integrity: &core.SystemIntegrity{
			Status:      "healthy",
			LastCheck:   time.Now().Add(-12 * time.Hour),
			Issues:      []string{},
			CheckMethod: "test",
		},
	}, nil
}

// TestNetworkCollector_Basic 测试网络采集器基本功能
func TestNetworkCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewNetworkCollector(adapter)

	// 测试基本属性
	if collector.Name() != "network" {
		t.Errorf("Expected name 'network', got '%s'", collector.Name())
	}

	if collector.RequiresPrivileges() {
		t.Error("Network collector should not require privileges")
	}

	platforms := collector.SupportedPlatforms()
	expectedPlatforms := []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}

	if len(platforms) != len(expectedPlatforms) {
		t.Errorf("Expected %d platforms, got %d", len(expectedPlatforms), len(platforms))
	}

	for i, platform := range platforms {
		if platform != expectedPlatforms[i] {
			t.Errorf("Expected platform %v, got %v", expectedPlatforms[i], platform)
		}
	}
}

// TestNetworkCollector_Collect_Success 测试成功的网络信息采集
func TestNetworkCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewNetworkCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if len(result.Errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(result.Errors))
	}

	networkInfo, ok := result.Data.(*core.NetworkInfo)
	if !ok {
		t.Fatal("Result data should be NetworkInfo")
	}

	// 验证网络信息结构
	if len(networkInfo.Interfaces) == 0 {
		t.Error("Should have at least one network interface")
	}

	if len(networkInfo.Routes) == 0 {
		t.Error("Should have at least one route")
	}

	if len(networkInfo.DNS.Servers) == 0 {
		t.Error("Should have at least one DNS server")
	}

	if len(networkInfo.Connections) == 0 {
		t.Error("Should have at least one connection")
	}

	if len(networkInfo.Listeners) == 0 {
		t.Error("Should have at least one listener")
	}

	// 验证元数据
	if networkInfo.Metadata.SessionID == "" {
		t.Error("Metadata should have session ID")
	}

	if networkInfo.Metadata.Hostname == "" {
		t.Error("Metadata should have hostname")
	}

	if networkInfo.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	if networkInfo.Metadata.CollectorVersion == "" {
		t.Error("Metadata should have collector version")
	}

	if networkInfo.Metadata.CollectedAt.IsZero() {
		t.Error("Metadata should have collection timestamp")
	}
}

// TestNetworkCollector_Collect_AdapterError 测试适配器错误时的回退机制
func TestNetworkCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)
	collector := NewNetworkCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	// 应该成功，因为有回退机制
	if err != nil {
		t.Fatalf("Collect should not return error with fallback: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// 应该有一个错误记录适配器失败
	if len(result.Errors) == 0 {
		t.Error("Should have at least one error from adapter failure")
	}

	// 验证错误信息
	adapterError := result.Errors[0]
	if adapterError.Module != "network" {
		t.Errorf("Expected error module 'network', got '%s'", adapterError.Module)
	}

	if adapterError.Operation != "GetNetworkInfo" {
		t.Errorf("Expected error operation 'GetNetworkInfo', got '%s'", adapterError.Operation)
	}

	if adapterError.Severity != core.SeverityError {
		t.Errorf("Expected error severity 'error', got '%v'", adapterError.Severity)
	}

	// 数据应该来自通用方法
	networkInfo, ok := result.Data.(*core.NetworkInfo)
	if !ok {
		t.Fatal("Result data should be NetworkInfo")
	}

	// 验证基本结构存在
	if networkInfo.Interfaces == nil {
		t.Error("Interfaces should not be nil")
	}

	if networkInfo.Routes == nil {
		t.Error("Routes should not be nil")
	}

	if networkInfo.Connections == nil {
		t.Error("Connections should not be nil")
	}

	if networkInfo.Listeners == nil {
		t.Error("Listeners should not be nil")
	}
}

// TestNetworkCollector_Collect_ContextCancellation 测试上下文取消
func TestNetworkCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewNetworkCollector(adapter)

	// 创建已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 即使上下文被取消，采集也应该完成（因为是快速操作）
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestNetworkCollector_Collect_Timeout 测试超时处理
func TestNetworkCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewNetworkCollector(adapter)

	// 创建短超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// 等待超时
	time.Sleep(2 * time.Millisecond)

	// 采集应该仍然成功（因为是快速操作）
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestNetworkCollector_DataIntegrity 测试数据完整性
func TestNetworkCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewNetworkCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	networkInfo := result.Data.(*core.NetworkInfo)

	// 验证接口信息完整性
	for i, iface := range networkInfo.Interfaces {
		if iface.Name == "" {
			t.Errorf("Interface %d should have name", i)
		}
		if iface.MTU <= 0 {
			t.Errorf("Interface %d should have positive MTU", i)
		}
	}

	// 验证路由信息完整性
	for i, route := range networkInfo.Routes {
		if route.Destination == "" {
			t.Errorf("Route %d should have destination", i)
		}
		if route.Interface == "" {
			t.Errorf("Route %d should have interface", i)
		}
	}

	// 验证连接信息完整性
	for i, conn := range networkInfo.Connections {
		if conn.LocalAddr == "" {
			t.Errorf("Connection %d should have local address", i)
		}
		if conn.Protocol == "" {
			t.Errorf("Connection %d should have protocol", i)
		}
	}

	// 验证监听器信息完整性
	for i, listener := range networkInfo.Listeners {
		if listener.LocalAddr == "" {
			t.Errorf("Listener %d should have local address", i)
		}
		if listener.Protocol == "" {
			t.Errorf("Listener %d should have protocol", i)
		}
	}
}
