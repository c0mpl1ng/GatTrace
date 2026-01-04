package platform

import (
	"errors"
	"runtime"
	"testing"

	"GatTrace/internal/core"
)

func TestLinuxAdapter_Creation(t *testing.T) {
	adapter := NewLinuxAdapter()
	if adapter == nil {
		t.Fatal("NewLinuxAdapter() returned nil")
	}

	detector := adapter.GetPlatformDetector()
	if detector == nil {
		t.Fatal("GetPlatformDetector() returned nil")
	}
}

func TestLinuxAdapter_GetNetworkInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	networkInfo, err := adapter.GetNetworkInfo()
	if err != nil {
		t.Fatalf("GetNetworkInfo() failed: %v", err)
	}

	if networkInfo == nil {
		t.Fatal("GetNetworkInfo() returned nil")
	}

	// 验证元数据
	if networkInfo.Metadata.SessionID == "" {
		t.Error("NetworkInfo metadata should have session ID")
	}

	if networkInfo.Metadata.Platform == "" {
		t.Error("NetworkInfo metadata should have platform")
	}

	// 网络接口应该至少有一个（回环接口）
	if len(networkInfo.Interfaces) == 0 {
		t.Error("Should have at least one network interface")
	}
}

func TestLinuxAdapter_GetProcessInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	processInfo, err := adapter.GetProcessInfo()
	if err != nil {
		t.Fatalf("GetProcessInfo() failed: %v", err)
	}

	if processInfo == nil {
		t.Fatal("GetProcessInfo() returned nil")
	}

	// 验证元数据
	if processInfo.Metadata.SessionID == "" {
		t.Error("ProcessInfo metadata should have session ID")
	}

	// 应该至少有一些进程
	if len(processInfo.Processes) == 0 {
		t.Error("Should have at least some processes")
	}

	// 验证进程信息结构
	for _, proc := range processInfo.Processes {
		if proc.PID <= 0 {
			t.Errorf("Process PID should be positive, got %d", proc.PID)
		}
	}
}

func TestLinuxAdapter_GetUserInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	userInfo, err := adapter.GetUserInfo()
	if err != nil {
		t.Fatalf("GetUserInfo() failed: %v", err)
	}

	if userInfo == nil {
		t.Fatal("GetUserInfo() returned nil")
	}

	// 验证元数据
	if userInfo.Metadata.SessionID == "" {
		t.Error("UserInfo metadata should have session ID")
	}

	// 应该至少有一些用户
	if len(userInfo.CurrentUsers) == 0 {
		t.Error("Should have at least some users")
	}
}

func TestLinuxAdapter_GetPersistenceInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	persistenceInfo, err := adapter.GetPersistenceInfo()
	if err != nil {
		t.Fatalf("GetPersistenceInfo() failed: %v", err)
	}

	if persistenceInfo == nil {
		t.Fatal("GetPersistenceInfo() returned nil")
	}

	// 验证元数据
	if persistenceInfo.Metadata.SessionID == "" {
		t.Error("PersistenceInfo metadata should have session ID")
	}

	// 持久化项目可能为空，这是正常的
}

func TestLinuxAdapter_GetFileSystemInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	fileSystemInfo, err := adapter.GetFileSystemInfo()
	if err != nil {
		t.Fatalf("GetFileSystemInfo() failed: %v", err)
	}

	if fileSystemInfo == nil {
		t.Fatal("GetFileSystemInfo() returned nil")
	}

	// 验证元数据
	if fileSystemInfo.Metadata.SessionID == "" {
		t.Error("FileSystemInfo metadata should have session ID")
	}

	// 最近文件可能为空，这是正常的
}

func TestLinuxAdapter_GetSecurityLogs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	securityLogs, err := adapter.GetSecurityLogs()
	if err != nil {
		t.Fatalf("GetSecurityLogs() failed: %v", err)
	}

	if securityLogs == nil {
		t.Fatal("GetSecurityLogs() returned nil")
	}

	// 验证元数据
	if securityLogs.Metadata.SessionID == "" {
		t.Error("SecurityLogs metadata should have session ID")
	}

	// 日志条目可能为空，这是正常的
}

func TestLinuxAdapter_GetSystemInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()
	systemInfo, err := adapter.GetSystemInfo()
	if err != nil {
		t.Fatalf("GetSystemInfo() failed: %v", err)
	}

	if systemInfo == nil {
		t.Fatal("GetSystemInfo() returned nil")
	}

	// 验证元数据
	if systemInfo.Metadata.SessionID == "" {
		t.Error("SystemInfo metadata should have session ID")
	}

	// 验证系统信息
	if systemInfo.BootTime.IsZero() {
		t.Error("Boot time should not be zero")
	}

	if systemInfo.Uptime <= 0 {
		t.Error("Uptime should be positive")
	}
}

func TestLinuxAdapter_PlatformSpecificMethods(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()

	// 测试 sudo 权限检查
	hasSudo := adapter.checkSudoAccess()
	// 不验证具体值，因为取决于运行环境
	_ = hasSudo

	// 测试用户组获取
	groups, err := adapter.getUserGroups("root")
	if err != nil {
		t.Errorf("getUserGroups() failed: %v", err)
	}
	_ = groups // 可能为空，这是正常的

	// 测试 DNS 配置获取
	dnsConfig, err := adapter.getDNSConfig()
	if err != nil {
		t.Errorf("getDNSConfig() failed: %v", err)
	}
	_ = dnsConfig

	// 测试路由表获取
	routes, err := adapter.getRoutes()
	if err != nil {
		t.Errorf("getRoutes() failed: %v", err)
	}
	_ = routes
}

// 测试非 Linux 平台的兼容性
func TestLinuxAdapter_CrossPlatformCompatibility(t *testing.T) {
	adapter := NewLinuxAdapter()

	// 在非 Linux 平台上，方法应该返回适当的错误
	if runtime.GOOS != "linux" {
		_, err := adapter.GetNetworkInfo()
		if err == nil {
			t.Error("GetNetworkInfo() should return error on non-Linux platform")
		}

		_, err = adapter.GetProcessInfo()
		if err == nil {
			t.Error("GetProcessInfo() should return error on non-Linux platform")
		}

		_, err = adapter.GetUserInfo()
		if err == nil {
			t.Error("GetUserInfo() should return error on non-Linux platform")
		}

		_, err = adapter.GetPersistenceInfo()
		if err == nil {
			t.Error("GetPersistenceInfo() should return error on non-Linux platform")
		}

		_, err = adapter.GetFileSystemInfo()
		if err == nil {
			t.Error("GetFileSystemInfo() should return error on non-Linux platform")
		}

		_, err = adapter.GetSecurityLogs()
		if err == nil {
			t.Error("GetSecurityLogs() should return error on non-Linux platform")
		}

		_, err = adapter.GetSystemInfo()
		if err == nil {
			t.Error("GetSystemInfo() should return error on non-Linux platform")
		}
	}
}

func TestLinuxAdapter_ErrorHandling(t *testing.T) {
	adapter := NewLinuxAdapter()

	// 测试错误处理
	err := &core.CollectionError{
		Module:    "test",
		Operation: "test_op",
		Err:       errors.New("test error"),
		Severity:  core.SeverityError,
	}

	handledErr := adapter.HandlePrivilegeError(err.Err)
	if handledErr == nil {
		t.Fatal("HandlePrivilegeError() should not return nil")
	}

	if handledErr.Module != "privilege" {
		t.Errorf("Expected module 'privilege', got '%s'", handledErr.Module)
	}
}

func TestLinuxAdapter_UtilityMethods(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	adapter := NewLinuxAdapter()

	// 测试 IP 地址转换
	ip := adapter.hexToIP("0100007F") // 127.0.0.1 in little-endian hex
	expectedIP := "127.0.0.1"
	if ip != expectedIP {
		t.Errorf("hexToIP() expected %s, got %s", expectedIP, ip)
	}

	// 测试无效的十六进制字符串
	invalidIP := adapter.hexToIP("invalid")
	if invalidIP != "0.0.0.0" {
		t.Errorf("hexToIP() should return 0.0.0.0 for invalid input, got %s", invalidIP)
	}

	// 测试字符串哈希计算
	hash := adapter.calculateStringHash("test")
	if hash == "" {
		t.Error("calculateStringHash() should not return empty string")
	}
}