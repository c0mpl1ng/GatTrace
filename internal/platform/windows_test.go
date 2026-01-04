package platform

import (
	"errors"
	"runtime"
	"testing"

	"GatTrace/internal/core"
)

func TestWindowsAdapter_Creation(t *testing.T) {
	adapter := NewWindowsAdapter()
	if adapter == nil {
		t.Fatal("NewWindowsAdapter() returned nil")
	}

	detector := adapter.GetPlatformDetector()
	if detector == nil {
		t.Fatal("GetPlatformDetector() returned nil")
	}
}

func TestWindowsAdapter_GetNetworkInfo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

func TestWindowsAdapter_GetProcessInfo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

func TestWindowsAdapter_GetUserInfo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

	// 应该至少有当前用户
	if len(userInfo.CurrentUsers) == 0 {
		t.Error("Should have at least current user")
	}
}

func TestWindowsAdapter_GetPersistenceInfo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

func TestWindowsAdapter_GetFileSystemInfo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

func TestWindowsAdapter_GetSecurityLogs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

func TestWindowsAdapter_GetSystemInfo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()
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

func TestWindowsAdapter_PlatformSpecificMethods(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows platform")
	}

	adapter := NewWindowsAdapter()

	// 测试管理员权限检查
	isAdmin := adapter.isCurrentUserAdmin()
	// 不验证具体值，因为取决于运行环境
	_ = isAdmin

	// 测试注册表读取
	items, err := adapter.getRegistryStartupItems()
	if err != nil {
		t.Errorf("getRegistryStartupItems() failed: %v", err)
	}
	_ = items // 可能为空，这是正常的
}

// 测试非 Windows 平台的兼容性
func TestWindowsAdapter_CrossPlatformCompatibility(t *testing.T) {
	adapter := NewWindowsAdapter()

	// 在非 Windows 平台上，某些方法应该优雅地处理
	if runtime.GOOS != "windows" {
		// 测试数字签名检查
		signature, err := adapter.checkDigitalSignature("test.exe")
		if err != nil {
			t.Errorf("checkDigitalSignature() should handle non-Windows gracefully: %v", err)
		}
		if signature != "" {
			t.Error("checkDigitalSignature() should return empty string on non-Windows")
		}

		// 测试管理员检查
		isAdmin := adapter.isCurrentUserAdmin()
		if isAdmin {
			t.Error("isCurrentUserAdmin() should return false on non-Windows")
		}
	}
}

func TestWindowsAdapter_ErrorHandling(t *testing.T) {
	adapter := NewWindowsAdapter()

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