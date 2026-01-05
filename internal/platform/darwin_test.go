package platform

import (
	"errors"
	"runtime"
	"testing"

	"GatTrace/internal/core"
)

func TestDarwinAdapter_Creation(t *testing.T) {
	adapter := NewDarwinAdapter()
	if adapter == nil {
		t.Fatal("NewDarwinAdapter() returned nil")
	}

	detector := adapter.GetPlatformDetector()
	if detector == nil {
		t.Fatal("GetPlatformDetector() returned nil")
	}
}

func TestDarwinAdapter_GetNetworkInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_GetProcessInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_GetUserInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_GetPersistenceInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_GetFileSystemInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_GetSecurityLogs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_GetSystemInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()
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

func TestDarwinAdapter_PlatformSpecificMethods(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()

	// 测试 sudo 权限检查
	hasSudo := adapter.checkSudoAccess()
	// 不验证具体值，因为取决于运行环境
	_ = hasSudo

	// 测试管理员权限检查
	isAdmin := adapter.isCurrentUserAdmin()
	// 不验证具体值，因为取决于运行环境
	_ = isAdmin

	// 测试用户组获取
	groups, err := adapter.getUserGroups("root")
	if err != nil {
		t.Errorf("getUserGroups() failed: %v", err)
	}
	_ = groups // 可能为空，这是正常的

	// 测试用户信息获取
	uid := adapter.getUserUID("root")
	if uid == "" {
		t.Error("getUserUID() should not return empty string")
	}

	gid := adapter.getUserGID("root")
	if gid == "" {
		t.Error("getUserGID() should not return empty string")
	}

	homeDir := adapter.getUserHomeDir("root")
	if homeDir == "" {
		t.Error("getUserHomeDir() should not return empty string")
	}

	shell := adapter.getUserShell("root")
	if shell == "" {
		t.Error("getUserShell() should not return empty string")
	}
}

// 测试非 Darwin 平台的兼容性
func TestDarwinAdapter_CrossPlatformCompatibility(t *testing.T) {
	adapter := NewDarwinAdapter()

	// 在非 Darwin 平台上，方法应该返回适当的错误
	if runtime.GOOS != "darwin" {
		_, err := adapter.GetNetworkInfo()
		if err == nil {
			t.Error("GetNetworkInfo() should return error on non-Darwin platform")
		}

		_, err = adapter.GetProcessInfo()
		if err == nil {
			t.Error("GetProcessInfo() should return error on non-Darwin platform")
		}

		_, err = adapter.GetUserInfo()
		if err == nil {
			t.Error("GetUserInfo() should return error on non-Darwin platform")
		}

		_, err = adapter.GetPersistenceInfo()
		if err == nil {
			t.Error("GetPersistenceInfo() should return error on non-Darwin platform")
		}

		_, err = adapter.GetFileSystemInfo()
		if err == nil {
			t.Error("GetFileSystemInfo() should return error on non-Darwin platform")
		}

		_, err = adapter.GetSecurityLogs()
		if err == nil {
			t.Error("GetSecurityLogs() should return error on non-Darwin platform")
		}

		_, err = adapter.GetSystemInfo()
		if err == nil {
			t.Error("GetSystemInfo() should return error on non-Darwin platform")
		}

		// 测试存根方法
		if adapter.checkSudoAccess() {
			t.Error("checkSudoAccess() should return false on non-Darwin platform")
		}

		if adapter.isCurrentUserAdmin() {
			t.Error("isCurrentUserAdmin() should return false on non-Darwin platform")
		}

		groups, err := adapter.getUserGroups("test")
		if err != nil {
			t.Errorf("getUserGroups() should not return error on non-Darwin platform: %v", err)
		}
		if len(groups) != 0 {
			t.Error("getUserGroups() should return empty slice on non-Darwin platform")
		}

		uid := adapter.getUserUID("test")
		if uid != "0" {
			t.Errorf("getUserUID() should return '0' on non-Darwin platform, got '%s'", uid)
		}

		gid := adapter.getUserGID("test")
		if gid != "0" {
			t.Errorf("getUserGID() should return '0' on non-Darwin platform, got '%s'", gid)
		}

		homeDir := adapter.getUserHomeDir("test")
		if homeDir != "/Users/test" {
			t.Errorf("getUserHomeDir() should return '/Users/test' on non-Darwin platform, got '%s'", homeDir)
		}

		shell := adapter.getUserShell("test")
		if shell != "/bin/bash" {
			t.Errorf("getUserShell() should return '/bin/bash' on non-Darwin platform, got '%s'", shell)
		}

		hash := adapter.calculateStringHash("test")
		if hash != "" {
			t.Errorf("calculateStringHash() should return empty string on non-Darwin platform, got '%s'", hash)
		}
	}
}

func TestDarwinAdapter_ErrorHandling(t *testing.T) {
	adapter := NewDarwinAdapter()

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

func TestDarwinAdapter_UtilityMethods(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping Darwin-specific test on non-Darwin platform")
	}

	adapter := NewDarwinAdapter()

	// 测试字符串哈希计算
	hash := adapter.calculateStringHash("test")
	if hash == "" {
		t.Error("calculateStringHash() should not return empty string")
	}

	// 测试不同输入的哈希应该不同
	hash1 := adapter.calculateStringHash("test1")
	hash2 := adapter.calculateStringHash("test2")
	if hash1 == hash2 {
		t.Error("calculateStringHash() should return different hashes for different inputs")
	}
}
