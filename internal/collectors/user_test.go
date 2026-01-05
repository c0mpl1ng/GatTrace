package collectors

import (
	"context"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestUserCollector_Basic 测试用户采集器基本功能
func TestUserCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

	// 测试基本属性
	if collector.Name() != "user" {
		t.Errorf("Expected name 'user', got '%s'", collector.Name())
	}

	if !collector.RequiresPrivileges() {
		t.Error("User collector should require privileges")
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

// TestUserCollector_Collect_Success 测试成功的用户信息采集
func TestUserCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

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

	userInfo, ok := result.Data.(*core.UserInfo)
	if !ok {
		t.Fatal("Result data should be UserInfo")
	}

	// 验证用户信息结构
	if userInfo.CurrentUsers == nil {
		t.Error("CurrentUsers should not be nil")
	}

	if userInfo.RecentLogins == nil {
		t.Error("RecentLogins should not be nil")
	}

	if userInfo.Privileges == nil {
		t.Error("Privileges should not be nil")
	}

	if userInfo.SSHKeys == nil {
		t.Error("SSHKeys should not be nil")
	}

	// 验证元数据
	if userInfo.Metadata.SessionID == "" {
		t.Error("Metadata should have session ID")
	}

	if userInfo.Metadata.Hostname == "" {
		t.Error("Metadata should have hostname")
	}

	if userInfo.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	if userInfo.Metadata.CollectorVersion == "" {
		t.Error("Metadata should have collector version")
	}

	if userInfo.Metadata.CollectedAt.IsZero() {
		t.Error("Metadata should have collection timestamp")
	}
}

// TestUserCollector_Collect_AdapterError 测试适配器错误时的回退机制
func TestUserCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)
	collector := NewUserCollector(adapter)

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
	if adapterError.Module != "user" {
		t.Errorf("Expected error module 'user', got '%s'", adapterError.Module)
	}

	if adapterError.Operation != "GetUserInfo" {
		t.Errorf("Expected error operation 'GetUserInfo', got '%s'", adapterError.Operation)
	}

	if adapterError.Severity != core.SeverityError {
		t.Errorf("Expected error severity 'error', got '%v'", adapterError.Severity)
	}

	// 数据应该来自通用方法
	userInfo, ok := result.Data.(*core.UserInfo)
	if !ok {
		t.Fatal("Result data should be UserInfo")
	}

	// 验证基本结构存在
	if userInfo.CurrentUsers == nil {
		t.Error("CurrentUsers should not be nil")
	}

	if userInfo.RecentLogins == nil {
		t.Error("RecentLogins should not be nil")
	}

	if userInfo.Privileges == nil {
		t.Error("Privileges should not be nil")
	}

	if userInfo.SSHKeys == nil {
		t.Error("SSHKeys should not be nil")
	}
}

// TestUserCollector_Collect_ContextCancellation 测试上下文取消
func TestUserCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

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

// TestUserCollector_Collect_Timeout 测试超时处理
func TestUserCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

	// 创建短超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// 采集应该仍然成功（因为是快速操作）
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestUserCollector_DataIntegrity 测试数据完整性
func TestUserCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	userInfo := result.Data.(*core.UserInfo)

	// 验证用户信息完整性
	for i, user := range userInfo.CurrentUsers {
		if user.Username == "" {
			t.Errorf("User %d should have username", i)
		}
		if user.UID == "" {
			t.Errorf("User %d should have UID", i)
		}
		if user.HomeDir == "" {
			t.Errorf("User %d should have home directory", i)
		}
	}

	// 验证登录记录完整性
	for i, login := range userInfo.RecentLogins {
		if login.Username == "" {
			t.Errorf("Login record %d should have username", i)
		}
		if login.LoginTime.IsZero() {
			t.Errorf("Login record %d should have login time", i)
		}
		if login.Status == "" {
			t.Errorf("Login record %d should have status", i)
		}
	}

	// 验证权限信息完整性
	for i, privilege := range userInfo.Privileges {
		if privilege.Username == "" {
			t.Errorf("Privilege %d should have username", i)
		}
		if privilege.Groups == nil {
			t.Errorf("Privilege %d should have groups list", i)
		}
	}

	// 验证SSH密钥完整性
	for i, key := range userInfo.SSHKeys {
		if key.Username == "" {
			t.Errorf("SSH key %d should have username", i)
		}
		if key.KeyType == "" {
			t.Errorf("SSH key %d should have key type", i)
		}
		if key.FilePath == "" {
			t.Errorf("SSH key %d should have file path", i)
		}
	}
}

// TestUserCollector_PrivilegeDetection 测试权限检测
func TestUserCollector_PrivilegeDetection(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	userInfo := result.Data.(*core.UserInfo)

	// 验证至少有一个用户的权限信息
	if len(userInfo.Privileges) == 0 {
		t.Error("Should have at least one privilege record")
		return
	}

	privilege := userInfo.Privileges[0]

	// 验证权限检测逻辑
	hasAdminGroup := false
	hasSudoGroup := false

	for _, group := range privilege.Groups {
		if collector.isAdminGroup(group) {
			hasAdminGroup = true
		}
		if collector.isSudoGroup(group) {
			hasSudoGroup = true
		}
	}

	// 如果有管理员组，Admin 标志应该为 true
	if hasAdminGroup && !privilege.Admin {
		t.Error("Admin flag should be true when user is in admin group")
	}

	// 如果有sudo组，Sudo 标志应该为 true
	if hasSudoGroup && !privilege.Sudo {
		t.Error("Sudo flag should be true when user is in sudo group")
	}
}

// TestUserCollector_SSHKeyParsing 测试SSH密钥解析
func TestUserCollector_SSHKeyParsing(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewUserCollector(adapter)

	// 测试SSH密钥解析
	testContent := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... user@example.com
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbJ... user@laptop
# This is a comment
ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY... user@server`

	keys := collector.parseSSHKeys(testContent, "testuser", "/home/testuser/.ssh/authorized_keys")

	if len(keys) != 3 {
		t.Errorf("Expected 3 SSH keys, got %d", len(keys))
	}

	// 验证第一个密钥
	if keys[0].KeyType != "ssh-rsa" {
		t.Errorf("Expected key type 'ssh-rsa', got '%s'", keys[0].KeyType)
	}
	if keys[0].Comment != "user@example.com" {
		t.Errorf("Expected comment 'user@example.com', got '%s'", keys[0].Comment)
	}
	if keys[0].Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", keys[0].Username)
	}

	// 验证第二个密钥
	if keys[1].KeyType != "ssh-ed25519" {
		t.Errorf("Expected key type 'ssh-ed25519', got '%s'", keys[1].KeyType)
	}
	if keys[1].Comment != "user@laptop" {
		t.Errorf("Expected comment 'user@laptop', got '%s'", keys[1].Comment)
	}

	// 验证第三个密钥
	if keys[2].KeyType != "ssh-ecdsa" {
		t.Errorf("Expected key type 'ssh-ecdsa', got '%s'", keys[2].KeyType)
	}
	if keys[2].Comment != "user@server" {
		t.Errorf("Expected comment 'user@server', got '%s'", keys[2].Comment)
	}
}
