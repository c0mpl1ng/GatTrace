package collectors

import (
	"context"
	"runtime"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestPersistenceCollector_Basic 测试持久化采集器基本功能
func TestPersistenceCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

	// 测试基本属性
	if collector.Name() != "persistence" {
		t.Errorf("Expected name 'persistence', got '%s'", collector.Name())
	}

	if !collector.RequiresPrivileges() {
		t.Error("Persistence collector should require privileges")
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

// TestPersistenceCollector_Collect_Success 测试成功的持久化信息采集
func TestPersistenceCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

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

	persistenceInfo, ok := result.Data.(*core.PersistenceInfo)
	if !ok {
		t.Fatal("Result data should be PersistenceInfo")
	}

	// 验证持久化信息结构
	if persistenceInfo.Items == nil {
		t.Error("Items should not be nil")
	}

	// 验证元数据
	if persistenceInfo.Metadata.SessionID == "" {
		t.Error("Metadata should have session ID")
	}

	if persistenceInfo.Metadata.Hostname == "" {
		t.Error("Metadata should have hostname")
	}

	if persistenceInfo.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	if persistenceInfo.Metadata.CollectorVersion == "" {
		t.Error("Metadata should have collector version")
	}

	if persistenceInfo.Metadata.CollectedAt.IsZero() {
		t.Error("Metadata should have collection timestamp")
	}
}

// TestPersistenceCollector_Collect_AdapterError 测试适配器错误时的回退机制
func TestPersistenceCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)
	collector := NewPersistenceCollector(adapter)

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
	if adapterError.Module != "persistence" {
		t.Errorf("Expected error module 'persistence', got '%s'", adapterError.Module)
	}

	if adapterError.Operation != "GetPersistenceInfo" {
		t.Errorf("Expected error operation 'GetPersistenceInfo', got '%s'", adapterError.Operation)
	}

	if adapterError.Severity != core.SeverityError {
		t.Errorf("Expected error severity 'error', got '%v'", adapterError.Severity)
	}

	// 数据应该来自通用方法
	persistenceInfo, ok := result.Data.(*core.PersistenceInfo)
	if !ok {
		t.Fatal("Result data should be PersistenceInfo")
	}

	// 验证基本结构存在
	if persistenceInfo.Items == nil {
		t.Error("Items should not be nil")
	}
}

// TestPersistenceCollector_Collect_ContextCancellation 测试上下文取消
func TestPersistenceCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

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

// TestPersistenceCollector_Collect_Timeout 测试超时处理
func TestPersistenceCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

	// 创建短超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// 等待确保上下文超时
	<-ctx.Done()

	// 采集应该仍然成功（因为是快速操作）
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

// TestPersistenceCollector_DataIntegrity 测试数据完整性
func TestPersistenceCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	persistenceInfo := result.Data.(*core.PersistenceInfo)

	// 验证持久化项目完整性
	for i, item := range persistenceInfo.Items {
		if item.Type == "" {
			t.Errorf("Persistence item %d should have type", i)
		}
		if item.Name == "" {
			t.Errorf("Persistence item %d should have name", i)
		}
		if item.Path == "" {
			t.Errorf("Persistence item %d should have path", i)
		}
		if item.User == "" {
			t.Errorf("Persistence item %d should have user", i)
		}
		if item.Properties == nil {
			t.Errorf("Persistence item %d should have properties", i)
		}
	}
}

// TestPersistenceCollector_PlatformSpecific 测试平台特定功能
func TestPersistenceCollector_PlatformSpecific(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true) // 强制使用通用方法
	collector := NewPersistenceCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	persistenceInfo := result.Data.(*core.PersistenceInfo)

	// 验证根据当前平台返回了相应的持久化项目
	hasExpectedItems := false

	switch runtime.GOOS {
	case "windows":
		// Windows应该有注册表和服务项目
		for _, item := range persistenceInfo.Items {
			if item.Type == "registry" || item.Type == "service" {
				hasExpectedItems = true
				break
			}
		}
	case "linux":
		// Linux应该有systemd或cron项目
		for _, item := range persistenceInfo.Items {
			if item.Type == "systemd_service" || item.Type == "cron" {
				hasExpectedItems = true
				break
			}
		}
	case "darwin":
		// macOS应该有launch项目
		for _, item := range persistenceInfo.Items {
			if item.Type == "launch_daemon" || item.Type == "launch_agent" {
				hasExpectedItems = true
				break
			}
		}
	}

	if !hasExpectedItems {
		t.Errorf("Should have platform-specific persistence items for %s", runtime.GOOS)
	}
}

// TestPersistenceCollector_ItemTypes 测试持久化项目类型
func TestPersistenceCollector_ItemTypes(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	persistenceInfo := result.Data.(*core.PersistenceInfo)

	// 验证持久化项目类型的有效性
	validTypes := map[string]bool{
		"startup":         true,
		"registry":        true,
		"service":         true,
		"systemd_service": true,
		"cron":            true,
		"init_script":     true,
		"xdg_autostart":   true,
		"launch_daemon":   true,
		"launch_agent":    true,
		"login_item":      true,
	}

	for i, item := range persistenceInfo.Items {
		if !validTypes[item.Type] {
			t.Errorf("Persistence item %d has invalid type: %s", i, item.Type)
		}
	}
}

// TestPersistenceCollector_Properties 测试持久化项目属性
func TestPersistenceCollector_Properties(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	persistenceInfo := result.Data.(*core.PersistenceInfo)

	// 验证持久化项目属性
	for i, item := range persistenceInfo.Items {
		// 所有项目都应该有location属性
		if location, exists := item.Properties["location"]; !exists || location == "" {
			t.Errorf("Persistence item %d should have location property", i)
		}

		// 验证启用状态是合理的
		if item.Type == "registry" || item.Type == "service" {
			// 注册表和服务项目通常是启用的
			if !item.Enabled {
				t.Errorf("Persistence item %d of type %s should typically be enabled", i, item.Type)
			}
		}
	}
}

// TestPersistenceCollector_UserContext 测试用户上下文
func TestPersistenceCollector_UserContext(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewPersistenceCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	persistenceInfo := result.Data.(*core.PersistenceInfo)

	// 验证用户上下文的合理性
	hasSystemItems := false
	hasUserItems := false

	for _, item := range persistenceInfo.Items {
		if item.User == "root" || item.User == "SYSTEM" {
			hasSystemItems = true
		}
		if item.User == "current_user" {
			hasUserItems = true
		}
	}

	// 应该同时有系统级和用户级的持久化项目
	if !hasSystemItems {
		t.Error("Should have system-level persistence items")
	}
	if !hasUserItems {
		t.Error("Should have user-level persistence items")
	}
}
