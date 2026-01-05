package collectors

import (
	"context"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestSystemCollector_Basic 测试系统采集器基本功能
func TestSystemCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 测试基本属性
	if collector.Name() != "system" {
		t.Errorf("Expected name 'system', got '%s'", collector.Name())
	}

	if collector.RequiresPrivileges() {
		t.Error("System collector should not require privileges")
	}

	expectedPlatforms := []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}

	supportedPlatforms := collector.SupportedPlatforms()
	if len(supportedPlatforms) != len(expectedPlatforms) {
		t.Errorf("Expected %d supported platforms, got %d", len(expectedPlatforms), len(supportedPlatforms))
	}

	for i, platform := range expectedPlatforms {
		if supportedPlatforms[i] != platform {
			t.Errorf("Expected platform %v at index %d, got %v", platform, i, supportedPlatforms[i])
		}
	}
}

// TestSystemCollector_Collect_Success 测试成功采集
func TestSystemCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 模拟成功的系统状态
	expectedSystemStatus := &core.SystemStatus{
		Metadata: core.Metadata{
			SessionID:        "test-session",
			Hostname:         "test-host",
			Platform:         "test-platform",
			CollectedAt:      time.Now().UTC(),
			CollectorVersion: "1.0.0",
		},
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
	}

	adapter.systemStatus = expectedSystemStatus

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Errors) != 0 {
		t.Errorf("Expected no errors, got %d errors", len(result.Errors))
	}

	systemStatus, ok := result.Data.(*core.SystemStatus)
	if !ok {
		t.Fatalf("Expected SystemStatus, got %T", result.Data)
	}

	if systemStatus.Metadata.SessionID != expectedSystemStatus.Metadata.SessionID {
		t.Errorf("Expected session ID '%s', got '%s'", expectedSystemStatus.Metadata.SessionID, systemStatus.Metadata.SessionID)
	}

	if len(systemStatus.KernelModules) != 1 {
		t.Errorf("Expected 1 kernel module, got %d", len(systemStatus.KernelModules))
	}

	if systemStatus.NTPStatus.Synchronized != true {
		t.Error("Expected NTP to be synchronized")
	}

	if systemStatus.Integrity.Status != "healthy" {
		t.Errorf("Expected integrity status 'healthy', got '%s'", systemStatus.Integrity.Status)
	}
}

// TestSystemCollector_Collect_AdapterError 测试适配器错误处理
func TestSystemCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 模拟适配器错误
	adapter.shouldFailSystemStatus = true

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	// 应该回退到通用方法，不应该返回错误
	if err != nil {
		t.Fatalf("Expected no error with fallback, got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected at least one error from adapter failure")
	}

	// 检查错误类型
	if result.Errors[0].Module != "system" {
		t.Errorf("Expected error module 'system', got '%s'", result.Errors[0].Module)
	}

	if result.Errors[0].Severity != core.SeverityError {
		t.Errorf("Expected error severity %v, got %v", core.SeverityError, result.Errors[0].Severity)
	}
}

// TestSystemCollector_Collect_ContextCancellation 测试上下文取消
func TestSystemCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 让适配器失败，这样会使用通用方法
	adapter.shouldFailSystemStatus = true

	// 创建已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := collector.Collect(ctx)

	// 应该处理上下文取消
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}

	if result == nil {
		t.Fatal("Expected result even with error")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected errors due to context cancellation")
	}
}

// TestSystemCollector_Collect_Timeout 测试超时处理
func TestSystemCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 让适配器失败，这样会使用通用方法
	adapter.shouldFailSystemStatus = true

	// 创建已经超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// 等待确保上下文超时
	time.Sleep(1 * time.Millisecond)

	result, err := collector.Collect(ctx)

	// 应该处理超时
	if err == nil {
		t.Error("Expected error due to timeout")
	}

	if result == nil {
		t.Fatal("Expected result even with timeout")
	}
}

// TestSystemCollector_DataIntegrity 测试数据完整性
func TestSystemCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 设置测试数据
	expectedSystemStatus := &core.SystemStatus{
		Metadata: core.Metadata{
			SessionID:        "integrity-test",
			Hostname:         "integrity-host",
			Platform:         "test-platform",
			CollectedAt:      time.Now().UTC(),
			CollectorVersion: "1.0.0",
		},
		BootTime: time.Now().Add(-4 * time.Hour),
		Uptime:   4 * time.Hour,
		NTPStatus: &core.NTPStatus{
			Synchronized: false,
			Error:        "NTP server unreachable",
		},
		KernelModules: []core.KernelModule{
			{
				Name:        "module1",
				Path:        "/lib/modules/module1.ko",
				Version:     "2.0.0",
				Description: "First test module",
				Size:        2048,
				Signed:      true,
			},
			{
				Name:        "module2",
				Path:        "/lib/modules/module2.ko",
				Version:     "1.5.0",
				Description: "Second test module",
				Size:        1536,
				Signed:      false,
			},
		},
		Integrity: &core.SystemIntegrity{
			Status:      "issues_found",
			LastCheck:   time.Now().Add(-6 * time.Hour),
			Issues:      []string{"Missing file: /etc/important.conf", "Checksum mismatch: /bin/critical"},
			CheckMethod: "aide",
		},
	}

	adapter.systemStatus = expectedSystemStatus

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	systemStatus := result.Data.(*core.SystemStatus)

	// 验证元数据完整性
	if systemStatus.Metadata.SessionID != expectedSystemStatus.Metadata.SessionID {
		t.Error("Session ID mismatch")
	}

	if systemStatus.Metadata.Hostname != expectedSystemStatus.Metadata.Hostname {
		t.Error("Hostname mismatch")
	}

	// 验证系统状态数据
	if systemStatus.Uptime != expectedSystemStatus.Uptime {
		t.Error("Uptime mismatch")
	}

	// 验证NTP状态
	if systemStatus.NTPStatus.Synchronized != expectedSystemStatus.NTPStatus.Synchronized {
		t.Error("NTP synchronized status mismatch")
	}

	if systemStatus.NTPStatus.Error != expectedSystemStatus.NTPStatus.Error {
		t.Error("NTP error message mismatch")
	}

	// 验证内核模块数据
	if len(systemStatus.KernelModules) != len(expectedSystemStatus.KernelModules) {
		t.Errorf("Expected %d kernel modules, got %d", len(expectedSystemStatus.KernelModules), len(systemStatus.KernelModules))
	}

	for i, expectedModule := range expectedSystemStatus.KernelModules {
		if i >= len(systemStatus.KernelModules) {
			break
		}

		actualModule := systemStatus.KernelModules[i]
		if actualModule.Name != expectedModule.Name {
			t.Errorf("Module %d name mismatch: expected '%s', got '%s'", i, expectedModule.Name, actualModule.Name)
		}

		if actualModule.Size != expectedModule.Size {
			t.Errorf("Module %d size mismatch: expected %d, got %d", i, expectedModule.Size, actualModule.Size)
		}

		if actualModule.Signed != expectedModule.Signed {
			t.Errorf("Module %d signed status mismatch: expected %v, got %v", i, expectedModule.Signed, actualModule.Signed)
		}
	}

	// 验证完整性检查数据
	if systemStatus.Integrity.Status != expectedSystemStatus.Integrity.Status {
		t.Error("Integrity status mismatch")
	}

	if len(systemStatus.Integrity.Issues) != len(expectedSystemStatus.Integrity.Issues) {
		t.Errorf("Expected %d integrity issues, got %d", len(expectedSystemStatus.Integrity.Issues), len(systemStatus.Integrity.Issues))
	}

	for i, expectedIssue := range expectedSystemStatus.Integrity.Issues {
		if i >= len(systemStatus.Integrity.Issues) {
			break
		}

		if systemStatus.Integrity.Issues[i] != expectedIssue {
			t.Errorf("Integrity issue %d mismatch: expected '%s', got '%s'", i, expectedIssue, systemStatus.Integrity.Issues[i])
		}
	}
}

// TestSystemCollector_PlatformSpecific 测试平台特定功能
func TestSystemCollector_PlatformSpecific(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	// 测试不同平台的支持
	platforms := collector.SupportedPlatforms()

	expectedPlatforms := map[core.Platform]bool{
		core.PlatformWindows: true,
		core.PlatformLinux:   true,
		core.PlatformDarwin:  true,
	}

	for _, platform := range platforms {
		if !expectedPlatforms[platform] {
			t.Errorf("Unexpected platform support: %v", platform)
		}
	}

	// 验证所有预期平台都被支持
	for platform := range expectedPlatforms {
		found := false
		for _, supportedPlatform := range platforms {
			if supportedPlatform == platform {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected platform %v not found in supported platforms", platform)
		}
	}
}

// TestSystemCollector_NTPStatusHandling 测试NTP状态处理
func TestSystemCollector_NTPStatusHandling(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	testCases := []struct {
		name        string
		ntpStatus   *core.NTPStatus
		expectError bool
	}{
		{
			name: "Synchronized NTP",
			ntpStatus: &core.NTPStatus{
				Synchronized: true,
				Server:       "pool.ntp.org",
				LastSync:     time.Now().Add(-5 * time.Minute),
				Offset:       2 * time.Millisecond,
			},
			expectError: false,
		},
		{
			name: "Unsynchronized NTP",
			ntpStatus: &core.NTPStatus{
				Synchronized: false,
				Error:        "NTP server unreachable",
			},
			expectError: false,
		},
		{
			name:        "NTP Status Error",
			ntpStatus:   nil,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			systemStatus := &core.SystemStatus{
				Metadata: core.Metadata{
					SessionID:        "ntp-test",
					Hostname:         "ntp-host",
					Platform:         "test-platform",
					CollectedAt:      time.Now().UTC(),
					CollectorVersion: "1.0.0",
				},
				BootTime:      time.Now().Add(-1 * time.Hour),
				Uptime:        1 * time.Hour,
				NTPStatus:     tc.ntpStatus,
				KernelModules: []core.KernelModule{},
				Integrity: &core.SystemIntegrity{
					Status:      "healthy",
					LastCheck:   time.Now().UTC(),
					Issues:      []string{},
					CheckMethod: "test",
				},
			}

			adapter.systemStatus = systemStatus
			if tc.expectError {
				adapter.shouldFailSystemStatus = true
			}

			ctx := context.Background()
			result, err := collector.Collect(ctx)

			if err != nil && !tc.expectError {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result != nil {
				resultStatus := result.Data.(*core.SystemStatus)
				if tc.ntpStatus != nil {
					if resultStatus.NTPStatus.Synchronized != tc.ntpStatus.Synchronized {
						t.Error("NTP synchronized status mismatch")
					}
				}
			}
		})
	}
}

// TestSystemCollector_IntegrityStatusHandling 测试完整性状态处理
func TestSystemCollector_IntegrityStatusHandling(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSystemCollector(adapter)

	testCases := []struct {
		name      string
		integrity *core.SystemIntegrity
	}{
		{
			name: "Healthy System",
			integrity: &core.SystemIntegrity{
				Status:      "healthy",
				LastCheck:   time.Now().Add(-1 * time.Hour),
				Issues:      []string{},
				CheckMethod: "sfc",
			},
		},
		{
			name: "System with Issues",
			integrity: &core.SystemIntegrity{
				Status:      "issues_found",
				LastCheck:   time.Now().Add(-2 * time.Hour),
				Issues:      []string{"File missing", "Checksum error"},
				CheckMethod: "aide",
			},
		},
		{
			name: "Unknown Status",
			integrity: &core.SystemIntegrity{
				Status:      "unknown",
				LastCheck:   time.Now().Add(-24 * time.Hour),
				Issues:      []string{},
				CheckMethod: "manual",
				Error:       "Unable to perform integrity check",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			systemStatus := &core.SystemStatus{
				Metadata: core.Metadata{
					SessionID:        "integrity-test",
					Hostname:         "integrity-host",
					Platform:         "test-platform",
					CollectedAt:      time.Now().UTC(),
					CollectorVersion: "1.0.0",
				},
				BootTime: time.Now().Add(-1 * time.Hour),
				Uptime:   1 * time.Hour,
				NTPStatus: &core.NTPStatus{
					Synchronized: true,
					Server:       "test.ntp.org",
				},
				KernelModules: []core.KernelModule{},
				Integrity:     tc.integrity,
			}

			adapter.systemStatus = systemStatus

			ctx := context.Background()
			result, err := collector.Collect(ctx)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			resultStatus := result.Data.(*core.SystemStatus)
			if resultStatus.Integrity.Status != tc.integrity.Status {
				t.Errorf("Expected integrity status '%s', got '%s'", tc.integrity.Status, resultStatus.Integrity.Status)
			}

			if len(resultStatus.Integrity.Issues) != len(tc.integrity.Issues) {
				t.Errorf("Expected %d integrity issues, got %d", len(tc.integrity.Issues), len(resultStatus.Integrity.Issues))
			}
		})
	}
}
