package collectors

import (
	"context"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestAllCollectorsIntegration 集成测试：验证所有采集器正常工作
func TestAllCollectorsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping all collectors integration test in short mode")
	}

	adapter := NewMockPlatformAdapter()

	// 创建所有采集器
	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 测试每个采集器
	for _, collector := range collectors {
		t.Run(collector.Name(), func(t *testing.T) {
			// 验证基本属性
			if collector.Name() == "" {
				t.Error("Collector should have a name")
			}

			platforms := collector.SupportedPlatforms()
			if len(platforms) == 0 {
				t.Error("Collector should support at least one platform")
			}

			// 验证采集功能
			result, err := collector.Collect(ctx)
			if err != nil {
				t.Errorf("Collector %s failed: %v", collector.Name(), err)
			}

			if result == nil {
				t.Errorf("Collector %s returned nil result", collector.Name())
			}

			if result.Data == nil {
				t.Errorf("Collector %s returned nil data", collector.Name())
			}

			// 验证元数据
			if !validateCollectorMetadata(t, collector.Name(), result.Data) {
				t.Errorf("Collector %s has invalid metadata", collector.Name())
			}
		})
	}
}

// validateCollectorMetadata 验证采集器元数据
func validateCollectorMetadata(t *testing.T, collectorName string, data interface{}) bool {
	// 这里重用了data_integrity_test.go中的验证逻辑
	return validateMetadataIntegrity(t, collectorName, data)
}

// TestCollectorErrorHandling 测试采集器错误处理
func TestCollectorErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping collector error handling test in short mode")
	}

	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true) // 强制适配器返回错误

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	ctx := context.Background()

	for _, collector := range collectors {
		t.Run(collector.Name()+"_error_handling", func(t *testing.T) {
			result, err := collector.Collect(ctx)

			// 采集器应该有错误恢复机制，不应该返回错误
			if err != nil {
				t.Errorf("Collector %s should handle adapter errors gracefully: %v", collector.Name(), err)
			}

			if result == nil {
				t.Errorf("Collector %s should return result even with adapter error", collector.Name())
			}

			// 应该有错误记录
			if len(result.Errors) == 0 {
				t.Errorf("Collector %s should record adapter errors", collector.Name())
			}

			// 数据应该仍然有效（来自回退机制）
			if result.Data == nil {
				t.Errorf("Collector %s should provide fallback data", collector.Name())
			}
		})
	}
}

// TestCollectorPlatformSupport 测试采集器平台支持
func TestCollectorPlatformSupport(t *testing.T) {
	adapter := NewMockPlatformAdapter()

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	expectedPlatforms := []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}

	for _, collector := range collectors {
		t.Run(collector.Name()+"_platform_support", func(t *testing.T) {
			platforms := collector.SupportedPlatforms()

			if len(platforms) != len(expectedPlatforms) {
				t.Errorf("Collector %s should support %d platforms, got %d",
					collector.Name(), len(expectedPlatforms), len(platforms))
			}

			// 验证所有预期平台都被支持
			for _, expectedPlatform := range expectedPlatforms {
				found := false
				for _, platform := range platforms {
					if platform == expectedPlatform {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Collector %s should support platform %v", collector.Name(), expectedPlatform)
				}
			}
		})
	}
}

// TestCollectorPrivilegeRequirements 测试采集器权限需求
func TestCollectorPrivilegeRequirements(t *testing.T) {
	adapter := NewMockPlatformAdapter()

	// 定义预期的权限需求
	expectedPrivileges := map[string]bool{
		"network":     false, // 网络信息通常不需要特权
		"process":     true,  // 进程信息通常需要特权
		"user":        true,  // 用户信息通常需要特权
		"persistence": true,  // 持久化机制通常需要特权
		"filesystem":  true,  // 文件系统扫描通常需要特权
		"security":    true,  // 安全日志通常需要特权
		"system":      false, // 基础系统信息通常不需要特权
	}

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	for _, collector := range collectors {
		t.Run(collector.Name()+"_privilege_requirements", func(t *testing.T) {
			expected, exists := expectedPrivileges[collector.Name()]
			if !exists {
				t.Errorf("Unknown collector: %s", collector.Name())
				return
			}

			actual := collector.RequiresPrivileges()
			if actual != expected {
				t.Errorf("Collector %s privilege requirement mismatch: expected %v, got %v",
					collector.Name(), expected, actual)
			}
		})
	}
}

// TestCollectorContextHandling 测试采集器上下文处理
func TestCollectorContextHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping collector context handling test in short mode")
	}

	adapter := NewMockPlatformAdapter()

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	for _, collector := range collectors {
		t.Run(collector.Name()+"_context_timeout", func(t *testing.T) {
			// 创建短超时的上下文
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			// 等待超时
			time.Sleep(2 * time.Millisecond)

			// 采集应该仍然成功（因为是快速操作）或优雅处理超时
			result, err := collector.Collect(ctx)

			// 不应该panic或返回严重错误
			if err != nil {
				// 如果返回错误，应该是上下文相关的错误
				t.Logf("Collector %s returned context error (acceptable): %v", collector.Name(), err)
			}

			if result != nil && result.Data == nil {
				t.Errorf("Collector %s should provide data or handle timeout gracefully", collector.Name())
			}
		})

		t.Run(collector.Name()+"_context_cancellation", func(t *testing.T) {
			// 创建已取消的上下文
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			// 采集应该处理取消的上下文
			result, err := collector.Collect(ctx)

			// 不应该panic
			if err != nil {
				t.Logf("Collector %s returned cancellation error (acceptable): %v", collector.Name(), err)
			}

			if result != nil && result.Data == nil {
				t.Errorf("Collector %s should provide data or handle cancellation gracefully", collector.Name())
			}
		})
	}
}

// TestCollectorDataConsistency 测试采集器数据一致性
func TestCollectorDataConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping collector data consistency test in short mode")
	}

	adapter := NewMockPlatformAdapter()

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	ctx := context.Background()

	for _, collector := range collectors {
		t.Run(collector.Name()+"_data_consistency", func(t *testing.T) {
			// 多次运行同一个采集器
			var results []*core.CollectionResult
			for i := 0; i < 3; i++ {
				result, err := collector.Collect(ctx)
				if err != nil {
					t.Fatalf("Collection %d failed: %v", i, err)
				}
				results = append(results, result)
			}

			// 验证多次采集的结构一致性
			for i := 1; i < len(results); i++ {
				if !compareDataStructures(results[0].Data, results[i].Data) {
					t.Errorf("Collector %s collection %d data structure differs from first collection",
						collector.Name(), i)
				}
			}
		})
	}
}
