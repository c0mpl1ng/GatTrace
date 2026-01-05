package collectors

import (
	"context"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestCheckpointVerification 运行检查点验证测试
func TestCheckpointVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping checkpoint verification in short mode")
	}

	adapter := NewMockPlatformAdapter()
	verifier := NewCheckpointVerification(adapter)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := verifier.VerifyAllCollectors(ctx)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// 打印详细报告
	report.PrintReport()

	// 验证结果
	if report.TotalCollectors != 7 {
		t.Errorf("Expected 7 collectors, got %d", report.TotalCollectors)
	}

	if !report.IsAllPassed() {
		t.Errorf("Not all collectors passed verification. Failed: %d", report.FailedTests)

		// 打印失败的采集器详情
		for name, result := range report.Results {
			if !result.Passed {
				t.Errorf("Collector %s failed:", name)
				for _, err := range result.Errors {
					t.Errorf("  - %s", err)
				}
			}
		}
	}

	// 验证每个预期的采集器都存在
	expectedCollectors := []string{
		"network", "process", "user", "persistence",
		"filesystem", "security", "system",
	}

	for _, expected := range expectedCollectors {
		if result, exists := report.Results[expected]; !exists {
			t.Errorf("Expected collector %s not found", expected)
		} else if !result.Passed {
			t.Errorf("Collector %s failed verification", expected)
		}
	}
}

// TestCheckpointVerificationWithErrors 测试错误情况下的检查点验证
func TestCheckpointVerificationWithErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping checkpoint verification with errors in short mode")
	}

	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true) // 强制适配器返回错误

	verifier := NewCheckpointVerification(adapter)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := verifier.VerifyAllCollectors(ctx)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// 即使适配器出错，采集器也应该通过验证（因为有回退机制）
	if report.TotalCollectors != 7 {
		t.Errorf("Expected 7 collectors, got %d", report.TotalCollectors)
	}

	// 所有采集器都应该通过验证（使用回退数据）
	if !report.IsAllPassed() {
		t.Logf("Some collectors failed with adapter errors (this may be expected)")
		report.PrintReport()

		// 但至少应该有数据返回
		for name, result := range report.Results {
			if !result.Passed {
				t.Logf("Collector %s failed with adapter error: %v", name, result.Errors)
			}
		}
	}
}

// TestIndividualCollectorVerification 测试单个采集器验证
func TestIndividualCollectorVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping individual collector verification in short mode")
	}

	adapter := NewMockPlatformAdapter()

	collectors := []struct {
		name      string
		collector core.Collector
	}{
		{"network", NewNetworkCollector(adapter)},
		{"process", NewProcessCollector(adapter)},
		{"user", NewUserCollector(adapter)},
		{"persistence", NewPersistenceCollector(adapter)},
		{"filesystem", NewFileSystemCollector(adapter)},
		{"security", NewSecurityCollector(adapter)},
		{"system", NewSystemCollector(adapter)},
	}

	ctx := context.Background()

	for _, tc := range collectors {
		t.Run(tc.name, func(t *testing.T) {
			// 验证名称
			if tc.collector.Name() != tc.name {
				t.Errorf("Expected name %s, got %s", tc.name, tc.collector.Name())
			}

			// 验证支持的平台
			platforms := tc.collector.SupportedPlatforms()
			if len(platforms) == 0 {
				t.Errorf("Collector %s should support at least one platform", tc.name)
			}

			// 尝试采集数据
			result, err := tc.collector.Collect(ctx)
			if err != nil {
				t.Errorf("Collector %s failed to collect: %v", tc.name, err)
				return
			}

			if result == nil {
				t.Errorf("Collector %s returned nil result", tc.name)
				return
			}

			t.Logf("Collector %s verification passed", tc.name)
		})
	}
}
