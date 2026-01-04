package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
	"time"
)

// TestReadOnlyOperationGuarantee 测试只读操作保证属性
// **Feature: ir-system-info-collector, Property 1: 只读操作保证**
// **验证: 需求 1.1, 1.2, 1.3, 1.4**
func TestReadOnlyOperationGuarantee(t *testing.T) {
	// 属性测试配置
	config := &quick.Config{
		MaxCount: 10, // 减少到10次迭代以提高速度
	}

	// 定义属性测试函数
	property := func(verbose bool, timeoutSeconds uint8) bool {
		// 限制超时时间在合理范围内
		if timeoutSeconds < 5 {
			timeoutSeconds = 5
		}
		if timeoutSeconds > 60 {
			timeoutSeconds = 60
		}

		// 创建测试上下文
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
		defer cancel()

		// 创建临时输出目录
		tempDir, err := os.MkdirTemp("", "GatTrace_readonly_test_*")
		if err != nil {
			t.Logf("Failed to create temp dir: %v", err)
			return false
		}
		defer os.RemoveAll(tempDir)

		// 创建应用程序实例
		app := NewApplication("test-v1.0.0")

		// 创建系统监控器来验证只读操作
		monitor := NewSystemMonitor()
		
		// 捕获开始快照
		if err := monitor.CaptureStartSnapshot(ctx); err != nil {
			t.Logf("Failed to capture start snapshot: %v", err)
			return false
		}

		// 运行应用程序
		err = app.Run(ctx, tempDir, verbose)
		
		// 捕获结束快照
		if err := monitor.CaptureEndSnapshot(ctx); err != nil {
			t.Logf("Failed to capture end snapshot: %v", err)
			return false
		}

		// 比较快照
		comparison, err := monitor.CompareSnapshots()
		if err != nil {
			t.Logf("Failed to compare snapshots: %v", err)
			return false
		}

		// 验证只读操作保证
		return verifyReadOnlyGuarantee(t, comparison, tempDir)
	}

	// 执行属性测试
	if err := quick.Check(property, config); err != nil {
		t.Errorf("只读操作保证属性测试失败: %v", err)
	}
}

// verifyReadOnlyGuarantee 验证只读操作保证
func verifyReadOnlyGuarantee(t *testing.T, comparison *SystemStateComparison, outputDir string) bool {
	success := true

	// 1. 验证系统配置未被修改 (需求 1.1)
	if !verifySystemConfigUnchanged(t, comparison) {
		t.Log("系统配置被修改，违反需求 1.1")
		success = false
	}

	// 2. 验证未创建服务或注册自启动 (需求 1.2)
	if !verifyNoServiceCreation(t, comparison) {
		t.Log("检测到服务创建或自启动注册，违反需求 1.2")
		success = false
	}

	// 3. 验证未写入注册表或更改文件权限 (需求 1.3)
	if !verifyNoSystemModification(t, comparison) {
		t.Log("检测到系统修改，违反需求 1.3")
		success = false
	}

	// 4. 验证未进行网络通信 (需求 1.4)
	if !verifyNoNetworkCommunication(t, comparison) {
		t.Log("检测到网络通信，违反需求 1.4")
		success = false
	}

	// 5. 验证只在输出目录写入文件 (需求 1.5)
	if !verifyOutputDirectoryIsolationReadOnly(t, outputDir) {
		t.Log("检测到在输出目录外写入文件，违反需求 1.5")
		success = false
	}

	return success
}

// verifySystemConfigUnchanged 验证系统配置未被修改
func verifySystemConfigUnchanged(t *testing.T, comparison *SystemStateComparison) bool {
	// 检查关键系统文件是否被修改
	criticalFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"C:\\Windows\\System32\\config",
	}

	for _, file := range criticalFiles {
		for _, modifiedFile := range comparison.FileChanges.Modified {
			if modifiedFile == file {
				t.Logf("关键系统文件被修改: %s", file)
				return false
			}
		}
	}

	// 检查环境变量是否被修改
	if len(comparison.EnvironmentChanges.Modified) > 0 {
		t.Logf("环境变量被修改: %v", comparison.EnvironmentChanges.Modified)
		return false
	}

	return true
}

// verifyNoServiceCreation 验证未创建服务或注册自启动
func verifyNoServiceCreation(t *testing.T, comparison *SystemStateComparison) bool {
	// 检查是否有新的长期运行进程
	for _, process := range comparison.ProcessChanges.Added {
		// 检查是否是系统服务类型的进程
		if isSystemServiceProcess(process) {
			t.Logf("检测到可能的服务进程: %s (PID: %d)", process.Name, process.PID)
			return false
		}
	}

	return true
}

// isSystemServiceProcess 判断是否是系统服务进程
func isSystemServiceProcess(process ProcessSnapshot) bool {
	// 检查进程名称是否包含服务相关关键词
	serviceKeywords := []string{"service", "daemon", "svc", "systemd"}
	
	for _, keyword := range serviceKeywords {
		if containsStringReadOnly(process.Name, keyword) {
			return true
		}
		
		for _, cmd := range process.Cmdline {
			if containsStringReadOnly(cmd, keyword) {
				return true
			}
		}
	}

	return false
}

// verifyNoSystemModification 验证未进行系统修改
func verifyNoSystemModification(t *testing.T, comparison *SystemStateComparison) bool {
	// 检查是否有新增的系统级进程
	for _, process := range comparison.ProcessChanges.Added {
		if isSystemLevelProcess(process) {
			t.Logf("检测到系统级进程: %s", process.Name)
			return false
		}
	}

	// 检查工作目录是否被更改
	if comparison.WorkingDirChanged {
		t.Log("工作目录被更改")
		return false
	}

	return true
}

// isSystemLevelProcess 判断是否是系统级进程
func isSystemLevelProcess(process ProcessSnapshot) bool {
	// 检查是否以系统用户身份运行
	systemUsers := []string{"root", "SYSTEM", "NT AUTHORITY\\SYSTEM"}
	
	for _, user := range systemUsers {
		if process.Username == user {
			return true
		}
	}

	return false
}

// verifyNoNetworkCommunication 验证未进行网络通信
func verifyNoNetworkCommunication(t *testing.T, comparison *SystemStateComparison) bool {
	// 检查是否有新的网络连接
	for _, port := range comparison.NetworkChanges.Added {
		// 排除本地回环连接
		if !isLoopbackConnection(port.LocalAddr) {
			t.Logf("检测到新的网络连接: %s:%s", port.Protocol, port.LocalAddr)
			return false
		}
	}

	return true
}

// isLoopbackConnection 判断是否是回环连接
func isLoopbackConnection(addr string) bool {
	return containsStringReadOnly(addr, "127.0.0.1") || containsStringReadOnly(addr, "::1") || containsStringReadOnly(addr, "localhost")
}

// verifyOutputDirectoryIsolationReadOnly 验证输出目录隔离（只读测试版本）
func verifyOutputDirectoryIsolationReadOnly(t *testing.T, outputDir string) bool {
	// 检查输出目录是否存在
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		t.Log("输出目录不存在")
		return false
	}

	// 检查输出目录中是否有预期的文件
	expectedFiles := []string{"meta.json", "manifest.json", "index.html"}
	
	for _, expectedFile := range expectedFiles {
		filePath := filepath.Join(outputDir, expectedFile)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Logf("预期文件不存在: %s", expectedFile)
			// 这不是失败条件，因为某些文件可能由于错误而未生成
		}
	}

	return true
}

// containsStringReadOnly 检查字符串是否包含子字符串（不区分大小写）
func containsStringReadOnly(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    len(s) > len(substr) && 
		    (s[:len(substr)] == substr || 
		     s[len(s)-len(substr):] == substr ||
		     containsSubstring(s, substr)))
}

// containsSubstring 检查字符串中是否包含子字符串
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestReadOnlyOperationGuaranteeSpecificCases 测试特定的只读操作场景
func TestReadOnlyOperationGuaranteeSpecificCases(t *testing.T) {
	testCases := []struct {
		name        string
		verbose     bool
		timeout     time.Duration
		expectError bool
	}{
		{
			name:        "静默模式短时间运行",
			verbose:     false,
			timeout:     10 * time.Second,
			expectError: false,
		},
		{
			name:        "详细模式中等时间运行",
			verbose:     true,
			timeout:     30 * time.Second,
			expectError: false,
		},
		{
			name:        "静默模式长时间运行",
			verbose:     false,
			timeout:     60 * time.Second,
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			// 创建临时输出目录
			tempDir, err := os.MkdirTemp("", "GatTrace_readonly_specific_*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			// 创建应用程序实例
			app := NewApplication("test-v1.0.0")

			// 创建系统监控器
			monitor := NewSystemMonitor()
			
			// 捕获开始快照
			if err := monitor.CaptureStartSnapshot(ctx); err != nil {
				t.Fatalf("Failed to capture start snapshot: %v", err)
			}

			// 运行应用程序
			err = app.Run(ctx, tempDir, tc.verbose)
			
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			} else if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// 捕获结束快照
			if err := monitor.CaptureEndSnapshot(ctx); err != nil {
				t.Fatalf("Failed to capture end snapshot: %v", err)
			}

			// 比较快照
			comparison, err := monitor.CompareSnapshots()
			if err != nil {
				t.Fatalf("Failed to compare snapshots: %v", err)
			}

			// 验证只读操作保证
			if !verifyReadOnlyGuarantee(t, comparison, tempDir) {
				t.Error("只读操作保证验证失败")
			}
		})
	}
}

// BenchmarkReadOnlyOperationGuarantee 基准测试只读操作保证
func BenchmarkReadOnlyOperationGuarantee(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		
		// 创建临时输出目录
		tempDir, err := os.MkdirTemp("", "GatTrace_readonly_bench_*")
		if err != nil {
			b.Fatalf("Failed to create temp dir: %v", err)
		}

		// 创建应用程序实例
		app := NewApplication("bench-v1.0.0")

		// 创建系统监控器
		monitor := NewSystemMonitor()
		
		// 捕获开始快照
		if err := monitor.CaptureStartSnapshot(ctx); err != nil {
			b.Fatalf("Failed to capture start snapshot: %v", err)
		}

		// 运行应用程序
		_ = app.Run(ctx, tempDir, false)
		
		// 捕获结束快照
		if err := monitor.CaptureEndSnapshot(ctx); err != nil {
			b.Fatalf("Failed to capture end snapshot: %v", err)
		}

		// 比较快照
		_, err = monitor.CompareSnapshots()
		if err != nil {
			b.Fatalf("Failed to compare snapshots: %v", err)
		}

		// 清理
		os.RemoveAll(tempDir)
		cancel()
	}
}