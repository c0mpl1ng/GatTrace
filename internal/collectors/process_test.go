package collectors

import (
	"context"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestProcessCollector_Basic 测试进程采集器基本功能
func TestProcessCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

	// 测试基本属性
	if collector.Name() != "process" {
		t.Errorf("Expected name 'process', got '%s'", collector.Name())
	}

	if !collector.RequiresPrivileges() {
		t.Error("Process collector should require privileges")
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

// TestProcessCollector_Collect_Success 测试成功的进程信息采集
func TestProcessCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

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

	processInfo, ok := result.Data.(*core.ProcessInfo)
	if !ok {
		t.Fatal("Result data should be ProcessInfo")
	}

	// 验证进程信息结构
	if len(processInfo.Processes) == 0 {
		t.Error("Should have at least one process")
	}

	// 验证元数据
	if processInfo.Metadata.SessionID == "" {
		t.Error("Metadata should have session ID")
	}

	if processInfo.Metadata.Hostname == "" {
		t.Error("Metadata should have hostname")
	}

	if processInfo.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	if processInfo.Metadata.CollectorVersion == "" {
		t.Error("Metadata should have collector version")
	}

	if processInfo.Metadata.CollectedAt.IsZero() {
		t.Error("Metadata should have collection timestamp")
	}
}

// TestProcessCollector_Collect_AdapterError 测试适配器错误时的回退机制
func TestProcessCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)
	collector := NewProcessCollector(adapter)

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
	if adapterError.Module != "process" {
		t.Errorf("Expected error module 'process', got '%s'", adapterError.Module)
	}

	if adapterError.Operation != "GetProcessInfo" {
		t.Errorf("Expected error operation 'GetProcessInfo', got '%s'", adapterError.Operation)
	}

	if adapterError.Severity != core.SeverityError {
		t.Errorf("Expected error severity 'error', got '%v'", adapterError.Severity)
	}

	// 数据应该来自通用方法
	processInfo, ok := result.Data.(*core.ProcessInfo)
	if !ok {
		t.Fatal("Result data should be ProcessInfo")
	}

	// 验证基本结构存在
	if processInfo.Processes == nil {
		t.Error("Processes should not be nil")
	}
}

// TestProcessCollector_Collect_ContextCancellation 测试上下文取消
func TestProcessCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

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

// TestProcessCollector_Collect_Timeout 测试超时处理
func TestProcessCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

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

// TestProcessCollector_DataIntegrity 测试数据完整性
func TestProcessCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	processInfo := result.Data.(*core.ProcessInfo)

	// 验证进程信息完整性
	for i, proc := range processInfo.Processes {
		if proc.PID <= 0 {
			t.Errorf("Process %d should have positive PID", i)
		}
		if proc.Name == "" {
			t.Errorf("Process %d should have name", i)
		}
		if proc.CreateTime.IsZero() {
			t.Errorf("Process %d should have create time", i)
		}
		if proc.Status == "" {
			t.Errorf("Process %d should have status", i)
		}
	}
}

// TestProcessCollector_ProcessFiltering 测试进程过滤
func TestProcessCollector_ProcessFiltering(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	processInfo := result.Data.(*core.ProcessInfo)

	// 验证进程列表不为空
	if len(processInfo.Processes) == 0 {
		t.Error("Should have at least one process")
	}

	// 验证进程信息的基本字段
	foundInit := false
	foundSshd := false
	
	for _, proc := range processInfo.Processes {
		if proc.Name == "init" && proc.PID == 1 {
			foundInit = true
			if proc.PPID != 0 {
				t.Error("Init process should have PPID 0")
			}
		}
		if proc.Name == "sshd" && proc.PID == 1234 {
			foundSshd = true
			if proc.PPID != 1 {
				t.Error("SSH daemon should have PPID 1")
			}
		}
	}

	if !foundInit {
		t.Error("Should find init process")
	}
	if !foundSshd {
		t.Error("Should find sshd process")
	}
}

// TestProcessCollector_HashCalculation 测试哈希计算
func TestProcessCollector_HashCalculation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewProcessCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	processInfo := result.Data.(*core.ProcessInfo)

	// 验证至少有一个进程有哈希值
	hasHashFound := false
	for _, proc := range processInfo.Processes {
		if proc.ExeHash != "" {
			hasHashFound = true
			// 验证哈希格式（应该是64个十六进制字符）
			if len(proc.ExeHash) != 64 {
				t.Errorf("Process %s hash should be 64 characters, got %d", proc.Name, len(proc.ExeHash))
			}
		}
	}

	if !hasHashFound {
		t.Error("Should have at least one process with hash")
	}
}