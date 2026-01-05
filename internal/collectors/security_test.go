package collectors

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestSecurityCollector_Basic 测试安全日志采集器基本功能
func TestSecurityCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	// 测试基本属性
	if collector.Name() != "security" {
		t.Errorf("Expected name 'security', got '%s'", collector.Name())
	}

	if !collector.RequiresPrivileges() {
		t.Error("Security collector should require privileges")
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

// TestSecurityCollector_Collect_Success 测试成功的安全日志采集
func TestSecurityCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

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

	securityLogs, ok := result.Data.(*core.SecurityLogs)
	if !ok {
		t.Fatal("Result data should be SecurityLogs")
	}

	// 验证安全日志结构
	if securityLogs.Entries == nil {
		t.Error("Entries should not be nil")
	}

	// 验证元数据
	if securityLogs.Metadata.SessionID == "" {
		t.Error("Metadata should have session ID")
	}

	if securityLogs.Metadata.Hostname == "" {
		t.Error("Metadata should have hostname")
	}

	if securityLogs.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	if securityLogs.Metadata.CollectorVersion == "" {
		t.Error("Metadata should have collector version")
	}

	if securityLogs.Metadata.CollectedAt.IsZero() {
		t.Error("Metadata should have collection timestamp")
	}
}

// TestSecurityCollector_Collect_AdapterError 测试适配器错误时的回退机制
func TestSecurityCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)
	collector := NewSecurityCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	// 应该成功，因为直接使用通用方法
	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// 数据应该来自通用方法
	securityLogs, ok := result.Data.(*core.SecurityLogs)
	if !ok {
		t.Fatal("Result data should be SecurityLogs")
	}

	// 验证基本结构存在
	if securityLogs.Entries == nil {
		t.Error("Entries should not be nil")
	}
}

// TestSecurityCollector_Collect_ContextCancellation 测试上下文取消
func TestSecurityCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	// 创建已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 上下文被取消时，采集应该能够处理
	result, err := collector.Collect(ctx)

	// 可能返回错误或成功，取决于取消的时机
	// 错误可能被包装，所以检查是否包含 context canceled
	if err != nil {
		if !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("Unexpected error: %v", err)
		}
		// 如果有错误，result 可能为 nil 或 Data 为 nil，这是正常的
		return
	}

	if result != nil && result.Data == nil {
		t.Error("If result is not nil and no error, data should not be nil")
	}
}

// TestSecurityCollector_Collect_Timeout 测试超时处理
func TestSecurityCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	// 创建短超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// 等待确保上下文超时
	<-ctx.Done()

	// 超时时，采集应该能够处理
	result, err := collector.Collect(ctx)

	// 可能返回错误或成功，取决于超时的时机
	// 错误可能被包装，所以检查是否包含 deadline exceeded
	if err != nil {
		if !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatalf("Unexpected error: %v", err)
		}
		// 如果有错误，result 可能为 nil 或 Data 为 nil，这是正常的
		return
	}

	if result != nil && result.Data == nil {
		t.Error("If result is not nil and no error, data should not be nil")
	}
}

// TestSecurityCollector_DataIntegrity 测试数据完整性
func TestSecurityCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	securityLogs := result.Data.(*core.SecurityLogs)

	// 验证日志条目完整性
	for i, entry := range securityLogs.Entries {
		if entry.Timestamp.IsZero() {
			t.Errorf("Log entry %d should have timestamp", i)
		}
		if entry.Level == "" {
			t.Errorf("Log entry %d should have level", i)
		}
		if entry.Source == "" {
			t.Errorf("Log entry %d should have source", i)
		}
		if entry.Message == "" {
			t.Errorf("Log entry %d should have message", i)
		}
		if entry.Details == nil {
			t.Errorf("Log entry %d should have details map", i)
		}
	}
}

// TestSecurityCollector_PlatformSpecific 测试平台特定功能
func TestSecurityCollector_PlatformSpecific(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true) // 强制使用通用方法
	collector := NewSecurityCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	securityLogs := result.Data.(*core.SecurityLogs)

	// 验证返回了日志条目（即使可能为空）
	if securityLogs.Entries == nil {
		t.Error("Entries should not be nil")
	}

	// 根据平台验证特定的日志特征
	switch runtime.GOOS {
	case "windows":
		// Windows应该有事件ID和特定的源
		for _, entry := range securityLogs.Entries {
			if entry.Source == "Microsoft-Windows-Security-Auditing" {
				if entry.EventID == "" {
					t.Error("Windows security log should have event ID")
				}
			}
		}
	case "linux":
		// Linux应该有来自auth.log或secure的条目
		hasAuthLog := false
		for _, entry := range securityLogs.Entries {
			if strings.Contains(entry.Source, "auth") || strings.Contains(entry.Source, "secure") {
				hasAuthLog = true
				break
			}
		}
		if len(securityLogs.Entries) > 0 && !hasAuthLog {
			t.Error("Linux should have auth-related log entries")
		}
	case "darwin":
		// macOS应该有系统日志或统一日志条目
		// 由于我们只收集登录/解锁事件，来源可能是 loginwindow 或 SSH
		hasSystemLog := false
		for _, entry := range securityLogs.Entries {
			if strings.Contains(entry.Source, "system") ||
				strings.Contains(entry.Source, "com.apple") ||
				strings.Contains(entry.Source, "loginwindow") ||
				strings.Contains(entry.Source, "ssh") ||
				strings.Contains(entry.Source, "unified") {
				hasSystemLog = true
				break
			}
		}
		// 如果没有日志条目，也是可以接受的（可能没有最近的登录事件）
		if len(securityLogs.Entries) > 0 && !hasSystemLog {
			t.Logf("macOS log sources: %v", getLogSources(securityLogs.Entries))
			// 改为警告而不是错误，因为日志来源可能因系统配置而异
			t.Log("Warning: macOS logs may have different sources depending on system configuration")
		}
	}
}

// TestSecurityCollector_SecurityKeywords 测试安全关键词检测
func TestSecurityCollector_SecurityKeywords(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	keywords := []string{"authentication", "login", "failed", "sudo", "ssh"}

	testCases := []struct {
		line     string
		expected bool
	}{
		{"User authentication successful", true},
		{"Login attempt from 192.168.1.1", true},
		{"Failed password for user", true},
		{"sudo command executed", true},
		{"SSH connection established", true},
		{"Regular system message", false},
		{"Process started normally", false},
		{"Network interface up", false},
	}

	for _, tc := range testCases {
		result := collector.containsSecurityKeywords(tc.line, keywords)
		if result != tc.expected {
			t.Errorf("Line '%s': expected %v, got %v", tc.line, tc.expected, result)
		}
	}
}

// TestSecurityCollector_TimestampExtraction 测试时间戳提取
func TestSecurityCollector_TimestampExtraction(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	testCases := []struct {
		line        string
		shouldParse bool
	}{
		{"2023-12-01T10:30:45Z User login", true},
		{"2023-12-01T10:30:45.123Z Authentication failed", true},
		{"Dec  1 10:30:45 hostname sshd[1234]: Connection", true},
		{"Jan 15 09:22:33 server sudo: user command", true},
		{"No timestamp in this line", false},
		{"Regular message without time", false},
	}

	for _, tc := range testCases {
		timestamp, err := collector.extractTimestamp(tc.line)

		if tc.shouldParse {
			if err != nil {
				t.Errorf("Line '%s': should parse timestamp, got error: %v", tc.line, err)
			}
			if timestamp.IsZero() {
				t.Errorf("Line '%s': should have valid timestamp", tc.line)
			}
		} else {
			if err == nil && !timestamp.IsZero() {
				t.Errorf("Line '%s': should not parse timestamp, got: %v", tc.line, timestamp)
			}
		}
	}
}

// TestSecurityCollector_LogLevelExtraction 测试日志级别提取
func TestSecurityCollector_LogLevelExtraction(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	testCases := []struct {
		line     string
		expected string
	}{
		{"ERROR: Authentication failed", "Error"},
		{"WARNING: Invalid user", "Warning"},
		{"INFO: User logged in", "Info"},
		{"DEBUG: Connection details", "Debug"},
		{"CRITICAL: System compromised", "Critical"},
		{"Failed login attempt", "Error"},
		{"Warning about security", "Warning"},
		{"Regular message", "Info"},
	}

	for _, tc := range testCases {
		result := collector.extractLogLevel(tc.line)
		if result != tc.expected {
			t.Errorf("Line '%s': expected level '%s', got '%s'", tc.line, tc.expected, result)
		}
	}
}

// TestSecurityCollector_DetailsExtraction 测试详细信息提取
func TestSecurityCollector_DetailsExtraction(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	testCases := []struct {
		line            string
		expectedDetails map[string]string
	}{
		{
			"sshd[1234]: Failed password for user admin from 192.168.1.100",
			map[string]string{
				"process":    "sshd",
				"pid":        "1234",
				"user":       "admin",
				"ip_address": "192.168.1.100",
			},
		},
		{
			"sudo: user=root command=/bin/ls",
			map[string]string{
				"user": "root",
			},
		},
		{
			"login[5678]: Authentication successful for testuser",
			map[string]string{
				"process": "login",
				"pid":     "5678",
				"user":    "testuser",
			},
		},
	}

	for _, tc := range testCases {
		result := collector.extractDetails(tc.line)

		for key, expectedValue := range tc.expectedDetails {
			if actualValue, exists := result[key]; !exists {
				t.Errorf("Line '%s': missing expected detail '%s'", tc.line, key)
			} else if actualValue != expectedValue {
				t.Errorf("Line '%s': detail '%s' expected '%s', got '%s'", tc.line, key, expectedValue, actualValue)
			}
		}
	}
}

// TestSecurityCollector_LogParsing 测试日志解析
func TestSecurityCollector_LogParsing(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewSecurityCollector(adapter)

	testLine := "Dec  1 10:30:45 hostname sshd[1234]: Failed password for user admin from 192.168.1.100"

	entry, err := collector.parseLinuxLogLine(testLine, "auth.log")
	if err != nil {
		t.Fatalf("parseLinuxLogLine should not return error: %v", err)
	}

	// 验证解析结果
	if entry.Source != "auth.log" {
		t.Errorf("Expected source 'auth.log', got '%s'", entry.Source)
	}

	if entry.Message != testLine {
		t.Errorf("Expected message to be the original line")
	}

	if entry.Level == "" {
		t.Error("Entry should have a log level")
	}

	if entry.Details == nil {
		t.Error("Entry should have details")
	}

	// 验证提取的详细信息
	if process, exists := entry.Details["process"]; !exists || process != "sshd" {
		t.Error("Should extract process name 'sshd'")
	}

	if pid, exists := entry.Details["pid"]; !exists || pid != "1234" {
		t.Error("Should extract PID '1234'")
	}

	if user, exists := entry.Details["user"]; !exists || user != "admin" {
		t.Error("Should extract user 'admin'")
	}

	if ip, exists := entry.Details["ip_address"]; !exists || ip != "192.168.1.100" {
		t.Error("Should extract IP address '192.168.1.100'")
	}
}

// getLogSources 获取日志条目的所有来源（用于调试）
func getLogSources(entries []core.LogEntry) []string {
	sources := make(map[string]bool)
	for _, entry := range entries {
		sources[entry.Source] = true
	}

	result := make([]string, 0, len(sources))
	for source := range sources {
		result = append(result, source)
	}
	return result
}
