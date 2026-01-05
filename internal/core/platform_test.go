package core

import (
	"errors"
	"runtime"
	"testing"
)

func TestPlatformDetection(t *testing.T) {
	// 测试平台检测函数
	switch runtime.GOOS {
	case "windows":
		if !isWindows() {
			t.Error("isWindows() should return true on Windows")
		}
		if isLinux() {
			t.Error("isLinux() should return false on Windows")
		}
		if isDarwin() {
			t.Error("isDarwin() should return false on Windows")
		}
	case "linux":
		if isWindows() {
			t.Error("isWindows() should return false on Linux")
		}
		if !isLinux() {
			t.Error("isLinux() should return true on Linux")
		}
		if isDarwin() {
			t.Error("isDarwin() should return false on Linux")
		}
	case "darwin":
		if isWindows() {
			t.Error("isWindows() should return false on macOS")
		}
		if isLinux() {
			t.Error("isLinux() should return false on macOS")
		}
		if !isDarwin() {
			t.Error("isDarwin() should return true on macOS")
		}
	}
}

func TestGetPlatform(t *testing.T) {
	platform := getPlatform()

	// 验证返回的平台字符串不为空
	if platform == "" {
		t.Error("getPlatform() should not return empty string")
	}

	// 验证返回的平台字符串是预期的值之一
	validPlatforms := []string{"windows", "linux", "darwin", "unknown"}
	found := false
	for _, valid := range validPlatforms {
		if platform == valid {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("getPlatform() returned unexpected platform: %s", platform)
	}

	// 验证与 runtime.GOOS 的一致性
	switch runtime.GOOS {
	case "windows":
		if platform != "windows" {
			t.Errorf("Expected 'windows', got '%s'", platform)
		}
	case "linux":
		if platform != "linux" {
			t.Errorf("Expected 'linux', got '%s'", platform)
		}
	case "darwin":
		if platform != "darwin" {
			t.Errorf("Expected 'darwin', got '%s'", platform)
		}
	default:
		if platform != "unknown" {
			t.Errorf("Expected 'unknown' for unsupported OS, got '%s'", platform)
		}
	}
}

func TestPlatformDetector(t *testing.T) {
	detector := NewPlatformDetector()

	// 测试平台检测
	platform := detector.DetectPlatform()
	if platform == PlatformUnknown && runtime.GOOS != "unknown" {
		t.Errorf("DetectPlatform() returned unknown for supported OS: %s", runtime.GOOS)
	}

	// 测试平台信息获取
	info, err := detector.GetPlatformInfo()
	if err != nil {
		t.Fatalf("GetPlatformInfo() failed: %v", err)
	}

	if info.Platform != platform {
		t.Errorf("Platform mismatch: detector=%v, info=%v", platform, info.Platform)
	}

	if info.Architecture != runtime.GOARCH {
		t.Errorf("Architecture mismatch: expected=%s, got=%s", runtime.GOARCH, info.Architecture)
	}

	// 测试权限检查
	_, err = detector.CheckPrivileges()
	if err != nil {
		t.Errorf("CheckPrivileges() failed: %v", err)
	}
}

func TestPlatformCapabilities(t *testing.T) {
	detector := NewPlatformDetector()

	// 测试平台特定功能
	switch runtime.GOOS {
	case "windows":
		if !detector.HasCapability(CapabilityEventLogs) {
			t.Error("Windows should support event logs")
		}
		if !detector.HasCapability(CapabilityRegistry) {
			t.Error("Windows should support registry")
		}
		if !detector.HasCapability(CapabilityServices) {
			t.Error("Windows should support services")
		}
		if !detector.HasCapability(CapabilityDigitalSignatures) {
			t.Error("Windows should support digital signatures")
		}
	case "linux":
		if !detector.HasCapability(CapabilityCrontab) {
			t.Error("Linux should support crontab")
		}
		// systemd 和 auditd 可能不可用，所以不强制要求
	case "darwin":
		if !detector.HasCapability(CapabilityUnifiedLogs) {
			t.Error("macOS should support unified logs")
		}
		if !detector.HasCapability(CapabilityLaunchAgents) {
			t.Error("macOS should support launch agents")
		}
	}
}

func TestBasePlatformAdapter(t *testing.T) {
	adapter := NewBasePlatformAdapter()

	// 测试平台检测器获取
	detector := adapter.GetPlatformDetector()
	if detector == nil {
		t.Fatal("GetPlatformDetector() returned nil")
	}

	// 测试权限错误处理
	testErr := &CollectionError{
		Module:    "test",
		Operation: "test_op",
		Err:       errors.New("test error"),
		Severity:  SeverityError,
	}

	handledErr := adapter.HandlePrivilegeError(testErr.Err)
	if handledErr == nil {
		t.Fatal("HandlePrivilegeError() returned nil")
	}

	if handledErr.Module != "privilege" {
		t.Errorf("Expected module 'privilege', got '%s'", handledErr.Module)
	}

	if handledErr.Severity != SeverityWarning {
		t.Errorf("Expected severity warning, got %v", handledErr.Severity)
	}
}

func TestCollectionError(t *testing.T) {
	err := &CollectionError{
		Module:    "test_module",
		Operation: "test_operation",
		Err:       errors.New("test error"),
		Severity:  SeverityError,
	}

	errorStr := err.Error()
	expectedPrefix := "[test_module] test_operation:"
	if len(errorStr) < len(expectedPrefix) || errorStr[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Error string format incorrect: %s", errorStr)
	}
}

func TestErrorSeverity(t *testing.T) {
	tests := []struct {
		severity ErrorSeverity
		expected string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityError, "error"},
		{SeverityCritical, "critical"},
		{ErrorSeverity(999), "unknown"},
	}

	for _, test := range tests {
		if test.severity.String() != test.expected {
			t.Errorf("Severity %d: expected '%s', got '%s'",
				test.severity, test.expected, test.severity.String())
		}
	}
}
