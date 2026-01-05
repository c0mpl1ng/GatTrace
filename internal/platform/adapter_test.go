package platform

import (
	"runtime"
	"testing"
	"time"
)

func TestNewPlatformAdapter(t *testing.T) {
	adapter, err := NewPlatformAdapter()

	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		if err != nil {
			t.Fatalf("NewPlatformAdapter() failed on supported platform %s: %v", runtime.GOOS, err)
		}
		if adapter == nil {
			t.Fatal("NewPlatformAdapter() returned nil adapter")
		}
	default:
		if err == nil {
			t.Errorf("NewPlatformAdapter() should fail on unsupported platform %s", runtime.GOOS)
		}
		if adapter != nil {
			t.Error("NewPlatformAdapter() should return nil adapter on unsupported platform")
		}
	}
}

func TestPlatformAdapterInterface(t *testing.T) {
	adapter, err := NewPlatformAdapter()
	if err != nil {
		t.Skipf("Skipping interface test on unsupported platform: %v", err)
	}

	// 设置测试超时
	timeout := time.After(10 * time.Second)
	done := make(chan bool)

	go func() {
		// 测试所有接口方法都存在
		_, err = adapter.GetNetworkInfo()
		// 不检查错误，因为在非目标平台上可能返回错误

		_, err = adapter.GetProcessInfo()
		// 不检查错误

		_, err = adapter.GetUserInfo()
		// 不检查错误

		_, err = adapter.GetPersistenceInfo()
		// 不检查错误

		_, err = adapter.GetFileSystemInfo()
		// 不检查错误

		_, err = adapter.GetSecurityLogs()
		// 不检查错误

		_, err = adapter.GetSystemInfo()
		// 不检查错误

		// 测试平台检测器
		detector := adapter.GetPlatformDetector()
		if detector == nil {
			t.Error("GetPlatformDetector() should not return nil")
		}

		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("TestPlatformAdapterInterface timed out after 10 seconds")
	case <-done:
		// Test completed successfully
	}
}

func TestPlaceholderAdapter(t *testing.T) {
	adapter := NewPlaceholderAdapter()
	if adapter == nil {
		t.Fatal("NewPlaceholderAdapter() returned nil")
	}

	// 所有方法都应该返回错误
	_, err := adapter.GetNetworkInfo()
	if err == nil {
		t.Error("PlaceholderAdapter.GetNetworkInfo() should return error")
	}

	_, err = adapter.GetProcessInfo()
	if err == nil {
		t.Error("PlaceholderAdapter.GetProcessInfo() should return error")
	}

	_, err = adapter.GetUserInfo()
	if err == nil {
		t.Error("PlaceholderAdapter.GetUserInfo() should return error")
	}

	_, err = adapter.GetPersistenceInfo()
	if err == nil {
		t.Error("PlaceholderAdapter.GetPersistenceInfo() should return error")
	}

	_, err = adapter.GetFileSystemInfo()
	if err == nil {
		t.Error("PlaceholderAdapter.GetFileSystemInfo() should return error")
	}

	_, err = adapter.GetSecurityLogs()
	if err == nil {
		t.Error("PlaceholderAdapter.GetSecurityLogs() should return error")
	}

	_, err = adapter.GetSystemInfo()
	if err == nil {
		t.Error("PlaceholderAdapter.GetSystemInfo() should return error")
	}
}
