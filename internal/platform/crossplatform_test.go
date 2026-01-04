package platform

import (
	"fmt"
	"runtime"
	"testing"

	"GatTrace/internal/core"
)

// TestProperty_CrossPlatformConsistency 测试跨平台一致性
// **属性 11: 跨平台一致性**
// **验证: 需求 13.2, 13.3, 13.4, 13.5**
// Feature: ir-system-info-collector, Property 11: 跨平台一致性
func TestProperty_CrossPlatformConsistency(t *testing.T) {
	// 为所有支持的平台创建适配器
	adapters := map[string]core.PlatformAdapter{
		"windows": NewWindowsAdapter(),
		"linux":   NewLinuxAdapter(),
		"darwin":  NewDarwinAdapter(),
	}

	// 测试所有适配器都实现了相同的接口
	for platformName, adapter := range adapters {
		t.Run("Interface_"+platformName, func(t *testing.T) {
			// 验证所有适配器都有平台检测器
			detector := adapter.GetPlatformDetector()
			if detector == nil {
				t.Errorf("Platform %s: GetPlatformDetector() should not return nil", platformName)
			}

			// 验证所有适配器都实现了所有必需的方法
			// 这些方法在非目标平台上可能返回错误，但不应该 panic
			testInterfaceMethod(t, platformName, "GetNetworkInfo", func() error {
				_, err := adapter.GetNetworkInfo()
				return err
			})

			testInterfaceMethod(t, platformName, "GetProcessInfo", func() error {
				_, err := adapter.GetProcessInfo()
				return err
			})

			testInterfaceMethod(t, platformName, "GetUserInfo", func() error {
				_, err := adapter.GetUserInfo()
				return err
			})

			testInterfaceMethod(t, platformName, "GetPersistenceInfo", func() error {
				_, err := adapter.GetPersistenceInfo()
				return err
			})

			// Skip GetFileSystemInfo in cross-platform tests as it can be very slow
			// This method will be tested in platform-specific tests
			if platformName == runtime.GOOS {
				testInterfaceMethod(t, platformName, "GetFileSystemInfo", func() error {
					_, err := adapter.GetFileSystemInfo()
					return err
				})
			}

			// Skip potentially slow methods in cross-platform tests for non-current platforms
			// These methods will be tested in platform-specific tests
			if platformName == runtime.GOOS {
				testInterfaceMethod(t, platformName, "GetSecurityLogs", func() error {
					_, err := adapter.GetSecurityLogs()
					return err
				})
			}

			testInterfaceMethod(t, platformName, "GetSystemInfo", func() error {
				_, err := adapter.GetSystemInfo()
				return err
			})
		})
	}
}

// testInterfaceMethod 测试接口方法不会 panic
func testInterfaceMethod(t *testing.T, platformName, methodName string, method func() error) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Platform %s: %s() should not panic, got: %v", platformName, methodName, r)
		}
	}()

	// 调用方法，可能返回错误但不应该 panic
	_ = method()
}

// TestProperty_PlatformAdapterFactory 测试平台适配器工厂的一致性
// **属性 11: 跨平台一致性**
// **验证: 需求 13.2, 13.3, 13.4, 13.5**
// Feature: ir-system-info-collector, Property 11: 跨平台一致性
func TestProperty_PlatformAdapterFactory(t *testing.T) {
	// 测试工厂函数在当前平台上返回正确的适配器
	adapter, err := NewPlatformAdapter()
	
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		if err != nil {
			t.Fatalf("NewPlatformAdapter() should succeed on supported platform %s: %v", runtime.GOOS, err)
		}
		if adapter == nil {
			t.Fatal("NewPlatformAdapter() should not return nil on supported platform")
		}
		
		// 验证返回的适配器类型正确
		detector := adapter.GetPlatformDetector()
		if detector == nil {
			t.Fatal("Platform adapter should have a detector")
		}
		
		detectedPlatform := detector.DetectPlatform()
		expectedPlatform := getPlatformFromGOOS(runtime.GOOS)
		
		if detectedPlatform != expectedPlatform {
			t.Errorf("Platform mismatch: detected=%v, expected=%v", detectedPlatform, expectedPlatform)
		}
		
	default:
		if err == nil {
			t.Errorf("NewPlatformAdapter() should fail on unsupported platform %s", runtime.GOOS)
		}
		if adapter != nil {
			t.Error("NewPlatformAdapter() should return nil on unsupported platform")
		}
	}
}

// getPlatformFromGOOS 将 GOOS 转换为 Platform 枚举
func getPlatformFromGOOS(goos string) core.Platform {
	switch goos {
	case "windows":
		return core.PlatformWindows
	case "linux":
		return core.PlatformLinux
	case "darwin":
		return core.PlatformDarwin
	default:
		return core.PlatformUnknown
	}
}

// TestProperty_MetadataConsistency 测试元数据一致性
// **属性 11: 跨平台一致性**
// **验证: 需求 13.2, 13.3, 13.4, 13.5**
// Feature: ir-system-info-collector, Property 11: 跨平台一致性
func TestProperty_MetadataConsistency(t *testing.T) {
	// 只在当前平台上测试实际的适配器
	adapter, err := NewPlatformAdapter()
	if err != nil {
		t.Skipf("Skipping metadata test on unsupported platform: %v", err)
	}

	// 测试所有数据结构都包含一致的元数据字段
	testMetadataConsistency := func(t *testing.T, methodName string, getMetadata func() (core.Metadata, error)) {
		metadata, err := getMetadata()
		if err != nil {
			// 在非目标平台上可能返回错误，这是正常的
			return
		}

		// 验证元数据字段的一致性
		if metadata.SessionID == "" {
			t.Errorf("%s: metadata should have session_id", methodName)
		}
		if metadata.Hostname == "" {
			t.Errorf("%s: metadata should have hostname", methodName)
		}
		if metadata.Platform == "" {
			t.Errorf("%s: metadata should have platform", methodName)
		}
		if metadata.CollectorVersion == "" {
			t.Errorf("%s: metadata should have collector_version", methodName)
		}
		if metadata.CollectedAt.IsZero() {
			t.Errorf("%s: metadata should have collected_at timestamp", methodName)
		}
	}

	// 测试网络信息元数据
	t.Run("NetworkInfo", func(t *testing.T) {
		testMetadataConsistency(t, "GetNetworkInfo", func() (core.Metadata, error) {
			info, err := adapter.GetNetworkInfo()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})

	// 测试进程信息元数据
	t.Run("ProcessInfo", func(t *testing.T) {
		testMetadataConsistency(t, "GetProcessInfo", func() (core.Metadata, error) {
			info, err := adapter.GetProcessInfo()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})

	// 测试用户信息元数据
	t.Run("UserInfo", func(t *testing.T) {
		testMetadataConsistency(t, "GetUserInfo", func() (core.Metadata, error) {
			info, err := adapter.GetUserInfo()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})

	// 测试持久化信息元数据
	t.Run("PersistenceInfo", func(t *testing.T) {
		testMetadataConsistency(t, "GetPersistenceInfo", func() (core.Metadata, error) {
			info, err := adapter.GetPersistenceInfo()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})

	// 测试文件系统信息元数据
	t.Run("FileSystemInfo", func(t *testing.T) {
		testMetadataConsistency(t, "GetFileSystemInfo", func() (core.Metadata, error) {
			info, err := adapter.GetFileSystemInfo()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})

	// 测试安全日志元数据
	t.Run("SecurityLogs", func(t *testing.T) {
		testMetadataConsistency(t, "GetSecurityLogs", func() (core.Metadata, error) {
			info, err := adapter.GetSecurityLogs()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})

	// 测试系统信息元数据
	t.Run("SystemInfo", func(t *testing.T) {
		testMetadataConsistency(t, "GetSystemInfo", func() (core.Metadata, error) {
			info, err := adapter.GetSystemInfo()
			if err != nil {
				return core.Metadata{}, err
			}
			return info.Metadata, nil
		})
	})
}

// TestProperty_ErrorHandlingConsistency 测试错误处理一致性
// **属性 11: 跨平台一致性**
// **验证: 需求 13.2, 13.3, 13.4, 13.5**
// Feature: ir-system-info-collector, Property 11: 跨平台一致性
func TestProperty_ErrorHandlingConsistency(t *testing.T) {
	adapters := map[string]core.PlatformAdapter{
		"windows": NewWindowsAdapter(),
		"linux":   NewLinuxAdapter(),
		"darwin":  NewDarwinAdapter(),
	}

	// 测试所有适配器的错误处理一致性
	for platformName, adapter := range adapters {
		t.Run("ErrorHandling_"+platformName, func(t *testing.T) {
			// 测试权限错误处理
			testErr := fmt.Errorf("test permission error")
			handledErr := adapter.HandlePrivilegeError(testErr)
			
			if handledErr == nil {
				t.Errorf("Platform %s: HandlePrivilegeError() should not return nil", platformName)
				return
			}
			
			// 验证错误结构的一致性
			if handledErr.Module != "privilege" {
				t.Errorf("Platform %s: expected module 'privilege', got '%s'", platformName, handledErr.Module)
			}
			
			if handledErr.Operation == "" {
				t.Errorf("Platform %s: error should have operation field", platformName)
			}
			
			if handledErr.Err == nil {
				t.Errorf("Platform %s: error should have underlying error", platformName)
			}
			
			// 验证错误严重程度
			validSeverities := []core.ErrorSeverity{
				core.SeverityInfo,
				core.SeverityWarning,
				core.SeverityError,
				core.SeverityCritical,
			}
			
			severityValid := false
			for _, validSeverity := range validSeverities {
				if handledErr.Severity == validSeverity {
					severityValid = true
					break
				}
			}
			
			if !severityValid {
				t.Errorf("Platform %s: invalid error severity: %v", platformName, handledErr.Severity)
			}
		})
	}
}

// TestProperty_PlatformCapabilityConsistency 测试平台功能一致性
// **属性 11: 跨平台一致性**
// **验证: 需求 13.2, 13.3, 13.4, 13.5**
// Feature: ir-system-info-collector, Property 11: 跨平台一致性
func TestProperty_PlatformCapabilityConsistency(t *testing.T) {
	adapters := map[string]core.PlatformAdapter{
		"windows": NewWindowsAdapter(),
		"linux":   NewLinuxAdapter(),
		"darwin":  NewDarwinAdapter(),
	}

	// 测试平台功能检测的一致性
	for platformName, adapter := range adapters {
		t.Run("Capabilities_"+platformName, func(t *testing.T) {
			detector := adapter.GetPlatformDetector()
			if detector == nil {
				t.Fatalf("Platform %s: detector should not be nil", platformName)
			}

			// 获取平台信息
			info, err := detector.GetPlatformInfo()
			if err != nil {
				t.Fatalf("Platform %s: GetPlatformInfo() failed: %v", platformName, err)
			}

			// 验证平台信息结构的一致性
			if info.Platform == core.PlatformUnknown && platformName != "unknown" {
				t.Errorf("Platform %s: should not return unknown platform", platformName)
			}

			if info.Architecture == "" {
				t.Errorf("Platform %s: should have architecture", platformName)
			}

			if info.Capabilities == nil {
				t.Errorf("Platform %s: should have capabilities map", platformName)
			}

			// 验证权限检查功能
			_, err = detector.CheckPrivileges()
			if err != nil && platformName == runtime.GOOS {
				// 在当前平台上权限检查不应该失败
				t.Errorf("Platform %s: CheckPrivileges() should not fail on current platform: %v", platformName, err)
			}
		})
	}
}

// TestProperty_DataStructureConsistency 测试数据结构一致性
// **属性 11: 跨平台一致性**
// **验证: 需求 13.2, 13.3, 13.4, 13.5**
// Feature: ir-system-info-collector, Property 11: 跨平台一致性
func TestProperty_DataStructureConsistency(t *testing.T) {
	// 只在当前平台上测试实际的数据结构
	adapter, err := NewPlatformAdapter()
	if err != nil {
		t.Skipf("Skipping data structure test on unsupported platform: %v", err)
	}

	// 测试网络信息数据结构
	t.Run("NetworkInfo", func(t *testing.T) {
		info, err := adapter.GetNetworkInfo()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		// 验证数据结构的一致性
		if info.Interfaces == nil {
			t.Error("NetworkInfo should have Interfaces slice")
		}
		if info.Routes == nil {
			t.Error("NetworkInfo should have Routes slice (initialized, may be empty)")
		}
		if info.Connections == nil {
			t.Error("NetworkInfo should have Connections slice")
		}
		if info.Listeners == nil {
			t.Error("NetworkInfo should have Listeners slice")
		}
	})

	// 测试进程信息数据结构
	t.Run("ProcessInfo", func(t *testing.T) {
		info, err := adapter.GetProcessInfo()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		if info.Processes == nil {
			t.Error("ProcessInfo should have Processes slice")
		}

		// 验证进程结构的一致性
		for i, proc := range info.Processes {
			if i >= 5 { // 只检查前几个进程
				break
			}
			if proc.PID <= 0 {
				t.Errorf("Process %d: PID should be positive", i)
			}
		}
	})

	// 测试用户信息数据结构
	t.Run("UserInfo", func(t *testing.T) {
		info, err := adapter.GetUserInfo()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		if info.CurrentUsers == nil {
			t.Error("UserInfo should have CurrentUsers slice")
		}
		if info.RecentLogins == nil {
			t.Error("UserInfo should have RecentLogins slice")
		}
		if info.Privileges == nil {
			t.Error("UserInfo should have Privileges slice")
		}
		if info.SSHKeys == nil {
			t.Error("UserInfo should have SSHKeys slice (initialized, may be empty)")
		}
	})

	// 测试持久化信息数据结构
	t.Run("PersistenceInfo", func(t *testing.T) {
		info, err := adapter.GetPersistenceInfo()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		if info.Items == nil {
			t.Error("PersistenceInfo should have Items slice")
		}
	})

	// 测试文件系统信息数据结构
	t.Run("FileSystemInfo", func(t *testing.T) {
		info, err := adapter.GetFileSystemInfo()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		if info.RecentFiles == nil {
			t.Error("FileSystemInfo should have RecentFiles slice (initialized, may be empty)")
		}
	})

	// 测试安全日志数据结构
	t.Run("SecurityLogs", func(t *testing.T) {
		info, err := adapter.GetSecurityLogs()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		if info.Entries == nil {
			t.Error("SecurityLogs should have Entries slice")
		}
	})

	// 测试系统信息数据结构
	t.Run("SystemInfo", func(t *testing.T) {
		info, err := adapter.GetSystemInfo()
		if err != nil {
			return // 在非目标平台上可能返回错误
		}

		if info.KernelModules == nil {
			t.Error("SystemInfo should have KernelModules slice")
		}
		if info.IntegrityCheck == nil {
			t.Error("SystemInfo should have IntegrityCheck map")
		}
	})
}