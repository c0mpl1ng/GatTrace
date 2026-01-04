package collectors

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"GatTrace/internal/core"
)

// TestFileSystemCollector_Basic 测试文件系统采集器基本功能
func TestFileSystemCollector_Basic(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	// 测试基本属性
	if collector.Name() != "filesystem" {
		t.Errorf("Expected name 'filesystem', got '%s'", collector.Name())
	}

	if !collector.RequiresPrivileges() {
		t.Error("FileSystem collector should require privileges")
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

// TestFileSystemCollector_Collect_Success 测试成功的文件系统信息采集
func TestFileSystemCollector_Collect_Success(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

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

	fileSystemInfo, ok := result.Data.(*core.FileSystemInfo)
	if !ok {
		t.Fatal("Result data should be FileSystemInfo")
	}

	// 验证文件系统信息结构
	if fileSystemInfo.RecentFiles == nil {
		t.Error("RecentFiles should not be nil")
	}

	// 验证元数据
	if fileSystemInfo.Metadata.SessionID == "" {
		t.Error("Metadata should have session ID")
	}

	if fileSystemInfo.Metadata.Hostname == "" {
		t.Error("Metadata should have hostname")
	}

	if fileSystemInfo.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	if fileSystemInfo.Metadata.CollectorVersion == "" {
		t.Error("Metadata should have collector version")
	}

	if fileSystemInfo.Metadata.CollectedAt.IsZero() {
		t.Error("Metadata should have collection timestamp")
	}
}

// TestFileSystemCollector_Collect_AdapterError 测试适配器错误时的回退机制
func TestFileSystemCollector_Collect_AdapterError(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)
	collector := NewFileSystemCollector(adapter)

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
	fileSystemInfo, ok := result.Data.(*core.FileSystemInfo)
	if !ok {
		t.Fatal("Result data should be FileSystemInfo")
	}

	// 验证基本结构存在
	if fileSystemInfo.RecentFiles == nil {
		t.Error("RecentFiles should not be nil")
	}
}

// TestFileSystemCollector_Collect_ContextCancellation 测试上下文取消
func TestFileSystemCollector_Collect_ContextCancellation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	// 创建已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 上下文被取消时，采集应该能够处理
	result, err := collector.Collect(ctx)

	// 可能返回错误或成功，取决于取消的时机
	// 错误可能被包装，所以检查是否包含 context.Canceled
	if err != nil {
		if !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	if result != nil && result.Data == nil {
		t.Error("If result is not nil, data should not be nil")
	}
}

// TestFileSystemCollector_Collect_Timeout 测试超时处理
func TestFileSystemCollector_Collect_Timeout(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	// 创建短超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// 等待超时
	time.Sleep(2 * time.Millisecond)

	// 超时时，采集应该能够处理
	result, err := collector.Collect(ctx)

	// 可能返回错误或成功，取决于超时的时机
	// 错误可能被包装，所以检查是否包含 deadline exceeded
	if err != nil {
		if !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	if result != nil && result.Data == nil {
		t.Error("If result is not nil, data should not be nil")
	}
}

// TestFileSystemCollector_DataIntegrity 测试数据完整性
func TestFileSystemCollector_DataIntegrity(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	fileSystemInfo := result.Data.(*core.FileSystemInfo)

	// 验证文件信息完整性
	for i, file := range fileSystemInfo.RecentFiles {
		if file.Path == "" {
			t.Errorf("File %d should have path", i)
		}
		if file.Size < 0 {
			t.Errorf("File %d should have non-negative size", i)
		}
		if file.Mode == "" {
			t.Errorf("File %d should have mode", i)
		}
		if file.ModTime.IsZero() {
			t.Errorf("File %d should have modification time", i)
		}
		if file.Owner == "" {
			t.Errorf("File %d should have owner", i)
		}
		if file.Group == "" {
			t.Errorf("File %d should have group", i)
		}
	}
}

// TestFileSystemCollector_KeyDirectories 测试关键目录获取
func TestFileSystemCollector_KeyDirectories(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	directories := collector.getKeyDirectories()

	if len(directories) == 0 {
		t.Error("Should have at least one key directory")
	}

	// 验证目录路径的合理性
	for i, dir := range directories {
		if dir == "" {
			t.Errorf("Directory %d should not be empty", i)
		}
		
		// 根据平台验证目录格式
		switch runtime.GOOS {
		case "windows":
			if !strings.HasPrefix(dir, "C:\\") {
				t.Errorf("Windows directory %d should start with C:\\, got %s", i, dir)
			}
		case "linux", "darwin":
			if !strings.HasPrefix(dir, "/") {
				t.Errorf("Unix directory %d should start with /, got %s", i, dir)
			}
		}
	}
}

// TestFileSystemCollector_InterestingFiles 测试有趣文件检测
func TestFileSystemCollector_InterestingFiles(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	testCases := []struct {
		filePath    string
		interesting bool
	}{
		{"/bin/bash", true},           // 可执行文件
		{"/etc/passwd", true},         // 系统文件
		{"/home/user/.bashrc", false}, // 普通配置文件
		{"config.yaml", true},         // 配置文件
		{"script.sh", true},           // 脚本文件
		{"document.txt", false},       // 普通文档
		{"program.exe", true},         // Windows可执行文件
		{"library.dll", true},         // Windows库文件
		{"id_rsa", true},              // SSH密钥
		{"authorized_keys", true},     // SSH授权密钥
	}

	for _, tc := range testCases {
		result := collector.isInterestingFile(tc.filePath)
		if result != tc.interesting {
			t.Errorf("File %s: expected interesting=%v, got %v", tc.filePath, tc.interesting, result)
		}
	}
}

// TestFileSystemCollector_FileSystemStat 测试文件系统统计信息
func TestFileSystemCollector_FileSystemStat(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	// 测试当前文件的统计信息
	stat, err := collector.getFileSystemStat("filesystem_test.go")
	if err != nil {
		t.Fatalf("getFileSystemStat should not return error: %v", err)
	}

	if stat == nil {
		t.Fatal("FileSystemStat should not be nil")
	}

	// 验证统计信息字段
	if stat.Owner == "" {
		t.Error("FileSystemStat should have owner")
	}

	if stat.Group == "" {
		t.Error("FileSystemStat should have group")
	}

	if stat.AccessTime.IsZero() {
		t.Error("FileSystemStat should have access time")
	}

	if stat.ChangeTime.IsZero() {
		t.Error("FileSystemStat should have change time")
	}
}

// TestFileSystemCollector_HashCalculation 测试哈希计算
func TestFileSystemCollector_HashCalculation(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	// 测试当前文件的哈希计算
	hash, err := collector.calculateFileHash("filesystem_test.go")
	if err != nil {
		t.Fatalf("calculateFileHash should not return error: %v", err)
	}

	if hash == "" {
		t.Error("Hash should not be empty")
	}

	// 验证哈希格式（应该是64个十六进制字符）
	if len(hash) != 64 {
		t.Errorf("Hash should be 64 characters, got %d", len(hash))
	}

	// 验证哈希一致性（同一文件应该产生相同哈希）
	hash2, err := collector.calculateFileHash("filesystem_test.go")
	if err != nil {
		t.Fatalf("Second calculateFileHash should not return error: %v", err)
	}

	if hash != hash2 {
		t.Error("Hash should be consistent for the same file")
	}
}

// TestFileSystemCollector_PlatformSpecific 测试平台特定功能
func TestFileSystemCollector_PlatformSpecific(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true) // 强制使用通用方法
	collector := NewFileSystemCollector(adapter)

	ctx := context.Background()
	result, err := collector.Collect(ctx)

	if err != nil {
		t.Fatalf("Collect should not return error: %v", err)
	}

	fileSystemInfo := result.Data.(*core.FileSystemInfo)

	// 验证返回了文件信息（即使可能为空）
	if fileSystemInfo.RecentFiles == nil {
		t.Error("RecentFiles should not be nil")
	}

	// 验证关键目录是平台特定的
	directories := collector.getKeyDirectories()
	hasExpectedDirs := false

	switch runtime.GOOS {
	case "windows":
		// Windows应该有C:\目录
		for _, dir := range directories {
			if strings.HasPrefix(dir, "C:\\") {
				hasExpectedDirs = true
				break
			}
		}
	case "linux", "darwin":
		// Unix系统应该有/bin或/usr/bin目录
		for _, dir := range directories {
			if dir == "/bin" || dir == "/usr/bin" {
				hasExpectedDirs = true
				break
			}
		}
	}

	if !hasExpectedDirs {
		t.Errorf("Should have platform-specific directories for %s", runtime.GOOS)
	}
}