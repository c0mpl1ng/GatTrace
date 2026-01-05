package collectors

import (
	"context"
	"runtime"
	"testing"

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
	if testing.Short() {
		t.Skip("Skipping filesystem collection test in short mode (full disk scan)")
	}

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
	if testing.Short() {
		t.Skip("Skipping filesystem adapter error test in short mode (full disk scan)")
	}

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

// TestFileSystemCollector_DataIntegrity 测试数据完整性
func TestFileSystemCollector_DataIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping filesystem data integrity test in short mode (full disk scan)")
	}

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

// TestFileSystemCollector_WhitelistExtensions 测试白名单扩展名
func TestFileSystemCollector_WhitelistExtensions(t *testing.T) {
	adapter := NewMockPlatformAdapter()
	collector := NewFileSystemCollector(adapter)

	// 验证采集器创建成功
	if collector == nil {
		t.Fatal("Collector should not be nil")
	}

	// 验证采集器名称
	if collector.Name() != "filesystem" {
		t.Errorf("Expected name 'filesystem', got '%s'", collector.Name())
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
	if testing.Short() {
		t.Skip("Skipping filesystem platform specific test in short mode (full disk scan)")
	}

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

	// 验证平台信息
	if fileSystemInfo.Metadata.Platform == "" {
		t.Error("Metadata should have platform")
	}

	// 验证平台与当前运行平台一致
	expectedPlatform := runtime.GOOS
	if fileSystemInfo.Metadata.Platform != expectedPlatform {
		t.Errorf("Expected platform %s, got %s", expectedPlatform, fileSystemInfo.Metadata.Platform)
	}
}
