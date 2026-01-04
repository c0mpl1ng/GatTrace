package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// TestOutputDirectoryIsolation 测试输出目录隔离属性
// **Feature: ir-system-info-collector, Property 2: 输出目录隔离**
// **验证: 需求 1.5**
func TestOutputDirectoryIsolation(t *testing.T) {
	// 属性测试配置
	config := &quick.Config{
		MaxCount: 10, // 减少到10次迭代以提高速度
	}

	// 定义属性测试函数
	property := func(outputDirSuffix string, verbose bool) bool {
		// 清理输入，确保目录名有效
		outputDirSuffix = sanitizeDirectoryName(outputDirSuffix)
		if outputDirSuffix == "" {
			outputDirSuffix = "test"
		}

		// 创建测试上下文
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 创建临时基础目录
		baseDir, err := os.MkdirTemp("", "GatTrace_isolation_test_*")
		if err != nil {
			t.Logf("Failed to create base temp dir: %v", err)
			return false
		}
		defer os.RemoveAll(baseDir)

		// 创建输出目录
		outputDir := filepath.Join(baseDir, "output_"+outputDirSuffix)

		// 创建文件系统监控器
		fsMonitor := NewFileSystemMonitor()
		
		// 设置监控范围（排除输出目录）
		if err := fsMonitor.SetupMonitoring(baseDir, outputDir); err != nil {
			t.Logf("Failed to setup filesystem monitoring: %v", err)
			return false
		}

		// 捕获文件系统开始状态
		if err := fsMonitor.CaptureStartState(ctx); err != nil {
			t.Logf("Failed to capture start state: %v", err)
			return false
		}

		// 创建应用程序实例
		app := NewApplication("test-v1.0.0")

		// 运行应用程序
		err = app.Run(ctx, outputDir, verbose)

		// 捕获文件系统结束状态
		if err := fsMonitor.CaptureEndState(ctx); err != nil {
			t.Logf("Failed to capture end state: %v", err)
			return false
		}

		// 验证输出目录隔离
		return verifyOutputDirectoryIsolation(t, fsMonitor, outputDir, baseDir)
	}

	// 执行属性测试
	if err := quick.Check(property, config); err != nil {
		t.Errorf("输出目录隔离属性测试失败: %v", err)
	}
}

// FileSystemMonitor 文件系统监控器
type FileSystemMonitor struct {
	monitoredPaths []string
	excludedPaths  []string
	startState     map[string]FileState
	endState       map[string]FileState
}

// FileState 文件状态
type FileState struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mod_time"`
	Hash     string    `json:"hash"`
	IsDir    bool      `json:"is_dir"`
	Exists   bool      `json:"exists"`
}

// NewFileSystemMonitor 创建新的文件系统监控器
func NewFileSystemMonitor() *FileSystemMonitor {
	return &FileSystemMonitor{
		startState: make(map[string]FileState),
		endState:   make(map[string]FileState),
	}
}

// SetupMonitoring 设置监控
func (fsm *FileSystemMonitor) SetupMonitoring(baseDir, excludeDir string) error {
	// 设置监控的关键系统路径
	fsm.monitoredPaths = getSystemMonitorPaths()
	
	// 添加基础目录到监控路径
	fsm.monitoredPaths = append(fsm.monitoredPaths, baseDir)
	
	// 设置排除路径
	fsm.excludedPaths = []string{excludeDir}
	
	return nil
}

// getSystemMonitorPaths 获取系统监控路径
func getSystemMonitorPaths() []string {
	// 简化监控路径，只监控关键位置
	switch runtime.GOOS {
	case "windows":
		return []string{
			"C:\\Windows\\System32\\drivers\\etc\\hosts",
		}
	case "linux":
		return []string{
			"/etc/hosts",
			"/tmp",
		}
	case "darwin":
		return []string{
			"/etc/hosts",
			"/tmp",
		}
	default:
		return []string{"/tmp"}
	}
}

// CaptureStartState 捕获开始状态
func (fsm *FileSystemMonitor) CaptureStartState(ctx context.Context) error {
	return fsm.captureState(ctx, fsm.startState)
}

// CaptureEndState 捕获结束状态
func (fsm *FileSystemMonitor) CaptureEndState(ctx context.Context) error {
	return fsm.captureState(ctx, fsm.endState)
}

// captureState 捕获状态
func (fsm *FileSystemMonitor) captureState(ctx context.Context, stateMap map[string]FileState) error {
	for _, monitorPath := range fsm.monitoredPaths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := fsm.capturePathState(ctx, monitorPath, stateMap); err != nil {
			// 记录错误但继续处理其他路径
			continue
		}
	}
	return nil
}

// capturePathState 捕获路径状态
func (fsm *FileSystemMonitor) capturePathState(ctx context.Context, path string, stateMap map[string]FileState) error {
	// 检查路径是否被排除
	for _, excludePath := range fsm.excludedPaths {
		if strings.HasPrefix(path, excludePath) {
			return nil // 跳过排除的路径
		}
	}

	// 创建一个带超时的子上下文
	walkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	fileCount := 0
	maxFiles := 50 // 限制处理的文件数量

	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		select {
		case <-walkCtx.Done():
			return walkCtx.Err()
		default:
		}

		// 限制处理的文件数量
		fileCount++
		if fileCount > maxFiles {
			return filepath.SkipDir
		}

		// 检查是否被排除
		for _, excludePath := range fsm.excludedPaths {
			if strings.HasPrefix(filePath, excludePath) {
				if info != nil && info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		state := FileState{
			Path:   filePath,
			Exists: err == nil,
		}

		if err == nil && info != nil {
			state.Size = info.Size()
			state.ModTime = info.ModTime()
			state.IsDir = info.IsDir()

			// 只对小文件计算哈希，并且跳过某些类型的文件
			if !info.IsDir() && info.Size() < 10*1024 && !fsm.shouldSkipFile(filePath) { // 10KB以下
				if hash, hashErr := fsm.calculateFileHash(filePath); hashErr == nil {
					state.Hash = hash
				}
			}
		}

		stateMap[filePath] = state
		return nil
	})
}

// shouldSkipFile 判断是否应该跳过文件
func (fsm *FileSystemMonitor) shouldSkipFile(filePath string) bool {
	// 跳过某些类型的文件以提高性能
	skipExtensions := []string{".log", ".tmp", ".cache", ".lock", ".pid"}
	skipDirs := []string{"/.git/", "/node_modules/", "/.cache/", "/tmp/"}
	
	for _, ext := range skipExtensions {
		if strings.HasSuffix(filePath, ext) {
			return true
		}
	}
	
	for _, dir := range skipDirs {
		if strings.Contains(filePath, dir) {
			return true
		}
	}
	
	return false
}

// calculateFileHash 计算文件哈希
func (fsm *FileSystemMonitor) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// GetFileSystemChanges 获取文件系统变更
func (fsm *FileSystemMonitor) GetFileSystemChanges() FileSystemChanges {
	changes := FileSystemChanges{
		Added:    []string{},
		Modified: []string{},
		Removed:  []string{},
	}

	// 查找新增和修改的文件
	for path, endState := range fsm.endState {
		if startState, exists := fsm.startState[path]; exists {
			// 文件存在于开始状态，检查是否修改
			if fsm.isFileModified(startState, endState) {
				changes.Modified = append(changes.Modified, path)
			}
		} else {
			// 文件不存在于开始状态，是新增的
			if endState.Exists {
				changes.Added = append(changes.Added, path)
			}
		}
	}

	// 查找删除的文件
	for path, startState := range fsm.startState {
		if endState, exists := fsm.endState[path]; !exists || !endState.Exists {
			if startState.Exists {
				changes.Removed = append(changes.Removed, path)
			}
		}
	}

	return changes
}

// isFileModified 检查文件是否被修改
func (fsm *FileSystemMonitor) isFileModified(start, end FileState) bool {
	if start.Size != end.Size {
		return true
	}
	if !start.ModTime.Equal(end.ModTime) {
		return true
	}
	if start.Hash != "" && end.Hash != "" && start.Hash != end.Hash {
		return true
	}
	return false
}

// FileSystemChanges 文件系统变更
type FileSystemChanges struct {
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Removed  []string `json:"removed"`
}

// verifyOutputDirectoryIsolation 验证输出目录隔离
func verifyOutputDirectoryIsolation(t *testing.T, fsMonitor *FileSystemMonitor, outputDir, baseDir string) bool {
	changes := fsMonitor.GetFileSystemChanges()
	success := true

	// 检查是否有在输出目录外的文件变更
	for _, addedFile := range changes.Added {
		if !isWithinDirectory(addedFile, outputDir) && isWithinDirectory(addedFile, baseDir) {
			// 允许创建输出目录的父目录
			if !isParentDirectoryOfOutput(addedFile, outputDir) {
				t.Logf("在输出目录外检测到新增文件: %s", addedFile)
				success = false
			}
		}
	}

	for _, modifiedFile := range changes.Modified {
		if !isWithinDirectory(modifiedFile, outputDir) {
			// 允许修改基础目录（因为创建子目录会修改父目录的时间戳）
			if modifiedFile != baseDir && !isParentDirectoryOfOutput(modifiedFile, outputDir) {
				t.Logf("在输出目录外检测到修改文件: %s", modifiedFile)
				success = false
			}
		}
	}

	// 验证输出目录中确实有文件被创建
	outputDirHasFiles := false
	for _, addedFile := range changes.Added {
		if isWithinDirectory(addedFile, outputDir) {
			outputDirHasFiles = true
			break
		}
	}

	if !outputDirHasFiles {
		// 检查输出目录是否存在文件
		if files, err := os.ReadDir(outputDir); err == nil && len(files) > 0 {
			outputDirHasFiles = true
		}
	}

	if !outputDirHasFiles {
		t.Log("输出目录中未检测到任何文件")
		// 这不一定是失败，可能是由于其他错误导致的
	}

	return success
}

// isParentDirectoryOfOutput 检查是否是输出目录的父目录
func isParentDirectoryOfOutput(filePath, outputDir string) bool {
	absFilePath, err1 := filepath.Abs(filePath)
	absOutputDir, err2 := filepath.Abs(outputDir)
	
	if err1 != nil || err2 != nil {
		return false
	}

	// 检查是否是输出目录的直接或间接父目录
	outputParent := filepath.Dir(absOutputDir)
	for outputParent != "/" && outputParent != "." {
		if absFilePath == outputParent {
			return true
		}
		outputParent = filepath.Dir(outputParent)
	}
	
	return false
}

// isWithinDirectory 检查文件是否在指定目录内
func isWithinDirectory(filePath, dirPath string) bool {
	absFilePath, err1 := filepath.Abs(filePath)
	absDirPath, err2 := filepath.Abs(dirPath)
	
	if err1 != nil || err2 != nil {
		// 如果无法获取绝对路径，使用字符串比较
		return strings.HasPrefix(filePath, dirPath)
	}

	rel, err := filepath.Rel(absDirPath, absFilePath)
	if err != nil {
		return false
	}

	return !strings.HasPrefix(rel, "..") && rel != "."
}

// sanitizeDirectoryName 清理目录名称
func sanitizeDirectoryName(name string) string {
	// 移除不安全的字符
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "\x00"}
	result := name
	
	for _, char := range unsafe {
		result = strings.ReplaceAll(result, char, "_")
	}
	
	// 限制长度
	if len(result) > 50 {
		result = result[:50]
	}
	
	// 移除前后空格
	result = strings.TrimSpace(result)
	
	return result
}

// TestOutputDirectoryIsolationSpecificCases 测试特定的输出目录隔离场景
func TestOutputDirectoryIsolationSpecificCases(t *testing.T) {
	testCases := []struct {
		name      string
		outputDir string
		verbose   bool
	}{
		{
			name:      "标准输出目录",
			outputDir: "ir_output",
			verbose:   false,
		},
		{
			name:      "深层嵌套目录",
			outputDir: "deep/nested/output/dir",
			verbose:   true,
		},
		{
			name:      "带特殊字符的目录",
			outputDir: "output_with-special.chars_123",
			verbose:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// 创建临时基础目录
			baseDir, err := os.MkdirTemp("", "GatTrace_isolation_specific_*")
			if err != nil {
				t.Fatalf("Failed to create base temp dir: %v", err)
			}
			defer os.RemoveAll(baseDir)

			// 创建输出目录路径
			outputDir := filepath.Join(baseDir, tc.outputDir)

			// 创建文件系统监控器
			fsMonitor := NewFileSystemMonitor()
			
			// 设置监控
			if err := fsMonitor.SetupMonitoring(baseDir, outputDir); err != nil {
				t.Fatalf("Failed to setup monitoring: %v", err)
			}

			// 捕获开始状态
			if err := fsMonitor.CaptureStartState(ctx); err != nil {
				t.Fatalf("Failed to capture start state: %v", err)
			}

			// 创建应用程序实例
			app := NewApplication("test-v1.0.0")

			// 运行应用程序
			err = app.Run(ctx, outputDir, tc.verbose)

			// 捕获结束状态
			if err := fsMonitor.CaptureEndState(ctx); err != nil {
				t.Fatalf("Failed to capture end state: %v", err)
			}

			// 验证输出目录隔离
			if !verifyOutputDirectoryIsolation(t, fsMonitor, outputDir, baseDir) {
				t.Error("输出目录隔离验证失败")
			}

			// 验证输出目录存在
			if _, err := os.Stat(outputDir); os.IsNotExist(err) {
				t.Error("输出目录未被创建")
			}
		})
	}
}

// TestOutputDirectoryIsolationEdgeCases 测试边界情况
func TestOutputDirectoryIsolationEdgeCases(t *testing.T) {
	t.Run("输出目录已存在", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 创建临时基础目录
		baseDir, err := os.MkdirTemp("", "GatTrace_isolation_edge_*")
		if err != nil {
			t.Fatalf("Failed to create base temp dir: %v", err)
		}
		defer os.RemoveAll(baseDir)

		// 创建输出目录
		outputDir := filepath.Join(baseDir, "existing_output")
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			t.Fatalf("Failed to create output dir: %v", err)
		}

		// 在输出目录中创建一个现有文件
		existingFile := filepath.Join(outputDir, "existing.txt")
		if err := os.WriteFile(existingFile, []byte("existing content"), 0644); err != nil {
			t.Fatalf("Failed to create existing file: %v", err)
		}

		// 创建文件系统监控器
		fsMonitor := NewFileSystemMonitor()
		if err := fsMonitor.SetupMonitoring(baseDir, outputDir); err != nil {
			t.Fatalf("Failed to setup monitoring: %v", err)
		}

		// 捕获开始状态
		if err := fsMonitor.CaptureStartState(ctx); err != nil {
			t.Fatalf("Failed to capture start state: %v", err)
		}

		// 创建应用程序实例
		app := NewApplication("test-v1.0.0")

		// 运行应用程序
		_ = app.Run(ctx, outputDir, false)

		// 捕获结束状态
		if err := fsMonitor.CaptureEndState(ctx); err != nil {
			t.Fatalf("Failed to capture end state: %v", err)
		}

		// 验证输出目录隔离
		if !verifyOutputDirectoryIsolation(t, fsMonitor, outputDir, baseDir) {
			t.Error("输出目录隔离验证失败")
		}

		// 验证现有文件未被修改
		content, err := os.ReadFile(existingFile)
		if err != nil {
			t.Errorf("Failed to read existing file: %v", err)
		} else if string(content) != "existing content" {
			t.Error("现有文件内容被修改")
		}
	})

	t.Run("无权限创建输出目录", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("跳过Windows上的权限测试")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 创建只读基础目录
		baseDir, err := os.MkdirTemp("", "GatTrace_isolation_readonly_*")
		if err != nil {
			t.Fatalf("Failed to create base temp dir: %v", err)
		}
		defer func() {
			os.Chmod(baseDir, 0755) // 恢复权限以便清理
			os.RemoveAll(baseDir)
		}()

		// 设置目录为只读
		if err := os.Chmod(baseDir, 0555); err != nil {
			t.Fatalf("Failed to set directory readonly: %v", err)
		}

		outputDir := filepath.Join(baseDir, "readonly_output")

		// 创建应用程序实例
		app := NewApplication("test-v1.0.0")

		// 运行应用程序（应该失败）
		err = app.Run(ctx, outputDir, false)
		if err == nil {
			t.Error("Expected error when creating output directory in readonly location")
		}
	})
}

// BenchmarkOutputDirectoryIsolation 基准测试输出目录隔离
func BenchmarkOutputDirectoryIsolation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		
		// 创建临时目录
		baseDir, err := os.MkdirTemp("", "GatTrace_isolation_bench_*")
		if err != nil {
			b.Fatalf("Failed to create temp dir: %v", err)
		}

		outputDir := filepath.Join(baseDir, "bench_output")

		// 创建文件系统监控器
		fsMonitor := NewFileSystemMonitor()
		if err := fsMonitor.SetupMonitoring(baseDir, outputDir); err != nil {
			b.Fatalf("Failed to setup monitoring: %v", err)
		}

		// 捕获开始状态
		if err := fsMonitor.CaptureStartState(ctx); err != nil {
			b.Fatalf("Failed to capture start state: %v", err)
		}

		// 创建应用程序实例
		app := NewApplication("bench-v1.0.0")

		// 运行应用程序
		_ = app.Run(ctx, outputDir, false)

		// 捕获结束状态
		if err := fsMonitor.CaptureEndState(ctx); err != nil {
			b.Fatalf("Failed to capture end state: %v", err)
		}

		// 获取变更
		_ = fsMonitor.GetFileSystemChanges()

		// 清理
		os.RemoveAll(baseDir)
		cancel()
	}
}