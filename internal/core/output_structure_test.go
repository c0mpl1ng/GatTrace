package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOutputStructureIntegrityProperty 测试输出结构完整性属性 (Task 9.5)
// 属性 8: 输出结构完整性
// 验证: 需求 10.3, 10.5
func TestOutputStructureIntegrityProperty(t *testing.T) {
	const iterations = 10

	t.Run("OutputStructureIntegrityProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			// 创建临时输出目录
			tempDir := t.TempDir()
			outputDir := filepath.Join(tempDir, fmt.Sprintf("test-output-%d", i))

			// 创建应用程序实例
			app := NewApplication(fmt.Sprintf("v1.0.%d", i))

			// 创建上下文
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// 运行应用程序
			err := app.Run(ctx, outputDir, false)
			if err != nil {
				t.Errorf("Iteration %d: Application run failed: %v", i, err)
				continue
			}

			// 验证输出目录结构
			if err := verifyOutputStructure(outputDir, i, t); err != nil {
				t.Errorf("Iteration %d: Output structure verification failed: %v", i, err)
			}

			// 验证文件完整性
			if err := verifyFileIntegrity(outputDir, i, t); err != nil {
				t.Errorf("Iteration %d: File integrity verification failed: %v", i, err)
			}

			// 验证文件权限
			if err := verifyFilePermissions(outputDir, i, t); err != nil {
				t.Errorf("Iteration %d: File permissions verification failed: %v", i, err)
			}

			// 验证目录隔离
			if err := verifyDirectoryIsolation(outputDir, tempDir, i, t); err != nil {
				t.Errorf("Iteration %d: Directory isolation verification failed: %v", i, err)
			}
		}

		t.Logf("✅ Output structure integrity property verified with %d iterations", iterations)
	})
}

// verifyOutputStructure 验证输出目录结构
func verifyOutputStructure(outputDir string, iteration int, t *testing.T) error {
	// 检查输出目录是否存在
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return fmt.Errorf("output directory does not exist: %s", outputDir)
	}

	// 检查必需的文件
	requiredFiles := []string{
		"meta.json",
		"manifest.json",
		"index.html",
	}

	for _, filename := range requiredFiles {
		filePath := filepath.Join(outputDir, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("required file missing: %s", filename)
		}
	}

	// 检查文件不为空
	for _, filename := range requiredFiles {
		filePath := filepath.Join(outputDir, filename)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", filename, err)
		}
		if fileInfo.Size() == 0 {
			return fmt.Errorf("file %s is empty", filename)
		}
	}

	return nil
}

// verifyFileIntegrity 验证文件完整性
func verifyFileIntegrity(outputDir string, iteration int, t *testing.T) error {
	// 读取并验证meta.json
	metaPath := filepath.Join(outputDir, "meta.json")
	metaContent, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("failed to read meta.json: %w", err)
	}

	// 验证meta.json包含必要字段
	metaStr := string(metaContent)
	requiredFields := []string{
		"session_id",
		"hostname",
		"platform",
		"collected_at",
		"collector_version",
	}

	for _, field := range requiredFields {
		if !strings.Contains(metaStr, field) {
			return fmt.Errorf("meta.json missing required field: %s", field)
		}
	}

	// 读取并验证manifest.json
	manifestPath := filepath.Join(outputDir, "manifest.json")
	manifestContent, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest.json: %w", err)
	}

	// 验证manifest.json包含必要字段
	manifestStr := string(manifestContent)
	manifestFields := []string{
		"metadata",
		"files",
	}

	for _, field := range manifestFields {
		if !strings.Contains(manifestStr, field) {
			return fmt.Errorf("manifest.json missing required field: %s", field)
		}
	}

	// 读取并验证index.html
	htmlPath := filepath.Join(outputDir, "index.html")
	htmlContent, err := os.ReadFile(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to read index.html: %w", err)
	}

	// 验证HTML文件包含基本结构
	htmlStr := string(htmlContent)
	htmlElements := []string{
		"<!DOCTYPE html>",
		"<html",
		"<head>",
		"<body>",
		"GatTrace",
	}

	for _, element := range htmlElements {
		if !strings.Contains(htmlStr, element) {
			return fmt.Errorf("index.html missing required element: %s", element)
		}
	}

	return nil
}

// verifyFilePermissions 验证文件权限
func verifyFilePermissions(outputDir string, iteration int, t *testing.T) error {
	// 检查输出目录权限
	dirInfo, err := os.Stat(outputDir)
	if err != nil {
		return fmt.Errorf("failed to stat output directory: %w", err)
	}

	// 验证目录权限 (应该是可读写的)
	dirMode := dirInfo.Mode()
	if !dirMode.IsDir() {
		return fmt.Errorf("output path is not a directory")
	}

	// 检查文件权限
	files := []string{"meta.json", "manifest.json", "index.html"}
	for _, filename := range files {
		filePath := filepath.Join(outputDir, filename)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", filename, err)
		}

		// 验证文件权限 (应该是可读的)
		fileMode := fileInfo.Mode()
		if fileMode.IsDir() {
			return fmt.Errorf("file %s is actually a directory", filename)
		}

		// 检查文件是否可读
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("file %s is not readable: %w", filename, err)
		}
		file.Close()
	}

	return nil
}

// verifyDirectoryIsolation 验证目录隔离
func verifyDirectoryIsolation(outputDir, tempDir string, iteration int, t *testing.T) error {
	// 验证输出目录在临时目录内
	if !strings.HasPrefix(outputDir, tempDir) {
		return fmt.Errorf("output directory not properly isolated: %s not under %s", outputDir, tempDir)
	}

	// 验证没有在输出目录外创建文件
	err := filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过输出目录内的文件
		if strings.HasPrefix(path, outputDir) {
			return nil
		}

		// 跳过临时目录本身
		if path == tempDir {
			return nil
		}

		// 如果发现输出目录外的文件，这可能是隔离问题
		if !info.IsDir() {
			return fmt.Errorf("unexpected file outside output directory: %s", path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("directory isolation check failed: %w", err)
	}

	return nil
}

// TestOutputConsistencyProperty 测试输出一致性属性
func TestOutputConsistencyProperty(t *testing.T) {
	const iterations = 10

	t.Run("OutputConsistencyProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			// 创建两个相同配置的应用程序实例
			tempDir1 := t.TempDir()
			tempDir2 := t.TempDir()
			
			outputDir1 := filepath.Join(tempDir1, "output1")
			outputDir2 := filepath.Join(tempDir2, "output2")

			version := fmt.Sprintf("v1.0.%d", i)
			app1 := NewApplication(version)
			app2 := NewApplication(version)

			ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel1()
			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			// 运行两个应用程序实例
			err1 := app1.Run(ctx1, outputDir1, false)
			err2 := app2.Run(ctx2, outputDir2, false)

			if err1 != nil {
				t.Errorf("Iteration %d: First app run failed: %v", i, err1)
				continue
			}
			if err2 != nil {
				t.Errorf("Iteration %d: Second app run failed: %v", i, err2)
				continue
			}

			// 验证两个输出目录都有相同的基本结构
			if err := verifyOutputStructure(outputDir1, i, t); err != nil {
				t.Errorf("Iteration %d: First output structure invalid: %v", i, err)
			}
			if err := verifyOutputStructure(outputDir2, i, t); err != nil {
				t.Errorf("Iteration %d: Second output structure invalid: %v", i, err)
			}

			// 验证文件类型一致性 (不验证内容，因为会话ID等会不同)
			files1, err := os.ReadDir(outputDir1)
			if err != nil {
				t.Errorf("Iteration %d: Failed to read first output dir: %v", i, err)
				continue
			}
			files2, err := os.ReadDir(outputDir2)
			if err != nil {
				t.Errorf("Iteration %d: Failed to read second output dir: %v", i, err)
				continue
			}

			// 验证文件数量一致
			if len(files1) != len(files2) {
				t.Errorf("Iteration %d: File count mismatch: %d vs %d", i, len(files1), len(files2))
			}

			// 验证文件名一致 (排序后比较)
			names1 := make([]string, len(files1))
			names2 := make([]string, len(files2))
			for j, file := range files1 {
				names1[j] = file.Name()
			}
			for j, file := range files2 {
				names2[j] = file.Name()
			}

			// 简单的排序比较
			if len(names1) == len(names2) {
				for j := 0; j < len(names1); j++ {
					found := false
					for k := 0; k < len(names2); k++ {
						if names1[j] == names2[k] {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Iteration %d: File %s not found in second output", i, names1[j])
					}
				}
			}
		}

		t.Logf("✅ Output consistency property verified with %d iterations", iterations)
	})
}