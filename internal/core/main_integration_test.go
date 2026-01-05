package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMainIntegrationProperty 测试主程序集成属性
func TestMainIntegrationProperty(t *testing.T) {
	const iterations = 10 // 减少迭代次数以加快测试

	t.Run("MainIntegrationProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			version := fmt.Sprintf("v1.0.%d", i)

			// 创建临时输出目录
			tempDir := t.TempDir()
			outputDir := filepath.Join(tempDir, fmt.Sprintf("integration-test-%d", i))

			// 创建应用程序实例
			app := NewApplication(version)

			// 创建上下文
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// 运行应用程序
			err := app.Run(ctx, outputDir, true) // Enable verbose mode for debugging
			if err != nil {
				t.Errorf("Iteration %d: Application run failed: %v", i, err)
				continue
			}

			// 验证输出目录存在
			if _, err := os.Stat(outputDir); os.IsNotExist(err) {
				t.Errorf("Iteration %d: Output directory not created: %s", i, outputDir)
				continue
			}

			// 验证必需文件存在
			requiredFiles := []string{"meta.json", "manifest.json", "index.html"}
			for _, filename := range requiredFiles {
				filePath := filepath.Join(outputDir, filename)
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					t.Errorf("Iteration %d: Required file missing: %s", i, filename)
				}
			}

			// 验证文件不为空
			for _, filename := range requiredFiles {
				filePath := filepath.Join(outputDir, filename)
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					continue
				}
				if fileInfo.Size() == 0 {
					t.Errorf("Iteration %d: File %s is empty", i, filename)
				}
			}
		}

		t.Logf("✅ Main integration property verified with %d iterations", iterations)
	})
}

// TestSessionManagerBasic 测试会话管理器基本功能
func TestSessionManagerBasic(t *testing.T) {
	const iterations = 10

	t.Run("SessionManagerBasic", func(t *testing.T) {
		sessionIDs := make(map[string]bool)

		for i := 0; i < iterations; i++ {
			version := fmt.Sprintf("v1.0.%d", i)

			// 创建会话管理器
			sessionManager, err := NewSessionManager(version)
			if err != nil {
				t.Errorf("Iteration %d: Failed to create session manager: %v", i, err)
				continue
			}

			// 验证会话ID唯一性
			sessionID := sessionManager.GetSessionID()
			if sessionID == "" {
				t.Errorf("Iteration %d: Session ID should not be empty", i)
				continue
			}

			if sessionIDs[sessionID] {
				t.Errorf("Iteration %d: Duplicate session ID: %s", i, sessionID)
			}
			sessionIDs[sessionID] = true

			// 验证基本信息
			if sessionManager.GetHostname() == "" {
				t.Errorf("Iteration %d: Hostname should not be empty", i)
			}

			if sessionManager.GetPlatform() == "" {
				t.Errorf("Iteration %d: Platform should not be empty", i)
			}

			// 验证元数据
			metadata := sessionManager.GetMetadata()
			if metadata.SessionID != sessionID {
				t.Errorf("Iteration %d: Metadata session ID mismatch", i)
			}

			if metadata.CollectorVersion != version {
				t.Errorf("Iteration %d: Version mismatch: expected %s, got %s", i, version, metadata.CollectorVersion)
			}
		}

		// 验证所有会话ID都是唯一的
		if len(sessionIDs) != iterations {
			t.Errorf("Expected %d unique session IDs, got %d", iterations, len(sessionIDs))
		}

		t.Logf("✅ Session manager basic functionality verified with %d iterations", iterations)
	})
}

// TestApplicationVersionConsistency 测试应用程序版本一致性
func TestApplicationVersionConsistency(t *testing.T) {
	const iterations = 20

	t.Run("ApplicationVersionConsistency", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			version := fmt.Sprintf("v2.%d.%d", i/10, i%10)

			// 创建临时输出目录
			tempDir := t.TempDir()
			outputDir := filepath.Join(tempDir, fmt.Sprintf("version-test-%d", i))

			// 创建应用程序实例
			app := NewApplication(version)

			// 创建上下文
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// 运行应用程序
			err := app.Run(ctx, outputDir, false)
			if err != nil {
				t.Errorf("Iteration %d: Application run failed: %v", i, err)
				continue
			}

			// 读取meta.json并验证版本
			metaPath := filepath.Join(outputDir, "meta.json")
			metaContent, err := os.ReadFile(metaPath)
			if err != nil {
				t.Errorf("Iteration %d: Failed to read meta.json: %v", i, err)
				continue
			}

			metaStr := string(metaContent)
			if !containsString(metaStr, version) {
				t.Errorf("Iteration %d: Version %s not found in meta.json", i, version)
			}

			// 读取HTML并验证版本
			htmlPath := filepath.Join(outputDir, "index.html")
			htmlContent, err := os.ReadFile(htmlPath)
			if err != nil {
				t.Errorf("Iteration %d: Failed to read index.html: %v", i, err)
				continue
			}

			htmlStr := string(htmlContent)
			if !containsString(htmlStr, version) {
				t.Errorf("Iteration %d: Version %s not found in index.html", i, version)
			}
		}

		t.Logf("✅ Application version consistency verified with %d iterations", iterations)
	})
}

// containsString 检查字符串是否包含子字符串
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

// findSubstring 查找子字符串
func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
