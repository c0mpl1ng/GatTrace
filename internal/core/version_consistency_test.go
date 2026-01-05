package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVersionConsistencyProperty 测试版本信息一致性属性 (Task 9.6)
// 属性 9: 版本信息一致性
// 验证: 需求 15.1, 15.2, 15.3, 15.4, 15.5
func TestVersionConsistencyProperty(t *testing.T) {
	const iterations = 10

	t.Run("VersionConsistencyProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			version := fmt.Sprintf("v1.%d.%d", i/10, i%10)

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

			// 验证版本信息一致性
			if err := verifyVersionConsistency(outputDir, version, i, t); err != nil {
				t.Errorf("Iteration %d: Version consistency verification failed: %v", i, err)
			}

			// 验证版本格式
			if err := verifyVersionFormat(version, i, t); err != nil {
				t.Errorf("Iteration %d: Version format verification failed: %v", i, err)
			}

			// 验证版本在所有输出中的一致性
			if err := verifyVersionInAllOutputs(outputDir, version, i, t); err != nil {
				t.Errorf("Iteration %d: Version consistency across outputs failed: %v", i, err)
			}
		}

		t.Logf("✅ Version consistency property verified with %d iterations", iterations)
	})
}

// verifyVersionConsistency 验证版本信息一致性
func verifyVersionConsistency(outputDir, expectedVersion string, iteration int, t *testing.T) error {
	// 读取meta.json文件
	metaPath := filepath.Join(outputDir, "meta.json")
	metaContent, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("failed to read meta.json: %w", err)
	}

	// 解析JSON
	var metaData map[string]interface{}
	if err := json.Unmarshal(metaContent, &metaData); err != nil {
		return fmt.Errorf("failed to parse meta.json: %w", err)
	}

	// 检查metadata部分
	metadata, ok := metaData["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("metadata section not found or invalid")
	}

	// 验证collector_version字段
	collectorVersion, ok := metadata["collector_version"].(string)
	if !ok {
		return fmt.Errorf("collector_version field not found or not string")
	}

	if collectorVersion != expectedVersion {
		return fmt.Errorf("version mismatch in meta.json: expected %s, got %s", expectedVersion, collectorVersion)
	}

	// 读取manifest.json文件
	manifestPath := filepath.Join(outputDir, "manifest.json")
	manifestContent, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest.json: %w", err)
	}

	// 解析manifest JSON
	var manifestData map[string]interface{}
	if err := json.Unmarshal(manifestContent, &manifestData); err != nil {
		return fmt.Errorf("failed to parse manifest.json: %w", err)
	}

	// 检查manifest中的metadata部分
	manifestMetadata, ok := manifestData["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("metadata section not found in manifest.json")
	}

	// 验证manifest中的collector_version字段
	manifestVersion, ok := manifestMetadata["collector_version"].(string)
	if !ok {
		return fmt.Errorf("collector_version field not found in manifest.json")
	}

	if manifestVersion != expectedVersion {
		return fmt.Errorf("version mismatch in manifest.json: expected %s, got %s", expectedVersion, manifestVersion)
	}

	// 验证两个文件中的版本信息一致
	if collectorVersion != manifestVersion {
		return fmt.Errorf("version inconsistency between files: meta.json has %s, manifest.json has %s",
			collectorVersion, manifestVersion)
	}

	return nil
}

// verifyVersionFormat 验证版本格式
func verifyVersionFormat(version string, iteration int, t *testing.T) error {
	// 验证版本不为空
	if version == "" {
		return fmt.Errorf("version should not be empty")
	}

	// 验证版本格式 (应该以v开头)
	if !strings.HasPrefix(version, "v") {
		return fmt.Errorf("version should start with 'v': %s", version)
	}

	// 验证版本包含数字
	hasDigit := false
	for _, char := range version {
		if char >= '0' && char <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return fmt.Errorf("version should contain digits: %s", version)
	}

	// 验证版本长度合理
	if len(version) < 2 || len(version) > 20 {
		return fmt.Errorf("version length unreasonable: %s", version)
	}

	// 验证版本不包含非法字符
	for _, char := range version {
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			char == '.' || char == '-' || char == '_' || char == 'v') {
			return fmt.Errorf("version contains invalid character: %c in %s", char, version)
		}
	}

	return nil
}

// verifyVersionInAllOutputs 验证版本在所有输出中的一致性
func verifyVersionInAllOutputs(outputDir, expectedVersion string, iteration int, t *testing.T) error {
	// 读取HTML文件并检查版本信息
	htmlPath := filepath.Join(outputDir, "index.html")
	htmlContent, err := os.ReadFile(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to read index.html: %w", err)
	}

	htmlStr := string(htmlContent)

	// 检查HTML中是否包含版本信息
	if !strings.Contains(htmlStr, expectedVersion) {
		return fmt.Errorf("version %s not found in HTML output", expectedVersion)
	}

	// 验证HTML中版本信息的上下文合理性
	if strings.Contains(htmlStr, "采集器版本") && !strings.Contains(htmlStr, expectedVersion) {
		return fmt.Errorf("version context found but version missing in HTML")
	}

	// 检查所有JSON文件中的版本一致性
	files, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("failed to read output directory: %w", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(outputDir, file.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue // 跳过无法读取的文件
		}

		// 如果文件包含版本信息，验证其一致性
		contentStr := string(content)
		if strings.Contains(contentStr, "collector_version") {
			if !strings.Contains(contentStr, expectedVersion) {
				return fmt.Errorf("version inconsistency in file %s", file.Name())
			}
		}
	}

	return nil
}

// TestVersionImmutabilityProperty 测试版本不可变性属性
func TestVersionImmutabilityProperty(t *testing.T) {
	const iterations = 10

	t.Run("VersionImmutabilityProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			version := fmt.Sprintf("v2.%d.%d", i/10, i%10)

			// 创建应用程序实例
			app := NewApplication(version)

			// 多次运行应用程序，验证版本信息不变
			for run := 0; run < 3; run++ {
				tempDir := t.TempDir()
				outputDir := filepath.Join(tempDir, fmt.Sprintf("run-%d", run))

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := app.Run(ctx, outputDir, false)
				cancel()

				if err != nil {
					t.Errorf("Iteration %d, Run %d: Application run failed: %v", i, run, err)
					continue
				}

				// 验证版本信息
				if err := verifyVersionConsistency(outputDir, version, i, t); err != nil {
					t.Errorf("Iteration %d, Run %d: Version consistency failed: %v", i, run, err)
				}
			}
		}

		t.Logf("✅ Version immutability property verified with %d iterations", iterations)
	})
}

// TestVersionMetadataProperty 测试版本元数据属性
func TestVersionMetadataProperty(t *testing.T) {
	const iterations = 10

	t.Run("VersionMetadataProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			version := fmt.Sprintf("v3.%d.%d", i/10, i%10)

			// 创建会话管理器
			sessionManager, err := NewSessionManager(version)
			if err != nil {
				t.Errorf("Iteration %d: Failed to create session manager: %v", i, err)
				continue
			}

			// 验证会话管理器中的版本信息
			metadata := sessionManager.GetMetadata()
			if metadata.CollectorVersion != version {
				t.Errorf("Iteration %d: Version mismatch in session metadata: expected %s, got %s",
					i, version, metadata.CollectorVersion)
			}

			// 验证版本信息的时间戳一致性
			if metadata.CollectedAt.IsZero() {
				t.Errorf("Iteration %d: CollectedAt timestamp should not be zero", i)
			}

			// 验证版本信息与其他元数据的关联性
			if metadata.SessionID == "" {
				t.Errorf("Iteration %d: SessionID should not be empty when version is set", i)
			}

			if metadata.Hostname == "" {
				t.Errorf("Iteration %d: Hostname should not be empty when version is set", i)
			}

			if metadata.Platform == "" {
				t.Errorf("Iteration %d: Platform should not be empty when version is set", i)
			}

			// 验证版本信息在多次调用中的一致性
			metadata2 := sessionManager.GetMetadata()
			if metadata.CollectorVersion != metadata2.CollectorVersion {
				t.Errorf("Iteration %d: Version should be consistent across calls", i)
			}
		}

		t.Logf("✅ Version metadata property verified with %d iterations", iterations)
	})
}
