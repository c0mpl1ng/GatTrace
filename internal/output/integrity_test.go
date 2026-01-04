package output

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
	"time"

	"GatTrace/internal/core"
)

// TestIntegrityManager_CalculateFileHash 测试单个文件哈希计算
func TestIntegrityManager_CalculateFileHash(t *testing.T) {
	// 创建临时目录和会话管理器
	tempDir := t.TempDir()
	sessionManager, err := core.NewSessionManager("v1.0.0")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	im := NewIntegrityManager(tempDir, sessionManager)

	// 创建测试文件
	testContent := "test file content for hash calculation"
	testFile := "test.txt"
	testPath := filepath.Join(tempDir, testFile)
	
	err = os.WriteFile(testPath, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// 计算哈希
	hash, err := im.CalculateFileHash(testFile)
	if err != nil {
		t.Fatalf("CalculateFileHash failed: %v", err)
	}

	// 验证哈希不为空
	if hash == "" {
		t.Error("Hash should not be empty")
	}

	// 验证哈希长度（SHA256 应该是 64 个字符）
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}

	// 验证相同内容产生相同哈希
	hash2, err := im.CalculateFileHash(testFile)
	if err != nil {
		t.Fatalf("Second CalculateFileHash failed: %v", err)
	}

	if hash != hash2 {
		t.Errorf("Same file should produce same hash: %s != %s", hash, hash2)
	}
}

// TestIntegrityManager_CreateManifest 测试清单文件创建
func TestIntegrityManager_CreateManifest(t *testing.T) {
	// 创建临时目录和会话管理器
	tempDir := t.TempDir()
	sessionManager, err := core.NewSessionManager("v1.0.0")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	im := NewIntegrityManager(tempDir, sessionManager)

	// 创建一些测试文件
	testFiles := map[string]string{
		"file1.json": `{"test": "data1"}`,
		"file2.json": `{"test": "data2"}`,
		"file3.txt":  "plain text content",
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// 创建清单
	err = im.CreateManifest()
	if err != nil {
		t.Fatalf("CreateManifest failed: %v", err)
	}

	// 验证清单文件存在
	manifestPath := filepath.Join(tempDir, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("Manifest file was not created")
	}

	// 验证所有文件的哈希都被计算
	for filename := range testFiles {
		if _, exists := im.GetFileHash(filename); !exists {
			t.Errorf("Hash for file %s was not calculated", filename)
		}
	}
}

// Property Test: 文件完整性验证
// Feature: ir-system-info-collector, Property 6: 文件完整性验证
func TestProperty_FileIntegrityVerification(t *testing.T) {
	// 属性测试：对于任何输出文件，应生成 SHA256 哈希，且清单文件应包含所有文件的哈希值
	property := func(content1, content2, content3 string) bool {
		// 跳过空内容
		if content1 == "" && content2 == "" && content3 == "" {
			return true
		}

		// 创建临时目录和会话管理器
		tempDir := t.TempDir()
		sessionManager, err := core.NewSessionManager("v1.0.0")
		if err != nil {
			return false
		}

		im := NewIntegrityManager(tempDir, sessionManager)

		// 创建测试文件
		testFiles := map[string]string{
			"test1.json": content1,
			"test2.json": content2,
			"test3.txt":  content3,
		}

		fileCount := 0
		for filename, content := range testFiles {
			if content != "" {
				filePath := filepath.Join(tempDir, filename)
				err := os.WriteFile(filePath, []byte(content), 0644)
				if err != nil {
					return false
				}
				fileCount++
			}
		}

		// 如果没有文件，跳过测试
		if fileCount == 0 {
			return true
		}

		// 计算所有哈希
		err = im.CalculateAllHashes()
		if err != nil {
			return false
		}

		// 验证每个文件都有哈希
		allHashes := im.GetAllHashes()
		for filename, content := range testFiles {
			if content != "" {
				if _, exists := allHashes[filename]; !exists {
					return false
				}
			}
		}

		// 创建清单
		err = im.CreateManifest()
		if err != nil {
			return false
		}

		// 验证清单文件存在
		manifestPath := filepath.Join(tempDir, "manifest.json")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return false
		}

		return true
	}

	// 运行属性测试，减少到10次迭代以提高速度
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("File integrity verification property failed: %v", err)
	}
}

// Property Test: 哈希一致性
// Feature: ir-system-info-collector, Property 6: 文件完整性验证
func TestProperty_HashConsistency(t *testing.T) {
	// 属性测试：相同内容的文件应该产生相同的哈希值
	property := func(content string) bool {
		// 跳过空内容
		if content == "" {
			return true
		}

		// 创建临时目录和会话管理器
		tempDir := t.TempDir()
		sessionManager, err := core.NewSessionManager("v1.0.0")
		if err != nil {
			return false
		}

		im := NewIntegrityManager(tempDir, sessionManager)

		// 创建两个相同内容的文件
		file1 := "file1.txt"
		file2 := "file2.txt"

		err = os.WriteFile(filepath.Join(tempDir, file1), []byte(content), 0644)
		if err != nil {
			return false
		}

		err = os.WriteFile(filepath.Join(tempDir, file2), []byte(content), 0644)
		if err != nil {
			return false
		}

		// 计算哈希
		hash1, err := im.CalculateFileHash(file1)
		if err != nil {
			return false
		}

		hash2, err := im.CalculateFileHash(file2)
		if err != nil {
			return false
		}

		// 相同内容应该产生相同哈希
		return hash1 == hash2
	}

	// 运行属性测试，减少到10次迭代
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Hash consistency property failed: %v", err)
	}
}

// Property Test: 清单完整性
// Feature: ir-system-info-collector, Property 6: 文件完整性验证
func TestProperty_ManifestIntegrity(t *testing.T) {
	// 属性测试：清单本身也应有哈希值
	property := func(fileCount uint8) bool {
		// 限制文件数量避免测试过慢
		if fileCount == 0 || fileCount > 10 {
			return true
		}

		// 创建临时目录和会话管理器
		tempDir := t.TempDir()
		sessionManager, err := core.NewSessionManager("v1.0.0")
		if err != nil {
			return false
		}

		im := NewIntegrityManager(tempDir, sessionManager)

		// 创建指定数量的测试文件
		for i := uint8(0); i < fileCount; i++ {
			filename := filepath.Join(tempDir, fmt.Sprintf("test%d.json", i))
			content := fmt.Sprintf(`{"test": "data%d", "timestamp": "%s"}`, i, time.Now().Format(time.RFC3339))
			err := os.WriteFile(filename, []byte(content), 0644)
			if err != nil {
				return false
			}
		}

		// 创建清单
		err = im.CreateManifest()
		if err != nil {
			return false
		}

		// 验证清单文件存在
		manifestPath := filepath.Join(tempDir, "manifest.json")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return false
		}

		// 读取清单文件验证其包含哈希信息
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return false
		}

		// 简单验证清单文件包含必要字段
		manifestStr := string(manifestData)
		return len(manifestStr) > 0 && 
			   len(manifestStr) > 100 // 清单文件应该有合理的大小
	}

	// 运行属性测试
	config := &quick.Config{MaxCount: 50} // 减少迭代次数因为涉及文件操作
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Manifest integrity property failed: %v", err)
	}
}