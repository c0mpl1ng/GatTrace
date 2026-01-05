package output

import (
	"os"
	"path/filepath"
	"testing"

	"GatTrace/internal/core"
)

// TestOutputSystemIntegration 测试输出系统的完整集成
func TestOutputSystemIntegration(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "GatTrace-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建会话管理器
	sessionManager, err := core.NewSessionManager("v1.0.0")
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// 创建输出管理器
	outputManager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create output manager: %v", err)
	}

	// 设置会话管理器
	outputManager.SetSessionManager(sessionManager)

	// 确保输出目录存在
	err = outputManager.EnsureOutputDir()
	if err != nil {
		t.Fatalf("Failed to ensure output directory: %v", err)
	}

	// 验证输出目录存在
	outputDir := outputManager.GetOutputDir()
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		t.Fatal("Output directory was not created")
	}

	// 创建测试数据
	networkData := core.NetworkInfo{
		Metadata: sessionManager.GetMetadata(),
		Interfaces: []core.NetworkInterface{
			{
				Name:   "eth0",
				IPs:    []string{"192.168.1.100"},
				MAC:    "00:11:22:33:44:55",
				Status: "up",
			},
		},
	}

	processData := core.ProcessInfo{
		Metadata: sessionManager.GetMetadata(),
		Processes: []core.Process{
			{
				PID:  1234,
				Name: "test-process",
				Exe:  "/usr/bin/test",
			},
		},
	}

	// 写入 JSON 文件
	err = outputManager.WriteJSON("network.json", networkData)
	if err != nil {
		t.Fatalf("Failed to write network.json: %v", err)
	}

	err = outputManager.WriteJSON("process.json", processData)
	if err != nil {
		t.Fatalf("Failed to write process.json: %v", err)
	}

	// 写入元数据文件
	err = outputManager.WriteMetaFile()
	if err != nil {
		t.Fatalf("Failed to write meta.json: %v", err)
	}

	// 验证文件存在
	expectedFiles := []string{"network.json", "process.json", "meta.json"}
	for _, filename := range expectedFiles {
		filePath := filepath.Join(outputDir, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("Expected file %s was not created", filename)
		}
	}

	// 计算哈希
	err = outputManager.CalculateHashes()
	if err != nil {
		t.Fatalf("Failed to calculate hashes: %v", err)
	}

	// 创建清单
	err = outputManager.CreateManifest()
	if err != nil {
		t.Fatalf("Failed to create manifest: %v", err)
	}

	// 验证清单文件存在
	manifestPath := filepath.Join(outputDir, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("Manifest file was not created")
	}

	// 验证完整性管理器有所有文件的哈希
	integrityManager := outputManager.GetIntegrityManager()
	allHashes := integrityManager.GetAllHashes()

	for _, filename := range expectedFiles {
		if _, exists := allHashes[filename]; !exists {
			t.Errorf("Hash for file %s was not calculated", filename)
		}
	}

	// 验证完整性
	err = integrityManager.VerifyIntegrity()
	if err != nil {
		t.Fatalf("Integrity verification failed: %v", err)
	}

	t.Logf("Integration test completed successfully")
	t.Logf("Output directory: %s", outputDir)
	t.Logf("Files created: %d", len(expectedFiles)+1) // +1 for manifest.json
	t.Logf("Hashes calculated: %d", len(allHashes))
}
