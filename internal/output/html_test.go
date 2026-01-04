package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"GatTrace/internal/core"
)

func TestHTMLGenerator_ValidateAssets(t *testing.T) {
	sessionManager := core.NewSessionManager()
	generator := NewHTMLGenerator("/tmp", sessionManager)

	err := generator.ValidateAssets()
	if err != nil {
		t.Errorf("ValidateAssets() failed: %v", err)
	}
}

func TestHTMLGenerator_GetEmbeddedFiles(t *testing.T) {
	sessionManager := core.NewSessionManager()
	generator := NewHTMLGenerator("/tmp", sessionManager)

	files, err := generator.GetEmbeddedFiles()
	if err != nil {
		t.Fatalf("GetEmbeddedFiles() failed: %v", err)
	}

	expectedFiles := []string{
		"../../web/templates/index.html",
		"../../web/assets/style.css",
		"../../web/assets/script.js",
	}

	for _, expected := range expectedFiles {
		found := false
		for _, file := range files {
			if file == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file %s not found in embedded files", expected)
		}
	}

	t.Logf("Found %d embedded files", len(files))
}

func TestHTMLGenerator_GenerateReport(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "GatTrace-html-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建会话管理器
	sessionManager := core.NewSessionManager()
	
	// 创建HTML生成器
	generator := NewHTMLGenerator(tempDir, sessionManager)

	// 生成报告
	err = generator.GenerateReport()
	if err != nil {
		t.Fatalf("GenerateReport() failed: %v", err)
	}

	// 验证生成的文件
	expectedFiles := []string{
		"index.html",
		"assets/style.css",
		"assets/script.js",
	}

	for _, file := range expectedFiles {
		filePath := filepath.Join(tempDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("Expected file %s was not created", file)
		}
	}

	// 验证HTML文件内容
	htmlPath := filepath.Join(tempDir, "index.html")
	htmlContent, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("Failed to read HTML file: %v", err)
	}

	// 检查HTML内容包含必要的元素
	htmlStr := string(htmlContent)
	requiredElements := []string{
		"<title>GatTrace 系统信息报告</title>",
		"<link rel=\"stylesheet\" href=\"assets/style.css\">",
		"<script src=\"assets/script.js\"></script>",
		"class=\"nav-link\"",
		"class=\"data-table\"",
	}

	for _, element := range requiredElements {
		if !contains(htmlStr, element) {
			t.Errorf("HTML content missing required element: %s", element)
		}
	}

	// 验证CSS文件内容
	cssPath := filepath.Join(tempDir, "assets", "style.css")
	cssContent, err := os.ReadFile(cssPath)
	if err != nil {
		t.Fatalf("Failed to read CSS file: %v", err)
	}

	cssStr := string(cssContent)
	requiredCSSRules := []string{
		".container",
		".header",
		".nav-tabs",
		".data-table",
		".overview-grid",
	}

	for _, rule := range requiredCSSRules {
		if !contains(cssStr, rule) {
			t.Errorf("CSS content missing required rule: %s", rule)
		}
	}

	// 验证JavaScript文件内容
	jsPath := filepath.Join(tempDir, "assets", "script.js")
	jsContent, err := os.ReadFile(jsPath)
	if err != nil {
		t.Fatalf("Failed to read JavaScript file: %v", err)
	}

	jsStr := string(jsContent)
	requiredJSElements := []string{
		"class GatTraceReport",
		"async loadData()",
		"renderOverview()",
		"switchTab(",
		"formatTimestamp(",
	}

	for _, element := range requiredJSElements {
		if !contains(jsStr, element) {
			t.Errorf("JavaScript content missing required element: %s", element)
		}
	}

	t.Logf("HTML report generated successfully in %s", tempDir)
}

func TestHTMLGenerator_Integration(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "GatTrace-html-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建会话管理器和输出管理器
	sessionManager := core.NewSessionManager()
	outputManager, err := NewManager(sessionManager)
	if err != nil {
		t.Fatalf("Failed to create output manager: %v", err)
	}

	// 更新输出目录为测试目录
	outputManager.outputDir = tempDir

	// 确保输出目录存在
	err = outputManager.EnsureOutputDir()
	if err != nil {
		t.Fatalf("Failed to ensure output dir: %v", err)
	}

	// 创建一些示例JSON数据
	sampleData := map[string]interface{}{
		"metadata": core.NewMetadata(
			sessionManager.GetSessionID(),
			sessionManager.GetHostname(),
			sessionManager.GetPlatform(),
			"1.0.0",
		),
		"test_data": "sample",
	}

	// 写入JSON文件
	err = outputManager.WriteJSON("meta.json", sampleData)
	if err != nil {
		t.Fatalf("Failed to write JSON: %v", err)
	}

	// 生成HTML报告
	err = outputManager.GenerateHTML()
	if err != nil {
		t.Fatalf("Failed to generate HTML: %v", err)
	}

	// 验证所有文件都存在
	expectedFiles := []string{
		"meta.json",
		"index.html",
		"assets/style.css",
		"assets/script.js",
	}

	for _, file := range expectedFiles {
		filePath := filepath.Join(tempDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("Expected file %s was not created", file)
		}
	}

	t.Logf("Integration test completed successfully")
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr || 
			 containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}