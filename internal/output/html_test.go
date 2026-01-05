package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTMLGenerator_ValidateAssets(t *testing.T) {
	generator := NewHTMLGenerator("/tmp")

	err := generator.ValidateAssets()
	if err != nil {
		t.Errorf("ValidateAssets() failed: %v", err)
	}
}

func TestHTMLGenerator_GetEmbeddedFiles(t *testing.T) {
	generator := NewHTMLGenerator("/tmp")

	files, err := generator.GetEmbeddedFiles()
	if err != nil {
		t.Fatalf("GetEmbeddedFiles() failed: %v", err)
	}

	expectedFiles := []string{
		"web/templates/index.html",
		"web/assets/style.css",
		"web/assets/script.js",
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

	// 创建HTML生成器
	generator := NewHTMLGenerator(tempDir)

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
		"<title>",
		"GatTrace",
		"<link rel=\"stylesheet\"",
		"<script src=",
	}

	for _, element := range requiredElements {
		if !strings.Contains(htmlStr, element) {
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
		"body",
	}

	for _, rule := range requiredCSSRules {
		if !strings.Contains(cssStr, rule) {
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
		"function",
		"document",
	}

	for _, element := range requiredJSElements {
		if !strings.Contains(jsStr, element) {
			t.Errorf("JavaScript content missing required element: %s", element)
		}
	}

	t.Logf("HTML report generated successfully in %s", tempDir)
}
