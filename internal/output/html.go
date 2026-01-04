package output

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed web
var webAssets embed.FS

// HTMLGenerator HTML报告生成器
type HTMLGenerator struct {
	outputDir string
}

// NewHTMLGenerator 创建新的HTML生成器
func NewHTMLGenerator(outputDir string) *HTMLGenerator {
	return &HTMLGenerator{
		outputDir: outputDir,
	}
}

// GenerateReport 生成HTML报告
func (h *HTMLGenerator) GenerateReport() error {
	// 创建assets目录
	assetsDir := filepath.Join(h.outputDir, "assets")
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create assets directory: %w", err)
	}

	// 复制HTML模板
	if err := h.copyTemplate(); err != nil {
		return fmt.Errorf("failed to copy HTML template: %w", err)
	}

	// 复制CSS和JS资源
	if err := h.copyAssets(); err != nil {
		return fmt.Errorf("failed to copy assets: %w", err)
	}

	return nil
}

// copyTemplate 复制HTML模板文件
func (h *HTMLGenerator) copyTemplate() error {
	templateData, err := webAssets.ReadFile("web/templates/index.html")
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}

	templatePath := filepath.Join(h.outputDir, "index.html")
	if err := os.WriteFile(templatePath, templateData, 0644); err != nil {
		return fmt.Errorf("failed to write template: %w", err)
	}

	return nil
}

// copyAssets 复制CSS和JS资源文件
func (h *HTMLGenerator) copyAssets() error {
	// 复制CSS文件
	cssData, err := webAssets.ReadFile("web/assets/style.css")
	if err != nil {
		return fmt.Errorf("failed to read CSS: %w", err)
	}

	cssPath := filepath.Join(h.outputDir, "assets", "style.css")
	if err := os.WriteFile(cssPath, cssData, 0644); err != nil {
		return fmt.Errorf("failed to write CSS: %w", err)
	}

	// 复制JavaScript文件
	jsData, err := webAssets.ReadFile("web/assets/script.js")
	if err != nil {
		return fmt.Errorf("failed to read JavaScript: %w", err)
	}

	jsPath := filepath.Join(h.outputDir, "assets", "script.js")
	if err := os.WriteFile(jsPath, jsData, 0644); err != nil {
		return fmt.Errorf("failed to write JavaScript: %w", err)
	}

	return nil
}

// ValidateAssets 验证嵌入的资源文件
func (h *HTMLGenerator) ValidateAssets() error {
	requiredFiles := []string{
		"web/templates/index.html",
		"web/assets/style.css",
		"web/assets/script.js",
	}

	for _, file := range requiredFiles {
		if _, err := webAssets.ReadFile(file); err != nil {
			return fmt.Errorf("missing required asset: %s", file)
		}
	}

	return nil
}

// GetEmbeddedFiles 获取嵌入文件列表（用于测试）
func (h *HTMLGenerator) GetEmbeddedFiles() ([]string, error) {
	var files []string
	
	err := fs.WalkDir(webAssets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	
	return files, err
}