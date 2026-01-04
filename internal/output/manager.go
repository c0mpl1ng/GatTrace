package output

import (
	"fmt"
	"os"
	"time"

	"GatTrace/internal/core"
)

// Manager 输出管理器实现
type Manager struct {
	outputDir         string
	sessionManager    *core.SessionManager
	jsonSerializer    *JSONSerializer
	integrityManager  *IntegrityManager
}

// NewManager 创建新的输出管理器
func NewManager(outputDir string) (*Manager, error) {
	// 创建 JSON 序列化器
	jsonSerializer := NewJSONSerializer(outputDir, true) // 使用格式化输出

	// 创建完整性管理器 - 暂时不依赖SessionManager
	integrityManager := NewIntegrityManager(outputDir, nil)

	return &Manager{
		outputDir:         outputDir,
		sessionManager:    nil, // 暂时设为nil，后续通过SetSessionManager设置
		jsonSerializer:    jsonSerializer,
		integrityManager:  integrityManager,
	}, nil
}

// SetSessionManager 设置会话管理器
func (m *Manager) SetSessionManager(sessionManager *core.SessionManager) {
	m.sessionManager = sessionManager
	// 更新完整性管理器的会话管理器
	m.integrityManager = NewIntegrityManager(m.outputDir, sessionManager)
}

// GetOutputDir 获取输出目录路径
func (m *Manager) GetOutputDir() string {
	return m.outputDir
}

// WriteJSON 写入 JSON 文件
func (m *Manager) WriteJSON(filename string, data interface{}) error {
	return m.jsonSerializer.WriteJSON(filename, data)
}

// GenerateHTML 生成 HTML 报告
func (m *Manager) GenerateHTML() error {
	htmlGenerator := NewHTMLGenerator(m.outputDir)
	
	// 验证嵌入的资源文件
	if err := htmlGenerator.ValidateAssets(); err != nil {
		return fmt.Errorf("HTML assets validation failed: %w", err)
	}
	
	// 生成HTML报告
	if err := htmlGenerator.GenerateReport(); err != nil {
		return fmt.Errorf("HTML report generation failed: %w", err)
	}
	
	return nil
}

// CreateManifest 创建清单文件
func (m *Manager) CreateManifest() error {
	return m.integrityManager.CreateManifest()
}

// CalculateHashes 计算文件哈希
func (m *Manager) CalculateHashes() error {
	return m.integrityManager.CalculateAllHashes()
}

// EnsureOutputDir 确保输出目录存在
func (m *Manager) EnsureOutputDir() error {
	return os.MkdirAll(m.outputDir, 0755)
}

// WriteMetaFile 写入元数据文件
func (m *Manager) WriteMetaFile() error {
	metadata := m.sessionManager.GetMetadata()
	
	// 创建元数据结构
	metaData := struct {
		core.Metadata
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
	}{
		Metadata:  metadata,
		StartTime: m.sessionManager.GetStartTime(),
		EndTime:   time.Now().UTC(),
	}

	return m.WriteJSON("meta.json", metaData)
}

// GetIntegrityManager 获取完整性管理器
func (m *Manager) GetIntegrityManager() *IntegrityManager {
	return m.integrityManager
}