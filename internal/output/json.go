package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"GatTrace/internal/core"
)

// JSONSerializer JSON 序列化器
type JSONSerializer struct {
	outputDir string
	pretty    bool
}

// NewJSONSerializer 创建新的 JSON 序列化器
func NewJSONSerializer(outputDir string, pretty bool) *JSONSerializer {
	return &JSONSerializer{
		outputDir: outputDir,
		pretty:    pretty,
	}
}

// WriteJSON 写入 JSON 文件
func (js *JSONSerializer) WriteJSON(filename string, data interface{}) error {
	// 验证数据包含标准元数据字段
	if err := js.validateMetadata(data); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	// 验证 JSON 结构
	if err := js.validateJSONStructure(data); err != nil {
		return fmt.Errorf("JSON structure validation failed: %w", err)
	}

	// 确保输出目录存在
	if err := os.MkdirAll(js.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 序列化数据
	var jsonData []byte
	var err error

	if js.pretty {
		jsonData, err = json.MarshalIndent(data, "", "  ")
	} else {
		jsonData, err = json.Marshal(data)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// 写入文件
	filePath := filepath.Join(js.outputDir, filename)
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// validateMetadata 验证数据包含标准元数据字段
func (js *JSONSerializer) validateMetadata(data interface{}) error {
	v := reflect.ValueOf(data)

	// 处理指针
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return fmt.Errorf("data is nil")
		}
		v = v.Elem()
	}

	// 必须是结构体
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("data must be a struct, got %T", data)
	}

	// 查找 Metadata 字段
	metadataField := v.FieldByName("Metadata")
	if !metadataField.IsValid() {
		return fmt.Errorf("data must contain a 'Metadata' field")
	}

	// 验证 Metadata 字段类型
	if metadataField.Type() != reflect.TypeOf(core.Metadata{}) {
		return fmt.Errorf("Metadata field must be of type core.Metadata")
	}

	// 验证 Metadata 字段的必需子字段
	metadata := metadataField.Interface().(core.Metadata)

	if metadata.SessionID == "" {
		return fmt.Errorf("metadata.SessionID cannot be empty")
	}

	if metadata.Hostname == "" {
		return fmt.Errorf("metadata.Hostname cannot be empty")
	}

	if metadata.Platform == "" {
		return fmt.Errorf("metadata.Platform cannot be empty")
	}

	if metadata.CollectorVersion == "" {
		return fmt.Errorf("metadata.CollectorVersion cannot be empty")
	}

	if metadata.CollectedAt.IsZero() {
		return fmt.Errorf("metadata.CollectedAt cannot be zero")
	}

	return nil
}

// validateJSONStructure 验证 JSON 结构的可解析性
func (js *JSONSerializer) validateJSONStructure(data interface{}) error {
	// 先序列化
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// 再反序列化到通用接口验证结构
	var result interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// ValidateJSONFile 验证 JSON 文件的有效性
func (js *JSONSerializer) ValidateJSONFile(filename string) error {
	filePath := filepath.Join(js.outputDir, filename)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var result interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("invalid JSON in file %s: %w", filename, err)
	}

	return nil
}
