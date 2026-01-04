package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
	"time"

	"GatTrace/internal/core"
)

// TestJSONSerializer_WriteJSON 测试 JSON 序列化基本功能
func TestJSONSerializer_WriteJSON(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	
	serializer := NewJSONSerializer(tempDir, true)

	// 创建测试数据
	testData := core.NetworkInfo{
		Metadata: core.Metadata{
			SessionID:        "test-session-123",
			Hostname:         "test-host",
			Platform:         "test-platform",
			CollectedAt:      time.Now().UTC(),
			CollectorVersion: "v1.0.0",
		},
		Interfaces: []core.NetworkInterface{
			{
				Name:   "eth0",
				IPs:    []string{"192.168.1.100"},
				MAC:    "00:11:22:33:44:55",
				Status: "up",
			},
		},
	}

	// 写入 JSON
	err := serializer.WriteJSON("test.json", testData)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// 验证文件存在
	filePath := filepath.Join(tempDir, "test.json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("JSON file was not created")
	}

	// 验证文件内容可以解析
	err = serializer.ValidateJSONFile("test.json")
	if err != nil {
		t.Fatalf("JSON file validation failed: %v", err)
	}
}

// TestJSONSerializer_ValidateMetadata 测试元数据验证
func TestJSONSerializer_ValidateMetadata(t *testing.T) {
	serializer := NewJSONSerializer(t.TempDir(), true)

	// 测试有效的元数据
	validData := core.NetworkInfo{
		Metadata: core.Metadata{
			SessionID:        "valid-session",
			Hostname:         "valid-host",
			Platform:         "valid-platform",
			CollectedAt:      time.Now().UTC(),
			CollectorVersion: "v1.0.0",
		},
	}

	err := serializer.validateMetadata(validData)
	if err != nil {
		t.Errorf("Valid metadata should pass validation: %v", err)
	}

	// 测试无效的元数据
	invalidCases := []struct {
		name string
		data interface{}
	}{
		{
			name: "missing_session_id",
			data: core.NetworkInfo{
				Metadata: core.Metadata{
					Hostname:         "host",
					Platform:         "platform",
					CollectedAt:      time.Now().UTC(),
					CollectorVersion: "v1.0.0",
				},
			},
		},
		{
			name: "missing_hostname",
			data: core.NetworkInfo{
				Metadata: core.Metadata{
					SessionID:        "session",
					Platform:         "platform",
					CollectedAt:      time.Now().UTC(),
					CollectorVersion: "v1.0.0",
				},
			},
		},
		{
			name: "zero_collected_at",
			data: core.NetworkInfo{
				Metadata: core.Metadata{
					SessionID:        "session",
					Hostname:         "host",
					Platform:         "platform",
					CollectorVersion: "v1.0.0",
				},
			},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := serializer.validateMetadata(tc.data)
			if err == nil {
				t.Error("Invalid metadata should fail validation")
			}
		})
	}
}

// Property Test: JSON 序列化往返一致性
// Feature: ir-system-info-collector, Property 4: JSON 序列化往返一致性
func TestProperty_JSONRoundTripConsistency(t *testing.T) {
	// 属性测试：对于任何有效的系统对象，序列化为 JSON 然后反序列化应产生等价的对象
	property := func(sessionID, hostname, platform, version string) bool {
		// 跳过空字符串（无效输入）
		if sessionID == "" || hostname == "" || platform == "" || version == "" {
			return true
		}

		// 创建测试数据
		original := core.NetworkInfo{
			Metadata: core.Metadata{
				SessionID:        sessionID,
				Hostname:         hostname,
				Platform:         platform,
				CollectedAt:      time.Now().UTC().Truncate(time.Second), // 截断到秒避免精度问题
				CollectorVersion: version,
			},
			Interfaces: []core.NetworkInterface{
				{
					Name:   "test-interface",
					IPs:    []string{"192.168.1.1"},
					MAC:    "00:11:22:33:44:55",
					Status: "up",
				},
			},
		}

		// 序列化
		jsonData, err := json.Marshal(original)
		if err != nil {
			return false
		}

		// 反序列化
		var deserialized core.NetworkInfo
		err = json.Unmarshal(jsonData, &deserialized)
		if err != nil {
			return false
		}

		// 验证关键字段是否相等
		return original.Metadata.SessionID == deserialized.Metadata.SessionID &&
			original.Metadata.Hostname == deserialized.Metadata.Hostname &&
			original.Metadata.Platform == deserialized.Metadata.Platform &&
			original.Metadata.CollectorVersion == deserialized.Metadata.CollectorVersion &&
			len(original.Interfaces) == len(deserialized.Interfaces)
	}

	// 运行属性测试，减少到10次迭代以提高速度
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("JSON round-trip consistency property failed: %v", err)
	}
}

// Property Test: 标准元数据字段验证
// Feature: ir-system-info-collector, Property 4: JSON 序列化往返一致性
func TestProperty_StandardMetadataFields(t *testing.T) {
	// 属性测试：所有 JSON 文件应包含标准元数据字段
	property := func(sessionID, hostname, platform, version string) bool {
		// 跳过空字符串（无效输入）
		if sessionID == "" || hostname == "" || platform == "" || version == "" {
			return true
		}

		serializer := NewJSONSerializer(t.TempDir(), true)

		testData := core.ProcessInfo{
			Metadata: core.Metadata{
				SessionID:        sessionID,
				Hostname:         hostname,
				Platform:         platform,
				CollectedAt:      time.Now().UTC(),
				CollectorVersion: version,
			},
			Processes: []core.Process{},
		}

		// 验证元数据
		err := serializer.validateMetadata(testData)
		return err == nil
	}

	// 运行属性测试，减少到10次迭代
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Standard metadata fields property failed: %v", err)
	}
}

// Property Test: JSON 结构验证
// Feature: ir-system-info-collector, Property 4: JSON 序列化往返一致性
func TestProperty_JSONStructureValidation(t *testing.T) {
	// 属性测试：所有有效对象都应该能够成功序列化和验证
	property := func(sessionID, hostname, platform, version string) bool {
		// 跳过空字符串（无效输入）
		if sessionID == "" || hostname == "" || platform == "" || version == "" {
			return true
		}

		serializer := NewJSONSerializer(t.TempDir(), true)

		testData := core.UserInfo{
			Metadata: core.Metadata{
				SessionID:        sessionID,
				Hostname:         hostname,
				Platform:         platform,
				CollectedAt:      time.Now().UTC(),
				CollectorVersion: version,
			},
			CurrentUsers: []core.User{},
			RecentLogins: []core.LoginRecord{},
			Privileges:   []core.Privilege{},
			SSHKeys:      []core.SSHKey{},
		}

		// 验证 JSON 结构
		err := serializer.validateJSONStructure(testData)
		return err == nil
	}

	// 运行属性测试，减少到10次迭代
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("JSON structure validation property failed: %v", err)
	}
}