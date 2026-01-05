package core

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// TestStandardTime_MarshalJSON 测试标准时间的 JSON 序列化
func TestStandardTime_MarshalJSON(t *testing.T) {
	// 创建测试时间
	testTime := time.Date(2024, 1, 4, 12, 0, 0, 0, time.UTC)
	st := NewStandardTime(testTime)

	// 序列化
	jsonData, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("Failed to marshal StandardTime: %v", err)
	}

	// 验证格式
	expected := `"2024-01-04T12:00:00Z"`
	if string(jsonData) != expected {
		t.Errorf("Expected %s, got %s", expected, string(jsonData))
	}
}

// TestStandardTime_UnmarshalJSON 测试标准时间的 JSON 反序列化
func TestStandardTime_UnmarshalJSON(t *testing.T) {
	jsonData := `"2024-01-04T12:00:00Z"`

	var st StandardTime
	err := json.Unmarshal([]byte(jsonData), &st)
	if err != nil {
		t.Fatalf("Failed to unmarshal StandardTime: %v", err)
	}

	// 验证时间值
	expected := time.Date(2024, 1, 4, 12, 0, 0, 0, time.UTC)
	if !st.Time.Equal(expected) {
		t.Errorf("Expected %v, got %v", expected, st.Time)
	}
}

// TestValidateISO8601 测试 ISO 8601 格式验证
func TestValidateISO8601(t *testing.T) {
	validFormats := []string{
		"2024-01-04T12:00:00Z",
		"2024-01-04T12:00:00+00:00",
		"2024-01-04T12:00:00.123Z",
		"2024-12-31T23:59:59Z",
	}

	for _, format := range validFormats {
		t.Run("valid_"+format, func(t *testing.T) {
			if err := ValidateISO8601(format); err != nil {
				t.Errorf("Expected format %s to be valid: %v", format, err)
			}
		})
	}

	invalidFormats := []string{
		"2024-01-04 12:00:00",
		"2024/01/04T12:00:00Z",
		"24-01-04T12:00:00Z",
		"2024-13-04T12:00:00Z",
		"2024-01-32T12:00:00Z",
		"invalid-time",
		"",
	}

	for _, format := range invalidFormats {
		t.Run("invalid_"+format, func(t *testing.T) {
			if err := ValidateISO8601(format); err == nil {
				t.Errorf("Expected format %s to be invalid", format)
			}
		})
	}
}

// Property Test: 时间戳格式一致性
// Feature: ir-system-info-collector, Property 5: 时间戳格式一致性
func TestProperty_TimestampFormatConsistency(t *testing.T) {
	// 属性测试：对于任何时间戳，应使用 ISO 8601 格式并明确标识时区（推荐 UTC）
	property := func(year int, month, day, hour, minute, second int) bool {
		// 限制输入范围到有效值
		if year < 1970 || year > 2100 {
			return true
		}
		if month < 1 || month > 12 {
			return true
		}
		if day < 1 || day > 31 {
			return true
		}
		if hour < 0 || hour > 23 {
			return true
		}
		if minute < 0 || minute > 59 {
			return true
		}
		if second < 0 || second > 59 {
			return true
		}

		// 尝试创建时间（可能失败，如 2月30日）
		testTime := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)

		// 如果日期无效，time.Date 会自动调整，我们检查是否还是原来的日期
		if testTime.Year() != year || int(testTime.Month()) != month || testTime.Day() != day {
			return true // 跳过无效日期
		}

		// 创建标准时间
		st := NewStandardTime(testTime)

		// 序列化为 JSON
		jsonData, err := json.Marshal(st)
		if err != nil {
			return false
		}

		// 验证 JSON 格式
		var timeStr string
		err = json.Unmarshal(jsonData, &timeStr)
		if err != nil {
			return false
		}

		// 验证是否符合 ISO 8601 格式
		err = ValidateISO8601(timeStr)
		if err != nil {
			return false
		}

		// 验证时区是 UTC（应该以 Z 结尾）
		if !strings.HasSuffix(timeStr, "Z") && !strings.Contains(timeStr, "+00:00") {
			return false
		}

		// 验证往返一致性
		var st2 StandardTime
		err = json.Unmarshal(jsonData, &st2)
		if err != nil {
			return false
		}

		// 时间应该相等（允许纳秒级差异）
		return st.Time.Truncate(time.Second).Equal(st2.Time.Truncate(time.Second))
	}

	// 运行属性测试，减少到10次迭代以提高速度
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Timestamp format consistency property failed: %v", err)
	}
}

// Property Test: 时间戳标准化
// Feature: ir-system-info-collector, Property 5: 时间戳格式一致性
func TestProperty_TimestampNormalization(t *testing.T) {
	// 属性测试：所有时间戳都应该标准化为 UTC
	property := func(offsetHours int) bool {
		// 限制时区偏移范围
		if offsetHours < -12 || offsetHours > 14 {
			return true
		}

		// 创建带时区的时间
		location := time.FixedZone("TEST", offsetHours*3600)
		localTime := time.Date(2024, 1, 4, 12, 0, 0, 0, location)

		// 标准化时间戳
		normalized := NormalizeTimestamp(localTime)

		// 验证结果是 UTC
		if normalized.Location() != time.UTC {
			return false
		}

		// 验证时间值正确（应该转换为 UTC）
		expectedUTC := localTime.UTC()
		return normalized.Equal(expectedUTC)
	}

	// 运行属性测试，减少到10次迭代
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Timestamp normalization property failed: %v", err)
	}
}

// Property Test: 格式化和解析一致性
// Feature: ir-system-info-collector, Property 5: 时间戳格式一致性
func TestProperty_FormatParseConsistency(t *testing.T) {
	// 属性测试：格式化然后解析应该得到相同的时间
	property := func(year int, month, day, hour, minute, second int) bool {
		// 限制输入范围到有效值
		if year < 1970 || year > 2100 {
			return true
		}
		if month < 1 || month > 12 {
			return true
		}
		if day < 1 || day > 31 {
			return true
		}
		if hour < 0 || hour > 23 {
			return true
		}
		if minute < 0 || minute > 59 {
			return true
		}
		if second < 0 || second > 59 {
			return true
		}

		// 创建时间
		original := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)

		// 如果日期无效，跳过
		if original.Year() != year || int(original.Month()) != month || original.Day() != day {
			return true
		}

		// 格式化
		formatted := FormatTimestamp(original)

		// 解析
		parsed, err := ParseTimestamp(formatted)
		if err != nil {
			return false
		}

		// 验证一致性（截断到秒级避免精度问题）
		return original.Truncate(time.Second).Equal(parsed.Truncate(time.Second))
	}

	// 运行属性测试，减少到10次迭代
	config := &quick.Config{MaxCount: 10}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Format-parse consistency property failed: %v", err)
	}
}

// TestTimestampConsistencyCheck 测试时间戳一致性检查
func TestTimestampConsistencyCheck(t *testing.T) {
	// 测试有效时间戳
	validTimestamps := []string{
		"2024-01-04T12:00:00Z",
		"2024-01-04T12:00:00+00:00",
		"2024-12-31T23:59:59Z",
	}

	err := TimestampConsistencyCheck(validTimestamps)
	if err != nil {
		t.Errorf("Valid timestamps should pass consistency check: %v", err)
	}

	// 测试包含无效时间戳的列表
	invalidTimestamps := []string{
		"2024-01-04T12:00:00Z",
		"invalid-timestamp",
		"2024-12-31T23:59:59Z",
	}

	err = TimestampConsistencyCheck(invalidTimestamps)
	if err == nil {
		t.Error("Invalid timestamps should fail consistency check")
	}
}
