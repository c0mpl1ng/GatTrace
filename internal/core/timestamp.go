package core

import (
	"encoding/json"
	"fmt"
	"time"
)

// StandardTime 标准化时间类型，确保 JSON 序列化时使用 ISO 8601 格式和 UTC 时区
type StandardTime struct {
	time.Time
}

// NewStandardTime 创建新的标准化时间
func NewStandardTime(t time.Time) StandardTime {
	return StandardTime{Time: t.UTC()}
}

// Now 获取当前时间的标准化版本
func Now() StandardTime {
	return StandardTime{Time: time.Now().UTC()}
}

// MarshalJSON 实现 JSON 序列化，确保使用 ISO 8601 格式和 UTC 时区
func (st StandardTime) MarshalJSON() ([]byte, error) {
	// 使用 RFC3339 格式，这是 ISO 8601 的一个子集，并确保时区为 UTC
	formatted := st.Time.Format(time.RFC3339)
	return json.Marshal(formatted)
}

// UnmarshalJSON 实现 JSON 反序列化
func (st *StandardTime) UnmarshalJSON(data []byte) error {
	var timeStr string
	if err := json.Unmarshal(data, &timeStr); err != nil {
		return err
	}

	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return fmt.Errorf("failed to parse time %s: %w", timeStr, err)
	}

	st.Time = parsedTime.UTC()
	return nil
}

// String 返回标准化的时间字符串表示
func (st StandardTime) String() string {
	return st.Time.Format(time.RFC3339)
}

// ValidateISO8601 验证时间字符串是否符合 ISO 8601 格式
func ValidateISO8601(timeStr string) error {
	_, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return fmt.Errorf("time string '%s' is not in valid ISO 8601 format: %w", timeStr, err)
	}
	return nil
}

// NormalizeTimestamp 标准化时间戳，确保使用 UTC 时区
func NormalizeTimestamp(t time.Time) time.Time {
	return t.UTC()
}

// FormatTimestamp 格式化时间戳为 ISO 8601 格式
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// ParseTimestamp 解析 ISO 8601 格式的时间戳
func ParseTimestamp(timeStr string) (time.Time, error) {
	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp %s: %w", timeStr, err)
	}
	return parsedTime.UTC(), nil
}

// TimestampConsistencyCheck 检查时间戳格式一致性
func TimestampConsistencyCheck(timestamps []string) error {
	for i, ts := range timestamps {
		if err := ValidateISO8601(ts); err != nil {
			return fmt.Errorf("timestamp at index %d is invalid: %w", i, err)
		}
	}
	return nil
}