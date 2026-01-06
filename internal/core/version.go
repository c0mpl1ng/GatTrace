package core

import (
	"fmt"
	"regexp"
	"strings"
)

// Version 全局版本号常量
// 修改此处即可更新整个项目的版本号
const Version = "v1.2.2"

// GetVersion 获取当前版本号
func GetVersion() string {
	return Version
}

// ValidateSemanticVersion 验证语义化版本号格式
func ValidateSemanticVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}

	// 移除可选的 v 前缀
	v := strings.TrimPrefix(version, "v")

	// 语义化版本号正则表达式
	// 格式: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
	pattern := `^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`
	matched, err := regexp.MatchString(pattern, v)
	if err != nil {
		return fmt.Errorf("regex error: %w", err)
	}

	if !matched {
		return fmt.Errorf("invalid semantic version: %s", version)
	}

	return nil
}

// NormalizeVersion 标准化版本号（确保有 v 前缀）
func NormalizeVersion(version string) string {
	if version == "" {
		return ""
	}

	if strings.HasPrefix(version, "v") {
		return version
	}

	return "v" + version
}
