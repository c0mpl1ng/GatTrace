package core

import (
	"fmt"
	"regexp"
)

// ValidateSemanticVersion 验证版本号是否符合语义化版本规范
func ValidateSemanticVersion(version string) error {
	// 语义化版本正则表达式 (vX.Y.Z 或 X.Y.Z 格式)
	semverRegex := regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	
	if !semverRegex.MatchString(version) {
		return fmt.Errorf("version '%s' does not follow semantic versioning format (e.g., v1.0.0)", version)
	}
	
	return nil
}

// NormalizeVersion 标准化版本号格式
func NormalizeVersion(version string) string {
	// 确保版本号以 'v' 开头
	if len(version) > 0 && version[0] != 'v' {
		return "v" + version
	}
	return version
}