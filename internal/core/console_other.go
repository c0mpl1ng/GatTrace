//go:build !windows

package core

// InitWindowsConsole 非 Windows 平台的空实现
func InitWindowsConsole() {
	// 非 Windows 平台不需要特殊处理
}

// platformIsLegacyWindows 非 Windows 平台始终返回 false
func platformIsLegacyWindows() bool {
	return false
}

// convertToLegacyEncoding 非 Windows 平台不需要转换
func convertToLegacyEncoding(s string) string {
	return s
}
