//go:build windows

package core

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procGetVersionExW = kernel32.NewProc("GetVersionExW")
)

// OSVERSIONINFOEXW Windows 版本信息结构
type OSVERSIONINFOEXW struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        byte
	wReserved           byte
}

// windowsVersion 缓存的 Windows 版本信息
var windowsVersion struct {
	major       uint32
	minor       uint32
	build       uint32
	initialized bool
}

// getWindowsVersion 获取 Windows 版本
func getWindowsVersion() (major, minor, build uint32) {
	if windowsVersion.initialized {
		return windowsVersion.major, windowsVersion.minor, windowsVersion.build
	}

	var info OSVERSIONINFOEXW
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))

	ret, _, _ := procGetVersionExW.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		windowsVersion.major = info.dwMajorVersion
		windowsVersion.minor = info.dwMinorVersion
		windowsVersion.build = info.dwBuildNumber
		windowsVersion.initialized = true
	}

	return windowsVersion.major, windowsVersion.minor, windowsVersion.build
}

// isWindows7OrEarlier 检查是否为 Windows 7 或更早版本
func isWindows7OrEarlier() bool {
	major, minor, _ := getWindowsVersion()
	// Windows 7 = 6.1, Windows 8 = 6.2, Windows 10 = 10.0
	if major < 6 {
		return true
	}
	if major == 6 && minor <= 1 {
		return true
	}
	return false
}

// InitWindowsConsole 初始化 Windows 控制台
// 在 Windows 7 上不做任何特殊处理，只禁用 emoji
func InitWindowsConsole() {
	// 检查环境变量强制设置
	if os.Getenv("GATTRACE_LEGACY_CONSOLE") == "1" {
		SetLegacyMode(true)
		return
	}

	if isWindows7OrEarlier() {
		// Windows 7：禁用 emoji 和特殊 Unicode 字符
		SetLegacyMode(true)
	}
	// 不设置代码页，保持系统默认
}

// platformIsLegacyWindows 平台特定的旧版 Windows 检测
func platformIsLegacyWindows() bool {
	return isWindows7OrEarlier()
}

// convertToLegacyEncoding 不做编码转换
func convertToLegacyEncoding(s string) string {
	return s
}
