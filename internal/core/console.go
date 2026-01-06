package core

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
)

// ConsoleConfig 控制台配置
type ConsoleConfig struct {
	// UseEmoji 是否使用emoji字符
	UseEmoji bool
	// UseUnicode 是否使用Unicode特殊字符
	UseUnicode bool
}

var (
	consoleConfig     ConsoleConfig
	consoleConfigOnce sync.Once
)

// initConsoleConfig 初始化控制台配置
func initConsoleConfig() {
	consoleConfigOnce.Do(func() {
		consoleConfig = ConsoleConfig{
			UseEmoji:   true,
			UseUnicode: true,
		}

		// Windows 系统需要检查版本
		if runtime.GOOS == "windows" {
			if isLegacyWindows() {
				consoleConfig.UseEmoji = false
				consoleConfig.UseUnicode = false
			}
		}
	})
}

// isLegacyWindows 检查是否为旧版 Windows（Windows 7 或更早）
func isLegacyWindows() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// 检查环境变量 GATTRACE_LEGACY_CONSOLE
	if os.Getenv("GATTRACE_LEGACY_CONSOLE") == "1" {
		return true
	}

	// 使用平台特定的检测
	return platformIsLegacyWindows()
}

// GetConsoleConfig 获取控制台配置
func GetConsoleConfig() ConsoleConfig {
	initConsoleConfig()
	return consoleConfig
}

// SetLegacyMode 强制设置为兼容模式
func SetLegacyMode(legacy bool) {
	initConsoleConfig()
	consoleConfig.UseEmoji = !legacy
	consoleConfig.UseUnicode = !legacy
}

// emojiReplacements emoji 到 ASCII 的替换映射
var emojiReplacements = map[string]string{
	"✅": "[OK]",
	"❌": "[X]",
	"⚠️": "[!]",
	"⚠":  "[!]",
	"✓":  "[v]",
	"🔍": "[?]",
	"📊": "[#]",
	"🌐": "[N]",
	"⚙️": "[*]",
	"⚙":  "[*]",
	"👤": "[U]",
	"🔄": "[R]",
	"📁": "[F]",
	"🔒": "[S]",
	"💻": "[C]",
	"🎉": "[!]",
	"🔴": "[!!]",
	"ℹ️": "[i]",
	"ℹ":  "[i]",
}

// ConsoleText 转换文本以适应控制台输出
// 只替换 emoji，不做其他处理
func ConsoleText(text string) string {
	initConsoleConfig()

	if consoleConfig.UseEmoji {
		return text
	}

	// 替换 emoji 为 ASCII
	result := text
	for emoji, replacement := range emojiReplacements {
		result = strings.ReplaceAll(result, emoji, replacement)
	}

	return result
}

// Printf 格式化打印（只处理 emoji）
func Printf(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Print(ConsoleText(text))
}

// Println 打印并换行（只处理 emoji）
func Println(args ...interface{}) {
	text := fmt.Sprint(args...)
	fmt.Println(ConsoleText(text))
}

// ConsolePrint 打印文本到控制台
func ConsolePrint(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Print(ConsoleText(text))
}

// ConsolePrintln 打印文本到控制台并换行
func ConsolePrintln(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Println(ConsoleText(text))
}

// ConsoleSuccess 打印成功消息
func ConsoleSuccess(format string, args ...interface{}) {
	initConsoleConfig()
	prefix := "✅ "
	if !consoleConfig.UseEmoji {
		prefix = "[OK] "
	}
	text := fmt.Sprintf(format, args...)
	fmt.Println(ConsoleText(prefix + text))
}

// ConsoleWarning 打印警告消息
func ConsoleWarning(format string, args ...interface{}) {
	initConsoleConfig()
	prefix := "⚠️  "
	if !consoleConfig.UseEmoji {
		prefix = "[!] "
	}
	text := fmt.Sprintf(format, args...)
	fmt.Println(ConsoleText(prefix + text))
}

// ConsoleError 打印错误消息
func ConsoleError(format string, args ...interface{}) {
	initConsoleConfig()
	prefix := "❌ "
	if !consoleConfig.UseEmoji {
		prefix = "[X] "
	}
	text := fmt.Sprintf(format, args...)
	fmt.Println(ConsoleText(prefix + text))
}

// ConsoleInfo 打印信息消息
func ConsoleInfo(format string, args ...interface{}) {
	initConsoleConfig()
	prefix := "✓ "
	if !consoleConfig.UseEmoji {
		prefix = "[v] "
	}
	text := fmt.Sprintf(format, args...)
	fmt.Println(ConsoleText(prefix + text))
}
