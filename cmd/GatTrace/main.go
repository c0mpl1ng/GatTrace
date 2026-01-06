package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"GatTrace/internal/collectors"
	"GatTrace/internal/core"
	"GatTrace/internal/platform"
)

// Config 应用程序配置
type Config struct {
	OutputDir   string
	Verbose     bool
	Timeout     time.Duration
	ShowVersion bool
	ShowHelp    bool
	Days        int // 日志和文件系统采集的时间范围（天数）
}

func main() {
	// 初始化 Windows 控制台（设置正确的代码页）
	core.InitWindowsConsole()

	// 解析命令行参数
	config := parseFlags()

	// 处理版本和帮助信息
	if config.ShowVersion {
		core.Printf("GatTrace %s\n", core.Version)
		core.Println("应急响应系统信息采集工具")
		os.Exit(0)
	}

	if config.ShowHelp {
		printUsage()
		os.Exit(0)
	}

	// 检查管理员权限
	checkAdminPrivileges()

	// 设置日志级别
	if config.Verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	// 创建输出目录
	outputDir, err := createOutputDirectory(config.OutputDir)
	if err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	core.Printf("GatTrace %s - 应急响应系统信息采集工具\n", core.Version)
	core.Printf("输出目录: %s\n", outputDir)
	core.Printf("超时设置: %v\n", config.Timeout)
	core.Printf("采集时间范围: %d 天\n", config.Days)
	core.Println("开始采集系统信息...")

	// 创建并运行应用程序
	app := core.NewApplication(core.Version)

	// 注册所有采集器
	if err := registerCollectors(app, config.Days); err != nil {
		log.Fatalf("Failed to register collectors: %v", err)
	}

	if err := app.Run(ctx, outputDir, config.Verbose); err != nil {
		log.Printf("采集过程中发生错误: %v", err)
		os.Exit(1)
	}

	core.ConsoleSuccess("GatTrace 采集完成，结果保存在: %s", outputDir)
}

// checkAdminPrivileges 检查管理员权限并给出提示
func checkAdminPrivileges() {
	isAdmin := false

	switch runtime.GOOS {
	case "windows":
		isAdmin = isWindowsAdmin()
	case "linux", "darwin":
		isAdmin = os.Geteuid() == 0
	}

	if !isAdmin {
		core.ConsoleWarning("警告: 程序未以管理员权限运行")
		core.Println("   部分功能可能受限:")
		switch runtime.GOOS {
		case "windows":
			core.Println("   - Security 日志（登录/注销事件）无法访问")
			core.Println("   - 某些系统进程信息可能不完整")
			core.Println("   - 部分文件系统信息可能无法获取")
			core.Println("")
			core.Println("   建议: 右键点击程序，选择\"以管理员身份运行\"")
		case "linux", "darwin":
			core.Println("   - 安全日志可能无法完整访问")
			core.Println("   - 某些系统进程信息可能不完整")
			core.Println("   - 部分文件系统信息可能无法获取")
			core.Println("")
			core.Println("   建议: 使用 sudo 运行程序")
		}
		core.Println("")
	}
}

// isWindowsAdmin 检查 Windows 上是否具有管理员权限
func isWindowsAdmin() bool {
	// 尝试打开一个需要管理员权限的文件
	// 这是一个简单但有效的检测方法
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// registerCollectors 注册所有采集器
func registerCollectors(app *core.App, days int) error {
	// 创建平台适配器
	adapter, err := platform.NewPlatformAdapter()
	if err != nil {
		return fmt.Errorf("failed to create platform adapter: %w", err)
	}

	// 注册网络信息采集器
	app.RegisterCollector(collectors.NewNetworkCollector(adapter))

	// 注册进程信息采集器
	app.RegisterCollector(collectors.NewProcessCollector(adapter))

	// 注册用户信息采集器
	app.RegisterCollector(collectors.NewUserCollector(adapter))

	// 注册文件系统采集器（使用可配置的天数）
	app.RegisterCollector(collectors.NewFileSystemCollectorWithDays(adapter, days))

	// 注册安全日志采集器（使用可配置的天数）
	app.RegisterCollector(collectors.NewSecurityCollectorWithDays(adapter, days))

	// 注册系统信息采集器
	app.RegisterCollector(collectors.NewSystemCollector(adapter))

	// 注册持久化机制采集器
	app.RegisterCollector(collectors.NewPersistenceCollector(adapter))

	return nil
}

// parseFlags 解析命令行参数
func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.OutputDir, "output", "", "输出目录路径 (默认: ir_output/hostname-timestamp)")
	flag.StringVar(&config.OutputDir, "o", "", "输出目录路径 (简写)")
	flag.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")
	flag.BoolVar(&config.Verbose, "v", false, "详细输出模式 (简写)")
	flag.DurationVar(&config.Timeout, "timeout", 5*time.Minute, "采集超时时间")
	flag.DurationVar(&config.Timeout, "t", 5*time.Minute, "采集超时时间 (简写)")
	flag.IntVar(&config.Days, "days", 7, "日志和文件系统采集的时间范围（天数）")
	flag.IntVar(&config.Days, "d", 7, "日志和文件系统采集的时间范围（天数）(简写)")
	flag.BoolVar(&config.ShowVersion, "version", false, "显示版本信息")
	flag.BoolVar(&config.ShowHelp, "help", false, "显示帮助信息")
	flag.BoolVar(&config.ShowHelp, "h", false, "显示帮助信息 (简写)")

	flag.Parse()

	// 验证 days 参数
	if config.Days < 1 {
		config.Days = 1
	} else if config.Days > 365 {
		config.Days = 365
	}

	return config
}

// createOutputDirectory 创建输出目录
func createOutputDirectory(customDir string) (string, error) {
	var outputDir string

	if customDir != "" {
		// 使用用户指定的目录
		outputDir = customDir
	} else {
		// 使用默认格式: ir_output/hostname-timestamp
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		timestamp := time.Now().Format("20060102T150405Z")
		outputDir = filepath.Join("ir_output", fmt.Sprintf("%s-%s", hostname, timestamp))
	}

	// 创建目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", outputDir, err)
	}

	// 转换为绝对路径
	absPath, err := filepath.Abs(outputDir)
	if err != nil {
		return outputDir, nil // 如果无法获取绝对路径，返回相对路径
	}

	return absPath, nil
}

// printUsage 打印使用说明
func printUsage() {
	core.Printf("GatTrace %s - 应急响应系统信息采集工具\n\n", core.Version)
	core.Println("用法:")
	core.Printf("  %s [选项]\n\n", os.Args[0])
	core.Println("选项:")
	core.Println("  -o, --output <目录>     指定输出目录 (默认: ir_output/hostname-timestamp)")
	core.Println("  -v, --verbose           详细输出模式")
	core.Println("  -t, --timeout <时间>    采集超时时间 (默认: 5m)")
	core.Println("  -d, --days <天数>       日志和文件系统采集的时间范围 (默认: 7天, 范围: 1-365)")
	core.Println("  --version               显示版本信息")
	core.Println("  -h, --help              显示此帮助信息")
	core.Println("")
	core.Println("示例:")
	core.Printf("  %s                      # 使用默认设置采集\n", os.Args[0])
	core.Printf("  %s -o /tmp/ir-data      # 指定输出目录\n", os.Args[0])
	core.Printf("  %s -v -t 10m            # 详细模式，10分钟超时\n", os.Args[0])
	core.Printf("  %s -d 30                # 采集最近30天的日志和文件\n", os.Args[0])
	core.Println("")
	core.Println("输出:")
	core.Println("  工具会在指定目录中创建以下文件:")
	core.Println("  - *.json                各类系统信息的JSON文件")
	core.Println("  - index.html            可视化报告页面")
	core.Println("  - assets/               报告所需的CSS和JS资源")
	core.Println("  - manifest.json         文件清单和完整性哈希")
	core.Println("")
	core.Println("注意:")
	core.Println("  - 工具以只读模式运行，不会修改系统状态")
	core.Println("  - 某些功能可能需要管理员权限才能完整采集")
	core.Println("  - 生成的报告可以离线查看，无需网络连接")
}
