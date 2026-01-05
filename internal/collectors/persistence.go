package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"GatTrace/internal/core"
)

// PersistenceCollector 持久化机制采集器
type PersistenceCollector struct {
	adapter core.PlatformAdapter
}

// NewPersistenceCollector 创建持久化机制采集器
func NewPersistenceCollector(adapter core.PlatformAdapter) *PersistenceCollector {
	return &PersistenceCollector{
		adapter: adapter,
	}
}

// Name 返回采集器名称
func (c *PersistenceCollector) Name() string {
	return "persistence"
}

// RequiresPrivileges 返回是否需要特权
func (c *PersistenceCollector) RequiresPrivileges() bool {
	return true // 持久化机制采集通常需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *PersistenceCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行持久化机制信息采集
func (c *PersistenceCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 使用平台适配器获取持久化信息
	persistenceInfo, err := c.adapter.GetPersistenceInfo()
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "persistence",
			Operation: "GetPersistenceInfo",
			Err:       err,
			Severity:  core.SeverityError,
		}
		errors = append(errors, collectionErr)

		// 如果平台适配器失败，尝试使用通用方法
		persistenceInfo, err = c.collectGenericPersistenceInfo()
		if err != nil {
			collectionErr := core.CollectionError{
				Module:    "persistence",
				Operation: "collectGenericPersistenceInfo",
				Err:       err,
				Severity:  core.SeverityCritical,
			}
			errors = append(errors, collectionErr)
			return &core.CollectionResult{Data: nil, Errors: errors}, err
		}
	}

	return &core.CollectionResult{
		Data:   persistenceInfo,
		Errors: errors,
	}, nil
}

// collectGenericPersistenceInfo 使用通用方法采集持久化信息
func (c *PersistenceCollector) collectGenericPersistenceInfo() (*core.PersistenceInfo, error) {
	// 创建基础元数据
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	persistenceInfo := &core.PersistenceInfo{
		Metadata: metadata,
		Items:    []core.PersistenceItem{},
	}

	// 根据平台获取持久化项目
	var items []core.PersistenceItem
	var err error

	switch runtime.GOOS {
	case "windows":
		items, err = c.getWindowsPersistenceItems()
	case "linux":
		items, err = c.getLinuxPersistenceItems()
	case "darwin":
		items, err = c.getDarwinPersistenceItems()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get persistence items: %w", err)
	}

	persistenceInfo.Items = items
	return persistenceInfo, nil
}

// getWindowsPersistenceItems 获取Windows持久化项目
func (c *PersistenceCollector) getWindowsPersistenceItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// Windows启动项目位置
	startupPaths := []string{
		"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		"C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
	}

	for _, path := range startupPaths {
		// 展开环境变量
		expandedPath := os.ExpandEnv(path)
		startupItems, err := c.scanStartupDirectory(expandedPath, "startup")
		if err == nil {
			items = append(items, startupItems...)
		}
	}

	// 注册表启动项（简化实现）
	registryItems := []core.PersistenceItem{
		{
			Type:    "registry",
			Name:    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Path:    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Command: "",
			User:    "SYSTEM",
			Enabled: true,
			Properties: map[string]string{
				"location": "registry",
				"scope":    "machine",
			},
		},
		{
			Type:    "registry",
			Name:    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Path:    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Command: "",
			User:    "current_user",
			Enabled: true,
			Properties: map[string]string{
				"location": "registry",
				"scope":    "user",
			},
		},
	}

	items = append(items, registryItems...)

	// Windows服务（简化实现）
	serviceItems := []core.PersistenceItem{
		{
			Type:    "service",
			Name:    "Windows Services",
			Path:    "services.msc",
			Command: "",
			User:    "SYSTEM",
			Enabled: true,
			Properties: map[string]string{
				"location": "services",
				"scope":    "system",
			},
		},
	}

	items = append(items, serviceItems...)

	return items, nil
}

// getLinuxPersistenceItems 获取Linux持久化项目
func (c *PersistenceCollector) getLinuxPersistenceItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// systemd服务
	systemdItems, err := c.getSystemdServices()
	if err == nil {
		items = append(items, systemdItems...)
	}

	// crontab任务
	cronItems, err := c.getCronJobs()
	if err == nil {
		items = append(items, cronItems...)
	}

	// 启动脚本
	initScripts, err := c.getInitScripts()
	if err == nil {
		items = append(items, initScripts...)
	}

	// 用户自启动项
	userStartupItems, err := c.getUserStartupItems()
	if err == nil {
		items = append(items, userStartupItems...)
	}

	return items, nil
}

// getDarwinPersistenceItems 获取macOS持久化项目
func (c *PersistenceCollector) getDarwinPersistenceItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// LaunchAgents和LaunchDaemons
	launchItems, err := c.getLaunchItems()
	if err == nil {
		items = append(items, launchItems...)
	}

	// 登录项
	loginItems, err := c.getLoginItems()
	if err == nil {
		items = append(items, loginItems...)
	}

	// crontab任务（macOS也支持）
	cronItems, err := c.getCronJobs()
	if err == nil {
		items = append(items, cronItems...)
	}

	return items, nil
}

// scanStartupDirectory 扫描启动目录
func (c *PersistenceCollector) scanStartupDirectory(dirPath, itemType string) ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return items, nil
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(dirPath, entry.Name())
		item := core.PersistenceItem{
			Type:    itemType,
			Name:    entry.Name(),
			Path:    fullPath,
			Command: fullPath,
			User:    "current_user",
			Enabled: true,
			Properties: map[string]string{
				"location": "startup_folder",
			},
		}

		items = append(items, item)
	}

	return items, nil
}

// getSystemdServices 获取systemd服务
func (c *PersistenceCollector) getSystemdServices() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// systemd服务目录
	serviceDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, dir := range serviceDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}

			fullPath := filepath.Join(dir, entry.Name())
			serviceName := strings.TrimSuffix(entry.Name(), ".service")

			item := core.PersistenceItem{
				Type:    "systemd_service",
				Name:    serviceName,
				Path:    fullPath,
				Command: fmt.Sprintf("systemctl start %s", serviceName),
				User:    "root",
				Enabled: true, // 简化实现，实际应该检查服务状态
				Properties: map[string]string{
					"location":     "systemd",
					"service_type": "system",
				},
			}

			items = append(items, item)
		}
	}

	return items, nil
}

// getCronJobs 获取cron任务
func (c *PersistenceCollector) getCronJobs() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// 系统crontab
	systemCronPaths := []string{
		"/etc/crontab",
		"/etc/cron.d",
	}

	for _, path := range systemCronPaths {
		cronItems, err := c.parseCronFile(path, "root")
		if err == nil {
			items = append(items, cronItems...)
		}
	}

	// 用户crontab（简化实现）
	userCronItem := core.PersistenceItem{
		Type:    "cron",
		Name:    "user_crontab",
		Path:    "/var/spool/cron/crontabs",
		Command: "crontab -l",
		User:    "current_user",
		Enabled: true,
		Properties: map[string]string{
			"location": "user_cron",
		},
	}

	items = append(items, userCronItem)

	return items, nil
}

// getInitScripts 获取初始化脚本
func (c *PersistenceCollector) getInitScripts() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// SysV init脚本
	initDirs := []string{
		"/etc/init.d",
		"/etc/rc.d/init.d",
	}

	for _, dir := range initDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			fullPath := filepath.Join(dir, entry.Name())
			item := core.PersistenceItem{
				Type:    "init_script",
				Name:    entry.Name(),
				Path:    fullPath,
				Command: fullPath,
				User:    "root",
				Enabled: true,
				Properties: map[string]string{
					"location": "init_d",
				},
			}

			items = append(items, item)
		}
	}

	return items, nil
}

// getUserStartupItems 获取用户自启动项
func (c *PersistenceCollector) getUserStartupItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// XDG自启动目录
	xdgDirs := []string{
		"/etc/xdg/autostart",
		"~/.config/autostart",
	}

	for _, dir := range xdgDirs {
		expandedDir := os.ExpandEnv(dir)
		if strings.HasPrefix(expandedDir, "~") {
			// 简化处理，实际应该获取用户主目录
			continue
		}

		startupItems, err := c.scanStartupDirectory(expandedDir, "xdg_autostart")
		if err == nil {
			items = append(items, startupItems...)
		}
	}

	return items, nil
}

// getLaunchItems 获取macOS Launch项目
func (c *PersistenceCollector) getLaunchItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// LaunchDaemons和LaunchAgents目录
	launchDirs := []string{
		"/System/Library/LaunchDaemons",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/Library/LaunchAgents",
		"~/Library/LaunchAgents",
	}

	for _, dir := range launchDirs {
		expandedDir := os.ExpandEnv(dir)
		if strings.HasPrefix(expandedDir, "~") {
			// 简化处理，实际应该获取用户主目录
			continue
		}

		if _, err := os.Stat(expandedDir); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(expandedDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}

			fullPath := filepath.Join(expandedDir, entry.Name())
			itemType := "launch_daemon"
			if strings.Contains(dir, "LaunchAgents") {
				itemType = "launch_agent"
			}

			item := core.PersistenceItem{
				Type:    itemType,
				Name:    strings.TrimSuffix(entry.Name(), ".plist"),
				Path:    fullPath,
				Command: fmt.Sprintf("launchctl load %s", fullPath),
				User:    "root",
				Enabled: true,
				Properties: map[string]string{
					"location": "launchd",
				},
			}

			if itemType == "launch_agent" {
				item.User = "current_user"
			}

			items = append(items, item)
		}
	}

	return items, nil
}

// getLoginItems 获取macOS登录项
func (c *PersistenceCollector) getLoginItems() ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	// 登录项（简化实现）
	loginItem := core.PersistenceItem{
		Type:    "login_item",
		Name:    "Login Items",
		Path:    "~/Library/Preferences/com.apple.loginitems.plist",
		Command: "osascript -e 'tell application \"System Events\" to get the name of every login item'",
		User:    "current_user",
		Enabled: true,
		Properties: map[string]string{
			"location": "login_items",
		},
	}

	items = append(items, loginItem)

	return items, nil
}

// parseCronFile 解析cron文件
func (c *PersistenceCollector) parseCronFile(filePath, user string) ([]core.PersistenceItem, error) {
	var items []core.PersistenceItem

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return items, nil
	}

	// 简化实现，实际应该解析cron文件内容
	item := core.PersistenceItem{
		Type:    "cron",
		Name:    filepath.Base(filePath),
		Path:    filePath,
		Command: fmt.Sprintf("cat %s", filePath),
		User:    user,
		Enabled: true,
		Properties: map[string]string{
			"location": "cron_file",
		},
	}

	items = append(items, item)

	return items, nil
}
