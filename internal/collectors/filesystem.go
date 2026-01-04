package collectors

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"GatTrace/internal/core"
)

// FileSystemCollector 文件系统采集器
type FileSystemCollector struct {
	adapter core.PlatformAdapter
	days    int // 采集时间范围（天数）
}

// NewFileSystemCollector 创建文件系统采集器（默认7天）
func NewFileSystemCollector(adapter core.PlatformAdapter) *FileSystemCollector {
	return &FileSystemCollector{
		adapter: adapter,
		days:    7,
	}
}

// NewFileSystemCollectorWithDays 创建文件系统采集器（可配置天数）
func NewFileSystemCollectorWithDays(adapter core.PlatformAdapter, days int) *FileSystemCollector {
	if days < 1 {
		days = 1
	} else if days > 365 {
		days = 365
	}
	return &FileSystemCollector{
		adapter: adapter,
		days:    days,
	}
}

// Name 返回采集器名称
func (c *FileSystemCollector) Name() string {
	return "filesystem"
}

// RequiresPrivileges 返回是否需要特权
func (c *FileSystemCollector) RequiresPrivileges() bool {
	return true // 文件系统扫描通常需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *FileSystemCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行文件系统信息采集
func (c *FileSystemCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 直接使用通用方法采集文件系统信息（绕过平台适配器的简化实现）
	fileSystemInfo, err := c.collectGenericFileSystemInfo(ctx)
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "filesystem",
			Operation: "collectGenericFileSystemInfo",
			Err:       err,
			Severity:  core.SeverityCritical,
		}
		errors = append(errors, collectionErr)
		return &core.CollectionResult{Data: nil, Errors: errors}, err
	}

	return &core.CollectionResult{
		Data:   fileSystemInfo,
		Errors: errors,
	}, nil
}

// collectGenericFileSystemInfo 使用通用方法采集文件系统信息
func (c *FileSystemCollector) collectGenericFileSystemInfo(ctx context.Context) (*core.FileSystemInfo, error) {
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"
	
	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	fileSystemInfo := &core.FileSystemInfo{
		Metadata:    metadata,
		RecentFiles: []core.FileInfo{},
	}

	// 获取最近修改和访问的文件
	recentFiles, err := c.getRecentFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent files: %w", err)
	}

	fileSystemInfo.RecentFiles = recentFiles
	return fileSystemInfo, nil
}

// getRecentFiles 获取最近修改和访问的文件
func (c *FileSystemCollector) getRecentFiles(ctx context.Context) ([]core.FileInfo, error) {
	var files []core.FileInfo
	
	// 根据平台定义关键目录
	keyDirectories := c.getKeyDirectories()
	
	// 限制扫描的文件数量和时间
	maxFiles := 1000
	maxAge := time.Duration(c.days) * 24 * time.Hour
	cutoffTime := time.Now().Add(-maxAge)
	
	for _, dir := range keyDirectories {
		select {
		case <-ctx.Done():
			return files, ctx.Err()
		default:
		}
		
		// 扫描目录（同时检查修改时间和访问时间）
		dirFiles, err := c.scanDirectory(ctx, dir, cutoffTime, maxFiles-len(files))
		if err != nil {
			continue
		}
		
		files = append(files, dirFiles...)
		
		if len(files) >= maxFiles {
			break
		}
	}
	
	return files, nil
}

// getKeyDirectories 根据平台获取关键目录
func (c *FileSystemCollector) getKeyDirectories() []string {
	switch runtime.GOOS {
	case "windows":
		userProfile := os.Getenv("USERPROFILE")
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = "C:\\ProgramData"
		}
		dirs := []string{
			"C:\\Windows\\System32\\config",      // 注册表配置
			"C:\\Windows\\System32\\drivers",     // 驱动程序
			"C:\\Windows\\System32\\Tasks",       // 计划任务
			"C:\\Windows\\Prefetch",              // 预取文件
			"C:\\Windows\\Temp",                  // 临时文件
			programData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", // 启动项
		}
		if userProfile != "" {
			dirs = append(dirs,
				userProfile+"\\AppData\\Roaming\\Microsoft\\Windows\\Recent",           // 最近文件
				userProfile+"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", // 用户启动项
				userProfile+"\\AppData\\Local\\Temp",                                   // 用户临时文件
				userProfile+"\\Downloads",                                              // 下载目录
				userProfile+"\\Desktop",                                                // 桌面
			)
		}
		return dirs
	case "linux":
		homeDir := os.Getenv("HOME")
		dirs := []string{
			"/bin",
			"/sbin",
			"/usr/bin",
			"/usr/sbin",
			"/usr/local/bin",
			"/etc",
			"/var/log",
			"/tmp",
			"/var/tmp",
		}
		if homeDir != "" {
			dirs = append(dirs,
				homeDir,
				homeDir+"/.ssh",
				homeDir+"/.config",
			)
		}
		return dirs
	case "darwin":
		homeDir := os.Getenv("HOME")
		dirs := []string{
			"/bin",
			"/sbin",
			"/usr/bin",
			"/usr/sbin",
			"/usr/local/bin",
			"/Library/LaunchAgents",
			"/Library/LaunchDaemons",
			"/var/log",
			"/tmp",
			"/private/var/tmp",
		}
		if homeDir != "" {
			dirs = append(dirs,
				homeDir+"/Library/LaunchAgents",
				homeDir+"/Downloads",
				homeDir+"/Desktop",
				homeDir+"/.ssh",
				homeDir+"/.config",
			)
		}
		return dirs
	default:
		return []string{"/"}
	}
}

// scanDirectory 扫描目录获取最近修改或访问的文件
func (c *FileSystemCollector) scanDirectory(ctx context.Context, dirPath string, cutoffTime time.Time, maxFiles int) ([]core.FileInfo, error) {
	var files []core.FileInfo
	
	// 检查目录是否存在
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return files, nil
	}
	
	// 限制扫描深度
	maxDepth := 3
	baseDepth := strings.Count(dirPath, string(os.PathSeparator))
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		// 检查上下文
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		if err != nil {
			return nil // 跳过无法访问的文件/目录
		}
		
		// 检查深度限制
		currentDepth := strings.Count(path, string(os.PathSeparator))
		if currentDepth-baseDepth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		// 跳过目录
		if info.IsDir() {
			return nil
		}
		
		// 获取文件的访问时间和修改时间
		modTime := info.ModTime()
		accessTime := getFileAccessTime(info) // 使用平台特定的实现
		
		// 检查文件修改时间或访问时间是否在时间范围内
		modTimeInRange := modTime.After(cutoffTime)
		accessTimeInRange := accessTime.After(cutoffTime)
		
		if !modTimeInRange && !accessTimeInRange {
			return nil
		}
		
		// 跳过过大的文件
		if info.Size() > 100*1024*1024 { // 100MB
			return nil
		}
		
		// 创建文件信息
		fileInfo, err := c.createFileInfo(path, info, accessTime)
		if err != nil {
			return nil
		}
		
		files = append(files, fileInfo)
		
		if len(files) >= maxFiles {
			return filepath.SkipAll
		}
		
		return nil
	})
	
	return files, err
}



// createFileInfo 创建文件信息
func (c *FileSystemCollector) createFileInfo(filePath string, info os.FileInfo, accessTime time.Time) (core.FileInfo, error) {
	fileInfo := core.FileInfo{
		Path:       filePath,
		Size:       info.Size(),
		Mode:       info.Mode().String(),
		ModTime:    info.ModTime().UTC(),
		AccessTime: accessTime.UTC(),
		ChangeTime: info.ModTime().UTC(), // 大多数系统没有单独的 ctime
	}
	
	// 获取文件所有者信息（使用平台特定的实现）
	fileInfo.Owner, fileInfo.Group = getFileOwnership(info)
	
	// 计算文件哈希（仅对小文件）
	if info.Size() < 10*1024*1024 { // 10MB以下的文件
		if hash, err := c.calculateFileHash(filePath); err == nil {
			fileInfo.Hash = hash
		}
	}
	
	return fileInfo, nil
}

// FileSystemStat 文件系统统计信息
type FileSystemStat struct {
	AccessTime time.Time
	ChangeTime time.Time
	Owner      string
	Group      string
}

// getFileSystemStat 获取文件系统特定统计信息
func (c *FileSystemCollector) getFileSystemStat(filePath string) (*FileSystemStat, error) {
	stat := &FileSystemStat{}
	
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	
	stat.AccessTime = info.ModTime()
	stat.ChangeTime = info.ModTime()
	stat.Owner = "unknown"
	stat.Group = "unknown"
	
	switch runtime.GOOS {
	case "linux", "darwin":
		return c.getUnixFileSystemStat(filePath, stat)
	case "windows":
		return c.getWindowsFileSystemStat(filePath, stat)
	}
	
	return stat, nil
}

// getUnixFileSystemStat 获取Unix系统的文件统计信息
func (c *FileSystemCollector) getUnixFileSystemStat(filePath string, stat *FileSystemStat) (*FileSystemStat, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return stat, err
	}
	
	stat.Owner, stat.Group = getFileOwnership(info)
	stat.AccessTime = getFileAccessTime(info)
	
	return stat, nil
}

// getWindowsFileSystemStat 获取Windows系统的文件统计信息
func (c *FileSystemCollector) getWindowsFileSystemStat(filePath string, stat *FileSystemStat) (*FileSystemStat, error) {
	// Windows 使用不同的方式获取文件信息
	// 这里使用 PowerShell 获取详细信息
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-Item '%s').LastAccessTime.ToString('o')", filePath))
	output, err := cmd.Output()
	if err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(output))); err == nil {
			stat.AccessTime = t
		}
	}
	
	stat.Owner = "Administrator"
	stat.Group = "Administrators"
	return stat, nil
}

// calculateFileHash 计算文件的SHA256哈希
func (c *FileSystemCollector) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	
	// 限制读取的数据量
	limitedReader := io.LimitReader(file, 50*1024*1024) // 最多读取50MB
	
	if _, err := io.Copy(hash, limitedReader); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// isInterestingFile 判断文件是否值得关注
func (c *FileSystemCollector) isInterestingFile(filePath string) bool {
	// 可执行文件
	executableExtensions := []string{".exe", ".dll", ".so", ".dylib", ".app"}
	
	// 配置文件
	configExtensions := []string{".conf", ".config", ".ini", ".yaml", ".yml", ".json", ".xml"}
	
	// 脚本文件
	scriptExtensions := []string{".sh", ".bash", ".ps1", ".py", ".pl", ".rb", ".bat", ".cmd"}
	
	ext := strings.ToLower(filepath.Ext(filePath))
	
	allExtensions := append(executableExtensions, configExtensions...)
	allExtensions = append(allExtensions, scriptExtensions...)
	
	for _, interestingExt := range allExtensions {
		if ext == interestingExt {
			return true
		}
	}
	
	// 检查特殊文件名
	basename := strings.ToLower(filepath.Base(filePath))
	interestingNames := []string{
		"hosts", "passwd", "shadow", "sudoers", "crontab",
		"authorized_keys", "known_hosts", "id_rsa", "id_dsa",
	}
	
	for _, name := range interestingNames {
		if basename == name || strings.Contains(basename, name) {
			return true
		}
	}
	
	// 检查可执行目录中的文件
	executableDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"}
	dir := filepath.Dir(filePath)
	for _, execDir := range executableDirs {
		if dir == execDir {
			return true
		}
	}
	
	return false
}
