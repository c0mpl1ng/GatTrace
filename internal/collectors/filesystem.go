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
	adapter             core.PlatformAdapter
	days                int // 采集时间范围（天数）
	whitelistExtensions map[string]bool
	specialFiles        map[string]bool
	importantHiddenDirs map[string]bool
}

// NewFileSystemCollector 创建文件系统采集器（默认7天）
func NewFileSystemCollector(adapter core.PlatformAdapter) *FileSystemCollector {
	c := &FileSystemCollector{
		adapter: adapter,
		days:    7,
	}
	c.initCaches()
	return c
}

// NewFileSystemCollectorWithDays 创建文件系统采集器（可配置天数）
func NewFileSystemCollectorWithDays(adapter core.PlatformAdapter, days int) *FileSystemCollector {
	if days < 1 {
		days = 1
	} else if days > 365 {
		days = 365
	}
	c := &FileSystemCollector{
		adapter: adapter,
		days:    days,
	}
	c.initCaches()
	return c
}

// initCaches 初始化缓存（预构建 map，避免每次文件检查都重新创建）
func (c *FileSystemCollector) initCaches() {
	c.whitelistExtensions = c.buildWhitelistExtensions()
	c.specialFiles = c.buildSpecialFiles()
	c.importantHiddenDirs = map[string]bool{
		".ssh": true, ".config": true, ".local": true,
		".gnupg": true, ".aws": true, ".kube": true,
	}
}

// buildSpecialFiles 构建特殊文件名 map
func (c *FileSystemCollector) buildSpecialFiles() map[string]bool {
	return map[string]bool{
		"hosts":           true,
		"passwd":          true,
		"shadow":          true,
		"sudoers":         true,
		"crontab":         true,
		"authorized_keys": true,
		"known_hosts":     true,
		"id_rsa":          true,
		"id_dsa":          true,
		"id_ecdsa":        true,
		"id_ed25519":      true,
		"config":          true,
		"dockerfile":      true,
		"makefile":        true,
		"gemfile":         true,
		"rakefile":        true,
		"vagrantfile":     true,
		"jenkinsfile":     true,
		"procfile":        true,
		".bashrc":         true,
		".bash_profile":   true,
		".zshrc":          true,
		".profile":        true,
		".vimrc":          true,
		".npmrc":          true,
		".yarnrc":         true,
		".editorconfig":   true,
		".htaccess":       true,
		".htpasswd":       true,
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

// getRecentFiles 获取最近修改和访问的文件（全盘扫描）
func (c *FileSystemCollector) getRecentFiles(ctx context.Context) ([]core.FileInfo, error) {
	var files []core.FileInfo

	// 获取全盘扫描的根目录
	rootDirectories := c.getRootDirectories()
	skipDirectories := c.getSkipDirectories()

	// 只通过时间范围限制，移除文件数量限制
	maxAge := time.Duration(c.days) * 24 * time.Hour
	cutoffTime := time.Now().Add(-maxAge)

	for _, dir := range rootDirectories {
		select {
		case <-ctx.Done():
			return files, ctx.Err()
		default:
		}

		// 全盘扫描目录
		dirFiles, err := c.scanDirectoryFullDisk(ctx, dir, cutoffTime, skipDirectories)
		if err != nil {
			continue
		}

		files = append(files, dirFiles...)
	}

	return files, nil
}

// getRootDirectories 获取全盘扫描的根目录
func (c *FileSystemCollector) getRootDirectories() []string {
	switch runtime.GOOS {
	case "windows":
		// 获取所有可用的驱动器盘符
		var drives []string
		for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
			drivePath := string(drive) + ":\\"
			if _, err := os.Stat(drivePath); err == nil {
				drives = append(drives, drivePath)
			}
		}
		if len(drives) == 0 {
			drives = []string{"C:\\"}
		}
		return drives
	case "linux", "darwin":
		return []string{"/"}
	default:
		return []string{"/"}
	}
}

// getSkipDirectories 获取需要跳过的目录（避免扫描系统核心目录和虚拟文件系统）
func (c *FileSystemCollector) getSkipDirectories() map[string]bool {
	skipDirs := make(map[string]bool)

	switch runtime.GOOS {
	case "windows":
		// Windows 跳过的目录
		skipDirs["C:\\$Recycle.Bin"] = true
		skipDirs["C:\\System Volume Information"] = true
		skipDirs["C:\\Windows\\WinSxS"] = true        // 组件存储，文件太多
		skipDirs["C:\\Windows\\Installer"] = true     // 安装缓存
		skipDirs["C:\\Windows\\assembly"] = true      // GAC
		skipDirs["C:\\Windows\\Microsoft.NET"] = true // .NET 框架
	case "linux":
		// Linux 跳过的目录
		skipDirs["/proc"] = true
		skipDirs["/sys"] = true
		skipDirs["/dev"] = true
		skipDirs["/run"] = true
		skipDirs["/snap"] = true
		skipDirs["/boot"] = true
		skipDirs["/lost+found"] = true
	case "darwin":
		// macOS 跳过的目录
		skipDirs["/dev"] = true
		skipDirs["/System/Volumes"] = true
		skipDirs["/Volumes"] = true
		skipDirs["/private/var/vm"] = true
		skipDirs["/cores"] = true
		skipDirs["/.Spotlight-V100"] = true
		skipDirs["/.fseventsd"] = true
	}

	return skipDirs
}

// buildWhitelistExtensions 构建白名单文件后缀 map
func (c *FileSystemCollector) buildWhitelistExtensions() map[string]bool {
	whitelist := make(map[string]bool, 150) // 预分配容量

	// 文档文件
	docExtensions := []string{
		".txt", ".md", ".markdown", ".rst", ".rtf",
		".doc", ".docx", ".odt",
		".xls", ".xlsx", ".ods", ".csv",
		".ppt", ".pptx", ".odp",
		".pdf",
	}

	// 配置文件
	configExtensions := []string{
		".conf", ".config", ".cfg",
		".yaml", ".yml",
		".json", ".jsonc",
		".xml", ".xsl", ".xslt",
		".ini", ".inf",
		".toml",
		".env", ".properties",
		".plist",
		".reg",
	}

	// 脚本文件
	scriptExtensions := []string{
		".sh", ".bash", ".zsh", ".fish", ".csh", ".ksh",
		".ps1", ".psm1", ".psd1",
		".bat", ".cmd",
		".py", ".pyw", ".pyx",
		".rb", ".rake",
		".pl", ".pm", ".pod",
		".lua",
		".tcl",
		".awk",
		".sed",
		".vbs", ".vbe", ".wsf", ".wsh",
	}

	// 编程语言源代码
	codeExtensions := []string{
		".c", ".h", ".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh",
		".java", ".jar", ".class",
		".cs", ".csx",
		".go",
		".rs",
		".swift",
		".kt", ".kts",
		".scala", ".sc",
		".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
		".html", ".htm", ".xhtml", ".css", ".scss", ".sass", ".less",
		".sql",
		".r", ".R", ".rmd",
		".m", ".mat",
		".f", ".f90", ".f95", ".for",
		".asm", ".s",
		".hs", ".lhs",
		".erl", ".hrl", ".ex", ".exs",
		".clj", ".cljs", ".cljc", ".edn",
		".groovy", ".gvy", ".gy", ".gsh",
		".dart",
		".jl",
		".nim",
		".zig",
		".v",
		".mk", ".make",
	}

	// 数据/序列化文件
	dataExtensions := []string{
		".csv", ".tsv",
		".jsonl", ".ndjson",
		".proto",
		".avro", ".parquet",
	}

	// 安全相关文件
	securityExtensions := []string{
		".pem", ".crt", ".cer", ".key", ".csr",
		".pub",
		".asc", ".gpg", ".pgp",
	}

	// 合并所有后缀到白名单
	allExtensions := [][]string{
		docExtensions,
		configExtensions,
		scriptExtensions,
		codeExtensions,
		dataExtensions,
		securityExtensions,
	}

	for _, extList := range allExtensions {
		for _, ext := range extList {
			whitelist[ext] = true
		}
	}

	return whitelist
}

// getWhitelistExtensions 获取白名单文件后缀（返回缓存的 map）
func (c *FileSystemCollector) getWhitelistExtensions() map[string]bool {
	return c.whitelistExtensions
}

// isWhitelistedFile 检查文件是否在白名单中
func (c *FileSystemCollector) isWhitelistedFile(filePath string) bool {
	// 获取文件扩展名
	ext := strings.ToLower(filepath.Ext(filePath))

	// 检查扩展名是否在白名单中（使用缓存的 map）
	if c.whitelistExtensions[ext] {
		return true
	}

	// 检查特殊文件名（无扩展名的重要文件，使用缓存的 map）
	basename := strings.ToLower(filepath.Base(filePath))
	return c.specialFiles[basename]
}

// scanDirectoryFullDisk 全盘扫描目录获取最近修改或访问的文件
func (c *FileSystemCollector) scanDirectoryFullDisk(ctx context.Context, dirPath string, cutoffTime time.Time, skipDirs map[string]bool) ([]core.FileInfo, error) {
	var files []core.FileInfo

	// 检查目录是否存在
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return files, nil
	}

	// 使用 filepath.WalkDir 替代 filepath.Walk（更高效，不需要每个文件都调用 os.Stat）
	err := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		// 检查上下文
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // 跳过无法访问的文件/目录
		}

		// 检查是否需要跳过此目录
		if d.IsDir() {
			if skipDirs[path] {
				return filepath.SkipDir
			}
			// 跳过隐藏目录（以.开头，但不跳过根目录）
			if runtime.GOOS != "windows" && len(path) > 1 {
				base := filepath.Base(path)
				if len(base) > 0 && base[0] == '.' && base != "." && base != ".." {
					// 保留一些重要的隐藏目录（使用缓存的 map）
					if !c.importantHiddenDirs[base] {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}

		// 白名单过滤：只处理白名单中的文件类型（在获取 FileInfo 之前过滤，提高效率）
		if !c.isWhitelistedFile(path) {
			return nil
		}

		// 只有通过白名单过滤后才获取完整的 FileInfo
		info, err := d.Info()
		if err != nil {
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

		// 跳过过大的文件（保留这个限制以避免内存问题）
		if info.Size() > 100*1024*1024 { // 100MB
			return nil
		}

		// 创建文件信息
		fileInfo, err := c.createFileInfo(path, info, accessTime)
		if err != nil {
			return nil
		}

		files = append(files, fileInfo)

		return nil
	})

	return files, err
}

// scanDirectory 扫描目录获取最近修改或访问的文件（保留用于兼容）
func (c *FileSystemCollector) scanDirectory(ctx context.Context, dirPath string, cutoffTime time.Time) ([]core.FileInfo, error) {
	return c.scanDirectoryFullDisk(ctx, dirPath, cutoffTime, make(map[string]bool))
}

// isExecutableFile 判断文件是否为可执行文件
func (c *FileSystemCollector) isExecutableFile(filePath string, info os.FileInfo) bool {
	// 检查文件扩展名
	ext := strings.ToLower(filepath.Ext(filePath))
	executableExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".app", // 二进制可执行文件
		".msi", ".com", ".scr", // Windows 可执行文件
		".sys", ".drv", ".ocx", ".cpl", // Windows 驱动和系统文件
		".bin", ".elf", // Linux 可执行文件
		".dmg", ".pkg", // macOS 安装包
	}

	for _, execExt := range executableExtensions {
		if ext == execExt {
			return true
		}
	}

	// 在 Unix 系统上，检查文件是否有可执行权限且是二进制文件
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		// 检查是否有可执行权限
		mode := info.Mode()
		if mode&0111 != 0 { // 任何用户有执行权限
			// 检查是否在可执行目录中
			dir := filepath.Dir(filePath)
			executableDirs := []string{
				"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
				"/usr/local/sbin", "/opt/bin", "/opt/local/bin",
			}
			for _, execDir := range executableDirs {
				if dir == execDir {
					return true
				}
			}
		}
	}

	return false
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
