package collectors

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"GatTrace/internal/core"
)

// ProcessCollector 进程信息采集器
type ProcessCollector struct {
	adapter core.PlatformAdapter
}

// NewProcessCollector 创建进程信息采集器
func NewProcessCollector(adapter core.PlatformAdapter) *ProcessCollector {
	return &ProcessCollector{
		adapter: adapter,
	}
}

// Name 返回采集器名称
func (c *ProcessCollector) Name() string {
	return "process"
}

// RequiresPrivileges 返回是否需要特权
func (c *ProcessCollector) RequiresPrivileges() bool {
	return true // 进程信息采集通常需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *ProcessCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行进程信息采集
func (c *ProcessCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 使用平台适配器获取进程信息
	processInfo, err := c.adapter.GetProcessInfo()
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "process",
			Operation: "GetProcessInfo",
			Err:       err,
			Severity:  core.SeverityError,
		}
		errors = append(errors, collectionErr)

		// 如果平台适配器失败，尝试使用通用方法
		processInfo, err = c.collectGenericProcessInfo()
		if err != nil {
			collectionErr := core.CollectionError{
				Module:    "process",
				Operation: "collectGenericProcessInfo",
				Err:       err,
				Severity:  core.SeverityCritical,
			}
			errors = append(errors, collectionErr)
			return &core.CollectionResult{Data: nil, Errors: errors}, err
		}
	}

	return &core.CollectionResult{
		Data:   processInfo,
		Errors: errors,
	}, nil
}

// collectGenericProcessInfo 使用通用方法采集进程信息
func (c *ProcessCollector) collectGenericProcessInfo() (*core.ProcessInfo, error) {
	// 创建基础元数据
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	processInfo := &core.ProcessInfo{
		Metadata:  metadata,
		Processes: []core.Process{},
	}

	// 获取所有进程
	processes, err := c.getAllProcesses()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}

	processInfo.Processes = processes
	return processInfo, nil
}

// getAllProcesses 获取所有进程信息
func (c *ProcessCollector) getAllProcesses() ([]core.Process, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("failed to get process PIDs: %w", err)
	}

	var processes []core.Process
	for _, pid := range pids {
		proc, err := process.NewProcess(pid)
		if err != nil {
			// 进程可能已经退出，跳过
			continue
		}

		processInfo, err := c.getProcessInfo(proc)
		if err != nil {
			// 无法获取进程信息，跳过
			continue
		}

		processes = append(processes, processInfo)
	}

	return processes, nil
}

// getProcessInfo 获取单个进程的详细信息
func (c *ProcessCollector) getProcessInfo(proc *process.Process) (core.Process, error) {
	processInfo := core.Process{
		PID: proc.Pid,
	}

	// 获取进程名称
	if name, err := proc.Name(); err == nil {
		processInfo.Name = name
	}

	// 获取父进程ID
	if ppid, err := proc.Ppid(); err == nil {
		processInfo.PPID = ppid
	}

	// 获取可执行文件路径
	if exe, err := proc.Exe(); err == nil {
		processInfo.Exe = exe

		// 计算可执行文件哈希
		if hash, err := c.calculateFileHash(exe); err == nil {
			processInfo.ExeHash = hash
		}
	}

	// 获取完整命令行
	cmdline := c.getFullCmdline(proc)
	if cmdline != "" {
		processInfo.Cmdline = []string{cmdline}
	} else if processInfo.Exe != "" {
		processInfo.Cmdline = []string{processInfo.Exe}
	}

	// 获取工作目录
	if cwd, err := proc.Cwd(); err == nil {
		processInfo.Cwd = cwd
	}

	// 获取用户名
	if username, err := proc.Username(); err == nil {
		processInfo.Username = username
	}

	// 获取创建时间
	if createTime, err := proc.CreateTime(); err == nil {
		processInfo.CreateTime = time.Unix(createTime/1000, 0)
	}

	// 获取进程状态
	if status, err := proc.Status(); err == nil {
		if len(status) > 0 {
			processInfo.Status = status[0] // 取第一个状态
		}
	}

	return processInfo, nil
}

// getFullCmdline 获取进程的完整命令行
func (c *ProcessCollector) getFullCmdline(proc *process.Process) string {
	// 使用 gopsutil 的 Cmdline 获取完整命令行
	if cmdline, err := proc.Cmdline(); err == nil && cmdline != "" {
		return cmdline
	}

	// 如果 gopsutil 失败，尝试使用 ps 命令
	return c.getCmdlineFromPS(proc.Pid)
}

// getCmdlineFromPS 使用 ps 命令获取完整命令行
func (c *ProcessCollector) getCmdlineFromPS(pid int32) string {
	// 使用 ps -ww 获取完整命令行（-ww 表示不截断）
	cmd := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-ww", "-o", "args=")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	cmdline := strings.TrimSpace(string(output))
	return cmdline
}

// isAbsolutePath 判断路径是否为绝对路径
func isAbsolutePath(path string) bool {
	if len(path) == 0 {
		return false
	}
	// Unix 绝对路径以 / 开头
	if path[0] == '/' {
		return true
	}
	// Windows 绝对路径以盘符开头（如 C:\）
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	return false
}

// calculateFileHash 计算文件的SHA256哈希
func (c *ProcessCollector) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
