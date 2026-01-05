package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// SystemSnapshot 系统状态快照
type SystemSnapshot struct {
	Timestamp       time.Time                 `json:"timestamp"`
	Platform        string                    `json:"platform"`
	Processes       map[int32]ProcessSnapshot `json:"processes"`
	NetworkPorts    []NetworkPortSnapshot     `json:"network_ports"`
	FileHashes      map[string]string         `json:"file_hashes"`
	EnvironmentVars map[string]string         `json:"environment_vars"`
	WorkingDir      string                    `json:"working_dir"`
}

// ProcessSnapshot 进程快照
type ProcessSnapshot struct {
	PID      int32    `json:"pid"`
	Name     string   `json:"name"`
	Cmdline  []string `json:"cmdline"`
	Username string   `json:"username"`
	Status   string   `json:"status"`
}

// NetworkPortSnapshot 网络端口快照
type NetworkPortSnapshot struct {
	Protocol  string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	Status    string `json:"status"`
	PID       int32  `json:"pid"`
}

// SystemStateComparison 系统状态比较结果
type SystemStateComparison struct {
	StartSnapshot      *SystemSnapshot    `json:"start_snapshot"`
	EndSnapshot        *SystemSnapshot    `json:"end_snapshot"`
	ProcessChanges     ProcessChanges     `json:"process_changes"`
	NetworkChanges     NetworkChanges     `json:"network_changes"`
	FileChanges        FileChanges        `json:"file_changes"`
	EnvironmentChanges EnvironmentChanges `json:"environment_changes"`
	WorkingDirChanged  bool               `json:"working_dir_changed"`
	HasChanges         bool               `json:"has_changes"`
}

// ProcessChanges 进程变更
type ProcessChanges struct {
	Added   []ProcessSnapshot `json:"added"`
	Removed []ProcessSnapshot `json:"removed"`
	Changed []ProcessSnapshot `json:"changed"`
}

// NetworkChanges 网络变更
type NetworkChanges struct {
	Added   []NetworkPortSnapshot `json:"added"`
	Removed []NetworkPortSnapshot `json:"removed"`
}

// FileChanges 文件变更
type FileChanges struct {
	Modified []string `json:"modified"`
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
}

// EnvironmentChanges 环境变量变更
type EnvironmentChanges struct {
	Added    map[string]string `json:"added"`
	Removed  []string          `json:"removed"`
	Modified map[string]string `json:"modified"`
}

// SystemMonitor 系统状态监控器
type SystemMonitor struct {
	monitoredPaths []string
	startSnapshot  *SystemSnapshot
	endSnapshot    *SystemSnapshot
}

// NewSystemMonitor 创建新的系统监控器
func NewSystemMonitor() *SystemMonitor {
	return &SystemMonitor{
		monitoredPaths: getDefaultMonitoredPaths(),
	}
}

// getDefaultMonitoredPaths 获取默认监控路径
func getDefaultMonitoredPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			"C:\\Windows\\System32\\drivers\\etc\\hosts",
			"C:\\Windows\\System32\\config",
		}
	case "linux":
		return []string{
			"/etc/hosts",
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/etc/crontab",
		}
	case "darwin":
		return []string{
			"/etc/hosts",
			"/etc/passwd",
			"/private/etc/sudoers",
		}
	default:
		return []string{}
	}
}

// CaptureStartSnapshot 捕获开始快照
func (sm *SystemMonitor) CaptureStartSnapshot(ctx context.Context) error {
	snapshot, err := sm.captureSystemSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("failed to capture start snapshot: %w", err)
	}
	sm.startSnapshot = snapshot
	return nil
}

// CaptureEndSnapshot 捕获结束快照
func (sm *SystemMonitor) CaptureEndSnapshot(ctx context.Context) error {
	snapshot, err := sm.captureSystemSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("failed to capture end snapshot: %w", err)
	}
	sm.endSnapshot = snapshot
	return nil
}

// CompareSnapshots 比较快照
func (sm *SystemMonitor) CompareSnapshots() (*SystemStateComparison, error) {
	if sm.startSnapshot == nil || sm.endSnapshot == nil {
		return nil, fmt.Errorf("both start and end snapshots are required")
	}

	comparison := &SystemStateComparison{
		StartSnapshot: sm.startSnapshot,
		EndSnapshot:   sm.endSnapshot,
	}

	// 比较进程
	comparison.ProcessChanges = sm.compareProcesses()

	// 比较网络端口
	comparison.NetworkChanges = sm.compareNetworkPorts()

	// 比较文件
	comparison.FileChanges = sm.compareFiles()

	// 比较环境变量
	comparison.EnvironmentChanges = sm.compareEnvironment()

	// 比较工作目录
	comparison.WorkingDirChanged = sm.startSnapshot.WorkingDir != sm.endSnapshot.WorkingDir

	// 检查是否有任何变更
	comparison.HasChanges = sm.hasAnyChanges(comparison)

	return comparison, nil
}

// captureSystemSnapshot 捕获系统快照
func (sm *SystemMonitor) captureSystemSnapshot(ctx context.Context) (*SystemSnapshot, error) {
	snapshot := &SystemSnapshot{
		Timestamp:       time.Now().UTC(),
		Platform:        runtime.GOOS,
		Processes:       make(map[int32]ProcessSnapshot),
		NetworkPorts:    []NetworkPortSnapshot{},
		FileHashes:      make(map[string]string),
		EnvironmentVars: make(map[string]string),
	}

	// 获取工作目录
	if wd, err := os.Getwd(); err == nil {
		snapshot.WorkingDir = wd
	}

	// 捕获进程信息
	if err := sm.captureProcesses(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("failed to capture processes: %w", err)
	}

	// 捕获网络端口信息
	if err := sm.captureNetworkPorts(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("failed to capture network ports: %w", err)
	}

	// 捕获文件哈希
	if err := sm.captureFileHashes(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("failed to capture file hashes: %w", err)
	}

	// 捕获环境变量
	sm.captureEnvironmentVars(snapshot)

	return snapshot, nil
}

// captureProcesses 捕获进程信息
func (sm *SystemMonitor) captureProcesses(ctx context.Context, snapshot *SystemSnapshot) error {
	// 创建一个带超时的子上下文
	processCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	processes, err := process.ProcessesWithContext(processCtx)
	if err != nil {
		return fmt.Errorf("failed to get processes: %w", err)
	}

	// 限制处理的进程数量以避免超时
	maxProcesses := 20
	if len(processes) > maxProcesses {
		processes = processes[:maxProcesses]
	}

	for _, p := range processes {
		select {
		case <-processCtx.Done():
			return processCtx.Err()
		default:
		}

		processSnapshot := ProcessSnapshot{
			PID: p.Pid,
		}

		// 获取进程名称（使用超时）
		nameCtx, nameCancel := context.WithTimeout(processCtx, 50*time.Millisecond)
		if name, err := p.NameWithContext(nameCtx); err == nil {
			processSnapshot.Name = name
		}
		nameCancel()

		// 获取命令行（使用超时）
		cmdCtx, cmdCancel := context.WithTimeout(processCtx, 50*time.Millisecond)
		if cmdline, err := p.CmdlineSliceWithContext(cmdCtx); err == nil {
			processSnapshot.Cmdline = cmdline
		}
		cmdCancel()

		// 获取用户名（使用超时）
		userCtx, userCancel := context.WithTimeout(processCtx, 50*time.Millisecond)
		if username, err := p.UsernameWithContext(userCtx); err == nil {
			processSnapshot.Username = username
		}
		userCancel()

		// 获取状态（使用超时）
		statusCtx, statusCancel := context.WithTimeout(processCtx, 50*time.Millisecond)
		if status, err := p.StatusWithContext(statusCtx); err == nil {
			processSnapshot.Status = strings.Join(status, ",")
		}
		statusCancel()

		snapshot.Processes[p.Pid] = processSnapshot
	}

	return nil
}

// captureNetworkPorts 捕获网络端口信息
func (sm *SystemMonitor) captureNetworkPorts(ctx context.Context, snapshot *SystemSnapshot) error {
	// 获取TCP连接
	if err := sm.captureTCPPorts(ctx, snapshot); err != nil {
		return fmt.Errorf("failed to capture TCP ports: %w", err)
	}

	// 获取UDP连接
	if err := sm.captureUDPPorts(ctx, snapshot); err != nil {
		return fmt.Errorf("failed to capture UDP ports: %w", err)
	}

	return nil
}

// captureTCPPorts 捕获TCP端口
func (sm *SystemMonitor) captureTCPPorts(ctx context.Context, snapshot *SystemSnapshot) error {
	listeners, err := net.Listen("tcp", ":0")
	if err == nil {
		listeners.Close()
	}

	// 这里简化实现，实际应该使用更详细的网络连接获取方法
	// 由于gopsutil的net包在某些平台上可能有权限问题，我们使用基本的端口检测
	commonPorts := []int{22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306}

	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		address := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			snapshot.NetworkPorts = append(snapshot.NetworkPorts, NetworkPortSnapshot{
				Protocol:  "tcp",
				LocalAddr: address,
				Status:    "listening",
				PID:       0, // 无法轻易获取PID
			})
		}
	}

	return nil
}

// captureUDPPorts 捕获UDP端口
func (sm *SystemMonitor) captureUDPPorts(ctx context.Context, snapshot *SystemSnapshot) error {
	// UDP端口检测更复杂，这里简化处理
	commonUDPPorts := []int{53, 67, 68, 123, 161, 162}

	for _, port := range commonUDPPorts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		address := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.Dial("udp", address)
		if err == nil {
			conn.Close()
			snapshot.NetworkPorts = append(snapshot.NetworkPorts, NetworkPortSnapshot{
				Protocol:  "udp",
				LocalAddr: address,
				Status:    "active",
				PID:       0,
			})
		}
	}

	return nil
}

// captureFileHashes 捕获文件哈希
func (sm *SystemMonitor) captureFileHashes(ctx context.Context, snapshot *SystemSnapshot) error {
	for _, path := range sm.monitoredPaths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if hash, err := sm.calculateFileHash(path); err == nil {
			snapshot.FileHashes[path] = hash
		}
	}

	return nil
}

// calculateFileHash 计算文件哈希
func (sm *SystemMonitor) calculateFileHash(filePath string) (string, error) {
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

// captureEnvironmentVars 捕获环境变量
func (sm *SystemMonitor) captureEnvironmentVars(snapshot *SystemSnapshot) {
	// 只捕获关键的环境变量，避免敏感信息
	keyEnvVars := []string{"PATH", "HOME", "USER", "USERNAME", "COMPUTERNAME", "HOSTNAME"}

	for _, key := range keyEnvVars {
		if value := os.Getenv(key); value != "" {
			snapshot.EnvironmentVars[key] = value
		}
	}
}

// compareProcesses 比较进程
func (sm *SystemMonitor) compareProcesses() ProcessChanges {
	changes := ProcessChanges{
		Added:   []ProcessSnapshot{},
		Removed: []ProcessSnapshot{},
		Changed: []ProcessSnapshot{},
	}

	// 查找新增的进程
	for pid, endProcess := range sm.endSnapshot.Processes {
		if _, exists := sm.startSnapshot.Processes[pid]; !exists {
			changes.Added = append(changes.Added, endProcess)
		}
	}

	// 查找删除的进程
	for pid, startProcess := range sm.startSnapshot.Processes {
		if _, exists := sm.endSnapshot.Processes[pid]; !exists {
			changes.Removed = append(changes.Removed, startProcess)
		}
	}

	// 查找变更的进程
	for pid, endProcess := range sm.endSnapshot.Processes {
		if startProcess, exists := sm.startSnapshot.Processes[pid]; exists {
			if !sm.processesEqual(startProcess, endProcess) {
				changes.Changed = append(changes.Changed, endProcess)
			}
		}
	}

	return changes
}

// processesEqual 比较两个进程是否相等
func (sm *SystemMonitor) processesEqual(p1, p2 ProcessSnapshot) bool {
	if p1.Name != p2.Name || p1.Username != p2.Username || p1.Status != p2.Status {
		return false
	}

	if len(p1.Cmdline) != len(p2.Cmdline) {
		return false
	}

	for i, cmd := range p1.Cmdline {
		if cmd != p2.Cmdline[i] {
			return false
		}
	}

	return true
}

// compareNetworkPorts 比较网络端口
func (sm *SystemMonitor) compareNetworkPorts() NetworkChanges {
	changes := NetworkChanges{
		Added:   []NetworkPortSnapshot{},
		Removed: []NetworkPortSnapshot{},
	}

	startPorts := make(map[string]NetworkPortSnapshot)
	for _, port := range sm.startSnapshot.NetworkPorts {
		key := fmt.Sprintf("%s:%s", port.Protocol, port.LocalAddr)
		startPorts[key] = port
	}

	endPorts := make(map[string]NetworkPortSnapshot)
	for _, port := range sm.endSnapshot.NetworkPorts {
		key := fmt.Sprintf("%s:%s", port.Protocol, port.LocalAddr)
		endPorts[key] = port
	}

	// 查找新增的端口
	for key, port := range endPorts {
		if _, exists := startPorts[key]; !exists {
			changes.Added = append(changes.Added, port)
		}
	}

	// 查找删除的端口
	for key, port := range startPorts {
		if _, exists := endPorts[key]; !exists {
			changes.Removed = append(changes.Removed, port)
		}
	}

	return changes
}

// compareFiles 比较文件
func (sm *SystemMonitor) compareFiles() FileChanges {
	changes := FileChanges{
		Modified: []string{},
		Added:    []string{},
		Removed:  []string{},
	}

	// 查找修改的文件
	for path, endHash := range sm.endSnapshot.FileHashes {
		if startHash, exists := sm.startSnapshot.FileHashes[path]; exists {
			if startHash != endHash {
				changes.Modified = append(changes.Modified, path)
			}
		} else {
			changes.Added = append(changes.Added, path)
		}
	}

	// 查找删除的文件
	for path := range sm.startSnapshot.FileHashes {
		if _, exists := sm.endSnapshot.FileHashes[path]; !exists {
			changes.Removed = append(changes.Removed, path)
		}
	}

	return changes
}

// compareEnvironment 比较环境变量
func (sm *SystemMonitor) compareEnvironment() EnvironmentChanges {
	changes := EnvironmentChanges{
		Added:    make(map[string]string),
		Removed:  []string{},
		Modified: make(map[string]string),
	}

	// 查找新增和修改的环境变量
	for key, endValue := range sm.endSnapshot.EnvironmentVars {
		if startValue, exists := sm.startSnapshot.EnvironmentVars[key]; exists {
			if startValue != endValue {
				changes.Modified[key] = endValue
			}
		} else {
			changes.Added[key] = endValue
		}
	}

	// 查找删除的环境变量
	for key := range sm.startSnapshot.EnvironmentVars {
		if _, exists := sm.endSnapshot.EnvironmentVars[key]; !exists {
			changes.Removed = append(changes.Removed, key)
		}
	}

	return changes
}

// hasAnyChanges 检查是否有任何变更
func (sm *SystemMonitor) hasAnyChanges(comparison *SystemStateComparison) bool {
	return len(comparison.ProcessChanges.Added) > 0 ||
		len(comparison.ProcessChanges.Removed) > 0 ||
		len(comparison.ProcessChanges.Changed) > 0 ||
		len(comparison.NetworkChanges.Added) > 0 ||
		len(comparison.NetworkChanges.Removed) > 0 ||
		len(comparison.FileChanges.Modified) > 0 ||
		len(comparison.FileChanges.Added) > 0 ||
		len(comparison.FileChanges.Removed) > 0 ||
		len(comparison.EnvironmentChanges.Added) > 0 ||
		len(comparison.EnvironmentChanges.Removed) > 0 ||
		len(comparison.EnvironmentChanges.Modified) > 0 ||
		comparison.WorkingDirChanged
}

// GetStartSnapshot 获取开始快照
func (sm *SystemMonitor) GetStartSnapshot() *SystemSnapshot {
	return sm.startSnapshot
}

// GetEndSnapshot 获取结束快照
func (sm *SystemMonitor) GetEndSnapshot() *SystemSnapshot {
	return sm.endSnapshot
}

// AddMonitoredPath 添加监控路径
func (sm *SystemMonitor) AddMonitoredPath(path string) {
	sm.monitoredPaths = append(sm.monitoredPaths, path)
}

// SetMonitoredPaths 设置监控路径
func (sm *SystemMonitor) SetMonitoredPaths(paths []string) {
	sm.monitoredPaths = paths
}

// GetMonitoredPaths 获取监控路径
func (sm *SystemMonitor) GetMonitoredPaths() []string {
	return sm.monitoredPaths
}
