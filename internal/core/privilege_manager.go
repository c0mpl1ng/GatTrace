package core

import (
	"fmt"
	"sort"
	"time"
)

// PrivilegeManager 权限管理器
type PrivilegeManager struct {
	detector   PrivilegeDetector
	privileges *PrivilegeInfo
	checkCache map[string]*PrivilegeCheckResult
}

// NewPrivilegeManager 创建权限管理器
func NewPrivilegeManager() (*PrivilegeManager, error) {
	detector := NewPrivilegeDetector()

	privileges, err := detector.DetectPrivileges()
	if err != nil {
		return nil, fmt.Errorf("failed to detect privileges: %w", err)
	}

	return &PrivilegeManager{
		detector:   detector,
		privileges: privileges,
		checkCache: make(map[string]*PrivilegeCheckResult),
	}, nil
}

// GetPrivilegeInfo 获取当前权限信息
func (pm *PrivilegeManager) GetPrivilegeInfo() *PrivilegeInfo {
	return pm.privileges
}

// CheckCollector 检查单个采集器的权限
func (pm *PrivilegeManager) CheckCollector(collector Collector) (*PrivilegeCheckResult, error) {
	// 检查缓存
	if result, exists := pm.checkCache[collector.Name()]; exists {
		return result, nil
	}

	// 执行权限检查
	result, err := pm.detector.CheckCollectorPrivileges(collector)
	if err != nil {
		return nil, fmt.Errorf("failed to check collector privileges: %w", err)
	}

	// 缓存结果
	pm.checkCache[collector.Name()] = result
	return result, nil
}

// CheckAllCollectors 检查所有采集器的权限
func (pm *PrivilegeManager) CheckAllCollectors(collectors []Collector) (*PrivilegeReport, error) {
	report := &PrivilegeReport{
		SystemPrivileges: pm.privileges,
		CollectorChecks:  make([]*PrivilegeCheckResult, 0, len(collectors)),
		Summary: &PrivilegeSummary{
			TotalCollectors:     len(collectors),
			CanRunCollectors:    0,
			CannotRunCollectors: 0,
			RequiresElevation:   0,
		},
		GeneratedAt: NormalizeTimestamp(time.Now()),
	}

	for _, collector := range collectors {
		result, err := pm.CheckCollector(collector)
		if err != nil {
			return nil, fmt.Errorf("failed to check collector %s: %w", collector.Name(), err)
		}

		report.CollectorChecks = append(report.CollectorChecks, result)

		// 更新统计
		if result.CanRun {
			report.Summary.CanRunCollectors++
		} else {
			report.Summary.CannotRunCollectors++
			if pm.privileges.CanElevate {
				report.Summary.RequiresElevation++
			}
		}
	}

	// 按采集器名称排序
	sort.Slice(report.CollectorChecks, func(i, j int) bool {
		return report.CollectorChecks[i].CollectorName < report.CollectorChecks[j].CollectorName
	})

	return report, nil
}

// FilterRunnableCollectors 过滤可运行的采集器
func (pm *PrivilegeManager) FilterRunnableCollectors(collectors []Collector) ([]Collector, []Collector, error) {
	var runnable []Collector
	var blocked []Collector

	for _, collector := range collectors {
		result, err := pm.CheckCollector(collector)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check collector %s: %w", collector.Name(), err)
		}

		if result.CanRun {
			runnable = append(runnable, collector)
		} else {
			blocked = append(blocked, collector)
		}
	}

	return runnable, blocked, nil
}

// CreatePrivilegeError 创建权限错误
func (pm *PrivilegeManager) CreatePrivilegeError(collector Collector) *CollectionError {
	result, err := pm.CheckCollector(collector)
	if err != nil {
		return &CollectionError{
			Module:    collector.Name(),
			Operation: "privilege_check",
			Err:       err,
			Severity:  SeverityError,
		}
	}

	if result.CanRun {
		return nil // 没有权限错误
	}

	return &CollectionError{
		Module:    collector.Name(),
		Operation: "privilege_check",
		Err:       fmt.Errorf("insufficient privileges: %s", result.Reason),
		Severity:  SeverityWarning,
	}
}

// ShouldSkipCollector 判断是否应该跳过采集器
func (pm *PrivilegeManager) ShouldSkipCollector(collector Collector) (bool, string) {
	result, err := pm.CheckCollector(collector)
	if err != nil {
		return true, fmt.Sprintf("privilege check failed: %v", err)
	}

	if !result.CanRun {
		return true, result.Reason
	}

	return false, ""
}

// GetElevationInstructions 获取权限提升说明
func (pm *PrivilegeManager) GetElevationInstructions() []string {
	var instructions []string

	if !pm.privileges.CanElevate {
		instructions = append(instructions, "Current user cannot elevate privileges")
		instructions = append(instructions, "Contact system administrator for elevated access")
		return instructions
	}

	switch pm.privileges.Platform {
	case PlatformWindows:
		instructions = append(instructions, "To run with elevated privileges on Windows:")
		instructions = append(instructions, "1. Right-click on Command Prompt or PowerShell")
		instructions = append(instructions, "2. Select 'Run as administrator'")
		instructions = append(instructions, "3. Navigate to the GatTrace directory")
		instructions = append(instructions, "4. Run: .\\GatTrace.exe")

	case PlatformLinux, PlatformDarwin:
		instructions = append(instructions, "To run with elevated privileges on Unix-like systems:")
		instructions = append(instructions, "1. Open terminal")
		instructions = append(instructions, "2. Run: sudo ./GatTrace")
		instructions = append(instructions, "3. Enter your password when prompted")

	default:
		instructions = append(instructions, "Run the application with elevated privileges")
		instructions = append(instructions, "Consult your system documentation for privilege elevation")
	}

	return instructions
}

// PrivilegeReport 权限检查报告
type PrivilegeReport struct {
	SystemPrivileges *PrivilegeInfo          `json:"system_privileges"`
	CollectorChecks  []*PrivilegeCheckResult `json:"collector_checks"`
	Summary          *PrivilegeSummary       `json:"summary"`
	GeneratedAt      time.Time               `json:"generated_at"`
}

// PrivilegeSummary 权限检查摘要
type PrivilegeSummary struct {
	TotalCollectors     int `json:"total_collectors"`
	CanRunCollectors    int `json:"can_run_collectors"`
	CannotRunCollectors int `json:"cannot_run_collectors"`
	RequiresElevation   int `json:"requires_elevation"`
}

// PrintReport 打印权限报告
func (pr *PrivilegeReport) PrintReport() {
	Println("=== GatTrace 权限检查报告 ===")
	Printf("生成时间: %s\n", pr.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	Println("")

	// 系统权限信息
	Println("系统权限信息:")
	Printf("  用户: %s (%s)\n", pr.SystemPrivileges.Username, pr.SystemPrivileges.UserID)
	Printf("  权限级别: %s\n", pr.SystemPrivileges.Level)
	Printf("  管理员权限: %v\n", pr.SystemPrivileges.IsAdmin)
	Printf("  可提升权限: %v\n", pr.SystemPrivileges.CanElevate)
	Printf("  平台: %s\n", pr.SystemPrivileges.Platform)
	Println("")

	// 采集器检查摘要
	Println("采集器权限检查摘要:")
	Printf("  总采集器数: %d\n", pr.Summary.TotalCollectors)
	Printf("  可运行: %d\n", pr.Summary.CanRunCollectors)
	Printf("  无法运行: %d\n", pr.Summary.CannotRunCollectors)
	Printf("  需要提升权限: %d\n", pr.Summary.RequiresElevation)
	Println("")

	// 详细检查结果
	Println("详细检查结果:")
	config := GetConsoleConfig()
	for _, check := range pr.CollectorChecks {
		var status string
		if config.UseEmoji {
			status = "✅"
			if !check.CanRun {
				status = "❌"
			}
		} else {
			status = "[OK]"
			if !check.CanRun {
				status = "[X]"
			}
		}

		Printf("  %s %s\n", status, check.CollectorName)
		Printf("    需要权限: %s\n", check.RequiredLevel)
		Printf("    当前权限: %s\n", check.CurrentLevel)
		Printf("    状态: %s\n", check.Reason)

		if !check.CanRun {
			Printf("    建议: %s\n", check.Recommendation)
		}
		Println("")
	}
}

// HasPrivilegeIssues 检查是否有权限问题
func (pr *PrivilegeReport) HasPrivilegeIssues() bool {
	return pr.Summary.CannotRunCollectors > 0
}

// GetBlockedCollectors 获取被阻止的采集器列表
func (pr *PrivilegeReport) GetBlockedCollectors() []string {
	var blocked []string
	for _, check := range pr.CollectorChecks {
		if !check.CanRun {
			blocked = append(blocked, check.CollectorName)
		}
	}
	return blocked
}

// GetRunnableCollectors 获取可运行的采集器列表
func (pr *PrivilegeReport) GetRunnableCollectors() []string {
	var runnable []string
	for _, check := range pr.CollectorChecks {
		if check.CanRun {
			runnable = append(runnable, check.CollectorName)
		}
	}
	return runnable
}

// CanRunWithDegradation 检查是否可以在降级模式下运行
func (pm *PrivilegeManager) CanRunWithDegradation(collectors []Collector) bool {
	runnable, _, err := pm.FilterRunnableCollectors(collectors)
	if err != nil {
		return false
	}

	// 如果至少有一个采集器可以运行，就可以在降级模式下运行
	return len(runnable) > 0
}

// CreateDegradationWarning 创建降级警告
func (pm *PrivilegeManager) CreateDegradationWarning(collectors []Collector) *CollectionError {
	_, blocked, err := pm.FilterRunnableCollectors(collectors)
	if err != nil {
		return &CollectionError{
			Module:    "privilege_manager",
			Operation: "degradation_check",
			Err:       err,
			Severity:  SeverityError,
		}
	}

	if len(blocked) == 0 {
		return nil // 没有被阻止的采集器
	}

	blockedNames := make([]string, len(blocked))
	for i, collector := range blocked {
		blockedNames[i] = collector.Name()
	}

	return &CollectionError{
		Module:    "privilege_manager",
		Operation: "degradation_warning",
		Err:       fmt.Errorf("running in degraded mode: %d collectors skipped due to insufficient privileges: %v", len(blocked), blockedNames),
		Severity:  SeverityWarning,
	}
}
