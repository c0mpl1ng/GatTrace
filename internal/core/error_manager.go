package core

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrorCategory 错误分类
type ErrorCategory string

const (
	ErrorCategoryPrivilege    ErrorCategory = "privilege"
	ErrorCategoryPlatform     ErrorCategory = "platform"
	ErrorCategoryNetwork      ErrorCategory = "network"
	ErrorCategoryFileSystem   ErrorCategory = "filesystem"
	ErrorCategorySystem       ErrorCategory = "system"
	ErrorCategoryData         ErrorCategory = "data"
	ErrorCategoryTimeout      ErrorCategory = "timeout"
	ErrorCategoryUnknown      ErrorCategory = "unknown"
)

// ErrorRecord 错误记录
type ErrorRecord struct {
	ID          string        `json:"id"`
	Timestamp   time.Time     `json:"timestamp"`
	Category    ErrorCategory `json:"category"`
	Severity    ErrorSeverity `json:"severity"`
	Module      string        `json:"module"`
	Operation   string        `json:"operation"`
	Message     string        `json:"message"`
	Details     string        `json:"details,omitempty"`
	StackTrace  string        `json:"stack_trace,omitempty"`
	Context     map[string]string `json:"context,omitempty"`
	Recovered   bool          `json:"recovered"`
	RetryCount  int           `json:"retry_count"`
}

// ErrorManager 错误管理器
type ErrorManager struct {
	mu           sync.RWMutex
	errors       []*ErrorRecord
	errorCounter int
	maxErrors    int
	panicHandler func(interface{})
}

// NewErrorManager 创建错误管理器
func NewErrorManager() *ErrorManager {
	return &ErrorManager{
		errors:    make([]*ErrorRecord, 0),
		maxErrors: 1000, // 最多保存1000个错误
		panicHandler: func(r interface{}) {
			// 默认panic处理器：记录但不重新panic
			fmt.Printf("Recovered from panic: %v\n", r)
		},
	}
}

// SetPanicHandler 设置panic处理器
func (em *ErrorManager) SetPanicHandler(handler func(interface{})) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.panicHandler = handler
}

// RecordError 记录错误
func (em *ErrorManager) RecordError(err *CollectionError) string {
	em.mu.Lock()
	defer em.mu.Unlock()

	em.errorCounter++
	record := &ErrorRecord{
		ID:        fmt.Sprintf("ERR-%06d", em.errorCounter),
		Timestamp: NormalizeTimestamp(time.Now()),
		Severity:  err.Severity,
		Module:    err.Module,
		Operation: err.Operation,
		Message:   err.Err.Error(),
		Recovered: true, // 如果能记录，说明已经恢复
		Context:   make(map[string]string),
	}

	// 分类错误
	record.Category = em.categorizeError(err)

	// 添加上下文信息
	record.Context["platform"] = GetCurrentPlatform().String()
	record.Context["go_version"] = runtime.Version()
	record.Context["num_goroutines"] = fmt.Sprintf("%d", runtime.NumGoroutine())

	// 如果是严重错误，添加堆栈跟踪
	if err.Severity >= SeverityError {
		record.StackTrace = em.captureStackTrace()
	}

	// 添加到错误列表
	em.errors = append(em.errors, record)

	// 限制错误数量
	if len(em.errors) > em.maxErrors {
		em.errors = em.errors[len(em.errors)-em.maxErrors:]
	}

	return record.ID
}

// RecordPanic 记录panic
func (em *ErrorManager) RecordPanic(r interface{}, module, operation string) string {
	em.mu.Lock()
	defer em.mu.Unlock()

	em.errorCounter++
	record := &ErrorRecord{
		ID:         fmt.Sprintf("PANIC-%06d", em.errorCounter),
		Timestamp:  NormalizeTimestamp(time.Now()),
		Category:   ErrorCategorySystem,
		Severity:   SeverityCritical,
		Module:     module,
		Operation:  operation,
		Message:    fmt.Sprintf("Panic occurred: %v", r),
		StackTrace: em.captureStackTrace(),
		Recovered:  true,
		Context:    make(map[string]string),
	}

	record.Context["panic_value"] = fmt.Sprintf("%v", r)
	record.Context["panic_type"] = fmt.Sprintf("%T", r)
	record.Context["platform"] = GetCurrentPlatform().String()

	em.errors = append(em.errors, record)

	// 限制错误数量
	if len(em.errors) > em.maxErrors {
		em.errors = em.errors[len(em.errors)-em.maxErrors:]
	}

	// 调用panic处理器
	if em.panicHandler != nil {
		em.panicHandler(r)
	}

	return record.ID
}

// categorizeError 分类错误
func (em *ErrorManager) categorizeError(err *CollectionError) ErrorCategory {
	switch err.Operation {
	case "privilege_check", "elevation":
		return ErrorCategoryPrivilege
	case "platform_detection", "platform_adapter":
		return ErrorCategoryPlatform
	case "network_info", "network_connections":
		return ErrorCategoryNetwork
	case "file_scan", "file_hash", "file_access":
		return ErrorCategoryFileSystem
	case "system_info", "system_status":
		return ErrorCategorySystem
	case "json_serialize", "data_validation":
		return ErrorCategoryData
	default:
		// 基于错误消息进行分类
		message := err.Err.Error()
		switch {
		case contains(message, "permission") || contains(message, "access denied") || contains(message, "privilege"):
			return ErrorCategoryPrivilege
		case contains(message, "timeout") || contains(message, "deadline"):
			return ErrorCategoryTimeout
		case contains(message, "network") || contains(message, "connection"):
			return ErrorCategoryNetwork
		case contains(message, "file") || contains(message, "directory"):
			return ErrorCategoryFileSystem
		case contains(message, "platform") || contains(message, "unsupported"):
			return ErrorCategoryPlatform
		default:
			return ErrorCategoryUnknown
		}
	}
}

// captureStackTrace 捕获堆栈跟踪
func (em *ErrorManager) captureStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// GetErrors 获取所有错误
func (em *ErrorManager) GetErrors() []*ErrorRecord {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// 返回副本
	errors := make([]*ErrorRecord, len(em.errors))
	copy(errors, em.errors)
	return errors
}

// GetErrorsByCategory 按分类获取错误
func (em *ErrorManager) GetErrorsByCategory(category ErrorCategory) []*ErrorRecord {
	em.mu.RLock()
	defer em.mu.RUnlock()

	var filtered []*ErrorRecord
	for _, err := range em.errors {
		if err.Category == category {
			filtered = append(filtered, err)
		}
	}
	return filtered
}

// GetErrorsBySeverity 按严重程度获取错误
func (em *ErrorManager) GetErrorsBySeverity(severity ErrorSeverity) []*ErrorRecord {
	em.mu.RLock()
	defer em.mu.RUnlock()

	var filtered []*ErrorRecord
	for _, err := range em.errors {
		if err.Severity >= severity {
			filtered = append(filtered, err)
		}
	}
	return filtered
}

// GetErrorCount 获取错误数量
func (em *ErrorManager) GetErrorCount() int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return len(em.errors)
}

// GetErrorCountByCategory 按分类获取错误数量
func (em *ErrorManager) GetErrorCountByCategory() map[ErrorCategory]int {
	em.mu.RLock()
	defer em.mu.RUnlock()

	counts := make(map[ErrorCategory]int)
	for _, err := range em.errors {
		counts[err.Category]++
	}
	return counts
}

// GetErrorCountBySeverity 按严重程度获取错误数量
func (em *ErrorManager) GetErrorCountBySeverity() map[ErrorSeverity]int {
	em.mu.RLock()
	defer em.mu.RUnlock()

	counts := make(map[ErrorSeverity]int)
	for _, err := range em.errors {
		counts[err.Severity]++
	}
	return counts
}

// HasCriticalErrors 检查是否有严重错误
func (em *ErrorManager) HasCriticalErrors() bool {
	em.mu.RLock()
	defer em.mu.RUnlock()

	for _, err := range em.errors {
		if err.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// Clear 清空错误记录
func (em *ErrorManager) Clear() {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.errors = em.errors[:0]
}

// CreateErrorReport 创建错误报告
func (em *ErrorManager) CreateErrorReport() *ErrorReport {
	em.mu.RLock()
	defer em.mu.RUnlock()

	report := &ErrorReport{
		Metadata: Metadata{
			SessionID:        "", // 将由调用者设置
			Hostname:         "", // 将由调用者设置
			Platform:         GetCurrentPlatform().String(),
			CollectedAt:      NormalizeTimestamp(time.Now()),
			CollectorVersion: "", // 将由调用者设置
		},
		Errors: make([]ErrorInfo, len(em.errors)),
	}

	// 转换错误记录为ErrorInfo
	for i, err := range em.errors {
		report.Errors[i] = ErrorInfo{
			Timestamp: err.Timestamp,
			Module:    err.Module,
			Error:     err.Message,
			Severity:  err.Severity.String(),
		}
	}

	// 按时间戳排序（最新的在前）
	sort.Slice(report.Errors, func(i, j int) bool {
		return report.Errors[i].Timestamp.After(report.Errors[j].Timestamp)
	})

	return report
}

// SafeExecute 安全执行函数，捕获panic
func (em *ErrorManager) SafeExecute(module, operation string, fn func() error) error {
	defer func() {
		if r := recover(); r != nil {
			em.RecordPanic(r, module, operation)
		}
	}()

	return fn()
}

// SafeExecuteWithResult 安全执行函数并返回结果，捕获panic
func (em *ErrorManager) SafeExecuteWithResult(module, operation string, fn func() (interface{}, error)) (interface{}, error) {
	var result interface{}
	var err error

	defer func() {
		if r := recover(); r != nil {
			em.RecordPanic(r, module, operation)
			result = nil
			err = fmt.Errorf("panic recovered: %v", r)
		}
	}()

	result, err = fn()
	return result, err
}

// RetryWithBackoff 带退避的重试机制
func (em *ErrorManager) RetryWithBackoff(ctx context.Context, module, operation string, maxRetries int, fn func() error) error {
	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := em.SafeExecute(module, operation, fn)
		if err == nil {
			return nil // 成功
		}

		lastErr = err
		
		// 记录重试错误
		collectionErr := &CollectionError{
			Module:    module,
			Operation: operation,
			Err:       err,
			Severity:  SeverityWarning,
		}
		
		errorID := em.RecordError(collectionErr)
		
		// 更新重试计数
		em.mu.Lock()
		for _, record := range em.errors {
			if record.ID == errorID {
				record.RetryCount = attempt
				break
			}
		}
		em.mu.Unlock()

		// 如果不是最后一次尝试，等待后重试
		if attempt < maxRetries {
			backoffDuration := time.Duration(1<<uint(attempt)) * time.Second // 指数退避
			if backoffDuration > 30*time.Second {
				backoffDuration = 30 * time.Second // 最大30秒
			}
			
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDuration):
				// 继续重试
			}
		}
	}

	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, lastErr)
}

// ErrorSummary 错误摘要
type ErrorSummary struct {
	TotalErrors    int                        `json:"total_errors"`
	CriticalErrors int                        `json:"critical_errors"`
	ErrorErrors    int                        `json:"error_errors"`
	WarningErrors  int                        `json:"warning_errors"`
	InfoErrors     int                        `json:"info_errors"`
	Categories     map[ErrorCategory]int      `json:"categories"`
}

// PrintSummary 打印错误摘要
func (er *ErrorReport) PrintSummary() {
	fmt.Println("=== 错误报告摘要 ===")
	fmt.Printf("总错误数: %d\n", len(er.Errors))
	
	if len(er.Errors) == 0 {
		fmt.Println("✅ 没有错误记录")
		return
	}

	// 统计各种严重程度的错误
	criticalCount := 0
	errorCount := 0
	warningCount := 0
	infoCount := 0

	for _, err := range er.Errors {
		switch err.Severity {
		case SeverityCritical.String():
			criticalCount++
		case SeverityError.String():
			errorCount++
		case SeverityWarning.String():
			warningCount++
		case SeverityInfo.String():
			infoCount++
		}
		// Note: ErrorInfo doesn't have Category field, so we skip category counting
	}

	fmt.Printf("严重错误: %d\n", criticalCount)
	fmt.Printf("错误: %d\n", errorCount)
	fmt.Printf("警告: %d\n", warningCount)
	fmt.Printf("信息: %d\n", infoCount)
	fmt.Println()

	// 显示最近的几个错误
	fmt.Println("最近的错误:")
	maxShow := 5
	if len(er.Errors) < maxShow {
		maxShow = len(er.Errors)
	}
	
	for i := 0; i < maxShow; i++ {
		err := er.Errors[i]
		severityIcon := "ℹ️"
		switch err.Severity {
		case SeverityCritical.String():
			severityIcon = "🔴"
		case SeverityError.String():
			severityIcon = "❌"
		case SeverityWarning.String():
			severityIcon = "⚠️"
		}
		
		fmt.Printf("  %s [%s] %s: %s\n", 
			severityIcon, err.Timestamp.Format("15:04:05"), err.Module, err.Error)
	}
	
	if len(er.Errors) > maxShow {
		fmt.Printf("  ... 还有 %d 个错误\n", len(er.Errors)-maxShow)
	}
}

// contains 检查字符串是否包含子字符串（不区分大小写）
func contains(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}