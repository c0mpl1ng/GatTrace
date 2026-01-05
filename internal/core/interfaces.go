package core

import (
	"context"
	"fmt"
)

// CollectionError 采集错误类型
type CollectionError struct {
	Module    string
	Operation string
	Err       error
	Severity  ErrorSeverity
}

// Error 实现 error 接口
func (e *CollectionError) Error() string {
	return fmt.Sprintf("[%s] %s: %v", e.Module, e.Operation, e.Err)
}

// ErrorSeverity 错误严重程度
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// String 返回严重程度字符串
func (s ErrorSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// CollectionResult 采集结果
type CollectionResult struct {
	Data   interface{}
	Errors []CollectionError
}

// Collector 定义采集器接口
type Collector interface {
	Name() string
	Collect(ctx context.Context) (*CollectionResult, error)
	RequiresPrivileges() bool
	SupportedPlatforms() []Platform
}

// PlatformAdapter 定义平台适配接口
type PlatformAdapter interface {
	// 平台信息
	GetPlatformDetector() PlatformDetector

	// 数据采集方法
	GetNetworkInfo() (*NetworkInfo, error)
	GetProcessInfo() (*ProcessInfo, error)
	GetUserInfo() (*UserInfo, error)
	GetPersistenceInfo() (*PersistenceInfo, error)
	GetFileSystemInfo() (*FileSystemInfo, error)
	GetSecurityLogs() (*SecurityLogs, error)
	GetSystemInfo() (*SystemInfo, error)
	GetSystemStatus() (*SystemStatus, error)

	// 权限和错误处理
	CheckRequiredPrivileges(collector Collector) error
	HandlePrivilegeError(err error) *CollectionError
}

// OutputManager 定义输出管理接口
type OutputManager interface {
	WriteJSON(filename string, data interface{}) error
	GenerateHTML() error
	CreateManifest() error
	CalculateHashes() error
}

// Application 主应用程序接口
type Application interface {
	Run(ctx context.Context, outputDir string, verbose bool) error
	RegisterCollector(collector Collector)
}
