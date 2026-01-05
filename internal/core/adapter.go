package core

import (
	"fmt"
)

// BasePlatformAdapter 基础平台适配器
type BasePlatformAdapter struct {
	detector PlatformDetector
}

// NewBasePlatformAdapter 创建基础平台适配器
func NewBasePlatformAdapter() *BasePlatformAdapter {
	return &BasePlatformAdapter{
		detector: NewPlatformDetector(),
	}
}

// GetPlatformDetector 获取平台检测器
func (a *BasePlatformAdapter) GetPlatformDetector() PlatformDetector {
	return a.detector
}

// CheckRequiredPrivileges 检查采集器所需权限
func (a *BasePlatformAdapter) CheckRequiredPrivileges(collector Collector) error {
	if !collector.RequiresPrivileges() {
		return nil
	}

	hasPrivileges, err := a.detector.CheckPrivileges()
	if err != nil {
		return fmt.Errorf("failed to check privileges: %w", err)
	}

	if !hasPrivileges {
		return fmt.Errorf("collector %s requires elevated privileges", collector.Name())
	}

	return nil
}

// HandlePrivilegeError 处理权限错误
func (a *BasePlatformAdapter) HandlePrivilegeError(err error) *CollectionError {
	return &CollectionError{
		Module:    "privilege",
		Operation: "check_access",
		Err:       err,
		Severity:  SeverityWarning,
	}
}

// IsPlatformSupported 检查平台是否支持特定采集器
func (a *BasePlatformAdapter) IsPlatformSupported(collector Collector) bool {
	currentPlatform := a.detector.DetectPlatform()
	supportedPlatforms := collector.SupportedPlatforms()

	for _, platform := range supportedPlatforms {
		if platform == currentPlatform {
			return true
		}
	}

	return false
}

// CreateUnsupportedPlatformError 创建不支持平台错误
func (a *BasePlatformAdapter) CreateUnsupportedPlatformError(collectorName string) *CollectionError {
	currentPlatform := a.detector.DetectPlatform()
	return &CollectionError{
		Module:    collectorName,
		Operation: "platform_check",
		Err:       fmt.Errorf("collector not supported on platform: %s", currentPlatform),
		Severity:  SeverityError,
	}
}

// NewUnsupportedPlatformError 创建不支持平台的错误
func NewUnsupportedPlatformError(module, operation string) error {
	return fmt.Errorf("[%s] %s: not supported on this platform", module, operation)
}

// ValidateCapability 验证平台功能
func (a *BasePlatformAdapter) ValidateCapability(capability PlatformCapability, collectorName string) *CollectionError {
	if !a.detector.HasCapability(capability) {
		return &CollectionError{
			Module:    collectorName,
			Operation: "capability_check",
			Err:       fmt.Errorf("required capability not available: %d", capability),
			Severity:  SeverityWarning,
		}
	}
	return nil
}
