package core

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
)

// PrivilegeLevel 权限级别
type PrivilegeLevel int

const (
	PrivilegeLevelNone PrivilegeLevel = iota
	PrivilegeLevelUser
	PrivilegeLevelAdmin
	PrivilegeLevelSystem
)

// String 返回权限级别字符串
func (p PrivilegeLevel) String() string {
	switch p {
	case PrivilegeLevelNone:
		return "none"
	case PrivilegeLevelUser:
		return "user"
	case PrivilegeLevelAdmin:
		return "admin"
	case PrivilegeLevelSystem:
		return "system"
	default:
		return "unknown"
	}
}

// PrivilegeInfo 权限信息
type PrivilegeInfo struct {
	Level       PrivilegeLevel `json:"level"`
	Username    string         `json:"username"`
	UserID      string         `json:"user_id"`
	GroupID     string         `json:"group_id"`
	Groups      []string       `json:"groups"`
	IsAdmin     bool           `json:"is_admin"`
	CanElevate  bool           `json:"can_elevate"`
	Platform    Platform       `json:"platform"`
	Details     map[string]string `json:"details"`
}

// PrivilegeDetector 权限检测器接口
type PrivilegeDetector interface {
	DetectPrivileges() (*PrivilegeInfo, error)
	CheckCollectorPrivileges(collector Collector) (*PrivilegeCheckResult, error)
	CanRunCollector(collector Collector) bool
}

// PrivilegeCheckResult 权限检查结果
type PrivilegeCheckResult struct {
	CollectorName   string         `json:"collector_name"`
	RequiredLevel   PrivilegeLevel `json:"required_level"`
	CurrentLevel    PrivilegeLevel `json:"current_level"`
	CanRun          bool           `json:"can_run"`
	Reason          string         `json:"reason"`
	Recommendation  string         `json:"recommendation"`
}

// DefaultPrivilegeDetector 默认权限检测器
type DefaultPrivilegeDetector struct {
	platform Platform
	cache    *PrivilegeInfo
}

// NewPrivilegeDetector 创建权限检测器
func NewPrivilegeDetector() PrivilegeDetector {
	return &DefaultPrivilegeDetector{
		platform: GetCurrentPlatform(),
	}
}

// DetectPrivileges 检测当前权限
func (d *DefaultPrivilegeDetector) DetectPrivileges() (*PrivilegeInfo, error) {
	if d.cache != nil {
		return d.cache, nil
	}

	info := &PrivilegeInfo{
		Platform: d.platform,
		Details:  make(map[string]string),
	}

	// 获取当前用户信息
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	info.Username = currentUser.Username
	info.UserID = currentUser.Uid
	info.GroupID = currentUser.Gid

	// 获取用户组信息
	groups, err := currentUser.GroupIds()
	if err == nil {
		info.Groups = groups
	}

	// 平台特定的权限检测
	switch d.platform {
	case PlatformWindows:
		d.detectWindowsPrivileges(info)
	case PlatformLinux:
		d.detectLinuxPrivileges(info)
	case PlatformDarwin:
		d.detectDarwinPrivileges(info)
	default:
		d.detectGenericPrivileges(info)
	}

	d.cache = info
	return info, nil
}

// detectWindowsPrivileges 检测Windows权限
func (d *DefaultPrivilegeDetector) detectWindowsPrivileges(info *PrivilegeInfo) {
	info.Details["platform"] = "windows"
	
	// 检查是否为管理员
	// 在Windows上，UID为空或"S-1-5-32-544"表示管理员组
	if info.UserID == "" {
		info.Level = PrivilegeLevelUser
		info.IsAdmin = false
	} else {
		// 简化的管理员检测：检查是否在管理员组中
		for _, groupID := range info.Groups {
			if strings.Contains(groupID, "S-1-5-32-544") || // Administrators group
			   strings.Contains(groupID, "S-1-5-32-545") {  // Users group (for comparison)
				if strings.Contains(groupID, "S-1-5-32-544") {
					info.IsAdmin = true
					info.Level = PrivilegeLevelAdmin
					info.CanElevate = true
					break
				}
			}
		}
		
		if !info.IsAdmin {
			info.Level = PrivilegeLevelUser
			info.CanElevate = true // Windows用户通常可以通过UAC提升权限
		}
	}

	info.Details["uac_available"] = "true"
	info.Details["admin_check_method"] = "group_membership"
}

// detectLinuxPrivileges 检测Linux权限
func (d *DefaultPrivilegeDetector) detectLinuxPrivileges(info *PrivilegeInfo) {
	info.Details["platform"] = "linux"
	
	// 检查是否为root用户
	if info.UserID == "0" {
		info.Level = PrivilegeLevelSystem
		info.IsAdmin = true
		info.CanElevate = false // root用户已经是最高权限
		info.Details["user_type"] = "root"
		return
	}

	// 检查是否在管理员组中
	adminGroups := []string{"sudo", "wheel", "admin", "root"}
	for _, groupID := range info.Groups {
		// 将组ID转换为组名（简化处理）
		for _, adminGroup := range adminGroups {
			if groupID == "0" || // root group
			   d.isInGroup(adminGroup) {
				info.IsAdmin = true
				info.Level = PrivilegeLevelAdmin
				info.CanElevate = true
				info.Details["admin_groups"] = strings.Join(adminGroups, ",")
				return
			}
		}
	}

	// 普通用户
	info.Level = PrivilegeLevelUser
	info.IsAdmin = false
	info.CanElevate = d.canUseSudo()
	info.Details["user_type"] = "regular"
}

// detectDarwinPrivileges 检测macOS权限
func (d *DefaultPrivilegeDetector) detectDarwinPrivileges(info *PrivilegeInfo) {
	info.Details["platform"] = "darwin"
	
	// 检查是否为root用户
	if info.UserID == "0" {
		info.Level = PrivilegeLevelSystem
		info.IsAdmin = true
		info.CanElevate = false
		info.Details["user_type"] = "root"
		return
	}

	// 检查是否在admin组中
	if d.isInGroup("admin") || d.isInGroup("wheel") {
		info.IsAdmin = true
		info.Level = PrivilegeLevelAdmin
		info.CanElevate = true
		info.Details["admin_groups"] = "admin,wheel"
	} else {
		info.Level = PrivilegeLevelUser
		info.IsAdmin = false
		info.CanElevate = d.canUseSudo()
		info.Details["user_type"] = "regular"
	}
}

// detectGenericPrivileges 通用权限检测
func (d *DefaultPrivilegeDetector) detectGenericPrivileges(info *PrivilegeInfo) {
	info.Details["platform"] = "generic"
	
	// 基于UID的简单检测
	if info.UserID == "0" {
		info.Level = PrivilegeLevelSystem
		info.IsAdmin = true
		info.CanElevate = false
	} else {
		info.Level = PrivilegeLevelUser
		info.IsAdmin = false
		info.CanElevate = false
	}
}

// isInGroup 检查用户是否在指定组中
func (d *DefaultPrivilegeDetector) isInGroup(groupName string) bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	groups, err := currentUser.GroupIds()
	if err != nil {
		return false
	}

	// 尝试通过组名查找组ID
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return false
	}

	for _, gid := range groups {
		if gid == group.Gid {
			return true
		}
	}

	return false
}

// canUseSudo 检查是否可以使用sudo
func (d *DefaultPrivilegeDetector) canUseSudo() bool {
	if runtime.GOOS == "windows" {
		return false
	}

	// 检查sudo命令是否存在
	if _, err := os.Stat("/usr/bin/sudo"); err != nil {
		if _, err := os.Stat("/bin/sudo"); err != nil {
			return false
		}
	}

	// 简化检查：假设在admin/sudo组中的用户可以使用sudo
	return d.isInGroup("sudo") || d.isInGroup("admin") || d.isInGroup("wheel")
}

// CheckCollectorPrivileges 检查采集器权限需求
func (d *DefaultPrivilegeDetector) CheckCollectorPrivileges(collector Collector) (*PrivilegeCheckResult, error) {
	currentPrivileges, err := d.DetectPrivileges()
	if err != nil {
		return nil, fmt.Errorf("failed to detect current privileges: %w", err)
	}

	result := &PrivilegeCheckResult{
		CollectorName: collector.Name(),
		CurrentLevel:  currentPrivileges.Level,
	}

	// 确定采集器所需的权限级别
	if collector.RequiresPrivileges() {
		result.RequiredLevel = PrivilegeLevelAdmin
	} else {
		result.RequiredLevel = PrivilegeLevelUser
	}

	// 检查是否可以运行
	result.CanRun = d.canRunWithPrivileges(result.RequiredLevel, currentPrivileges)

	// 设置原因和建议
	if result.CanRun {
		result.Reason = "Sufficient privileges"
		result.Recommendation = "Can run normally"
	} else {
		result.Reason = fmt.Sprintf("Insufficient privileges: required %s, current %s", 
			result.RequiredLevel, result.CurrentLevel)
		
		if currentPrivileges.CanElevate {
			switch runtime.GOOS {
			case "windows":
				result.Recommendation = "Run as Administrator or use 'Run as administrator'"
			case "linux", "darwin":
				result.Recommendation = "Run with sudo: sudo ./GatTrace"
			default:
				result.Recommendation = "Run with elevated privileges"
			}
		} else {
			result.Recommendation = "Contact system administrator for elevated privileges"
		}
	}

	return result, nil
}

// CanRunCollector 检查是否可以运行采集器
func (d *DefaultPrivilegeDetector) CanRunCollector(collector Collector) bool {
	result, err := d.CheckCollectorPrivileges(collector)
	if err != nil {
		return false
	}
	return result.CanRun
}

// canRunWithPrivileges 检查当前权限是否足够运行指定权限级别的操作
func (d *DefaultPrivilegeDetector) canRunWithPrivileges(required PrivilegeLevel, current *PrivilegeInfo) bool {
	switch required {
	case PrivilegeLevelNone:
		return true
	case PrivilegeLevelUser:
		return current.Level >= PrivilegeLevelUser
	case PrivilegeLevelAdmin:
		return current.Level >= PrivilegeLevelAdmin
	case PrivilegeLevelSystem:
		return current.Level >= PrivilegeLevelSystem
	default:
		return false
	}
}

// GetRequiredPrivilegeLevel 获取采集器所需的权限级别
func GetRequiredPrivilegeLevel(collector Collector) PrivilegeLevel {
	if collector.RequiresPrivileges() {
		return PrivilegeLevelAdmin
	}
	return PrivilegeLevelUser
}

// FormatPrivilegeInfo 格式化权限信息为可读字符串
func FormatPrivilegeInfo(info *PrivilegeInfo) string {
	var parts []string
	
	parts = append(parts, fmt.Sprintf("User: %s (%s)", info.Username, info.UserID))
	parts = append(parts, fmt.Sprintf("Level: %s", info.Level))
	parts = append(parts, fmt.Sprintf("Admin: %v", info.IsAdmin))
	parts = append(parts, fmt.Sprintf("Can Elevate: %v", info.CanElevate))
	parts = append(parts, fmt.Sprintf("Platform: %s", info.Platform))
	
	if len(info.Groups) > 0 {
		parts = append(parts, fmt.Sprintf("Groups: %d", len(info.Groups)))
	}
	
	return strings.Join(parts, ", ")
}