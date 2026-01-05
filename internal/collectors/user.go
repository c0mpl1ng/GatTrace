package collectors

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"GatTrace/internal/core"
)

// UserCollector 用户权限采集器
type UserCollector struct {
	adapter core.PlatformAdapter
}

// NewUserCollector 创建用户权限采集器
func NewUserCollector(adapter core.PlatformAdapter) *UserCollector {
	return &UserCollector{
		adapter: adapter,
	}
}

// Name 返回采集器名称
func (c *UserCollector) Name() string {
	return "user"
}

// RequiresPrivileges 返回是否需要特权
func (c *UserCollector) RequiresPrivileges() bool {
	return true // 用户权限信息采集通常需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *UserCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行用户权限信息采集
func (c *UserCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 使用平台适配器获取用户信息
	userInfo, err := c.adapter.GetUserInfo()
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "user",
			Operation: "GetUserInfo",
			Err:       err,
			Severity:  core.SeverityError,
		}
		errors = append(errors, collectionErr)

		// 如果平台适配器失败，尝试使用通用方法
		userInfo, err = c.collectGenericUserInfo()
		if err != nil {
			collectionErr := core.CollectionError{
				Module:    "user",
				Operation: "collectGenericUserInfo",
				Err:       err,
				Severity:  core.SeverityCritical,
			}
			errors = append(errors, collectionErr)
			return &core.CollectionResult{Data: nil, Errors: errors}, err
		}
	}

	return &core.CollectionResult{
		Data:   userInfo,
		Errors: errors,
	}, nil
}

// collectGenericUserInfo 使用通用方法采集用户信息
func (c *UserCollector) collectGenericUserInfo() (*core.UserInfo, error) {
	// 创建基础元数据
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"

	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	userInfo := &core.UserInfo{
		Metadata:     metadata,
		CurrentUsers: []core.User{},
		RecentLogins: []core.LoginRecord{},
		Privileges:   []core.Privilege{},
		SSHKeys:      []core.SSHKey{},
	}

	// 获取当前用户信息
	currentUsers, err := c.getCurrentUsers()
	if err == nil {
		userInfo.CurrentUsers = currentUsers
	}

	// 获取最近登录记录
	recentLogins, err := c.getRecentLogins()
	if err == nil {
		userInfo.RecentLogins = recentLogins
	}

	// 获取权限信息
	privileges, err := c.getPrivileges()
	if err == nil {
		userInfo.Privileges = privileges
	}

	// 获取SSH密钥
	sshKeys, err := c.getSSHKeys()
	if err == nil {
		userInfo.SSHKeys = sshKeys
	}

	return userInfo, nil
}

// getCurrentUsers 获取当前用户信息
func (c *UserCollector) getCurrentUsers() ([]core.User, error) {
	var users []core.User

	// 获取当前用户
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	userInfo := core.User{
		Username:  currentUser.Username,
		UID:       currentUser.Uid,
		GID:       currentUser.Gid,
		HomeDir:   currentUser.HomeDir,
		LastLogin: time.Now().UTC(),
		IsActive:  true,
	}

	// 尝试获取用户的shell
	if shell := os.Getenv("SHELL"); shell != "" {
		userInfo.Shell = shell
	}

	users = append(users, userInfo)

	return users, nil
}

// getRecentLogins 获取最近登录记录
func (c *UserCollector) getRecentLogins() ([]core.LoginRecord, error) {
	var logins []core.LoginRecord

	// 这里简化实现，实际应该根据平台读取不同的日志文件
	// 例如：Linux 的 /var/log/wtmp, macOS 的 /var/log/utx.log, Windows 的事件日志

	// 添加当前登录记录作为示例
	currentUser, err := user.Current()
	if err == nil {
		login := core.LoginRecord{
			Username:  currentUser.Username,
			Terminal:  "console",
			Host:      "localhost",
			LoginTime: time.Now().Add(-time.Hour).UTC(),
			Status:    "active",
		}
		logins = append(logins, login)
	}

	return logins, nil
}

// getPrivileges 获取权限信息
func (c *UserCollector) getPrivileges() ([]core.Privilege, error) {
	var privileges []core.Privilege

	// 获取当前用户
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	privilege := core.Privilege{
		Username: currentUser.Username,
		Groups:   []string{},
		Sudo:     false,
		Admin:    false,
	}

	// 获取用户组信息
	if groupIds, err := currentUser.GroupIds(); err == nil {
		for _, gid := range groupIds {
			if group, err := user.LookupGroupId(gid); err == nil {
				privilege.Groups = append(privilege.Groups, group.Name)

				// 检查是否为管理员组
				if c.isAdminGroup(group.Name) {
					privilege.Admin = true
				}

				// 检查是否有sudo权限
				if c.isSudoGroup(group.Name) {
					privilege.Sudo = true
				}
			}
		}
	}

	privileges = append(privileges, privilege)
	return privileges, nil
}

// isAdminGroup 检查是否为管理员组
func (c *UserCollector) isAdminGroup(groupName string) bool {
	adminGroups := []string{
		"admin", "administrators", "wheel", "root", "sudo",
	}

	groupLower := strings.ToLower(groupName)
	for _, adminGroup := range adminGroups {
		if groupLower == adminGroup {
			return true
		}
	}
	return false
}

// isSudoGroup 检查是否有sudo权限
func (c *UserCollector) isSudoGroup(groupName string) bool {
	sudoGroups := []string{
		"sudo", "wheel", "admin",
	}

	groupLower := strings.ToLower(groupName)
	for _, sudoGroup := range sudoGroups {
		if groupLower == sudoGroup {
			return true
		}
	}
	return false
}

// getSSHKeys 获取SSH密钥信息
func (c *UserCollector) getSSHKeys() ([]core.SSHKey, error) {
	var sshKeys []core.SSHKey

	// 获取当前用户
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	// 检查用户的SSH目录
	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return sshKeys, nil // SSH目录不存在，返回空列表
	}

	// 查找SSH密钥文件
	keyFiles := []string{
		"id_rsa.pub",
		"id_dsa.pub",
		"id_ecdsa.pub",
		"id_ed25519.pub",
		"authorized_keys",
	}

	for _, keyFile := range keyFiles {
		keyPath := filepath.Join(sshDir, keyFile)
		if _, err := os.Stat(keyPath); err == nil {
			// 读取密钥文件
			content, err := os.ReadFile(keyPath)
			if err != nil {
				continue
			}

			// 解析SSH密钥
			keys := c.parseSSHKeys(string(content), currentUser.Username, keyPath)
			sshKeys = append(sshKeys, keys...)
		}
	}

	return sshKeys, nil
}

// parseSSHKeys 解析SSH密钥内容
func (c *UserCollector) parseSSHKeys(content, username, filePath string) []core.SSHKey {
	var keys []core.SSHKey

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		keyType := parts[0]
		keyData := parts[1]
		comment := ""
		if len(parts) > 2 {
			comment = strings.Join(parts[2:], " ")
		}

		// 计算密钥哈希（简化版本）
		keyHash := fmt.Sprintf("%x", []byte(keyData)[:16])

		key := core.SSHKey{
			Username: username,
			KeyType:  keyType,
			KeyHash:  keyHash,
			Comment:  comment,
			FilePath: filePath,
		}

		keys = append(keys, key)
	}

	return keys
}
