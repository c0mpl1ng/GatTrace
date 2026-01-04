package core

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"
)

// SessionManager 管理会话信息
type SessionManager struct {
	sessionID string
	hostname  string
	platform  string
	version   string
	startTime time.Time
}

// NewSessionManager 创建新的会话管理器
func NewSessionManager(version string) (*SessionManager, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	platform := NewPlatformDetector().DetectPlatform().String()

	return &SessionManager{
		sessionID: sessionID,
		hostname:  hostname,
		platform:  platform,
		version:   version,
		startTime: time.Now().UTC(),
	}, nil
}

// GetMetadata 获取标准元数据
func (sm *SessionManager) GetMetadata() Metadata {
	return Metadata{
		SessionID:        sm.sessionID,
		Hostname:         sm.hostname,
		Platform:         sm.platform,
		CollectedAt:      NormalizeTimestamp(time.Now()),
		CollectorVersion: sm.version,
	}
}

// GetSessionID 获取会话ID
func (sm *SessionManager) GetSessionID() string {
	return sm.sessionID
}

// GetHostname 获取主机名
func (sm *SessionManager) GetHostname() string {
	return sm.hostname
}

// GetPlatform 获取平台信息
func (sm *SessionManager) GetPlatform() string {
	return sm.platform
}

// GetVersion 获取版本信息
func (sm *SessionManager) GetVersion() string {
	return sm.version
}

// GetStartTime 获取开始时间
func (sm *SessionManager) GetStartTime() time.Time {
	return sm.startTime
}

// generateSessionID 生成唯一的会话ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	// 添加时间戳确保唯一性
	timestamp := time.Now().Unix()
	
	return fmt.Sprintf("%x-%d", bytes, timestamp), nil
}

// NewSessionID 生成新的会话ID（公共函数）
func NewSessionID() (string, error) {
	return generateSessionID()
}

// GetSystemHostname 获取系统主机名（公共函数）
func GetSystemHostname() (string, error) {
	return os.Hostname()
}

// GetCurrentPlatform 获取当前平台（公共函数）
func GetCurrentPlatform() Platform {
	return NewPlatformDetector().DetectPlatform()
}

