package core

import (
	"testing"
	"time"
)

func TestNewSessionManager(t *testing.T) {
	version := Version
	sm, err := NewSessionManager(version)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}

	if sm.GetVersion() != version {
		t.Errorf("Expected version %s, got %s", version, sm.GetVersion())
	}

	if sm.GetSessionID() == "" {
		t.Error("Session ID should not be empty")
	}

	if sm.GetHostname() == "" {
		t.Error("Hostname should not be empty")
	}

	if sm.GetPlatform() == "" {
		t.Error("Platform should not be empty")
	}

	// 验证开始时间在合理范围内
	now := time.Now().UTC()
	startTime := sm.GetStartTime()
	if startTime.After(now) || now.Sub(startTime) > time.Second {
		t.Errorf("Start time %v is not within expected range", startTime)
	}
}

func TestSessionIDUniqueness(t *testing.T) {
	// 测试 SessionID 唯一性
	sessions := make(map[string]bool)

	for i := 0; i < 100; i++ {
		sm, err := NewSessionManager(Version)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		sessionID := sm.GetSessionID()
		if sessions[sessionID] {
			t.Errorf("Duplicate session ID found: %s", sessionID)
		}
		sessions[sessionID] = true
	}
}

func TestGetMetadata(t *testing.T) {
	version := Version
	sm, err := NewSessionManager(version)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}

	metadata := sm.GetMetadata()

	if metadata.SessionID != sm.GetSessionID() {
		t.Errorf("Metadata session ID mismatch")
	}

	if metadata.Hostname != sm.GetHostname() {
		t.Errorf("Metadata hostname mismatch")
	}

	if metadata.Platform != sm.GetPlatform() {
		t.Errorf("Metadata platform mismatch")
	}

	if metadata.CollectorVersion != version {
		t.Errorf("Metadata version mismatch")
	}

	// 验证时间戳格式
	if metadata.CollectedAt.IsZero() {
		t.Error("CollectedAt should not be zero")
	}

	// 验证时间戳是 UTC
	if metadata.CollectedAt.Location() != time.UTC {
		t.Error("CollectedAt should be in UTC")
	}
}
