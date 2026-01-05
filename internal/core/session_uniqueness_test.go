package core

import (
	"fmt"
	"testing"
	"time"
)

// TestSessionUniquenessProperty 测试会话唯一性属性 (Task 9.4)
// 属性 7: 会话唯一性
// 验证: 需求 9.1, 10.1
func TestSessionUniquenessProperty(t *testing.T) {
	const iterations = 10

	t.Run("SessionUniquenessProperty", func(t *testing.T) {
		sessionIDs := make(map[string]bool)
		var sessions []*SessionManager

		for i := 0; i < iterations; i++ {
			// 创建新的会话管理器
			sessionManager, err := NewSessionManager(fmt.Sprintf("v1.0.%d", i))
			if err != nil {
				t.Fatalf("Iteration %d: Failed to create session manager: %v", i, err)
			}

			sessions = append(sessions, sessionManager)
			sessionID := sessionManager.GetSessionID()

			// 验证会话ID不为空
			if sessionID == "" {
				t.Errorf("Iteration %d: Session ID should not be empty", i)
				continue
			}

			// 验证会话ID的唯一性
			if sessionIDs[sessionID] {
				t.Errorf("Iteration %d: Duplicate session ID found: %s", i, sessionID)
			}
			sessionIDs[sessionID] = true

			// 验证会话ID格式 (应该包含哈希和时间戳)
			if len(sessionID) < 32 { // 至少应该有32个字符的哈希部分
				t.Errorf("Iteration %d: Session ID too short: %s", i, sessionID)
			}

			// 验证会话ID包含时间戳部分
			if !sessionContainsTimestamp(sessionID) {
				t.Errorf("Iteration %d: Session ID should contain timestamp: %s", i, sessionID)
			}

			// 验证会话开始时间的合理性
			startTime := sessionManager.GetStartTime()
			now := time.Now()
			if startTime.After(now) {
				t.Errorf("Iteration %d: Session start time cannot be in the future", i)
			}
			if now.Sub(startTime) > time.Minute {
				t.Errorf("Iteration %d: Session start time too old", i)
			}

			// 验证主机名不为空
			hostname := sessionManager.GetHostname()
			if hostname == "" {
				t.Errorf("Iteration %d: Hostname should not be empty", i)
			}

			// 验证平台信息不为空
			platform := sessionManager.GetPlatform()
			if platform == "" {
				t.Errorf("Iteration %d: Platform should not be empty", i)
			}

			// 验证元数据的一致性
			metadata := sessionManager.GetMetadata()
			if metadata.SessionID != sessionID {
				t.Errorf("Iteration %d: Metadata session ID mismatch", i)
			}
			if metadata.Hostname != hostname {
				t.Errorf("Iteration %d: Metadata hostname mismatch", i)
			}
			if metadata.Platform != platform {
				t.Errorf("Iteration %d: Metadata platform mismatch", i)
			}
		}

		// 验证所有会话ID都是唯一的
		if len(sessionIDs) != iterations {
			t.Errorf("Expected %d unique session IDs, got %d", iterations, len(sessionIDs))
		}

		// 验证并发创建的会话也是唯一的
		t.Run("ConcurrentSessionUniqueness", func(t *testing.T) {
			concurrentSessions := make(chan string, 50)
			done := make(chan bool, 50)

			// 并发创建50个会话
			for i := 0; i < 50; i++ {
				go func(idx int) {
					defer func() { done <- true }()

					sessionManager, err := NewSessionManager(fmt.Sprintf("concurrent-v1.0.%d", idx))
					if err != nil {
						t.Errorf("Concurrent iteration %d: Failed to create session manager: %v", idx, err)
						return
					}

					concurrentSessions <- sessionManager.GetSessionID()
				}(i)
			}

			// 等待所有协程完成
			for i := 0; i < 50; i++ {
				<-done
			}
			close(concurrentSessions)

			// 检查并发创建的会话ID唯一性
			concurrentIDs := make(map[string]bool)
			for sessionID := range concurrentSessions {
				if concurrentIDs[sessionID] {
					t.Errorf("Duplicate concurrent session ID: %s", sessionID)
				}
				concurrentIDs[sessionID] = true
			}
		})

		t.Logf("✅ Session uniqueness property verified with %d iterations", iterations)
	})
}

// sessionContainsTimestamp 检查会话ID是否包含时间戳部分
func sessionContainsTimestamp(sessionID string) bool {
	// 会话ID格式通常是: hash-timestamp
	// 检查是否包含连字符和数字
	hasHyphen := false
	hasDigits := false

	for _, char := range sessionID {
		if char == '-' {
			hasHyphen = true
		}
		if char >= '0' && char <= '9' {
			hasDigits = true
		}
	}

	return hasHyphen && hasDigits
}

// TestSessionConsistencyProperty 测试会话一致性属性
func TestSessionConsistencyProperty(t *testing.T) {
	const iterations = 10

	t.Run("SessionConsistencyProperty", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			sessionManager, err := NewSessionManager(fmt.Sprintf("v1.0.%d", i))
			if err != nil {
				t.Fatalf("Iteration %d: Failed to create session manager: %v", i, err)
			}

			// 多次调用相同方法应该返回相同结果
			sessionID1 := sessionManager.GetSessionID()
			sessionID2 := sessionManager.GetSessionID()
			if sessionID1 != sessionID2 {
				t.Errorf("Iteration %d: Session ID should be consistent: %s != %s", i, sessionID1, sessionID2)
			}

			hostname1 := sessionManager.GetHostname()
			hostname2 := sessionManager.GetHostname()
			if hostname1 != hostname2 {
				t.Errorf("Iteration %d: Hostname should be consistent: %s != %s", i, hostname1, hostname2)
			}

			platform1 := sessionManager.GetPlatform()
			platform2 := sessionManager.GetPlatform()
			if platform1 != platform2 {
				t.Errorf("Iteration %d: Platform should be consistent: %s != %s", i, platform1, platform2)
			}

			startTime1 := sessionManager.GetStartTime()
			time.Sleep(time.Millisecond) // 短暂等待
			startTime2 := sessionManager.GetStartTime()
			if !startTime1.Equal(startTime2) {
				t.Errorf("Iteration %d: Start time should be consistent", i)
			}

			metadata1 := sessionManager.GetMetadata()
			metadata2 := sessionManager.GetMetadata()
			if metadata1.SessionID != metadata2.SessionID ||
				metadata1.Hostname != metadata2.Hostname ||
				metadata1.Platform != metadata2.Platform {
				t.Errorf("Iteration %d: Metadata should be consistent", i)
			}
		}

		t.Logf("✅ Session consistency property verified with %d iterations", iterations)
	})
}
