package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"GatTrace/internal/core"
)

// SecurityCollector 安全日志采集器
type SecurityCollector struct {
	adapter core.PlatformAdapter
	days    int // 采集时间范围（天数）
}

// NewSecurityCollector 创建安全日志采集器（默认7天）
func NewSecurityCollector(adapter core.PlatformAdapter) *SecurityCollector {
	return &SecurityCollector{
		adapter: adapter,
		days:    7,
	}
}

// NewSecurityCollectorWithDays 创建安全日志采集器（可配置天数）
func NewSecurityCollectorWithDays(adapter core.PlatformAdapter, days int) *SecurityCollector {
	if days < 1 {
		days = 1
	} else if days > 365 {
		days = 365
	}
	return &SecurityCollector{
		adapter: adapter,
		days:    days,
	}
}

// Name 返回采集器名称
func (c *SecurityCollector) Name() string {
	return "security"
}

// RequiresPrivileges 返回是否需要特权
func (c *SecurityCollector) RequiresPrivileges() bool {
	return true // 安全日志访问通常需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *SecurityCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行安全日志信息采集
func (c *SecurityCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 直接使用通用方法采集安全日志（绕过平台适配器的简化实现）
	securityLogs, err := c.collectGenericSecurityLogs(ctx)
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "security",
			Operation: "collectGenericSecurityLogs",
			Err:       err,
			Severity:  core.SeverityCritical,
		}
		errors = append(errors, collectionErr)
		return &core.CollectionResult{Data: nil, Errors: errors}, err
	}

	return &core.CollectionResult{
		Data:   securityLogs,
		Errors: errors,
	}, nil
}

// collectGenericSecurityLogs 使用通用方法采集安全日志
func (c *SecurityCollector) collectGenericSecurityLogs(ctx context.Context) (*core.SecurityLogs, error) {
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0"
	
	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	securityLogs := &core.SecurityLogs{
		Metadata: metadata,
		Entries:  []core.LogEntry{},
	}

	var entries []core.LogEntry
	var err error

	switch runtime.GOOS {
	case "windows":
		entries, err = c.getWindowsSecurityLogs(ctx)
	case "linux":
		entries, err = c.getLinuxSecurityLogs(ctx)
	case "darwin":
		entries, err = c.getDarwinSecurityLogs(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get security logs: %w", err)
	}

	securityLogs.Entries = entries
	return securityLogs, nil
}

// getWindowsSecurityLogs 获取Windows安全日志 - 通过事件日志类型过滤
func (c *SecurityCollector) getWindowsSecurityLogs(ctx context.Context) ([]core.LogEntry, error) {
	var entries []core.LogEntry
	cutoffTime := time.Now().Add(-time.Duration(c.days) * 24 * time.Hour)

	// ========== Security 日志 ==========
	// 认证与登录
	authEventIDs := []int{4624, 4625, 4634, 4647, 4648, 4672, 4776, 4778, 4779}
	// 权限与账户变更
	accountEventIDs := []int{4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4738, 4740, 4741, 4742, 4743}
	// 安全机制触发（新进程、服务、计划任务、审计策略、防火墙）
	securityEventIDs := []int{4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4907, 4946, 4947, 4948, 4949, 4950}
	// 日志自身操作（日志被清空）
	logEventIDs := []int{1102, 104, 1100, 1104}

	securityAllIDs := make(map[int]bool)
	for _, id := range authEventIDs {
		securityAllIDs[id] = true
	}
	for _, id := range accountEventIDs {
		securityAllIDs[id] = true
	}
	for _, id := range securityEventIDs {
		securityAllIDs[id] = true
	}
	for _, id := range logEventIDs {
		securityAllIDs[id] = true
	}

	// 查询 Security 日志
	securityEntries, err := c.queryWindowsEventLogDirect(ctx, "Security", securityAllIDs, cutoffTime)
	if err != nil {
		securityEntries, _ = c.queryWindowsEventLogWevtutil(ctx, "Security", "authentication", cutoffTime)
	}
	entries = append(entries, securityEntries...)

	// ========== System 日志 ==========
	// 服务/驱动/重启/时间变更
	systemEventIDs := map[int]bool{
		7034: true, // 服务意外终止
		7035: true, // 服务控制管理器
		7036: true, // 服务状态变更
		7040: true, // 服务启动类型变更
		7045: true, // 新服务安装
		6005: true, // 事件日志服务启动（系统启动）
		6006: true, // 事件日志服务停止（系统关闭）
		6008: true, // 意外关机
		6009: true, // 系统启动时的处理器信息
		6013: true, // 系统运行时间
		1:    true, // 时间变更 (Kernel-General)
		// 驱动加载
		219: true, // 驱动加载失败
	}
	
	systemEntries, err := c.queryWindowsEventLogDirect(ctx, "System", systemEventIDs, cutoffTime)
	if err == nil {
		for i := range systemEntries {
			systemEntries[i].Details["log_source"] = "System"
		}
		entries = append(entries, systemEntries...)
	}

	// ========== Application 日志 ==========
	// 安全软件报警（Windows Defender, 其他安全软件）
	applicationEventIDs := map[int]bool{
		// Windows Defender
		1116: true, // 检测到恶意软件
		1117: true, // 恶意软件操作
		1118: true, // 恶意软件操作失败
		1119: true, // 恶意软件操作严重失败
		1006: true, // 扫描发现恶意软件
		1007: true, // 执行操作保护系统
		1008: true, // 操作失败
		1009: true, // 无法还原隔离项
		1010: true, // 无法删除隔离项
		// 应用程序错误
		1000: true, // 应用程序错误
		1001: true, // Windows 错误报告
		1002: true, // 应用程序挂起
	}
	
	appEntries, err := c.queryWindowsEventLogDirect(ctx, "Application", applicationEventIDs, cutoffTime)
	if err == nil {
		for i := range appEntries {
			appEntries[i].Details["log_source"] = "Application"
		}
		entries = append(entries, appEntries...)
	}

	// ========== Microsoft-Windows-Windows Defender/Operational ==========
	// Windows Defender 操作日志
	defenderEntries, err := c.queryWindowsDefenderLogs(ctx, cutoffTime)
	if err == nil {
		entries = append(entries, defenderEntries...)
	}

	return entries, nil
}

// queryWindowsDefenderLogs 查询 Windows Defender 日志
func (c *SecurityCollector) queryWindowsDefenderLogs(ctx context.Context, cutoffTime time.Time) ([]core.LogEntry, error) {
	var entries []core.LogEntry
	
	// Windows Defender 事件ID
	defenderEventIDs := map[int]bool{
		1116: true, // 检测到恶意软件或潜在有害软件
		1117: true, // 已对恶意软件执行操作
		1118: true, // 恶意软件操作失败
		1119: true, // 恶意软件操作严重失败
		1006: true, // 扫描发现恶意软件
		1007: true, // 执行操作保护系统
		1008: true, // 操作失败
		1121: true, // 攻击面减少规则触发
		1122: true, // 攻击面减少规则审核
		5001: true, // 实时保护已禁用
		5004: true, // 实时保护配置已更改
		5007: true, // 配置已更改
		5010: true, // 扫描已禁用
		5012: true, // 扫描已启用
	}
	
	defenderEntries, err := c.queryWindowsEventLogDirect(ctx, "Microsoft-Windows-Windows Defender/Operational", defenderEventIDs, cutoffTime)
	if err == nil {
		for i := range defenderEntries {
			defenderEntries[i].Details["log_source"] = "Windows Defender"
			defenderEntries[i].Details["category"] = "security_alert"
		}
		entries = append(entries, defenderEntries...)
	}
	
	return entries, nil
}

// queryWindowsEventLogDirect 直接查询Windows事件日志
func (c *SecurityCollector) queryWindowsEventLogDirect(ctx context.Context, channel string, eventIDs map[int]bool, cutoffTime time.Time) ([]core.LogEntry, error) {
	var entries []core.LogEntry
	daysAgo := c.days

	// 构建事件ID过滤字符串
	var idList []string
	for id := range eventIDs {
		idList = append(idList, fmt.Sprintf("%d", id))
	}
	eventIDFilter := strings.Join(idList, ",")

	// 使用 wevtutil 获取事件日志，它能更好地获取本地化的消息
	// 构建 XPath 查询
	startTime := time.Now().AddDate(0, 0, -daysAgo)
	// Windows 事件日志时间格式
	timeFilter := startTime.UTC().Format("2006-01-02T15:04:05.000Z")
	
	// 构建事件ID过滤条件
	var idConditions []string
	for id := range eventIDs {
		idConditions = append(idConditions, fmt.Sprintf("EventID=%d", id))
	}
	idFilter := strings.Join(idConditions, " or ")
	
	// XPath 查询
	xpath := fmt.Sprintf("*[System[TimeCreated[@SystemTime>='%s'] and (%s)]]", timeFilter, idFilter)
	
	// 使用 wevtutil 查询，/rd:true 表示从最新到最旧，/f:text 输出文本格式
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", channel, "/q:"+xpath, "/c:500", "/rd:true", "/f:text")
	output, err := cmd.Output()
	if err != nil {
		// 如果 wevtutil 失败，回退到 PowerShell 方法
		return c.queryWindowsEventLogPowerShell(ctx, channel, eventIDFilter, daysAgo)
	}

	// wevtutil 输出使用系统默认编码（中文 Windows 是 GBK）
	// 需要将 GBK 转换为 UTF-8
	outputStr := decodeGBKBytes(output)
	
	// 解析 wevtutil 文本输出
	entries = c.parseWevtutilTextOutput(outputStr, cutoffTime)
	
	return entries, nil
}

// queryWindowsEventLogPowerShell 使用 PowerShell 查询事件日志（备用方法）
func (c *SecurityCollector) queryWindowsEventLogPowerShell(ctx context.Context, channel, eventIDFilter string, daysAgo int) ([]core.LogEntry, error) {
	var entries []core.LogEntry

	// 使用PowerShell获取事件
	psScript := fmt.Sprintf(`
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$events = Get-WinEvent -FilterHashtable @{LogName='%s'; StartTime=(Get-Date).AddDays(-%d)} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in @(%s) }
foreach ($e in $events) {
    $time = $e.TimeCreated.ToString('o')
    $id = $e.Id
    $level = $e.LevelDisplayName
    $provider = $e.ProviderName
    $msg = $e.Message
    if ([string]::IsNullOrEmpty($msg)) {
        $msg = ""
    }
    $msg = $msg -replace '[\r\n]+', ' '
    [Console]::WriteLine("$time|||$id|||$level|||$provider|||$msg")
}
`, channel, daysAgo, eventIDFilter)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return entries, err
	}

	outputStr := string(output)
	if !isValidUTF8(outputStr) {
		if decoded, err := decodeGBK(output); err == nil {
			outputStr = decoded
		}
	}

	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|||")
		if len(parts) < 5 {
			continue
		}

		timestamp := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[0])); err == nil {
			timestamp = t.UTC()
		}

		eventID := strings.TrimSpace(parts[1])
		level := strings.TrimSpace(parts[2])
		provider := strings.TrimSpace(parts[3])
		message := strings.TrimSpace(parts[4])
		user := c.extractUser(message)
		eventType := c.getWindowsEventTypeName(eventID)
		eventCategory := c.categorizeWindowsEvent(eventID)

		entry := core.LogEntry{
			Timestamp: timestamp,
			Source:    provider,
			Level:     level,
			EventID:   eventID,
			Message:   message,
			Details: map[string]string{
				"category":   eventCategory,
				"event_type": eventType,
				"user":       user,
			},
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// parseWevtutilTextOutput 解析 wevtutil 文本格式输出
func (c *SecurityCollector) parseWevtutilTextOutput(output string, cutoffTime time.Time) []core.LogEntry {
	var entries []core.LogEntry
	
	// wevtutil /f:text 输出格式：
	// Event[0]:
	//   Log Name:      Security
	//   Source:        Microsoft-Windows-Security-Auditing
	//   Date:          2024/1/4 18:38:36
	//   Event ID:      4672
	//   Task:          Special Logon
	//   Level:         信息
	//   Opcode:        信息
	//   Keyword:       审核成功
	//   User:          N/A
	//   User Name:     N/A
	//   Computer:      DESKTOP-XXX
	//   Description:
	//   为新登录分配了特殊权限。
	//   ...
	
	// 按事件分割（空行分隔）
	events := strings.Split(output, "\r\n\r\n")
	if len(events) <= 1 {
		events = strings.Split(output, "\n\n")
	}
	
	for _, event := range events {
		if strings.TrimSpace(event) == "" {
			continue
		}
		
		entry := c.parseWevtutilEvent(event, cutoffTime)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}
	
	return entries
}

// parseWevtutilEvent 解析单个 wevtutil 事件
func (c *SecurityCollector) parseWevtutilEvent(event string, cutoffTime time.Time) *core.LogEntry {
	lines := strings.Split(event, "\n")
	
	var eventID, level, source, user, description string
	var timestamp time.Time
	inDescription := false
	var descBuilder strings.Builder
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 检查是否进入描述区域
		if strings.HasPrefix(line, "Description:") || strings.HasPrefix(line, "描述:") {
			inDescription = true
			// 提取同一行的描述内容
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
				descBuilder.WriteString(strings.TrimSpace(parts[1]))
			}
			continue
		}
		
		if inDescription {
			// 如果遇到新的字段（包含冒号且不是描述内容），停止
			if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				colonIdx := strings.Index(line, ":")
				if colonIdx > 0 && colonIdx < 20 {
					// 可能是新字段，检查字段名是否合理
					fieldName := strings.TrimSpace(line[:colonIdx])
					if !strings.Contains(fieldName, " ") || len(fieldName) < 15 {
						break
					}
				}
			}
			if descBuilder.Len() > 0 {
				descBuilder.WriteString(" ")
			}
			descBuilder.WriteString(line)
			continue
		}
		
		// 解析字段
		if strings.HasPrefix(line, "Event ID:") || strings.HasPrefix(line, "事件 ID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				eventID = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Level:") || strings.HasPrefix(line, "级别:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				level = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Source:") || strings.HasPrefix(line, "来源:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				source = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Date:") || strings.HasPrefix(line, "日期:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				dateStr := strings.TrimSpace(parts[1])
				// 尝试多种日期格式
				formats := []string{
					"2006/1/2 15:04:05",
					"2006-01-02 15:04:05",
					"2006/01/02 15:04:05",
					"1/2/2006 15:04:05",
					"01/02/2006 15:04:05",
				}
				for _, format := range formats {
					if t, err := time.ParseInLocation(format, dateStr, time.Local); err == nil {
						timestamp = t.UTC()
						break
					}
				}
			}
		} else if strings.HasPrefix(line, "User:") || strings.HasPrefix(line, "用户:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				u := strings.TrimSpace(parts[1])
				if u != "N/A" && u != "" {
					user = u
				}
			}
		}
	}
	
	description = strings.TrimSpace(descBuilder.String())
	
	// 如果没有解析到事件ID，跳过
	if eventID == "" {
		return nil
	}
	
	// 如果时间戳为空，使用当前时间
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	
	// 检查时间是否在范围内
	if !cutoffTime.IsZero() && timestamp.Before(cutoffTime) {
		return nil
	}
	
	// 如果没有从 User 字段获取到用户，尝试从描述中提取
	if user == "" {
		user = c.extractUser(description)
	}
	
	eventType := c.getWindowsEventTypeName(eventID)
	eventCategory := c.categorizeWindowsEvent(eventID)
	
	return &core.LogEntry{
		Timestamp: timestamp,
		Source:    source,
		Level:     level,
		EventID:   eventID,
		Message:   description,
		Details: map[string]string{
			"category":   eventCategory,
			"event_type": eventType,
			"user":       user,
		},
	}
}

// isValidUTF8 检查字符串是否是有效的UTF-8
func isValidUTF8(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		i += size
	}
	return true
}

// decodeGBK 将 GBK 编码的字节转换为 UTF-8 字符串
func decodeGBK(data []byte) (string, error) {
	// 使用 golang.org/x/text 包进行正确的 GBK 解码
	reader := transform.NewReader(strings.NewReader(string(data)), simplifiedchinese.GBK.NewDecoder())
	decoded, err := bufio.NewReader(reader).ReadString(0)
	if err != nil && err.Error() != "EOF" {
		// 如果解码失败，尝试 GB18030（GBK 的超集）
		reader = transform.NewReader(strings.NewReader(string(data)), simplifiedchinese.GB18030.NewDecoder())
		decoded, err = bufio.NewReader(reader).ReadString(0)
		if err != nil && err.Error() != "EOF" {
			return string(data), err
		}
	}
	return decoded, nil
}

// decodeGBKBytes 将 GBK 编码的字节转换为 UTF-8 字符串（更可靠的版本）
func decodeGBKBytes(data []byte) string {
	// 首先检查是否已经是有效的 UTF-8
	if utf8.Valid(data) {
		// 检查是否包含常见的乱码模式（UTF-8 解码 GBK 数据的结果）
		s := string(data)
		if !strings.Contains(s, "�") && !containsGarbledPattern(s) {
			return s
		}
	}
	
	// 尝试 GBK 解码
	decoder := simplifiedchinese.GBK.NewDecoder()
	result, _, err := transform.Bytes(decoder, data)
	if err == nil {
		return string(result)
	}
	
	// 尝试 GB18030 解码
	decoder = simplifiedchinese.GB18030.NewDecoder()
	result, _, err = transform.Bytes(decoder, data)
	if err == nil {
		return string(result)
	}
	
	// 解码失败，返回原始数据
	return string(data)
}

// containsGarbledPattern 检查字符串是否包含乱码模式
func containsGarbledPattern(s string) bool {
	// 检查常见的乱码模式
	garbledPatterns := []string{
		"锟斤拷", // GBK 被错误解码为 UTF-8 的常见结果
		"烫烫烫",
		"屯屯屯",
	}
	for _, pattern := range garbledPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	return false
}

// queryWindowsEventLogWevtutil 使用 wevtutil 查询事件日志
func (c *SecurityCollector) queryWindowsEventLogWevtutil(ctx context.Context, channel, category string, cutoffTime time.Time) ([]core.LogEntry, error) {
	var entries []core.LogEntry

	// 使用 wevtutil 查询
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", channel, "/c:200", "/rd:true", "/f:text")
	output, err := cmd.Output()
	if err != nil {
		return entries, err
	}

	// 解析 wevtutil 输出
	entries = c.parseWevtutilOutput(string(output), category, cutoffTime)
	return entries, nil
}

// WindowsEventJSON Windows事件JSON结构（保留用于兼容）
type WindowsEventJSON struct {
	TimeCreated      string `json:"TimeCreated"`
	Id               int    `json:"Id"`
	LevelDisplayName string `json:"LevelDisplayName"`
	ProviderName     string `json:"ProviderName"`
	Message          string `json:"Message"`
}

// parseWindowsEventLogJSON 解析 PowerShell JSON 输出（保留用于兼容）
func (c *SecurityCollector) parseWindowsEventLogJSON(jsonStr, category string) []core.LogEntry {
	var entries []core.LogEntry
	
	// 尝试解析为JSON数组
	jsonStr = strings.TrimSpace(jsonStr)
	if jsonStr == "" {
		return entries
	}
	
	// 处理单个对象或数组
	var events []WindowsEventJSON
	if strings.HasPrefix(jsonStr, "[") {
		// JSON数组
		if err := json.Unmarshal([]byte(jsonStr), &events); err != nil {
			// 解析失败，回退到按行处理
			return c.parseWindowsEventLogJSONFallback(jsonStr, category)
		}
	} else if strings.HasPrefix(jsonStr, "{") {
		// 单个JSON对象
		var event WindowsEventJSON
		if err := json.Unmarshal([]byte(jsonStr), &event); err != nil {
			return c.parseWindowsEventLogJSONFallback(jsonStr, category)
		}
		events = append(events, event)
	} else {
		return c.parseWindowsEventLogJSONFallback(jsonStr, category)
	}
	
	for _, event := range events {
		eventID := fmt.Sprintf("%d", event.Id)
		eventCategory := c.categorizeWindowsEvent(eventID)
		
		// 解析时间戳
		timestamp := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, event.TimeCreated); err == nil {
			timestamp = t.UTC()
		}
		
		// 提取用户（从Message中提取）
		user := c.extractUser(event.Message)
		
		// 使用完整的Message作为事件内容（这是Windows事件查看器"常规"标签页的内容）
		eventContent := event.Message
		if eventContent == "" {
			eventContent = c.getWindowsEventTypeName(eventID)
		}
		
		entry := core.LogEntry{
			Timestamp: timestamp,
			Source:    event.ProviderName,
			Level:     event.LevelDisplayName,
			EventID:   eventID,
			Message:   eventContent,
			Details: map[string]string{
				"category":   eventCategory,
				"event_type": c.getWindowsEventTypeName(eventID),
				"user":       user,
			},
		}
		
		entries = append(entries, entry)
	}
	
	return entries
}

// parseWindowsEventLogJSONFallback 回退的JSON解析方法（按行处理）
func (c *SecurityCollector) parseWindowsEventLogJSONFallback(jsonStr, category string) []core.LogEntry {
	var entries []core.LogEntry
	
	lines := strings.Split(jsonStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" {
			continue
		}
		
		// 提取事件ID
		eventID := c.extractEventID(line)
		eventCategory := category
		if eventID != "" {
			eventCategory = c.categorizeWindowsEvent(eventID)
		}
		
		// 提取时间戳
		timestamp := time.Now().UTC()
		if t, err := c.extractTimestamp(line); err == nil {
			timestamp = t
		}
		
		// 提取用户
		user := c.extractUser(line)
		
		// 提取Message字段内容
		eventContent := c.extractMessageField(line)
		if eventContent == "" {
			eventContent = c.getWindowsEventTypeName(eventID)
		}
		
		entry := core.LogEntry{
			Timestamp: timestamp,
			Source:    "Windows Event Log",
			Level:     "Info",
			EventID:   eventID,
			Message:   eventContent,
			Details: map[string]string{
				"category":   eventCategory,
				"event_type": c.getWindowsEventTypeName(eventID),
				"user":       user,
			},
		}
		
		entries = append(entries, entry)
	}
	
	return entries
}

// extractMessageField 从JSON行中提取Message字段
func (c *SecurityCollector) extractMessageField(line string) string {
	// 尝试匹配 "Message":"..." 格式
	msgRegex := regexp.MustCompile(`"Message"\s*:\s*"([^"]*(?:\\.[^"]*)*)"`)
	if matches := msgRegex.FindStringSubmatch(line); len(matches) > 1 {
		// 处理转义字符
		msg := matches[1]
		msg = strings.ReplaceAll(msg, `\\n`, "\n")
		msg = strings.ReplaceAll(msg, `\\r`, "")
		msg = strings.ReplaceAll(msg, `\\t`, "\t")
		msg = strings.ReplaceAll(msg, `\\"`, `"`)
		return msg
	}
	return ""
}

// parseWevtutilOutput 解析 wevtutil 输出
func (c *SecurityCollector) parseWevtutilOutput(output, category string, cutoffTime time.Time) []core.LogEntry {
	var entries []core.LogEntry
	
	// 按事件分割（wevtutil text格式用空行分隔事件）
	events := strings.Split(output, "\r\n\r\n")
	for _, event := range events {
		if strings.TrimSpace(event) == "" {
			continue
		}
		
		// 提取事件ID
		eventID := c.extractEventID(event)
		eventCategory := category
		if eventID != "" {
			eventCategory = c.categorizeWindowsEvent(eventID)
		}
		
		// 提取时间戳
		timestamp := time.Now().UTC()
		if t, err := c.extractTimestamp(event); err == nil {
			timestamp = t
			if timestamp.Before(cutoffTime) {
				continue
			}
		}
		
		// 提取用户
		user := c.extractUser(event)
		
		// 提取完整的事件描述（wevtutil text格式中的Description字段）
		eventContent := c.extractWevtutilDescription(event)
		if eventContent == "" {
			eventContent = c.getWindowsEventTypeName(eventID)
		}
		
		entry := core.LogEntry{
			Timestamp: timestamp,
			Source:    "Windows Event Log",
			Level:     "Info",
			EventID:   eventID,
			Message:   eventContent,
			Details: map[string]string{
				"category":   eventCategory,
				"event_type": c.getWindowsEventTypeName(eventID),
				"user":       user,
			},
		}
		
		entries = append(entries, entry)
	}
	
	return entries
}

// extractWevtutilDescription 从wevtutil输出中提取事件描述
func (c *SecurityCollector) extractWevtutilDescription(event string) string {
	// wevtutil text格式中，Description:后面是事件描述
	lines := strings.Split(event, "\n")
	var description strings.Builder
	inDescription := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Description:") {
			inDescription = true
			desc := strings.TrimPrefix(line, "Description:")
			desc = strings.TrimSpace(desc)
			if desc != "" {
				description.WriteString(desc)
			}
			continue
		}
		
		// 如果在描述区域内，且不是新的字段，则继续添加
		if inDescription {
			// 检查是否是新字段（以字母开头，后跟冒号）
			if len(line) > 0 && strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && !strings.Contains(parts[0], " ") {
					// 这是一个新字段，停止读取描述
					break
				}
			}
			if description.Len() > 0 {
				description.WriteString(" ")
			}
			description.WriteString(line)
		}
	}
	
	return description.String()
}

// categorizeWindowsEvent 根据事件ID分类Windows事件
func (c *SecurityCollector) categorizeWindowsEvent(eventID string) string {
	// 认证与登录事件
	authEvents := map[string]bool{
		"4624": true, "4625": true, "4634": true, "4647": true, "4648": true,
		"4672": true, "4776": true, "4778": true, "4779": true,
	}
	// 权限与账户变更事件
	accountEvents := map[string]bool{
		"4720": true, "4722": true, "4723": true, "4724": true, "4725": true,
		"4726": true, "4727": true, "4728": true, "4729": true, "4730": true,
		"4731": true, "4732": true, "4733": true, "4734": true, "4735": true,
		"4737": true, "4738": true, "4740": true, "4741": true, "4742": true, "4743": true,
	}
	// 安全机制触发事件
	securityEvents := map[string]bool{
		"4688": true, "4689": true, "4697": true, "4698": true, "4699": true,
		"4700": true, "4701": true, "4702": true, "4719": true, "4907": true,
		"4946": true, "4947": true, "4948": true, "4949": true, "4950": true,
	}
	// 日志自身操作事件
	logEvents := map[string]bool{
		"1102": true, "104": true, "1100": true, "1104": true,
	}

	if authEvents[eventID] {
		return "authentication"
	}
	if accountEvents[eventID] {
		return "account_change"
	}
	if securityEvents[eventID] {
		return "security_mechanism"
	}
	if logEvents[eventID] {
		return "log_operation"
	}
	return "other"
}

// getWindowsEventTypeName 获取Windows事件类型的可读名称
func (c *SecurityCollector) getWindowsEventTypeName(eventID string) string {
	eventNames := map[string]string{
		// ========== Security 日志 ==========
		// 认证与登录
		"4624": "登录成功",
		"4625": "登录失败",
		"4634": "注销",
		"4647": "用户发起注销",
		"4648": "使用显式凭据登录",
		"4672": "特权登录",
		"4776": "凭据验证",
		"4778": "会话重连",
		"4779": "会话断开",
		// 权限与账户
		"4720": "创建用户账户",
		"4722": "启用用户账户",
		"4723": "更改密码尝试",
		"4724": "重置密码",
		"4725": "禁用用户账户",
		"4726": "删除用户账户",
		"4727": "创建安全组",
		"4728": "添加成员到安全组",
		"4729": "从安全组移除成员",
		"4730": "删除安全组",
		"4731": "创建分发组",
		"4732": "添加成员到分发组",
		"4733": "从分发组移除成员",
		"4734": "删除分发组",
		"4735": "更改安全组",
		"4737": "更改安全组",
		"4738": "更改用户账户",
		"4740": "账户锁定",
		"4741": "创建计算机账户",
		"4742": "更改计算机账户",
		"4743": "删除计算机账户",
		// 安全机制
		"4688": "创建新进程",
		"4689": "进程退出",
		"4697": "安装服务",
		"4698": "创建计划任务",
		"4699": "删除计划任务",
		"4700": "启用计划任务",
		"4701": "禁用计划任务",
		"4702": "更新计划任务",
		"4719": "系统审计策略更改",
		"4907": "审计设置更改",
		"4946": "防火墙规则添加",
		"4947": "防火墙规则修改",
		"4948": "防火墙规则删除",
		"4949": "防火墙恢复默认",
		"4950": "防火墙设置更改",
		// 日志操作
		"1102": "审计日志清除",
		"104":  "事件日志清除",
		"1100": "事件日志服务关闭",
		"1104": "安全日志已满",
		
		// ========== System 日志 ==========
		// 服务相关
		"7034": "服务意外终止",
		"7035": "服务控制请求",
		"7036": "服务状态变更",
		"7040": "服务启动类型变更",
		"7045": "新服务安装",
		// 系统启动/关闭
		"6005": "系统启动",
		"6006": "系统关闭",
		"6008": "意外关机",
		"6009": "系统启动信息",
		"6013": "系统运行时间",
		// 时间变更
		"1":    "时间变更",
		// 驱动
		"219":  "驱动加载失败",
		
		// ========== Application 日志 ==========
		// 应用程序错误
		"1000": "应用程序错误",
		"1001": "Windows错误报告",
		"1002": "应用程序挂起",
		
		// ========== Windows Defender ==========
		"1116": "检测到恶意软件",
		"1117": "恶意软件操作",
		"1118": "恶意软件操作失败",
		"1119": "恶意软件操作严重失败",
		"1006": "扫描发现恶意软件",
		"1007": "执行保护操作",
		"1008": "保护操作失败",
		"1009": "无法还原隔离项",
		"1010": "无法删除隔离项",
		"1121": "攻击面减少规则触发",
		"1122": "攻击面减少规则审核",
		"5001": "实时保护已禁用",
		"5004": "实时保护配置更改",
		"5007": "Defender配置更改",
		"5010": "扫描已禁用",
		"5012": "扫描已启用",
	}
	
	if name, ok := eventNames[eventID]; ok {
		return name
	}
	return "未知事件"
}

// generateWindowsEventSummary 生成Windows事件摘要
func (c *SecurityCollector) generateWindowsEventSummary(eventID, rawLog string) string {
	eventType := c.getWindowsEventTypeName(eventID)
	
	// 提取关键信息
	user := c.extractUser(rawLog)
	ip := c.extractIPAddress(rawLog)
	process := c.extractProcessName(rawLog)
	
	// 根据事件类型生成摘要
	var summary string
	switch eventID {
	case "4624", "4625":
		if user != "" && ip != "" {
			summary = fmt.Sprintf("%s: 用户 %s 从 %s", eventType, user, ip)
		} else if user != "" {
			summary = fmt.Sprintf("%s: 用户 %s", eventType, user)
		} else {
			summary = eventType
		}
	case "4634", "4647":
		if user != "" {
			summary = fmt.Sprintf("%s: 用户 %s", eventType, user)
		} else {
			summary = eventType
		}
	case "4688", "4689":
		if process != "" {
			summary = fmt.Sprintf("%s: %s", eventType, process)
		} else {
			summary = eventType
		}
	case "4720", "4722", "4723", "4724", "4725", "4726":
		if user != "" {
			summary = fmt.Sprintf("%s: %s", eventType, user)
		} else {
			summary = eventType
		}
	default:
		if user != "" {
			summary = fmt.Sprintf("%s (用户: %s)", eventType, user)
		} else {
			summary = eventType
		}
	}
	
	return summary
}

// extractUser 从日志中提取用户名
func (c *SecurityCollector) extractUser(line string) string {
	// 多种用户名提取模式
	patterns := []string{
		`(?i)Account\s*Name[:\s]+([^\s,\r\n]+)`,
		`(?i)User[:\s]+([^\s,\r\n]+)`,
		`(?i)user[=:\s]+([a-zA-Z0-9_\-\.]+)`,
		`(?i)for\s+user\s+([a-zA-Z0-9_\-\.]+)`,
		`(?i)for\s+([a-zA-Z0-9_\-\.]+)\s+from`,
		`(?i)Subject.*?Account\s*Name[:\s]+([^\s,\r\n]+)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			user := matches[1]
			// 过滤掉系统账户和无效值
			if user != "-" && user != "N/A" && user != "SYSTEM" && user != "$" && len(user) > 0 {
				return user
			}
		}
	}
	return ""
}

// extractIPAddress 从日志中提取IP地址
func (c *SecurityCollector) extractIPAddress(line string) string {
	// IPv4
	ipv4Regex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	if match := ipv4Regex.FindString(line); match != "" && match != "0.0.0.0" && match != "127.0.0.1" {
		return match
	}
	
	// 源网络地址
	srcAddrRegex := regexp.MustCompile(`(?i)Source\s*Network\s*Address[:\s]+([^\s,\r\n]+)`)
	if matches := srcAddrRegex.FindStringSubmatch(line); len(matches) > 1 {
		if matches[1] != "-" && matches[1] != "::1" {
			return matches[1]
		}
	}
	
	return ""
}

// extractProcessName 从日志中提取进程名
func (c *SecurityCollector) extractProcessName(line string) string {
	patterns := []string{
		`(?i)New\s*Process\s*Name[:\s]+([^\r\n]+)`,
		`(?i)Process\s*Name[:\s]+([^\r\n]+)`,
		`([a-zA-Z0-9_\-]+\.exe)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			process := strings.TrimSpace(matches[1])
			if process != "" && process != "-" {
				// 只返回文件名，不要完整路径
				if idx := strings.LastIndex(process, "\\"); idx >= 0 {
					process = process[idx+1:]
				}
				return process
			}
		}
	}
	return ""
}

// getLinuxSecurityLogs 获取Linux安全日志 - 通过日志文件类型过滤
func (c *SecurityCollector) getLinuxSecurityLogs(ctx context.Context) ([]core.LogEntry, error) {
	var entries []core.LogEntry
	cutoffTime := time.Now().Add(-time.Duration(c.days) * 24 * time.Hour)
	maxEntries := 2000

	// Linux 安全相关的日志文件 - 按日志类型分类
	logSources := []struct {
		path     string
		category string
	}{
		// 认证与登录日志
		{"/var/log/auth.log", "authentication"},      // Debian/Ubuntu
		{"/var/log/secure", "authentication"},        // RHEL/CentOS
		// 审计日志 - 安全机制触发
		{"/var/log/audit/audit.log", "security_mechanism"},
		// 系统日志 - 可能包含安全相关信息
		{"/var/log/syslog", "system"},
		{"/var/log/messages", "system"},
		// 登录失败日志
		{"/var/log/faillog", "authentication"},
		{"/var/log/btmp", "authentication"},
		// 最后登录日志
		{"/var/log/lastlog", "authentication"},
		{"/var/log/wtmp", "authentication"},
	}

	for _, logSource := range logSources {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}

		fileEntries, err := c.parseSecurityLogFile(logSource.path, logSource.category, cutoffTime, maxEntries-len(entries))
		if err != nil {
			continue
		}
		entries = append(entries, fileEntries...)

		if len(entries) >= maxEntries {
			break
		}
	}

	// 使用 journalctl 获取 systemd 安全日志
	journalEntries, err := c.getLinuxJournalSecurityLogs(ctx, cutoffTime, maxEntries-len(entries))
	if err == nil {
		entries = append(entries, journalEntries...)
	}

	return entries, nil
}

// parseSecurityLogFile 解析安全日志文件
func (c *SecurityCollector) parseSecurityLogFile(filePath, category string, cutoffTime time.Time, maxEntries int) ([]core.LogEntry, error) {
	var entries []core.LogEntry

	file, err := os.Open(filePath)
	if err != nil {
		return entries, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() && len(entries) < maxEntries {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 提取时间戳
		timestamp := time.Now().UTC()
		if t, err := c.extractTimestamp(line); err == nil {
			timestamp = t
			if timestamp.Before(cutoffTime) {
				continue
			}
		}

		// 提取用户
		user := c.extractUser(line)
		
		// 提取事件ID
		eventID := c.extractEventID(line)
		
		// 生成事件摘要
		eventType := c.categorizeLinuxLogLine(line, category)
		eventSummary := c.generateLinuxEventSummary(line, eventType, user)

		entry := core.LogEntry{
			Timestamp: timestamp,
			Source:    filepath.Base(filePath),
			Level:     c.extractLogLevel(line),
			EventID:   eventID,
			Message:   eventSummary,
			Details: map[string]string{
				"category":   category,
				"event_type": eventType,
				"user":       user,
				"file":       filePath,
			},
		}

		// 提取IP地址
		if ip := c.extractIPAddress(line); ip != "" {
			entry.Details["ip_address"] = ip
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// categorizeLinuxLogLine 分类Linux日志行
func (c *SecurityCollector) categorizeLinuxLogLine(line, defaultCategory string) string {
	lineLower := strings.ToLower(line)
	
	// 认证相关
	if strings.Contains(lineLower, "authentication") || 
	   strings.Contains(lineLower, "session opened") ||
	   strings.Contains(lineLower, "session closed") ||
	   strings.Contains(lineLower, "accepted") ||
	   strings.Contains(lineLower, "failed password") ||
	   strings.Contains(lineLower, "invalid user") {
		return "认证登录"
	}
	
	// sudo/权限相关
	if strings.Contains(lineLower, "sudo") ||
	   strings.Contains(lineLower, "su:") ||
	   strings.Contains(lineLower, "privilege") {
		return "权限提升"
	}
	
	// SSH相关
	if strings.Contains(lineLower, "sshd") {
		if strings.Contains(lineLower, "accepted") {
			return "SSH登录成功"
		}
		if strings.Contains(lineLower, "failed") {
			return "SSH登录失败"
		}
		return "SSH活动"
	}
	
	// 账户相关
	if strings.Contains(lineLower, "useradd") ||
	   strings.Contains(lineLower, "userdel") ||
	   strings.Contains(lineLower, "usermod") ||
	   strings.Contains(lineLower, "passwd") {
		return "账户变更"
	}
	
	return defaultCategory
}

// generateLinuxEventSummary 生成Linux事件摘要
func (c *SecurityCollector) generateLinuxEventSummary(line, eventType, user string) string {
	lineLower := strings.ToLower(line)
	
	// SSH登录
	if strings.Contains(lineLower, "accepted") && strings.Contains(lineLower, "ssh") {
		ip := c.extractIPAddress(line)
		if user != "" && ip != "" {
			return fmt.Sprintf("SSH登录成功: 用户 %s 从 %s", user, ip)
		} else if user != "" {
			return fmt.Sprintf("SSH登录成功: 用户 %s", user)
		}
		return "SSH登录成功"
	}
	
	// SSH登录失败
	if strings.Contains(lineLower, "failed password") || strings.Contains(lineLower, "invalid user") {
		ip := c.extractIPAddress(line)
		if user != "" && ip != "" {
			return fmt.Sprintf("SSH登录失败: 用户 %s 从 %s", user, ip)
		} else if user != "" {
			return fmt.Sprintf("SSH登录失败: 用户 %s", user)
		}
		return "SSH登录失败"
	}
	
	// 会话开启/关闭
	if strings.Contains(lineLower, "session opened") {
		if user != "" {
			return fmt.Sprintf("会话开启: 用户 %s", user)
		}
		return "会话开启"
	}
	if strings.Contains(lineLower, "session closed") {
		if user != "" {
			return fmt.Sprintf("会话关闭: 用户 %s", user)
		}
		return "会话关闭"
	}
	
	// sudo
	if strings.Contains(lineLower, "sudo") {
		// 提取执行的命令
		cmdRegex := regexp.MustCompile(`COMMAND=(.+)$`)
		if matches := cmdRegex.FindStringSubmatch(line); len(matches) > 1 {
			cmd := matches[1]
			if len(cmd) > 50 {
				cmd = cmd[:50] + "..."
			}
			if user != "" {
				return fmt.Sprintf("sudo执行: 用户 %s 执行 %s", user, cmd)
			}
			return fmt.Sprintf("sudo执行: %s", cmd)
		}
		if user != "" {
			return fmt.Sprintf("sudo活动: 用户 %s", user)
		}
		return "sudo活动"
	}
	
	// 默认：返回事件类型
	if user != "" {
		return fmt.Sprintf("%s: 用户 %s", eventType, user)
	}
	return eventType
}

// getLinuxJournalSecurityLogs 使用 journalctl 获取安全相关日志
func (c *SecurityCollector) getLinuxJournalSecurityLogs(ctx context.Context, cutoffTime time.Time, maxEntries int) ([]core.LogEntry, error) {
	var entries []core.LogEntry

	// 使用 journalctl 获取安全相关的日志单元
	// 按日志类型/单元过滤，而不是关键词
	securityUnits := []struct {
		unit     string
		category string
	}{
		{"sshd.service", "authentication"},
		{"systemd-logind.service", "authentication"},
		{"sudo", "authentication"},
		{"su", "authentication"},
		{"polkit.service", "security_mechanism"},
		{"auditd.service", "security_mechanism"},
		{"firewalld.service", "security_mechanism"},
		{"iptables.service", "security_mechanism"},
	}

	sinceTime := fmt.Sprintf("-%dd", c.days)

	for _, unitInfo := range securityUnits {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}

		cmd := exec.CommandContext(ctx, "journalctl", "-u", unitInfo.unit, "--since", sinceTime, "-n", "100", "--no-pager", "-o", "short-iso")
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
				continue
			}

			// 提取时间戳
			timestamp := time.Now().UTC()
			if t, err := c.extractTimestamp(line); err == nil {
				timestamp = t
			}
			
			// 提取用户
			user := c.extractUser(line)
			
			// 生成事件摘要
			eventType := c.categorizeLinuxLogLine(line, unitInfo.category)
			eventSummary := c.generateLinuxEventSummary(line, eventType, user)

			entry := core.LogEntry{
				Timestamp: timestamp,
				Source:    unitInfo.unit,
				Level:     c.extractLogLevel(line),
				EventID:   c.extractEventID(line),
				Message:   eventSummary,
				Details: map[string]string{
					"category":   unitInfo.category,
					"event_type": eventType,
					"user":       user,
					"source":     "journalctl",
				},
			}
			
			// 提取IP地址
			if ip := c.extractIPAddress(line); ip != "" {
				entry.Details["ip_address"] = ip
			}

			entries = append(entries, entry)

			if len(entries) >= maxEntries {
				return entries, nil
			}
		}
	}

	return entries, nil
}

// getDarwinSecurityLogs 获取macOS安全日志 - 通过日志子系统过滤
func (c *SecurityCollector) getDarwinSecurityLogs(ctx context.Context) ([]core.LogEntry, error) {
	var entries []core.LogEntry
	cutoffTime := time.Now().Add(-time.Duration(c.days) * 24 * time.Hour)
	maxEntries := 2000

	// 优先使用 log show 获取统一日志 - 按子系统过滤（更精确）
	unifiedEntries, err := c.getDarwinUnifiedSecurityLogs(ctx, cutoffTime, maxEntries)
	if err == nil {
		entries = append(entries, unifiedEntries...)
	}

	// 如果统一日志不够，再从文件日志补充
	if len(entries) < maxEntries {
		// macOS 安全相关的日志文件
		logSources := []struct {
			path     string
			category string
		}{
			{"/var/log/secure.log", "authentication"},
			{"/var/log/auth.log", "authentication"},
			{"/var/log/appfirewall.log", "security_mechanism"},
			{"/var/log/install.log", "system"},
			{"/var/log/system.log", "system"},
		}

		for _, logSource := range logSources {
			select {
			case <-ctx.Done():
				return entries, ctx.Err()
			default:
			}

			fileEntries, err := c.parseSecurityLogFile(logSource.path, logSource.category, cutoffTime, maxEntries-len(entries))
			if err != nil {
				continue
			}
			entries = append(entries, fileEntries...)

			if len(entries) >= maxEntries {
				break
			}
		}
	}

	return entries, nil
}

// getDarwinUnifiedSecurityLogs 获取macOS统一日志 - 按安全相关子系统过滤
func (c *SecurityCollector) getDarwinUnifiedSecurityLogs(ctx context.Context, cutoffTime time.Time, maxEntries int) ([]core.LogEntry, error) {
	var entries []core.LogEntry

	// macOS 安全相关的子系统 - 精简列表，只保留最重要的
	securitySubsystems := []struct {
		subsystem string
		category  string
		eventType string
	}{
		// 认证与登录（最重要）
		{"com.apple.securityd", "authentication", "安全守护进程"},
		{"com.apple.Authorization", "authentication", "授权服务"},
		{"com.apple.loginwindow", "authentication", "登录窗口"},
		// 权限与账户
		{"com.apple.TCC", "account_change", "隐私权限"},
		// 安全机制触发
		{"com.apple.sandboxd", "security_mechanism", "沙盒"},
		{"com.apple.alf", "security_mechanism", "应用防火墙"},
	}

	// 使用小时数，最多24小时
	hours := c.days * 24
	if hours > 24 {
		hours = 24
	}
	lastTime := fmt.Sprintf("%dh", hours)

	for _, subsystemInfo := range securitySubsystems {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}

		// 为每个子系统查询创建子上下文，限制单个查询时间
		queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		
		// 使用 log show 命令按子系统过滤
		predicate := fmt.Sprintf("subsystem == '%s'", subsystemInfo.subsystem)
		cmd := exec.CommandContext(queryCtx, "log", "show", "--predicate", predicate, "--last", lastTime, "--style", "syslog")
		
		output, err := cmd.Output()
		cancel() // 释放上下文
		
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		count := 0
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "Timestamp") {
				continue
			}

			// 提取时间戳
			timestamp := time.Now().UTC()
			if t, err := c.extractTimestamp(line); err == nil {
				timestamp = t
			}
			
			// 提取用户
			user := c.extractUser(line)
			
			// 生成事件摘要
			eventSummary := c.generateDarwinEventSummary(line, subsystemInfo.eventType, user)

			entry := core.LogEntry{
				Timestamp: timestamp,
				Source:    subsystemInfo.subsystem,
				Level:     c.extractLogLevel(line),
				EventID:   c.extractEventID(line),
				Message:   eventSummary,
				Details: map[string]string{
					"category":   subsystemInfo.category,
					"event_type": subsystemInfo.eventType,
					"user":       user,
					"subsystem":  subsystemInfo.subsystem,
					"source":     "unified_log",
				},
			}

			entries = append(entries, entry)
			count++

			if count >= 200 || len(entries) >= maxEntries {
				break
			}
		}

		if len(entries) >= maxEntries {
			break
		}
	}

	return entries, nil
}

// generateDarwinEventSummary 生成macOS事件摘要
func (c *SecurityCollector) generateDarwinEventSummary(line, eventType, user string) string {
	lineLower := strings.ToLower(line)
	
	// 授权相关
	if strings.Contains(lineLower, "authorization") {
		if strings.Contains(lineLower, "succeeded") || strings.Contains(lineLower, "allowed") {
			if user != "" {
				return fmt.Sprintf("授权成功: 用户 %s", user)
			}
			return "授权成功"
		}
		if strings.Contains(lineLower, "failed") || strings.Contains(lineLower, "denied") {
			if user != "" {
				return fmt.Sprintf("授权失败: 用户 %s", user)
			}
			return "授权失败"
		}
	}
	
	// TCC (隐私权限)
	if strings.Contains(lineLower, "tcc") {
		// 提取应用名
		appRegex := regexp.MustCompile(`'([^']+)'`)
		if matches := appRegex.FindStringSubmatch(line); len(matches) > 1 {
			return fmt.Sprintf("隐私权限请求: %s", matches[1])
		}
		return "隐私权限请求"
	}
	
	// 沙盒
	if strings.Contains(lineLower, "sandbox") {
		if strings.Contains(lineLower, "deny") || strings.Contains(lineLower, "violation") {
			return "沙盒违规"
		}
		return "沙盒活动"
	}
	
	// 防火墙
	if strings.Contains(lineLower, "alf") || strings.Contains(lineLower, "firewall") {
		if strings.Contains(lineLower, "allow") {
			return "防火墙允许连接"
		}
		if strings.Contains(lineLower, "deny") || strings.Contains(lineLower, "block") {
			return "防火墙阻止连接"
		}
		return "防火墙活动"
	}
	
	// 登录
	if strings.Contains(lineLower, "login") {
		if strings.Contains(lineLower, "success") {
			if user != "" {
				return fmt.Sprintf("登录成功: 用户 %s", user)
			}
			return "登录成功"
		}
		if strings.Contains(lineLower, "fail") {
			if user != "" {
				return fmt.Sprintf("登录失败: 用户 %s", user)
			}
			return "登录失败"
		}
	}
	
	// 默认
	if user != "" {
		return fmt.Sprintf("%s: 用户 %s", eventType, user)
	}
	return eventType
}

// extractTimestamp 从日志行中提取时间戳
func (c *SecurityCollector) extractTimestamp(line string) (time.Time, error) {
	// RFC3339格式
	rfc3339Regex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	if match := rfc3339Regex.FindString(line); match != "" {
		if t, err := time.Parse(time.RFC3339, match); err == nil {
			return t.UTC(), nil
		}
	}
	
	// ISO格式 (2024-01-15 10:30:45)
	isoRegex := regexp.MustCompile(`(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})`)
	if matches := isoRegex.FindStringSubmatch(line); len(matches) == 3 {
		timeStr := matches[1] + "T" + matches[2] + "Z"
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			return t.UTC(), nil
		}
	}
	
	// Syslog格式 (MMM dd HH:mm:ss)
	syslogRegex := regexp.MustCompile(`([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})`)
	if matches := syslogRegex.FindStringSubmatch(line); len(matches) == 4 {
		timeStr := fmt.Sprintf("%d %s %s %s", time.Now().Year(), matches[1], matches[2], matches[3])
		if t, err := time.Parse("2006 Jan 2 15:04:05", timeStr); err == nil {
			return t.UTC(), nil
		}
	}
	
	return time.Time{}, fmt.Errorf("no timestamp found")
}

// extractLogLevel 从日志行中提取日志级别
func (c *SecurityCollector) extractLogLevel(line string) string {
	lineLower := strings.ToLower(line)
	
	levels := []string{"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}
	
	for _, level := range levels {
		if strings.Contains(lineLower, level) {
			return strings.Title(level)
		}
	}
	
	if strings.Contains(lineLower, "err") {
		return "Error"
	}
	if strings.Contains(lineLower, "warn") {
		return "Warning"
	}
	if strings.Contains(lineLower, "fail") {
		return "Error"
	}
	
	return "Info"
}

// extractEventID 从日志行中提取事件ID
func (c *SecurityCollector) extractEventID(line string) string {
	// Windows 事件ID格式
	eventIDRegex := regexp.MustCompile(`(?:Event\s*ID|EventID|Id)[:\s]*(\d{3,5})`)
	if matches := eventIDRegex.FindStringSubmatch(line); len(matches) > 1 {
		return matches[1]
	}
	
	// 通用数字ID
	genericIDRegex := regexp.MustCompile(`\b(\d{3,5})\b`)
	if match := genericIDRegex.FindString(line); match != "" {
		return match
	}
	
	return ""
}

// extractDetails 从日志行中提取详细信息
func (c *SecurityCollector) extractDetails(line string) map[string]string {
	details := make(map[string]string)
	
	// 提取用户名
	userRegex := regexp.MustCompile(`(?i)(?:for\s+user\s+([a-zA-Z0-9_-]+)|user[=:\s]+([a-zA-Z0-9_-]+)|for\s+([a-zA-Z0-9_-]+))`)
	if matches := userRegex.FindStringSubmatch(line); len(matches) > 1 {
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				details["user"] = matches[i]
				break
			}
		}
	}
	
	// 提取IP地址
	ipRegex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	if match := ipRegex.FindString(line); match != "" {
		details["ip_address"] = match
	}
	
	// 提取进程名
	processRegex := regexp.MustCompile(`([a-zA-Z0-9_-]+)\[\d+\]`)
	if matches := processRegex.FindStringSubmatch(line); len(matches) > 1 {
		details["process"] = matches[1]
	}
	
	// 提取PID
	pidRegex := regexp.MustCompile(`\[(\d+)\]`)
	if matches := pidRegex.FindStringSubmatch(line); len(matches) > 1 {
		details["pid"] = matches[1]
	}
	
	return details
}

// containsSecurityKeywords 检查日志行是否包含安全关键词（保留用于兼容性）
func (c *SecurityCollector) containsSecurityKeywords(line string, keywords []string) bool {
	lineLower := strings.ToLower(line)
	for _, keyword := range keywords {
		if strings.Contains(lineLower, keyword) {
			return true
		}
	}
	return false
}

// parseLinuxLogLine 解析Linux日志行（保留用于测试兼容性）
func (c *SecurityCollector) parseLinuxLogLine(line, source string) (core.LogEntry, error) {
	entry := core.LogEntry{
		Source:  source,
		Details: make(map[string]string),
	}

	// 尝试解析时间戳
	entry.Timestamp = time.Now().UTC()
	if timestamp, err := c.extractTimestamp(line); err == nil {
		entry.Timestamp = timestamp
	}

	// 设置日志级别
	entry.Level = c.extractLogLevel(line)
	
	// 设置消息
	entry.Message = line
	
	// 提取事件ID
	entry.EventID = c.extractEventID(line)
	
	// 提取详细信息
	entry.Details = c.extractDetails(line)

	return entry, nil
}

// parseDarwinLogLine 解析macOS日志行（保留用于测试兼容性）
func (c *SecurityCollector) parseDarwinLogLine(line, source string) (core.LogEntry, error) {
	return c.parseLinuxLogLine(line, source)
}
