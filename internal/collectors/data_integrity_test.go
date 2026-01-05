package collectors

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"GatTrace/internal/core"
)

// TestDataCollectionIntegrity 实现属性3：数据采集完整性
// **Feature: ir-system-info-collector, Property 3: 数据采集完整性**
// 对于任何支持的平台，采集的网络、进程、用户、持久化、文件系统、日志和系统信息应包含所有必需字段且与系统实际状态一致
// **验证: 需求 2.1-2.5, 3.1-3.5, 4.1-4.5, 5.1-5.5, 6.1-6.5, 7.1-7.5, 8.1-8.5**
func TestDataCollectionIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping data collection integrity test in short mode")
	}

	config := &quick.Config{
		MaxCount: 10, // 减少到10次迭代以提高速度
	}

	// 测试所有采集器的数据完整性
	err := quick.Check(func() bool {
		return testAllCollectorsIntegrity(t)
	}, config)

	if err != nil {
		t.Errorf("Data collection integrity property failed: %v", err)
	}
}

// testAllCollectorsIntegrity 测试所有采集器的数据完整性
func testAllCollectorsIntegrity(t *testing.T) bool {
	adapter := NewMockPlatformAdapter()

	// 创建所有采集器
	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	ctx := context.Background()

	for _, collector := range collectors {
		// 测试每个采集器的数据完整性
		if !testCollectorDataIntegrity(t, collector, ctx) {
			return false
		}
	}

	return true
}

// testCollectorDataIntegrity 测试单个采集器的数据完整性
func testCollectorDataIntegrity(t *testing.T, collector core.Collector, ctx context.Context) bool {
	result, err := collector.Collect(ctx)

	// 采集应该成功或有明确的错误处理
	if err != nil {
		t.Logf("Collector %s returned error: %v", collector.Name(), err)
		return false
	}

	if result == nil {
		t.Logf("Collector %s returned nil result", collector.Name())
		return false
	}

	// 验证数据结构完整性
	if !validateDataStructureIntegrity(t, collector.Name(), result.Data) {
		return false
	}

	// 验证元数据完整性
	if !validateMetadataIntegrity(t, collector.Name(), result.Data) {
		return false
	}

	// 验证错误处理完整性
	if !validateErrorHandlingIntegrity(t, collector.Name(), result.Errors) {
		return false
	}

	// 验证时间戳一致性
	if !validateTimestampConsistency(t, collector.Name(), result.Data) {
		return false
	}

	return true
}

// validateDataStructureIntegrity 验证数据结构完整性
func validateDataStructureIntegrity(t *testing.T, collectorName string, data interface{}) bool {
	if data == nil {
		t.Logf("Collector %s returned nil data", collectorName)
		return false
	}

	switch collectorName {
	case "network":
		return validateNetworkDataIntegrity(t, data)
	case "process":
		return validateProcessDataIntegrity(t, data)
	case "user":
		return validateUserDataIntegrity(t, data)
	case "persistence":
		return validatePersistenceDataIntegrity(t, data)
	case "filesystem":
		return validateFileSystemDataIntegrity(t, data)
	case "security":
		return validateSecurityDataIntegrity(t, data)
	case "system":
		return validateSystemDataIntegrity(t, data)
	default:
		t.Logf("Unknown collector: %s", collectorName)
		return false
	}
}

// validateNetworkDataIntegrity 验证网络数据完整性
func validateNetworkDataIntegrity(t *testing.T, data interface{}) bool {
	networkInfo, ok := data.(*core.NetworkInfo)
	if !ok {
		t.Log("Network data is not NetworkInfo type")
		return false
	}

	// 验证必需字段存在
	if networkInfo.Interfaces == nil {
		t.Log("Network interfaces should not be nil")
		return false
	}

	if networkInfo.Routes == nil {
		t.Log("Network routes should not be nil")
		return false
	}

	if networkInfo.Connections == nil {
		t.Log("Network connections should not be nil")
		return false
	}

	if networkInfo.Listeners == nil {
		t.Log("Network listeners should not be nil")
		return false
	}

	// 验证接口数据完整性
	for i, iface := range networkInfo.Interfaces {
		if iface.Name == "" {
			t.Logf("Interface %d should have name", i)
			return false
		}
		if iface.MTU <= 0 {
			t.Logf("Interface %d should have positive MTU", i)
			return false
		}
	}

	// 验证连接数据完整性
	for i, conn := range networkInfo.Connections {
		if conn.LocalAddr == "" {
			t.Logf("Connection %d should have local address", i)
			return false
		}
		if conn.Protocol == "" {
			t.Logf("Connection %d should have protocol", i)
			return false
		}
	}

	return true
}

// validateProcessDataIntegrity 验证进程数据完整性
func validateProcessDataIntegrity(t *testing.T, data interface{}) bool {
	processInfo, ok := data.(*core.ProcessInfo)
	if !ok {
		t.Log("Process data is not ProcessInfo type")
		return false
	}

	if processInfo.Processes == nil {
		t.Log("Process list should not be nil")
		return false
	}

	// 验证进程数据完整性
	for i, proc := range processInfo.Processes {
		if proc.PID <= 0 {
			t.Logf("Process %d should have positive PID", i)
			return false
		}
		if proc.Name == "" {
			t.Logf("Process %d should have name", i)
			return false
		}
		if proc.CreateTime.IsZero() {
			t.Logf("Process %d should have create time", i)
			return false
		}
		if proc.ExeHash == "" {
			t.Logf("Process %d should have executable hash", i)
			return false
		}
	}

	return true
}

// validateUserDataIntegrity 验证用户数据完整性
func validateUserDataIntegrity(t *testing.T, data interface{}) bool {
	userInfo, ok := data.(*core.UserInfo)
	if !ok {
		t.Log("User data is not UserInfo type")
		return false
	}

	if userInfo.CurrentUsers == nil {
		t.Log("Current users should not be nil")
		return false
	}

	if userInfo.RecentLogins == nil {
		t.Log("Recent logins should not be nil")
		return false
	}

	if userInfo.Privileges == nil {
		t.Log("Privileges should not be nil")
		return false
	}

	if userInfo.SSHKeys == nil {
		t.Log("SSH keys should not be nil")
		return false
	}

	// 验证用户数据完整性
	for i, user := range userInfo.CurrentUsers {
		if user.Username == "" {
			t.Logf("User %d should have username", i)
			return false
		}
		if user.UID == "" {
			t.Logf("User %d should have UID", i)
			return false
		}
	}

	return true
}

// validatePersistenceDataIntegrity 验证持久化数据完整性
func validatePersistenceDataIntegrity(t *testing.T, data interface{}) bool {
	persistenceInfo, ok := data.(*core.PersistenceInfo)
	if !ok {
		t.Log("Persistence data is not PersistenceInfo type")
		return false
	}

	if persistenceInfo.Items == nil {
		t.Log("Persistence items should not be nil")
		return false
	}

	// 验证持久化项目数据完整性
	for i, item := range persistenceInfo.Items {
		if item.Type == "" {
			t.Logf("Persistence item %d should have type", i)
			return false
		}
		if item.Name == "" {
			t.Logf("Persistence item %d should have name", i)
			return false
		}
		if item.Path == "" {
			t.Logf("Persistence item %d should have path", i)
			return false
		}
	}

	return true
}

// validateFileSystemDataIntegrity 验证文件系统数据完整性
func validateFileSystemDataIntegrity(t *testing.T, data interface{}) bool {
	fileSystemInfo, ok := data.(*core.FileSystemInfo)
	if !ok {
		t.Log("FileSystem data is not FileSystemInfo type")
		return false
	}

	if fileSystemInfo.RecentFiles == nil {
		t.Log("Recent files should not be nil")
		return false
	}

	// 验证文件数据完整性
	for i, file := range fileSystemInfo.RecentFiles {
		if file.Path == "" {
			t.Logf("File %d should have path", i)
			return false
		}
		// 哈希可能为空（大文件或权限问题），这是正常的
		if file.ModTime.IsZero() {
			t.Logf("File %d should have modification time", i)
			return false
		}
	}

	return true
}

// validateSecurityDataIntegrity 验证安全日志数据完整性
func validateSecurityDataIntegrity(t *testing.T, data interface{}) bool {
	securityLogs, ok := data.(*core.SecurityLogs)
	if !ok {
		t.Log("Security data is not SecurityLogs type")
		return false
	}

	if securityLogs.Entries == nil {
		t.Log("Security log entries should not be nil")
		return false
	}

	// 验证日志条目数据完整性
	for i, entry := range securityLogs.Entries {
		if entry.Timestamp.IsZero() {
			t.Logf("Log entry %d should have timestamp", i)
			return false
		}
		if entry.Level == "" {
			t.Logf("Log entry %d should have level", i)
			return false
		}
		if entry.Source == "" {
			t.Logf("Log entry %d should have source", i)
			return false
		}
		if entry.Message == "" {
			t.Logf("Log entry %d should have message", i)
			return false
		}
	}

	return true
}

// validateSystemDataIntegrity 验证系统状态数据完整性
func validateSystemDataIntegrity(t *testing.T, data interface{}) bool {
	systemStatus, ok := data.(*core.SystemStatus)
	if !ok {
		t.Log("System data is not SystemStatus type")
		return false
	}

	if systemStatus.BootTime.IsZero() {
		t.Log("System should have boot time")
		return false
	}

	if systemStatus.Uptime <= 0 {
		t.Log("System should have positive uptime")
		return false
	}

	if systemStatus.KernelModules == nil {
		t.Log("Kernel modules should not be nil")
		return false
	}

	// 验证内核模块数据完整性
	for i, module := range systemStatus.KernelModules {
		if module.Name == "" {
			t.Logf("Kernel module %d should have name", i)
			return false
		}
	}

	return true
}

// validateMetadataIntegrity 验证元数据完整性
func validateMetadataIntegrity(t *testing.T, collectorName string, data interface{}) bool {
	// 使用反射获取元数据字段
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	metadataField := v.FieldByName("Metadata")
	if !metadataField.IsValid() {
		t.Logf("Collector %s data should have Metadata field", collectorName)
		return false
	}

	metadata, ok := metadataField.Interface().(core.Metadata)
	if !ok {
		t.Logf("Collector %s Metadata field should be core.Metadata type", collectorName)
		return false
	}

	// 验证必需的元数据字段
	if metadata.SessionID == "" {
		t.Logf("Collector %s metadata should have session ID", collectorName)
		return false
	}

	if metadata.Hostname == "" {
		t.Logf("Collector %s metadata should have hostname", collectorName)
		return false
	}

	if metadata.Platform == "" {
		t.Logf("Collector %s metadata should have platform", collectorName)
		return false
	}

	if metadata.CollectorVersion == "" {
		t.Logf("Collector %s metadata should have collector version", collectorName)
		return false
	}

	if metadata.CollectedAt.IsZero() {
		t.Logf("Collector %s metadata should have collection timestamp", collectorName)
		return false
	}

	return true
}

// validateErrorHandlingIntegrity 验证错误处理完整性
func validateErrorHandlingIntegrity(t *testing.T, collectorName string, errors []core.CollectionError) bool {
	// 验证错误结构完整性
	for i, err := range errors {
		if err.Module == "" {
			t.Logf("Collector %s error %d should have module", collectorName, i)
			return false
		}

		if err.Operation == "" {
			t.Logf("Collector %s error %d should have operation", collectorName, i)
			return false
		}

		if err.Err == nil {
			t.Logf("Collector %s error %d should have underlying error", collectorName, i)
			return false
		}

		// 验证严重程度有效性
		if err.Severity < core.SeverityInfo || err.Severity > core.SeverityCritical {
			t.Logf("Collector %s error %d should have valid severity", collectorName, i)
			return false
		}
	}

	return true
}

// validateTimestampConsistency 验证时间戳一致性
func validateTimestampConsistency(t *testing.T, collectorName string, data interface{}) bool {
	// 使用反射检查所有时间戳字段
	return validateTimestampsInStruct(t, collectorName, reflect.ValueOf(data), "")
}

// validateTimestampsInStruct 递归验证结构体中的时间戳
func validateTimestampsInStruct(t *testing.T, collectorName string, v reflect.Value, fieldPath string) bool {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return true
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		vType := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := vType.Field(i)
			currentPath := fieldPath + "." + fieldType.Name

			if fieldType.Type == reflect.TypeOf(time.Time{}) {
				// 验证时间戳格式
				if !field.Interface().(time.Time).IsZero() {
					timestamp := field.Interface().(time.Time)
					if !isValidTimestamp(timestamp) {
						t.Logf("Collector %s field %s has invalid timestamp format: %v (location: %v)", collectorName, currentPath, timestamp, timestamp.Location())
						return false
					}
				}
			} else if field.Kind() == reflect.Struct || field.Kind() == reflect.Ptr {
				if !validateTimestampsInStruct(t, collectorName, field, currentPath) {
					return false
				}
			} else if field.Kind() == reflect.Slice {
				for j := 0; j < field.Len(); j++ {
					sliceItem := field.Index(j)
					itemPath := fmt.Sprintf("%s[%d]", currentPath, j)
					if !validateTimestampsInStruct(t, collectorName, sliceItem, itemPath) {
						return false
					}
				}
			}
		}

	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			sliceItem := v.Index(i)
			itemPath := fmt.Sprintf("%s[%d]", fieldPath, i)
			if !validateTimestampsInStruct(t, collectorName, sliceItem, itemPath) {
				return false
			}
		}
	}

	return true
}

// isValidTimestamp 验证时间戳是否符合ISO 8601格式
func isValidTimestamp(timestamp time.Time) bool {
	// 验证时间戳是否为UTC时区
	if timestamp.Location() != time.UTC {
		return false
	}

	// 验证时间戳是否可以正确序列化为ISO 8601格式
	serialized := timestamp.Format(time.RFC3339)
	parsed, err := time.Parse(time.RFC3339, serialized)
	if err != nil {
		return false
	}

	// 验证往返一致性 - 截断到秒级精度进行比较
	return timestamp.Truncate(time.Second).Equal(parsed)
}

// TestDataCollectionConsistency 测试数据采集一致性
func TestDataCollectionConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping data collection consistency test in short mode")
	}

	adapter := NewMockPlatformAdapter()

	// 多次运行同一个采集器，验证数据一致性
	collector := NewNetworkCollector(adapter)
	ctx := context.Background()

	var results []*core.CollectionResult
	for i := 0; i < 5; i++ {
		result, err := collector.Collect(ctx)
		if err != nil {
			t.Fatalf("Collection %d failed: %v", i, err)
		}
		results = append(results, result)
	}

	// 验证多次采集的结构一致性
	for i := 1; i < len(results); i++ {
		if !compareDataStructures(results[0].Data, results[i].Data) {
			t.Errorf("Collection %d data structure differs from first collection", i)
		}
	}
}

// compareDataStructures 比较两个数据结构的类型和基本结构
func compareDataStructures(data1, data2 interface{}) bool {
	v1 := reflect.ValueOf(data1)
	v2 := reflect.ValueOf(data2)

	if v1.Type() != v2.Type() {
		return false
	}

	// 对于结构体，比较字段数量和类型
	if v1.Kind() == reflect.Ptr {
		v1 = v1.Elem()
		v2 = v2.Elem()
	}

	if v1.Kind() == reflect.Struct {
		if v1.NumField() != v2.NumField() {
			return false
		}

		for i := 0; i < v1.NumField(); i++ {
			field1 := v1.Field(i)
			field2 := v2.Field(i)

			if field1.Type() != field2.Type() {
				return false
			}

			// 对于切片，比较元素类型
			if field1.Kind() == reflect.Slice {
				if field1.Type().Elem() != field2.Type().Elem() {
					return false
				}
			}
		}
	}

	return true
}

// TestCollectorErrorRecovery 测试采集器错误恢复
func TestCollectorErrorRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping collector error recovery test in short mode")
	}

	adapter := NewMockPlatformAdapter()
	adapter.SetShouldError(true)

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
	}

	ctx := context.Background()

	for _, collector := range collectors {
		result, err := collector.Collect(ctx)

		// 即使适配器出错，采集器也应该返回结果（使用回退机制）
		if err != nil {
			t.Errorf("Collector %s should not return error with fallback: %v", collector.Name(), err)
		}

		if result == nil {
			t.Errorf("Collector %s should return result even with adapter error", collector.Name())
		}

		// 应该有错误记录
		if len(result.Errors) == 0 {
			t.Errorf("Collector %s should record adapter errors", collector.Name())
		}

		// 数据应该仍然有效（来自回退机制）
		if result.Data == nil {
			t.Errorf("Collector %s should provide fallback data", collector.Name())
		}
	}
}

// TestMetadataConsistency 测试元数据一致性
func TestMetadataConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping metadata consistency test in short mode")
	}

	adapter := NewMockPlatformAdapter()

	collectors := []core.Collector{
		NewNetworkCollector(adapter),
		NewProcessCollector(adapter),
		NewUserCollector(adapter),
		NewPersistenceCollector(adapter),
		NewFileSystemCollector(adapter),
		NewSecurityCollector(adapter),
		NewSystemCollector(adapter),
	}

	ctx := context.Background()
	var metadataList []core.Metadata

	// 收集所有采集器的元数据
	for _, collector := range collectors {
		result, err := collector.Collect(ctx)
		if err != nil {
			t.Fatalf("Collector %s failed: %v", collector.Name(), err)
		}

		// 提取元数据
		v := reflect.ValueOf(result.Data)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		metadataField := v.FieldByName("Metadata")
		metadata := metadataField.Interface().(core.Metadata)
		metadataList = append(metadataList, metadata)
	}

	// 验证元数据一致性
	if len(metadataList) < 2 {
		t.Skip("Need at least 2 collectors for consistency test")
	}

	baseMetadata := metadataList[0]
	for i, metadata := range metadataList[1:] {
		// SessionID 应该相同（同一次运行）
		if metadata.SessionID != baseMetadata.SessionID {
			t.Errorf("Collector %d has different session ID", i+1)
		}

		// Hostname 应该相同
		if metadata.Hostname != baseMetadata.Hostname {
			t.Errorf("Collector %d has different hostname", i+1)
		}

		// Platform 应该相同
		if metadata.Platform != baseMetadata.Platform {
			t.Errorf("Collector %d has different platform", i+1)
		}

		// CollectorVersion 应该相同
		if metadata.CollectorVersion != baseMetadata.CollectorVersion {
			t.Errorf("Collector %d has different collector version", i+1)
		}

		// CollectedAt 应该在合理的时间范围内
		timeDiff := metadata.CollectedAt.Sub(baseMetadata.CollectedAt)
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		if timeDiff > 5*time.Second {
			t.Errorf("Collector %d has collection time too far from base: %v", i+1, timeDiff)
		}
	}
}
