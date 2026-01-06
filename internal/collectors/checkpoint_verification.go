package collectors

import (
	"context"
	"fmt"
	"reflect"

	"GatTrace/internal/core"
)

// CheckpointVerification 检查点验证结构
type CheckpointVerification struct {
	adapter core.PlatformAdapter
}

// NewCheckpointVerification 创建检查点验证器
func NewCheckpointVerification(adapter core.PlatformAdapter) *CheckpointVerification {
	return &CheckpointVerification{
		adapter: adapter,
	}
}

// VerifyAllCollectors 验证所有采集器是否正常工作
func (cv *CheckpointVerification) VerifyAllCollectors(ctx context.Context) (*VerificationReport, error) {
	report := &VerificationReport{
		TotalCollectors: 0,
		PassedTests:     0,
		FailedTests:     0,
		Results:         make(map[string]*CollectorVerificationResult),
	}

	// 创建所有采集器
	collectors := []core.Collector{
		NewNetworkCollector(cv.adapter),
		NewProcessCollector(cv.adapter),
		NewUserCollector(cv.adapter),
		NewPersistenceCollector(cv.adapter),
		NewFileSystemCollector(cv.adapter),
		NewSecurityCollector(cv.adapter),
		NewSystemCollector(cv.adapter),
	}

	report.TotalCollectors = len(collectors)

	// 验证每个采集器
	for _, collector := range collectors {
		result := cv.verifyCollector(ctx, collector)
		report.Results[collector.Name()] = result

		if result.Passed {
			report.PassedTests++
		} else {
			report.FailedTests++
		}
	}

	return report, nil
}

// verifyCollector 验证单个采集器
func (cv *CheckpointVerification) verifyCollector(ctx context.Context, collector core.Collector) *CollectorVerificationResult {
	result := &CollectorVerificationResult{
		Name:     collector.Name(),
		Passed:   true,
		Messages: []string{},
		Errors:   []string{},
	}

	// 1. 验证基本接口实现
	if collector.Name() == "" {
		result.Passed = false
		result.Errors = append(result.Errors, "Collector name is empty")
	} else {
		result.Messages = append(result.Messages, fmt.Sprintf("✓ Name: %s", collector.Name()))
	}

	// 2. 验证平台支持
	platforms := collector.SupportedPlatforms()
	if len(platforms) == 0 {
		result.Passed = false
		result.Errors = append(result.Errors, "No supported platforms")
	} else {
		platformNames := make([]string, len(platforms))
		for i, p := range platforms {
			platformNames[i] = p.String()
		}
		result.Messages = append(result.Messages, fmt.Sprintf("✓ Supported platforms: %v", platformNames))
	}

	// 3. 验证权限需求
	requiresPrivileges := collector.RequiresPrivileges()
	result.Messages = append(result.Messages, fmt.Sprintf("✓ Requires privileges: %v", requiresPrivileges))

	// 4. 验证采集功能
	collectionResult, err := collector.Collect(ctx)
	if err != nil {
		result.Passed = false
		result.Errors = append(result.Errors, fmt.Sprintf("Collection failed: %v", err))
	} else if collectionResult == nil {
		result.Passed = false
		result.Errors = append(result.Errors, "Collection returned nil result")
	} else if collectionResult.Data == nil {
		result.Passed = false
		result.Errors = append(result.Errors, "Collection returned nil data")
	} else {
		result.Messages = append(result.Messages, "✓ Collection successful")

		// 5. 验证数据结构
		if cv.validateDataStructure(collector.Name(), collectionResult.Data) {
			result.Messages = append(result.Messages, "✓ Data structure valid")
		} else {
			result.Passed = false
			result.Errors = append(result.Errors, "Invalid data structure")
		}

		// 6. 验证元数据
		if cv.validateMetadata(collectionResult.Data) {
			result.Messages = append(result.Messages, "✓ Metadata valid")
		} else {
			result.Passed = false
			result.Errors = append(result.Errors, "Invalid metadata")
		}

		// 7. 验证错误处理
		if len(collectionResult.Errors) > 0 {
			result.Messages = append(result.Messages, fmt.Sprintf("⚠ Collection errors: %d", len(collectionResult.Errors)))
		} else {
			result.Messages = append(result.Messages, "✓ No collection errors")
		}
	}

	return result
}

// validateDataStructure 验证数据结构
func (cv *CheckpointVerification) validateDataStructure(collectorName string, data interface{}) bool {
	if data == nil {
		return false
	}

	// 验证数据类型是否正确
	switch collectorName {
	case "network":
		_, ok := data.(*core.NetworkInfo)
		return ok
	case "process":
		_, ok := data.(*core.ProcessInfo)
		return ok
	case "user":
		_, ok := data.(*core.UserInfo)
		return ok
	case "persistence":
		_, ok := data.(*core.PersistenceInfo)
		return ok
	case "filesystem":
		_, ok := data.(*core.FileSystemInfo)
		return ok
	case "security":
		_, ok := data.(*core.SecurityLogs)
		return ok
	case "system":
		_, ok := data.(*core.SystemStatus)
		return ok
	default:
		return false
	}
}

// validateMetadata 验证元数据
func (cv *CheckpointVerification) validateMetadata(data interface{}) bool {
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	metadataField := v.FieldByName("Metadata")
	if !metadataField.IsValid() {
		return false
	}

	metadata, ok := metadataField.Interface().(core.Metadata)
	if !ok {
		return false
	}

	// 验证必需的元数据字段
	return metadata.SessionID != "" &&
		metadata.Hostname != "" &&
		metadata.Platform != "" &&
		metadata.CollectorVersion != "" &&
		!metadata.CollectedAt.IsZero()
}

// VerificationReport 验证报告
type VerificationReport struct {
	TotalCollectors int                                     `json:"total_collectors"`
	PassedTests     int                                     `json:"passed_tests"`
	FailedTests     int                                     `json:"failed_tests"`
	Results         map[string]*CollectorVerificationResult `json:"results"`
}

// CollectorVerificationResult 采集器验证结果
type CollectorVerificationResult struct {
	Name     string   `json:"name"`
	Passed   bool     `json:"passed"`
	Messages []string `json:"messages"`
	Errors   []string `json:"errors"`
}

// PrintReport 打印验证报告
func (report *VerificationReport) PrintReport() {
	core.Println("=== GatTrace 采集器检查点验证报告 ===")
	core.Printf("总采集器数量: %d\n", report.TotalCollectors)
	core.Printf("通过测试: %d\n", report.PassedTests)
	core.Printf("失败测试: %d\n", report.FailedTests)
	core.Printf("成功率: %.1f%%\n", float64(report.PassedTests)/float64(report.TotalCollectors)*100)
	core.Println("")

	config := core.GetConsoleConfig()
	for name, result := range report.Results {
		if result.Passed {
			if config.UseEmoji {
				core.Printf("✅ %s - 通过\n", name)
			} else {
				core.Printf("[OK] %s - 通过\n", name)
			}
		} else {
			if config.UseEmoji {
				core.Printf("❌ %s - 失败\n", name)
			} else {
				core.Printf("[X] %s - 失败\n", name)
			}
		}

		for _, msg := range result.Messages {
			core.Printf("   %s\n", core.ConsoleText(msg))
		}

		for _, err := range result.Errors {
			if config.UseEmoji {
				core.Printf("   ❌ %s\n", err)
			} else {
				core.Printf("   [X] %s\n", err)
			}
		}
		core.Println("")
	}

	if report.FailedTests == 0 {
		if config.UseEmoji {
			core.Println("🎉 所有采集器验证通过！系统准备就绪。")
		} else {
			core.Println("[!] 所有采集器验证通过！系统准备就绪。")
		}
	} else {
		if config.UseEmoji {
			core.Printf("⚠️  有 %d 个采集器验证失败，需要修复。\n", report.FailedTests)
		} else {
			core.Printf("[!] 有 %d 个采集器验证失败，需要修复。\n", report.FailedTests)
		}
	}
}

// IsAllPassed 检查是否所有测试都通过
func (report *VerificationReport) IsAllPassed() bool {
	return report.FailedTests == 0
}
