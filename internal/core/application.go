package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// App 应用程序实现
type App struct {
	version        string
	sessionManager *SessionManager
	privilegeManager *PrivilegeManager
	errorManager   *ErrorManager
	systemMonitor  *SystemMonitor
	collectors     []Collector
}

// NewApplication 创建新的应用程序实例
func NewApplication(version string) *App {
	return &App{
		version: version,
	}
}

// Run 运行应用程序
func (a *App) Run(ctx context.Context, outputDir string, verbose bool) error {
	// 初始化系统监控器
	a.systemMonitor = NewSystemMonitor()
	
	// 捕获开始快照
	if verbose {
		fmt.Println("正在捕获系统开始状态快照...")
	}
	if err := a.systemMonitor.CaptureStartSnapshot(ctx); err != nil {
		return fmt.Errorf("failed to capture start snapshot: %w", err)
	}

	// 初始化会话管理器
	sessionManager, err := NewSessionManager(a.version)
	if err != nil {
		return fmt.Errorf("failed to initialize session manager: %w", err)
	}
	a.sessionManager = sessionManager

	// 初始化错误管理器
	a.errorManager = NewErrorManager()

	// 初始化权限管理器
	privilegeManager, err := NewPrivilegeManager()
	if err != nil {
		return fmt.Errorf("failed to initialize privilege manager: %w", err)
	}
	a.privilegeManager = privilegeManager

	// 获取当前权限信息
	privilegeInfo := a.privilegeManager.GetPrivilegeInfo()
	if verbose {
		log.Printf("当前权限级别: %s", privilegeInfo.Level)
	}

	// 注册所有采集器
	if err := a.registerCollectors(); err != nil {
		return fmt.Errorf("failed to register collectors: %w", err)
	}

	fmt.Printf("会话ID: %s\n", sessionManager.GetSessionID())
	fmt.Printf("主机名: %s\n", sessionManager.GetHostname())
	fmt.Printf("平台: %s\n", sessionManager.GetPlatform())
	fmt.Printf("权限级别: %s\n", privilegeInfo.Level)
	
	if verbose {
		fmt.Printf("注册了 %d 个采集器\n", len(a.collectors))
	}

	// 执行采集流程
	if err := a.runCollectionProcess(ctx, outputDir, verbose); err != nil {
		return fmt.Errorf("collection process failed: %w", err)
	}

	// 创建元数据文件 (在HTML生成之前)
	if err := a.createMetadataFile(outputDir); err != nil {
		a.errorManager.RecordError(&CollectionError{
			Module:    "application",
			Operation: "create_metadata",
			Err:       err,
			Severity:  SeverityWarning,
		})
		if verbose {
			log.Printf("Warning: Failed to create metadata file: %v", err)
		}
	}

	// 生成输出文件和报告 (Task 9.3 - 输出文件生成和验证)
	if err := a.generateOutputFiles(outputDir, verbose); err != nil {
		return fmt.Errorf("failed to generate output files: %w", err)
	}

	// 捕获结束快照并比较
	if verbose {
		fmt.Println("正在捕获系统结束状态快照...")
	}
	if err := a.systemMonitor.CaptureEndSnapshot(ctx); err != nil {
		a.errorManager.RecordError(&CollectionError{
			Module:    "system_monitor",
			Operation: "capture_end_snapshot",
			Err:       err,
			Severity:  SeverityWarning,
		})
		if verbose {
			log.Printf("Warning: Failed to capture end snapshot: %v", err)
		}
	} else {
		// 比较快照并生成报告
		if err := a.generateSystemStateReport(outputDir, verbose); err != nil {
			a.errorManager.RecordError(&CollectionError{
				Module:    "system_monitor",
				Operation: "generate_state_report",
				Err:       err,
				Severity:  SeverityWarning,
			})
			if verbose {
				log.Printf("Warning: Failed to generate system state report: %v", err)
			}
		}
	}

	return nil
}

// registerCollectors 注册所有采集器 (Task 9.3 - 采集器注册和执行)
func (a *App) registerCollectors() error {
	// 采集器注册将在main包中完成，避免循环导入
	if len(a.collectors) == 0 {
		log.Println("注意: 尚未注册任何采集器，这是正常的开发阶段状态")
		log.Println("在后续的开发中，将集成所有具体的采集器实现")
	}
	
	return nil
}

// RegisterCollector 注册单个采集器（供外部调用）
func (a *App) RegisterCollector(collector Collector) {
	a.collectors = append(a.collectors, collector)
}

// createMetadataFile 创建元数据文件
func (a *App) createMetadataFile(outputDir string) error {
	metadata := Metadata{
		SessionID:        a.sessionManager.GetSessionID(),
		Hostname:         a.sessionManager.GetHostname(),
		Platform:         a.sessionManager.GetPlatform(),
		CollectedAt:      NormalizeTimestamp(time.Now()),
		CollectorVersion: a.version,
	}

	metaData := map[string]interface{}{
		"metadata": metadata,
	}

	// 简单的JSON写入，不依赖output包
	return a.writeJSONFile(outputDir, "meta.json", metaData)
}

// writeJSONFile 简单的JSON文件写入
func (a *App) writeJSONFile(outputDir, filename string, data interface{}) error {
	// TODO: 在后续任务中集成完整的输出管理器
	// 这里暂时只是创建目录和基本文件
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// 创建文件
	filePath := filepath.Join(outputDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()
	
	// 使用JSON编码器写入数据
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON for %s: %w", filename, err)
	}
	
	return nil
}

// runCollectionProcess 执行采集流程控制 (Task 9.2)
func (a *App) runCollectionProcess(ctx context.Context, outputDir string, verbose bool) error {
	if len(a.collectors) == 0 {
		if verbose {
			log.Println("没有注册的采集器，跳过采集过程")
		}
		return nil
	}

	// 过滤可运行的采集器
	runnableCollectors, blockedCollectors, err := a.privilegeManager.FilterRunnableCollectors(a.collectors)
	if err != nil {
		return fmt.Errorf("failed to filter collectors: %w", err)
	}

	if len(blockedCollectors) > 0 {
		if verbose {
			log.Printf("由于权限不足，跳过 %d 个采集器", len(blockedCollectors))
			for _, collector := range blockedCollectors {
				log.Printf("  - %s", collector.Name())
			}
		}
	}

	if len(runnableCollectors) == 0 {
		return fmt.Errorf("no collectors can run with current privileges")
	}

	fmt.Printf("开始并发采集，共 %d 个采集器...\n", len(runnableCollectors))

	// 创建采集结果通道
	resultChan := make(chan *CollectorResult, len(runnableCollectors))
	
	// 使用WaitGroup等待所有采集器完成
	var wg sync.WaitGroup
	
	// 启动采集器
	for i, collector := range runnableCollectors {
		wg.Add(1)
		go func(idx int, c Collector) {
			defer wg.Done()
			
			if verbose {
				log.Printf("[%d/%d] 开始采集: %s", idx+1, len(runnableCollectors), c.Name())
			}
			
			// 为每个采集器创建子上下文
			collectorCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			
			// 执行采集
			result := a.executeCollector(collectorCtx, c, verbose)
			result.Index = idx + 1
			result.Total = len(runnableCollectors)
			
			// 发送结果
			select {
			case resultChan <- result:
			case <-ctx.Done():
				if verbose {
					log.Printf("采集器 %s 被取消", c.Name())
				}
			}
			
			if verbose {
				if result.Error != nil {
					log.Printf("[%d/%d] 采集失败: %s - %v", idx+1, len(runnableCollectors), c.Name(), result.Error)
				} else {
					log.Printf("[%d/%d] 采集完成: %s", idx+1, len(runnableCollectors), c.Name())
				}
			}
		}(i, collector)
	}

	// 启动结果处理协程
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 处理采集结果
	var successCount, failureCount int
	for result := range resultChan {
		if result.Error != nil {
			failureCount++
			a.errorManager.RecordError(&CollectionError{
				Module:    result.CollectorName,
				Operation: "collect",
				Err:       result.Error,
				Severity:  SeverityError,
			})
		} else {
			successCount++
			// 保存采集结果到文件
			if err := a.saveCollectionResult(outputDir, result); err != nil {
				if verbose {
					log.Printf("保存采集结果失败: %s - %v", result.CollectorName, err)
				}
				a.errorManager.RecordError(&CollectionError{
					Module:    result.CollectorName,
					Operation: "save_result",
					Err:       err,
					Severity:  SeverityWarning,
				})
			}
		}
		
		// 显示进度
		fmt.Printf("进度: %d/%d 完成 (成功: %d, 失败: %d)\n", 
			result.Index, result.Total, successCount, failureCount)
	}

	// 检查上下文是否被取消
	if ctx.Err() != nil {
		return fmt.Errorf("collection process cancelled: %w", ctx.Err())
	}

	fmt.Printf("采集过程完成: 成功 %d, 失败 %d\n", successCount, failureCount)
	return nil
}

// CollectorResult 采集器结果
type CollectorResult struct {
	CollectorName string
	Data          interface{}
	Error         error
	Duration      time.Duration
	Index         int // 当前索引
	Total         int // 总数
}

// executeCollector 执行单个采集器
func (a *App) executeCollector(ctx context.Context, collector Collector, verbose bool) *CollectorResult {
	startTime := time.Now()
	
	result := &CollectorResult{
		CollectorName: collector.Name(),
	}
	
	// 检查权限
	if skip, reason := a.privilegeManager.ShouldSkipCollector(collector); skip {
		result.Error = fmt.Errorf("skipped due to insufficient privileges: %s", reason)
		result.Duration = time.Since(startTime)
		return result
	}
	
	// 执行采集
	collectionResult, err := collector.Collect(ctx)
	result.Duration = time.Since(startTime)
	
	if err != nil {
		result.Error = fmt.Errorf("collection failed: %w", err)
		return result
	}
	
	if collectionResult == nil {
		result.Error = fmt.Errorf("collector returned nil result")
		return result
	}
	
	// 记录采集过程中的错误
	for _, collErr := range collectionResult.Errors {
		a.errorManager.RecordError(&collErr)
	}
	
	result.Data = collectionResult.Data
	return result
}

// saveCollectionResult 保存采集结果
func (a *App) saveCollectionResult(outputDir string, result *CollectorResult) error {
	if result.Data == nil {
		return fmt.Errorf("no data to save")
	}
	
	filename := fmt.Sprintf("%s.json", result.CollectorName)
	return a.writeJSONFile(outputDir, filename, result.Data)
}

// generateOutputFiles 生成输出文件和报告 (Task 9.3)
func (a *App) generateOutputFiles(outputDir string, verbose bool) error {
	if verbose {
		log.Println("开始生成输出文件和报告...")
	}

	// 确保输出目录存在
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 生成HTML报告 (先生成文件)
	if err := a.generateHTMLReport(outputDir, verbose); err != nil {
		a.errorManager.RecordError(&CollectionError{
			Module:    "html_generator",
			Operation: "generate_report",
			Err:       err,
			Severity:  SeverityWarning,
		})
		if verbose {
			log.Printf("HTML报告生成失败: %v", err)
		}
	} else if verbose {
		log.Println("HTML报告生成成功")
	}

	// 生成错误报告 (在清单之前生成)
	if err := a.generateErrorReport(outputDir, verbose); err != nil {
		if verbose {
			log.Printf("错误报告生成失败: %v", err)
		}
	} else if verbose {
		log.Println("错误报告生成成功")
	}

	// 生成清单文件 (最后生成，包含所有文件)
	if err := a.generateManifest(outputDir, verbose); err != nil {
		a.errorManager.RecordError(&CollectionError{
			Module:    "integrity_manager",
			Operation: "create_manifest",
			Err:       err,
			Severity:  SeverityWarning,
		})
		if verbose {
			log.Printf("清单文件生成失败: %v", err)
		}
	} else if verbose {
		log.Println("清单文件生成成功")
	}

	if verbose {
		log.Println("输出文件生成完成")
	}

	return nil
}

// generateHTMLReport 生成HTML报告
func (a *App) generateHTMLReport(outputDir string, verbose bool) error {
	// 创建HTML生成器接口的实现
	htmlGen := &htmlGeneratorImpl{outputDir: outputDir}
	
	// 生成HTML报告
	if err := htmlGen.GenerateReport(); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}
	
	if verbose {
		log.Println("HTML报告生成完成，包含交互式数据展示和PID链接功能")
	}
	
	return nil
}

// htmlGeneratorImpl HTML生成器实现
type htmlGeneratorImpl struct {
	outputDir string
}

// GenerateReport 生成自包含的HTML报告
func (h *htmlGeneratorImpl) GenerateReport() error {
	// 读取所有JSON数据
	data := h.loadAllJSONData()
	
	// 生成完整的自包含HTML
	html := h.generateFullHTML(data)
	
	// 写入HTML文件
	outputPath := filepath.Join(h.outputDir, "index.html")
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}
	
	return nil
}

// loadAllJSONData 加载所有JSON数据文件
func (h *htmlGeneratorImpl) loadAllJSONData() map[string]interface{} {
	data := make(map[string]interface{})
	jsonFiles := []string{
		"meta.json", "network.json", "process.json", "user.json",
		"persistence.json", "filesystem.json", "security.json",
		"system.json", "errors.json", "system_state.json",
	}
	
	for _, filename := range jsonFiles {
		filePath := filepath.Join(h.outputDir, filename)
		if content, err := os.ReadFile(filePath); err == nil {
			var jsonObj interface{}
			if json.Unmarshal(content, &jsonObj) == nil {
				key := strings.TrimSuffix(filename, ".json")
				data[key] = jsonObj
			}
		}
	}
	return data
}

// generateFullHTML 生成完整的自包含HTML
func (h *htmlGeneratorImpl) generateFullHTML(data map[string]interface{}) string {
	// 将数据转换为JSON字符串
	jsonBytes, _ := json.Marshal(data)
	jsonStr := string(jsonBytes)
	
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GatTrace 系统信息报告</title>
    <style>
%s
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🔍 GatTrace 系统信息报告</h1>
            <div class="meta-info" id="meta-info"></div>
        </header>
        
        <nav class="navigation">
            <button class="nav-btn active" data-tab="overview">📊 概览</button>
            <button class="nav-btn" data-tab="network">🌐 网络</button>
            <button class="nav-btn" data-tab="process">⚙️ 进程</button>
            <button class="nav-btn" data-tab="user">👤 用户</button>
            <button class="nav-btn" data-tab="persistence">🔄 持久化</button>
            <button class="nav-btn" data-tab="filesystem">📁 文件系统</button>
            <button class="nav-btn" data-tab="security">🔒 安全</button>
            <button class="nav-btn" data-tab="system">💻 系统</button>
        </nav>
        
        <main class="content">
            <div id="overview" class="tab-content active"></div>
            <div id="network" class="tab-content"></div>
            <div id="process" class="tab-content"></div>
            <div id="user" class="tab-content"></div>
            <div id="persistence" class="tab-content"></div>
            <div id="filesystem" class="tab-content"></div>
            <div id="security" class="tab-content"></div>
            <div id="system" class="tab-content"></div>
        </main>
        
        <footer class="footer">
            <p>GatTrace 系统信息采集工具 v1.0.0</p>
        </footer>
    </div>
    
    <script>
// 硬编码的采集数据
const DATA = %s;

class GatTraceReport {
    constructor() {
        this.data = DATA;
        this.init();
    }
    
    init() {
        this.renderMeta();
        this.renderOverview();
        this.setupNavigation();
    }
    
    setupNavigation() {
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                e.target.classList.add('active');
                const tab = e.target.dataset.tab;
                document.getElementById(tab).classList.add('active');
                this.renderTab(tab);
            });
        });
    }
    
    renderMeta() {
        const meta = this.data.meta?.metadata || {};
        document.getElementById('meta-info').innerHTML = 
            '<span>主机: ' + (meta.hostname || '未知') + '</span>' +
            '<span>平台: ' + (meta.platform || '未知') + '</span>' +
            '<span>采集时间: ' + this.formatTime(meta.collected_at) + '</span>' +
            '<span>版本: ' + (meta.collector_version || '未知') + '</span>';
    }
    
    renderOverview() {
        const net = this.data.network || {};
        const proc = this.data.process || {};
        const usr = this.data.user || {};
        const pers = this.data.persistence || {};
        
        document.getElementById('overview').innerHTML = 
            '<div class="overview-grid">' +
            '<div class="card"><h3>🌐 网络</h3><p>接口: ' + (net.interfaces?.length || 0) + '</p><p>连接: ' + (net.connections?.length || 0) + '</p></div>' +
            '<div class="card"><h3>⚙️ 进程</h3><p>运行中: ' + (proc.processes?.length || 0) + '</p></div>' +
            '<div class="card"><h3>👤 用户</h3><p>当前用户: ' + (usr.current_users?.length || 0) + '</p><p>登录记录: ' + (usr.recent_logins?.length || 0) + '</p></div>' +
            '<div class="card"><h3>🔄 持久化</h3><p>项目: ' + (pers.items?.length || 0) + '</p></div>' +
            '</div>';
    }
    
    renderTab(tab) {
        switch(tab) {
            case 'network': this.renderNetwork(); break;
            case 'process': this.renderProcess(); break;
            case 'user': this.renderUser(); break;
            case 'persistence': this.renderPersistence(); break;
            case 'filesystem': this.renderFilesystem(); break;
            case 'security': this.renderSecurity(); break;
            case 'system': this.renderSystem(); break;
        }
    }
    
    renderNetwork() {
        const net = this.data.network || {};
        let html = '<h2>网络接口</h2>';
        
        if (net.interfaces?.length) {
            html += '<div class="table-wrapper"><table class="data-table sortable"><thead><tr><th data-sort="string">名称 ⇅</th><th data-sort="string">IP地址 ⇅</th><th data-sort="string">MAC ⇅</th><th data-sort="string">状态 ⇅</th><th data-sort="number">MTU ⇅</th></tr></thead><tbody>';
            net.interfaces.forEach(i => {
                html += '<tr><td>' + i.name + '</td><td>' + (i.ips?.join(', ') || '-') + '</td><td>' + (i.mac || '-') + '</td><td>' + (i.status || '-') + '</td><td>' + (i.mtu || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        
        html += '<h2>网络连接</h2>';
        if (net.connections?.length) {
            html += '<div class="filter-bar"><input type="text" id="conn-filter" placeholder="搜索连接..." onkeyup="report.filterTable(\'conn-table\', this.value)"></div>';
            html += '<div class="table-wrapper"><table class="data-table sortable" id="conn-table"><thead><tr><th data-sort="string">本地地址 ⇅</th><th data-sort="string">远程地址 ⇅</th><th data-sort="string">状态 ⇅</th><th data-sort="number">PID ⇅</th><th data-sort="string">进程 ⇅</th><th data-sort="string">协议 ⇅</th></tr></thead><tbody>';
            net.connections.forEach(c => {
                const pidLink = '<a href="#" class="pid-link" onclick="report.jumpToProcess(' + c.pid + '); return false;">' + c.pid + '</a>';
                html += '<tr><td>' + c.local_addr + '</td><td>' + c.remote_addr + '</td><td><span class="status-' + (c.state?.toLowerCase() || 'unknown') + '">' + (c.state || '-') + '</span></td><td>' + pidLink + '</td><td>' + (c.process || '-') + '</td><td>' + (c.protocol === '1' ? 'TCP' : 'UDP') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        
        document.getElementById('network').innerHTML = html;
        this.initSortable();
    }
    
    renderProcess() {
        const proc = this.data.process || {};
        let html = '<h2>运行进程</h2>';
        
        if (proc.processes?.length) {
            html += '<div class="filter-bar"><input type="text" id="proc-filter" placeholder="搜索进程..." onkeyup="report.filterTable(\'proc-table\', this.value)"></div>';
            html += '<div class="table-wrapper"><table class="data-table sortable" id="proc-table"><thead><tr><th data-sort="number">PID ⇅</th><th data-sort="number">PPID ⇅</th><th data-sort="string">名称 ⇅</th><th data-sort="string">用户 ⇅</th><th data-sort="string">可执行文件 ⇅</th><th data-sort="date">创建时间 ⇅</th><th data-sort="string">状态 ⇅</th></tr></thead><tbody>';
            proc.processes.forEach(p => {
                html += '<tr id="pid-' + p.pid + '"><td>' + p.pid + '</td><td>' + p.ppid + '</td><td>' + (p.name || '-') + '</td><td>' + (p.username || '-') + '</td><td class="path">' + (p.exe || '-') + '</td><td data-value="' + (p.create_time || '') + '">' + this.formatTime(p.create_time) + '</td><td>' + (p.status || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        
        document.getElementById('process').innerHTML = html;
        this.initSortable();
    }
    
    renderUser() {
        const usr = this.data.user || {};
        let html = '<h2>当前用户</h2>';
        
        if (usr.current_users?.length) {
            html += '<div class="table-wrapper"><table class="data-table sortable"><thead><tr><th data-sort="string">用户名 ⇅</th><th data-sort="string">UID ⇅</th><th data-sort="string">主目录 ⇅</th><th data-sort="string">Shell ⇅</th></tr></thead><tbody>';
            usr.current_users.forEach(u => {
                html += '<tr><td>' + u.username + '</td><td>' + u.uid + '</td><td>' + (u.home_dir || '-') + '</td><td>' + (u.shell || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        
        html += '<h2>登录记录</h2>';
        if (usr.recent_logins?.length) {
            html += '<div class="table-wrapper"><table class="data-table sortable"><thead><tr><th data-sort="string">用户名 ⇅</th><th data-sort="string">终端 ⇅</th><th data-sort="string">主机 ⇅</th><th data-sort="date">登录时间 ⇅</th></tr></thead><tbody>';
            usr.recent_logins.forEach(l => {
                html += '<tr><td>' + l.username + '</td><td>' + (l.terminal || '-') + '</td><td>' + (l.host || '-') + '</td><td data-value="' + (l.login_time || '') + '">' + this.formatTime(l.login_time) + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        
        document.getElementById('user').innerHTML = html;
        this.initSortable();
    }
    
    renderPersistence() {
        const pers = this.data.persistence || {};
        let html = '<h2>持久化机制</h2>';
        
        if (pers.items?.length) {
            html += '<div class="table-wrapper"><table class="data-table sortable"><thead><tr><th data-sort="string">类型 ⇅</th><th data-sort="string">名称 ⇅</th><th data-sort="string">路径 ⇅</th><th data-sort="string">命令 ⇅</th><th data-sort="string">用户 ⇅</th><th data-sort="string">启用 ⇅</th></tr></thead><tbody>';
            pers.items.forEach(p => {
                html += '<tr><td>' + (p.type || '-') + '</td><td>' + (p.name || '-') + '</td><td class="path">' + (p.path || '-') + '</td><td>' + (p.command || '-') + '</td><td>' + (p.user || '-') + '</td><td>' + (p.enabled ? '是' : '否') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        } else {
            html += '<p class="no-data">暂无持久化数据</p>';
        }
        
        document.getElementById('persistence').innerHTML = html;
        this.initSortable();
    }
    
    renderFilesystem() {
        const fs = this.data.filesystem || {};
        let html = '<h2>最近文件</h2>';
        
        if (fs.recent_files?.length) {
            html += '<div class="table-wrapper"><table class="data-table sortable"><thead><tr><th data-sort="string">路径 ⇅</th><th data-sort="number">大小 ⇅</th><th data-sort="date">修改时间 ⇅</th><th data-sort="string">所有者 ⇅</th><th data-sort="string">权限 ⇅</th></tr></thead><tbody>';
            fs.recent_files.forEach(f => {
                html += '<tr><td class="path">' + f.path + '</td><td data-value="' + (f.size || 0) + '">' + this.formatSize(f.size) + '</td><td data-value="' + (f.mod_time || '') + '">' + this.formatTime(f.mod_time) + '</td><td>' + (f.owner || '-') + '</td><td>' + (f.mode || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        } else {
            html += '<p class="no-data">暂无文件系统数据</p>';
        }
        
        document.getElementById('filesystem').innerHTML = html;
        this.initSortable();
    }
    
    renderSecurity() {
        const sec = this.data.security || {};
        let html = '<h2>安全日志</h2>';
        
        if (sec.entries?.length) {
            html += '<div class="filter-bar"><input type="text" id="sec-filter" placeholder="搜索安全日志..." onkeyup="report.filterTable(\'sec-table\', this.value)"></div>';
            html += '<div class="table-wrapper"><table class="data-table sortable" id="sec-table"><thead><tr><th style="width:150px" data-sort="date">时间 ⇅</th><th style="width:100px" data-sort="string">用户 ⇅</th><th style="width:120px" data-sort="string">事件类型 ⇅</th><th style="width:80px" data-sort="number">事件ID ⇅</th><th data-sort="string">事件内容 ⇅</th></tr></thead><tbody>';
            sec.entries.forEach(e => {
                const user = e.details?.user || '-';
                const eventType = e.details?.event_type || e.details?.category || '-';
                const eventId = e.event_id || '-';
                html += '<tr><td data-value="' + (e.timestamp || '') + '">' + this.formatTime(e.timestamp) + '</td><td>' + user + '</td><td>' + eventType + '</td><td>' + eventId + '</td><td class="event-content">' + (e.message || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        } else {
            html += '<p class="no-data">暂无安全日志</p>';
        }
        
        document.getElementById('security').innerHTML = html;
        this.initSortable();
    }
    
    renderSystem() {
        const sys = this.data.system || {};
        const state = this.data.system_state || {};
        let html = '<h2>系统信息</h2>';
        
        html += '<div class="info-grid">';
        html += '<div class="info-item"><label>启动时间:</label><span>' + this.formatTime(sys.boot_time) + '</span></div>';
        html += '<div class="info-item"><label>运行时间:</label><span>' + this.formatDuration(sys.uptime) + '</span></div>';
        if (sys.ntp_status) {
            html += '<div class="info-item"><label>NTP同步:</label><span>' + (sys.ntp_status.synchronized ? '已同步' : '未同步') + '</span></div>';
        }
        html += '</div>';
        
        if (sys.kernel_modules?.length) {
            html += '<h2>内核模块</h2>';
            html += '<div class="table-wrapper"><table class="data-table sortable"><thead><tr><th data-sort="string">名称 ⇅</th><th data-sort="string">路径 ⇅</th><th data-sort="string">版本 ⇅</th><th data-sort="string">描述 ⇅</th></tr></thead><tbody>';
            sys.kernel_modules.forEach(m => {
                html += '<tr><td>' + m.name + '</td><td class="path">' + (m.path || '-') + '</td><td>' + (m.version || '-') + '</td><td>' + (m.description || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        
        document.getElementById('system').innerHTML = html;
    }
    
    jumpToProcess(pid) {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelector('[data-tab="process"]').classList.add('active');
        document.getElementById('process').classList.add('active');
        this.renderProcess();
        setTimeout(() => {
            const row = document.getElementById('pid-' + pid);
            if (row) {
                row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                row.classList.add('highlight');
                setTimeout(() => row.classList.remove('highlight'), 2000);
            }
        }, 100);
    }
    
    filterTable(tableId, filter) {
        const table = document.getElementById(tableId);
        if (!table) return;
        const rows = table.querySelectorAll('tbody tr');
        const term = filter.toLowerCase();
        rows.forEach(row => {
            row.style.display = row.textContent.toLowerCase().includes(term) ? '' : 'none';
        });
    }
    
    formatTime(t) {
        if (!t) return '-';
        try {
            return new Date(t).toLocaleString('zh-CN');
        } catch { return t; }
    }
    
    formatSize(bytes) {
        if (!bytes) return '-';
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
        return bytes.toFixed(1) + ' ' + units[i];
    }
    
    formatDuration(ns) {
        if (!ns) return '-';
        const sec = Math.floor(ns / 1000000000);
        const d = Math.floor(sec / 86400);
        const h = Math.floor((sec %% 86400) / 3600);
        const m = Math.floor((sec %% 3600) / 60);
        return d + '天 ' + h + '小时 ' + m + '分钟';
    }
    
    initSortable() {
        document.querySelectorAll('.data-table.sortable').forEach(table => {
            const headers = table.querySelectorAll('th[data-sort]');
            headers.forEach((th, colIndex) => {
                if (th.dataset.sortInit) return;
                th.dataset.sortInit = 'true';
                th.style.cursor = 'pointer';
                th.addEventListener('click', () => {
                    const sortType = th.dataset.sort;
                    const ascending = th.dataset.order !== 'asc';
                    th.dataset.order = ascending ? 'asc' : 'desc';
                    headers.forEach(h => {
                        if (h !== th) h.dataset.order = '';
                        h.classList.remove('sort-asc', 'sort-desc');
                    });
                    th.classList.add(ascending ? 'sort-asc' : 'sort-desc');
                    this.sortTable(table, colIndex, sortType, ascending);
                });
            });
        });
    }
    
    sortTable(table, colIndex, sortType, ascending) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort((a, b) => {
            const cellA = a.cells[colIndex];
            const cellB = b.cells[colIndex];
            let valA = cellA.dataset.value || cellA.textContent.trim();
            let valB = cellB.dataset.value || cellB.textContent.trim();
            let cmp = 0;
            if (sortType === 'number') {
                cmp = (parseFloat(valA) || 0) - (parseFloat(valB) || 0);
            } else if (sortType === 'date') {
                cmp = new Date(valA || 0) - new Date(valB || 0);
            } else {
                cmp = valA.localeCompare(valB, 'zh-CN');
            }
            return ascending ? cmp : -cmp;
        });
        rows.forEach(row => tbody.appendChild(row));
    }
}

let report;
document.addEventListener('DOMContentLoaded', () => { report = new GatTraceReport(); });
    </script>
</body>
</html>`, h.getCSS(), jsonStr)
}

// getCSS 返回内联CSS样式
func (h *htmlGeneratorImpl) getCSS() string {
	return `* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { width: 100%; height: 100%; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }
.container { width: 100%; max-width: 100%; margin: 0 auto; padding: 20px; box-sizing: border-box; }
.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }
.header h1 { font-size: 28px; margin-bottom: 15px; }
.meta-info { display: flex; flex-wrap: wrap; gap: 20px; font-size: 14px; opacity: 0.9; }
.meta-info span { background: rgba(255,255,255,0.2); padding: 5px 12px; border-radius: 20px; }
.navigation { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
.nav-btn { padding: 10px 20px; border: none; background: white; border-radius: 8px; cursor: pointer; font-size: 14px; transition: all 0.3s; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.nav-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
.nav-btn.active { background: #667eea; color: white; }
.content { background: white; border-radius: 12px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); min-height: 500px; width: 100%; box-sizing: border-box; overflow-x: auto; }
.tab-content { display: none; width: 100%; }
.tab-content.active { display: block; }
.overview-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
.card { background: linear-gradient(135deg, #f5f7fa 0%, #e4e8ec 100%); padding: 25px; border-radius: 12px; border-left: 4px solid #667eea; }
.card h3 { margin-bottom: 15px; color: #667eea; }
.card p { margin: 8px 0; font-size: 16px; }
h2 { color: #333; margin: 25px 0 15px; padding-bottom: 10px; border-bottom: 2px solid #eee; }
.table-wrapper { width: 100%; overflow-x: auto; margin: 15px 0; -webkit-overflow-scrolling: touch; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }
.data-table th { background: #667eea; color: white; padding: 12px 10px; text-align: left; font-weight: 500; overflow: hidden; text-overflow: ellipsis; }
.data-table.sortable th[data-sort] { cursor: pointer; user-select: none; transition: background 0.2s; }
.data-table.sortable th[data-sort]:hover { background: #5a6fd6; }
.data-table.sortable th.sort-asc, .data-table.sortable th.sort-desc { background: #4a5fc6; }
.data-table.sortable th.sort-asc::after { content: ' ▲'; font-size: 10px; }
.data-table.sortable th.sort-desc::after { content: ' ▼'; font-size: 10px; }
.data-table td { padding: 10px; border-bottom: 1px solid #eee; word-wrap: break-word; overflow-wrap: break-word; overflow: hidden; text-overflow: ellipsis; }
.data-table tr:hover { background: #f8f9ff; }
.data-table tr.highlight { background: #fff3cd !important; animation: pulse 0.5s ease-in-out; }
@keyframes pulse { 0%, 100% { background: #fff3cd; } 50% { background: #ffe69c; } }
.path { font-family: monospace; font-size: 12px; word-break: break-all; white-space: normal; }
.pid-link { color: #667eea; text-decoration: none; font-weight: 600; }
.pid-link:hover { text-decoration: underline; }
.filter-bar { margin-bottom: 15px; }
.filter-bar input { padding: 10px 15px; border: 1px solid #ddd; border-radius: 8px; width: 100%; max-width: 400px; font-size: 14px; }
.filter-bar input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.1); }
.status-established, .status-listen { color: #28a745; font-weight: 500; }
.status-close_wait, .status-time_wait { color: #ffc107; }
.status-closed { color: #dc3545; }
.level-error, .level-critical { color: #dc3545; font-weight: 600; }
.level-warning { color: #ffc107; }
.level-info { color: #17a2b8; }
.info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
.info-item { background: #f8f9fa; padding: 15px; border-radius: 8px; }
.info-item label { display: block; font-size: 12px; color: #666; margin-bottom: 5px; }
.info-item span { font-size: 16px; font-weight: 500; word-break: break-all; }
.no-data { text-align: center; padding: 40px; color: #999; font-size: 16px; }
.footer { text-align: center; padding: 20px; color: #666; font-size: 14px; margin-top: 20px; }`
}





// generateManifest 生成清单文件
func (a *App) generateManifest(outputDir string, verbose bool) error {
	// 简单的清单文件生成
	manifest := map[string]interface{}{
		"metadata": map[string]interface{}{
			"session_id":        a.sessionManager.GetSessionID(),
			"hostname":          a.sessionManager.GetHostname(),
			"platform":          a.sessionManager.GetPlatform(),
			"generated_at":      time.Now().UTC().Format(time.RFC3339),
			"collector_version": a.version,
		},
		"files": []map[string]interface{}{},
	}

	// 扫描输出目录中的文件
	files, err := os.ReadDir(outputDir)
	if err != nil {
		return fmt.Errorf("failed to read output directory: %w", err)
	}

	var fileList []map[string]interface{}
	for _, file := range files {
		if file.IsDir() || file.Name() == "manifest.json" {
			continue
		}

		filePath := filepath.Join(outputDir, file.Name())
		fileInfo, err := file.Info()
		if err != nil {
			continue
		}

		// 可以在这里计算文件哈希，但为了简化暂时跳过
		_ = filePath

		fileList = append(fileList, map[string]interface{}{
			"filename": file.Name(),
			"size":     fileInfo.Size(),
			"modified": fileInfo.ModTime().UTC().Format(time.RFC3339),
		})
	}

	manifest["files"] = fileList
	return a.writeJSONFile(outputDir, "manifest.json", manifest)
}

// generateErrorReport 生成错误报告
func (a *App) generateErrorReport(outputDir string, verbose bool) error {
	errors := a.errorManager.GetErrors()
	if len(errors) == 0 {
		return nil // 没有错误，不生成报告
	}

	errorReport := map[string]interface{}{
		"metadata": map[string]interface{}{
			"session_id":   a.sessionManager.GetSessionID(),
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"total_errors": len(errors),
		},
		"errors": errors,
	}

	return a.writeJSONFile(outputDir, "errors.json", errorReport)
}

// generateSystemStateReport 生成系统状态报告
func (a *App) generateSystemStateReport(outputDir string, verbose bool) error {
	if a.systemMonitor == nil {
		return fmt.Errorf("system monitor not initialized")
	}

	comparison, err := a.systemMonitor.CompareSnapshots()
	if err != nil {
		return fmt.Errorf("failed to compare snapshots: %w", err)
	}

	// 创建系统状态报告
	stateReport := map[string]interface{}{
		"metadata": map[string]interface{}{
			"session_id":   a.sessionManager.GetSessionID(),
			"hostname":     a.sessionManager.GetHostname(),
			"platform":     a.sessionManager.GetPlatform(),
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"collector_version": a.version,
		},
		"comparison": comparison,
	}

	// 写入系统状态报告
	if err := a.writeJSONFile(outputDir, "system_state.json", stateReport); err != nil {
		return fmt.Errorf("failed to write system state report: %w", err)
	}

	// 如果有变更，记录警告
	if comparison.HasChanges {
		a.errorManager.RecordError(&CollectionError{
			Module:    "system_monitor",
			Operation: "state_comparison",
			Err:       fmt.Errorf("system state changes detected during collection"),
			Severity:  SeverityWarning,
		})
		
		if verbose {
			fmt.Printf("警告: 检测到系统状态变更:\n")
			if len(comparison.ProcessChanges.Added) > 0 {
				fmt.Printf("  - 新增进程: %d 个\n", len(comparison.ProcessChanges.Added))
			}
			if len(comparison.ProcessChanges.Removed) > 0 {
				fmt.Printf("  - 删除进程: %d 个\n", len(comparison.ProcessChanges.Removed))
			}
			if len(comparison.NetworkChanges.Added) > 0 {
				fmt.Printf("  - 新增网络端口: %d 个\n", len(comparison.NetworkChanges.Added))
			}
			if len(comparison.NetworkChanges.Removed) > 0 {
				fmt.Printf("  - 删除网络端口: %d 个\n", len(comparison.NetworkChanges.Removed))
			}
			if len(comparison.FileChanges.Modified) > 0 {
				fmt.Printf("  - 修改文件: %d 个\n", len(comparison.FileChanges.Modified))
			}
			if comparison.WorkingDirChanged {
				fmt.Printf("  - 工作目录已变更\n")
			}
		}
	} else if verbose {
		fmt.Println("✓ 系统状态检查: 未检测到变更")
	}

	return nil
}