package collectors

import (
	"context"
	"fmt"

	gopsutil_net "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"GatTrace/internal/core"
)

// NetworkCollector 网络信息采集器
type NetworkCollector struct {
	adapter core.PlatformAdapter
}

// NewNetworkCollector 创建网络信息采集器
func NewNetworkCollector(adapter core.PlatformAdapter) *NetworkCollector {
	return &NetworkCollector{
		adapter: adapter,
	}
}

// Name 返回采集器名称
func (c *NetworkCollector) Name() string {
	return "network"
}

// RequiresPrivileges 返回是否需要特权
func (c *NetworkCollector) RequiresPrivileges() bool {
	return false // 基础网络信息不需要特权
}

// SupportedPlatforms 返回支持的平台
func (c *NetworkCollector) SupportedPlatforms() []core.Platform {
	return []core.Platform{
		core.PlatformWindows,
		core.PlatformLinux,
		core.PlatformDarwin,
	}
}

// Collect 执行网络信息采集
func (c *NetworkCollector) Collect(ctx context.Context) (*core.CollectionResult, error) {
	var errors []core.CollectionError

	// 使用平台适配器获取网络信息
	networkInfo, err := c.adapter.GetNetworkInfo()
	if err != nil {
		collectionErr := core.CollectionError{
			Module:    "network",
			Operation: "GetNetworkInfo",
			Err:       err,
			Severity:  core.SeverityError,
		}
		errors = append(errors, collectionErr)
		
		// 如果平台适配器失败，尝试使用通用方法
		networkInfo, err = c.collectGenericNetworkInfo()
		if err != nil {
			collectionErr := core.CollectionError{
				Module:    "network",
				Operation: "collectGenericNetworkInfo",
				Err:       err,
				Severity:  core.SeverityCritical,
			}
			errors = append(errors, collectionErr)
			return &core.CollectionResult{Data: nil, Errors: errors}, err
		}
	}

	return &core.CollectionResult{
		Data:   networkInfo,
		Errors: errors,
	}, nil
}

// collectGenericNetworkInfo 使用通用方法采集网络信息
func (c *NetworkCollector) collectGenericNetworkInfo() (*core.NetworkInfo, error) {
	// 创建基础元数据
	sessionID, _ := core.NewSessionID()
	hostname, _ := core.GetSystemHostname()
	platform := core.GetCurrentPlatform().String()
	version := "1.0.0" // 使用硬编码版本，稍后从配置获取
	
	metadata := core.NewMetadata(sessionID, hostname, platform, version)

	networkInfo := &core.NetworkInfo{
		Metadata:    metadata,
		Interfaces:  []core.NetworkInterface{},
		Routes:      []core.Route{},
		DNS:         core.DNSConfig{},
		Connections: []core.Connection{},
		Listeners:   []core.Listener{},
	}

	// 获取网络接口信息
	interfaces, err := c.getNetworkInterfaces()
	if err == nil {
		networkInfo.Interfaces = interfaces
	}

	// 获取路由信息
	routes, err := c.getRoutes()
	if err == nil {
		networkInfo.Routes = routes
	}

	// 获取DNS配置
	dns, err := c.getDNSConfig()
	if err == nil {
		networkInfo.DNS = dns
	}

	// 获取网络连接
	connections, err := c.getConnections()
	if err == nil {
		networkInfo.Connections = connections
	}

	// 获取监听端口
	listeners, err := c.getListeners()
	if err == nil {
		networkInfo.Listeners = listeners
	}

	return networkInfo, nil
}

// getNetworkInterfaces 获取网络接口信息
func (c *NetworkCollector) getNetworkInterfaces() ([]core.NetworkInterface, error) {
	interfaces, err := gopsutil_net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var result []core.NetworkInterface
	for _, iface := range interfaces {
		// 获取接口统计信息
		stats, err := gopsutil_net.IOCounters(true)
		if err != nil {
			continue
		}

		var ifaceStats *gopsutil_net.IOCountersStat
		for _, stat := range stats {
			if stat.Name == iface.Name {
				ifaceStats = &stat
				break
			}
		}

		// 获取IP地址
		var ips []string
		for _, addr := range iface.Addrs {
			ips = append(ips, addr.Addr)
		}

		// 获取接口标志
		var flags []string
		// gopsutil 返回的 Flags 是字符串切片，直接使用
		flags = iface.Flags

		netInterface := core.NetworkInterface{
			Name:   iface.Name,
			IPs:    ips,
			MAC:    iface.HardwareAddr,
			Status: "unknown",
			MTU:    int(iface.MTU),
			Flags:  flags,
		}

		// 根据统计信息判断接口状态
		if ifaceStats != nil {
			if ifaceStats.BytesRecv > 0 || ifaceStats.BytesSent > 0 {
				netInterface.Status = "up"
			} else {
				netInterface.Status = "down"
			}
		}

		result = append(result, netInterface)
	}

	return result, nil
}

// getRoutes 获取路由表信息
func (c *NetworkCollector) getRoutes() ([]core.Route, error) {
	// 使用系统命令获取路由信息
	// 这里简化实现，实际应该根据平台使用不同的方法
	return []core.Route{}, nil
}

// getDNSConfig 获取DNS配置
func (c *NetworkCollector) getDNSConfig() (core.DNSConfig, error) {
	config := core.DNSConfig{
		Servers:    []string{},
		SearchList: []string{},
		HostsFile:  make(map[string]string),
	}

	// 尝试读取系统DNS配置
	// 这里简化实现，实际应该根据平台读取不同的配置文件
	return config, nil
}

// getConnections 获取网络连接信息
func (c *NetworkCollector) getConnections() ([]core.Connection, error) {
	connections, err := gopsutil_net.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	var result []core.Connection
	for _, conn := range connections {
		connection := core.Connection{
			LocalAddr:  fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port),
			State:      conn.Status,
			PID:        conn.Pid,
			Protocol:   getProtocolString(conn.Type),
		}

		// 获取进程名称
		if conn.Pid > 0 {
			if proc, err := process.NewProcess(conn.Pid); err == nil {
				if name, err := proc.Name(); err == nil {
					connection.Process = name
				}
			}
		}

		result = append(result, connection)
	}

	return result, nil
}

// getListeners 获取监听端口信息
func (c *NetworkCollector) getListeners() ([]core.Listener, error) {
	connections, err := gopsutil_net.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	var result []core.Listener
	for _, conn := range connections {
		// 只处理监听状态的连接
		if conn.Status != "LISTEN" {
			continue
		}

		listener := core.Listener{
			LocalAddr: fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			PID:       conn.Pid,
			Protocol:  getProtocolString(conn.Type),
		}

		// 获取进程名称
		if conn.Pid > 0 {
			if proc, err := process.NewProcess(conn.Pid); err == nil {
				if name, err := proc.Name(); err == nil {
					listener.Process = name
				}
			}
		}

		result = append(result, listener)
	}

	return result, nil
}
// getProtocolString 将协议类型转换为字符串
func getProtocolString(protocolType uint32) string {
	switch protocolType {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	case 3:
		return "tcp6"
	case 4:
		return "udp6"
	default:
		return "unknown"
	}
}