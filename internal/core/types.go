package core

import (
	"time"
)

// Metadata 通用元数据结构
type Metadata struct {
	SessionID        string    `json:"session_id"`
	Hostname         string    `json:"hostname"`
	Platform         string    `json:"platform"`
	CollectedAt      time.Time `json:"collected_at"`
	CollectorVersion string    `json:"collector_version"`
}

// NewMetadata 创建新的元数据，确保时间戳标准化
func NewMetadata(sessionID, hostname, platform, version string) Metadata {
	return Metadata{
		SessionID:        sessionID,
		Hostname:         hostname,
		Platform:         platform,
		CollectedAt:      NormalizeTimestamp(time.Now()),
		CollectorVersion: version,
	}
}

// NetworkInterface 网络接口信息
type NetworkInterface struct {
	Name   string   `json:"name"`
	IPs    []string `json:"ips"`
	MAC    string   `json:"mac"`
	Status string   `json:"status"`
	MTU    int      `json:"mtu"`
	Flags  []string `json:"flags"`
}

// Route 路由信息
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

// DNSConfig DNS 配置
type DNSConfig struct {
	Servers    []string          `json:"servers"`
	SearchList []string          `json:"search_list"`
	HostsFile  map[string]string `json:"hosts_file"`
}

// Connection 网络连接
type Connection struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        int32  `json:"pid"`
	Process    string `json:"process"`
	Protocol   string `json:"protocol"`
}

// Listener 监听端口
type Listener struct {
	LocalAddr string `json:"local_addr"`
	PID       int32  `json:"pid"`
	Process   string `json:"process"`
	Protocol  string `json:"protocol"`
}

// NetworkInfo 网络信息结构
type NetworkInfo struct {
	Metadata    Metadata           `json:"metadata"`
	Interfaces  []NetworkInterface `json:"interfaces"`
	Routes      []Route            `json:"routes"`
	DNS         DNSConfig          `json:"dns"`
	Connections []Connection       `json:"connections"`
	Listeners   []Listener         `json:"listeners"`
}

// Process 进程信息
type Process struct {
	PID        int32     `json:"pid"`
	PPID       int32     `json:"ppid"`
	Name       string    `json:"name"`
	Cmdline    []string  `json:"cmdline"`
	Exe        string    `json:"exe"`
	Cwd        string    `json:"cwd"`
	Username   string    `json:"username"`
	CreateTime time.Time `json:"create_time"`
	Status     string    `json:"status"`
	ExeHash    string    `json:"exe_hash"`
	Signature  string    `json:"signature,omitempty"` // Windows only
}

// ProcessInfo 进程信息结构
type ProcessInfo struct {
	Metadata  Metadata  `json:"metadata"`
	Processes []Process `json:"processes"`
}

// User 用户信息
type User struct {
	Username  string    `json:"username"`
	UID       string    `json:"uid"`
	GID       string    `json:"gid"`
	HomeDir   string    `json:"home_dir"`
	Shell     string    `json:"shell"`
	LastLogin time.Time `json:"last_login"`
	IsActive  bool      `json:"is_active"`
}

// LoginRecord 登录记录
type LoginRecord struct {
	Username   string     `json:"username"`
	Terminal   string     `json:"terminal"`
	Host       string     `json:"host"`
	LoginTime  time.Time  `json:"login_time"`
	LogoutTime *time.Time `json:"logout_time,omitempty"`
	Status     string     `json:"status"`
}

// Privilege 权限信息
type Privilege struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
	Sudo     bool     `json:"sudo"`
	Admin    bool     `json:"admin"`
}

// SSHKey SSH 密钥信息
type SSHKey struct {
	Username string `json:"username"`
	KeyType  string `json:"key_type"`
	KeyHash  string `json:"key_hash"`
	Comment  string `json:"comment"`
	FilePath string `json:"file_path"`
}

// UserInfo 用户信息结构
type UserInfo struct {
	Metadata     Metadata      `json:"metadata"`
	CurrentUsers []User        `json:"current_users"`
	RecentLogins []LoginRecord `json:"recent_logins"`
	Privileges   []Privilege   `json:"privileges"`
	SSHKeys      []SSHKey      `json:"ssh_keys"`
}

// PersistenceItem 持久化项目
type PersistenceItem struct {
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Command    string            `json:"command"`
	User       string            `json:"user"`
	Enabled    bool              `json:"enabled"`
	Properties map[string]string `json:"properties"`
}

// PersistenceInfo 持久化信息结构
type PersistenceInfo struct {
	Metadata Metadata          `json:"metadata"`
	Items    []PersistenceItem `json:"items"`
}

// FileInfo 文件信息
type FileInfo struct {
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	ModTime    time.Time `json:"mod_time"`
	AccessTime time.Time `json:"access_time"`
	ChangeTime time.Time `json:"change_time"`
	Hash       string    `json:"hash"`
	Owner      string    `json:"owner"`
	Group      string    `json:"group"`
}

// FileSystemInfo 文件系统信息结构
type FileSystemInfo struct {
	Metadata    Metadata   `json:"metadata"`
	RecentFiles []FileInfo `json:"recent_files"`
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Level     string            `json:"level"`
	Source    string            `json:"source"`
	EventID   string            `json:"event_id"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details"`
}

// SecurityLogs 安全日志结构
type SecurityLogs struct {
	Metadata Metadata   `json:"metadata"`
	Entries  []LogEntry `json:"entries"`
}

// NTPStatus NTP同步状态
type NTPStatus struct {
	Synchronized bool          `json:"synchronized"`
	Server       string        `json:"server"`
	LastSync     time.Time     `json:"last_sync"`
	Offset       time.Duration `json:"offset"`
	Error        string        `json:"error,omitempty"`
}

// KernelModule 内核模块信息
type KernelModule struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Size        int64  `json:"size,omitempty"`
	Signed      bool   `json:"signed,omitempty"`
}

// SystemIntegrity 系统完整性信息
type SystemIntegrity struct {
	Status      string    `json:"status"`
	LastCheck   time.Time `json:"last_check"`
	Issues      []string  `json:"issues"`
	CheckMethod string    `json:"check_method"`
	Error       string    `json:"error,omitempty"`
}

// SystemStatus 系统状态结构
type SystemStatus struct {
	Metadata      Metadata         `json:"metadata"`
	BootTime      time.Time        `json:"boot_time"`
	Uptime        time.Duration    `json:"uptime"`
	NTPStatus     *NTPStatus       `json:"ntp_status"`
	KernelModules []KernelModule   `json:"kernel_modules"`
	Integrity     *SystemIntegrity `json:"integrity"`
}

// SystemInfo 系统信息结构
type SystemInfo struct {
	Metadata       Metadata          `json:"metadata"`
	BootTime       time.Time         `json:"boot_time"`
	Uptime         time.Duration     `json:"uptime"`
	SystemTime     time.Time         `json:"system_time"`
	NTPStatus      string            `json:"ntp_status"`
	KernelModules  []string          `json:"kernel_modules"`
	IntegrityCheck map[string]string `json:"integrity_check"`
}

// ErrorInfo 错误信息
type ErrorInfo struct {
	Timestamp time.Time `json:"timestamp"`
	Module    string    `json:"module"`
	Error     string    `json:"error"`
	Severity  string    `json:"severity"`
}

// ErrorReport 错误报告结构
type ErrorReport struct {
	Metadata Metadata    `json:"metadata"`
	Errors   []ErrorInfo `json:"errors"`
}

// ManifestEntry 清单条目
type ManifestEntry struct {
	Filename string `json:"filename"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
}

// Manifest 清单结构
type Manifest struct {
	Metadata     Metadata        `json:"metadata"`
	Files        []ManifestEntry `json:"files"`
	ManifestHash string          `json:"manifest_hash"`
}

// SystemStateReport 系统状态报告结构
type SystemStateReport struct {
	Metadata   Metadata               `json:"metadata"`
	Comparison *SystemStateComparison `json:"comparison"`
}
