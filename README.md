# GatTrace

**跨平台应急响应系统信息采集工具** v1.1.0

GatTrace 是一个专为应急响应和数字取证设计的系统信息采集工具，支持 Windows、Linux 和 macOS 平台。它能够安全、高效地收集系统信息，生成结构化报告，帮助安全分析师快速了解系统状态。

## ✨ 主要特性

- 🔒 **只读操作** - 不修改系统状态，确保取证完整性
- 🌐 **跨平台支持** - Windows、Linux、macOS 全平台兼容
- 📊 **结构化输出** - JSON 格式数据，便于后续分析
- 🌐 **交互式报告** - HTML 报告，支持搜索、排序、过滤
- 🛡️ **权限检测** - 自动检测管理员权限并给出提示
- 🔐 **完整性保证** - SHA256 校验，确保数据完整性
- ⚡ **高性能** - 并发采集，快速完成信息收集
- 📝 **详细日志** - 完整的错误报告和执行日志

## 🆕 v1.1.0 更新内容

- 🔧 **权限检测增强** - 程序启动时检测管理员权限并给出明确提示
- 📋 **Windows 安全日志改进** - 修复 Security 日志收集问题，支持完整的事件内容
- 🗂️ **文件系统优化** - 使用白名单模式过滤文件类型，提升扫描效率
- 🕐 **时区修复** - 修复日志时间显示为本地时间
- 🐛 **Bug 修复** - 修复多个平台兼容性问题

## 📁 项目结构

```
GatTrace/
├── cmd/                     # 应用程序入口点
│   └── GatTrace/           # 主程序入口
│       └── main.go         # 程序主入口文件
├── internal/               # 内部包（不对外暴露）
│   ├── collectors/         # 数据采集器
│   │   ├── network.go     # 网络信息采集
│   │   ├── process.go     # 进程信息采集
│   │   ├── user.go        # 用户信息采集
│   │   ├── persistence.go # 持久化机制采集
│   │   ├── filesystem.go  # 文件系统采集
│   │   ├── security.go    # 安全日志采集
│   │   └── system.go      # 系统状态采集
│   ├── core/              # 核心功能模块
│   │   ├── application.go # 应用程序主逻辑
│   │   ├── types.go       # 核心数据类型
│   │   ├── session.go     # 会话管理
│   │   ├── privilege.go   # 权限管理
│   │   └── error_manager.go # 错误管理
│   ├── output/            # 输出处理模块
│   │   ├── html.go        # HTML 报告生成
│   │   ├── json.go        # JSON 输出处理
│   │   └── manager.go     # 输出管理器
│   └── platform/          # 平台适配层
│       ├── windows.go     # Windows 平台适配
│       ├── linux.go       # Linux 平台适配
│       └── darwin.go      # macOS 平台适配
├── scripts/               # 构建和部署脚本
│   ├── build.sh          # Unix 系统构建脚本
│   ├── build.bat         # Windows 系统构建脚本
│   ├── release.sh        # 发布脚本
│   └── manual-build-guide.md # 手动构建指南（高级用户）
├── release/              # 编译输出目录
│   ├── GatTrace-*        # 各平台可执行文件
│   └── checksums.txt     # SHA256 校验和文件
├── BUILD_GUIDE.md        # 详细构建指南
├── go.mod               # Go 模块定义
├── go.sum               # 依赖校验文件
├── LICENSE              # 开源许可证
├── Makefile            # 构建配置文件
└── README.md           # 项目说明文档
```

### 📂 目录说明

| 目录/文件 | 作用 |
|-----------|------|
| `cmd/GatTrace/` | 程序入口点，包含 main 函数和命令行参数处理 |
| `internal/collectors/` | 各种数据采集器实现，负责收集不同类型的系统信息 |
| `internal/core/` | 核心业务逻辑，包括应用程序控制、会话管理、权限处理等 |
| `internal/output/` | 输出格式处理，支持 JSON 和 HTML 格式 |
| `internal/platform/` | 平台特定代码，处理不同操作系统的差异 |
| `scripts/` | 构建和部署脚本，支持跨平台编译 |
| `release/` | 编译后的可执行文件输出目录 |

### 📖 构建文档说明

- **BUILD_GUIDE.md**: 基础构建指南，适合大多数用户
- **scripts/manual-build-guide.md**: 详细的手动构建指南，包含高级构建选项、优化技巧和故障排除，适合需要深度定制构建过程的开发者

## 🚀 快速开始

### 下载安装

1. 从 [Releases](https://github.com/c0mpl1ng/GatTrace/releases) 页面下载对应平台的版本
2. 解压到目标目录
3. 运行程序

```bash
# Linux/macOS
./GatTrace --help

# Windows
GatTrace.exe --help
```

### 基本使用

```bash
# 收集系统信息到指定目录
GatTrace --output ./investigation-2024-01-04

# 静默模式运行
GatTrace --silent --output ./output

# 详细模式运行
GatTrace --verbose --output ./output

# 指定安全日志时间范围（Windows）
GatTrace --days 7 --output ./output
```

## 📋 采集内容

### 🌐 网络信息
- 网络接口配置（IP、MAC、状态）
- 活动连接和监听端口
- 连接与进程关联（PID 链接）

### 🔄 进程信息
- 运行中的进程列表
- 进程元数据（PID、PPID、用户、创建时间）
- 可执行文件路径和哈希
- 命令行参数

### 👤 用户和权限
- 当前登录用户信息
- 用户权限和组成员
- 最近登录记录

### 🔄 持久化机制
- 自启动项和服务
- 计划任务配置
- 系统服务状态

### 📁 文件系统
- 最近访问/修改的文件
- 文件元数据（大小、时间、权限）
- 文件哈希计算
- 数据量完全由时间范围参数控制（-d 参数）

### 🔒 安全日志
- **Windows**: Security、System、Application、Windows Defender 日志
- **Linux**: 系统日志 (/var/log)
- **macOS**: 统一日志系统
- 支持中文本地化显示
- 数据量完全由时间范围参数控制（-d 参数）

### ⚙️ 系统状态
- 系统启动时间和运行时间
- NTP 同步状态
- 内核模块信息

## 📊 输出格式

### JSON 数据文件
- `meta.json` - 采集元数据和会话信息
- `network.json` - 网络接口和连接信息
- `process.json` - 进程列表和详细信息
- `user.json` - 用户和登录信息
- `persistence.json` - 持久化机制
- `filesystem.json` - 文件系统信息
- `security.json` - 安全日志（支持中文）
- `system.json` - 系统状态信息
- `errors.json` - 错误报告
- `system_state.json` - 系统状态变更报告

### HTML 报告
- `index.html` - 交互式报告界面
- 支持表格排序（点击列标题）
- 支持搜索和过滤功能
- PID 链接跳转（网络连接 → 进程）
- 响应式设计，支持移动设备

### 完整性文件
- `manifest.json` - 文件清单和校验和

## 🔧 命令行选项

```
用法: GatTrace [选项]

选项:
  -o, --output DIR     输出目录 (默认: ./GatTrace-output-TIMESTAMP)
  -d, --days N         安全日志时间范围，天数 (默认: 7)
  -s, --silent         静默模式，减少输出信息
  -v, --verbose        详细模式，显示调试信息
  -h, --help          显示帮助信息
      --version       显示版本信息
```

## 🛡️ 安全考虑

### 权限要求
- **普通用户权限**: 可收集基本系统信息
- **管理员权限**: 可收集完整的系统信息和安全日志
  - Windows: 右键"以管理员身份运行"
  - Linux/macOS: 使用 `sudo ./GatTrace`

### 数据安全
- 所有操作都是只读的，不会修改系统状态
- 输出文件包含敏感系统信息，请妥善保管
- 建议在隔离环境中运行和分析
- 支持系统状态监控，检测采集过程中的变更

### 隐私保护
- 不收集文件内容，仅收集元数据
- 不记录用户密码或密钥内容
- 安全日志经过本地化处理，便于分析

## 🏗️ 构建和开发

### 环境要求
- Go 1.21 或更高版本
- Git
- Make (Unix 系统) 或 nmake (Windows)

### 🔧 Make 命令用法

#### 基本构建命令
```bash
# 构建当前平台版本
make build

# 跨平台构建所有版本（推荐）
make build-all

# 构建特定平台
make build-windows    # 构建 Windows 版本
make build-linux      # 构建 Linux 版本  
make build-darwin     # 构建 macOS 版本
```

#### 开发和测试命令
```bash
# 下载和管理依赖
make deps

# 运行所有测试
make test

# 运行快速测试（跳过耗时测试）
make test-fast

# 代码质量检查
make fmt              # 格式化代码
make vet              # 静态代码检查
make check            # 完整检查（格式化 + 检查 + 测试）
```

#### 实用工具命令
```bash
# 清理构建文件
make clean

# 构建并运行（显示帮助）
make run

# 安装到 GOPATH/bin
make install

# 开发模式构建（包含调试信息）
make dev

# 显示版本信息
make version

# 显示所有可用命令
make help
```

#### 完整开发流程示例
```bash
# 1. 克隆仓库
git clone https://github.com/your-org/GatTrace.git
cd GatTrace

# 2. 下载依赖
make deps

# 3. 运行测试
make test-fast

# 4. 构建所有平台版本
make build-all

# 5. 查看构建结果
ls -la release/
```

### 📦 构建输出

构建完成后，可执行文件将输出到 `release/` 目录：

```
release/
├── GatTrace-windows-amd64.exe    # Windows 64位 (Intel/AMD)
├── GatTrace-windows-arm64.exe    # Windows 64位 (ARM)
├── GatTrace-linux-amd64          # Linux 64位 (Intel/AMD)
├── GatTrace-linux-arm64          # Linux 64位 (ARM)
├── GatTrace-darwin-amd64         # macOS 64位 (Intel)
├── GatTrace-darwin-arm64         # macOS 64位 (Apple Silicon)
└── checksums.txt                 # SHA256 校验和文件
```

### 🔍 校验文件完整性

```bash
# 验证下载文件的完整性
cd release/
sha256sum -c checksums.txt        # Linux
shasum -a 256 -c checksums.txt    # macOS
# Windows: 使用 PowerShell 的 Get-FileHash 命令
```

### 开发工具

```bash
# 代码格式化
make fmt

# 静态检查
make vet

# 完整检查
make check

# 开发模式构建
make dev
```

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🆘 支持

如果您遇到问题或有疑问：

1. 查看 [构建指南](BUILD_GUIDE.md)
2. 搜索现有的 [Issues](https://github.com/your-org/GatTrace/issues)
3. 创建新的 Issue 描述问题

## 🙏 致谢

感谢以下开源项目：

- [gopsutil](https://github.com/shirou/gopsutil) - 系统信息库
- [golang.org/x/text](https://golang.org/x/text) - 文本编码支持

---

**⚠️ 免责声明**: 本工具仅用于合法的安全研究和应急响应目的。使用者需确保遵守相关法律法规和组织政策。