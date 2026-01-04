# GatTrace 编译全部平台版本指南

## 🚀 快速开始

### 一键构建所有平台
```bash
# 使用 Makefile（推荐）
make build-all

# 或使用构建脚本
./scripts/build.sh
```

## 📋 支持的平台

| 平台 | 架构 | 文件名 |
|------|------|--------|
| Windows | AMD64 | `GatTrace-windows-amd64.exe` |
| Windows | ARM64 | `GatTrace-windows-arm64.exe` |
| Linux | AMD64 | `GatTrace-linux-amd64` |
| Linux | ARM64 | `GatTrace-linux-arm64` |
| macOS | AMD64 (Intel) | `GatTrace-darwin-amd64` |
| macOS | ARM64 (Apple Silicon) | `GatTrace-darwin-arm64` |

## 🛠️ 构建方法

### 方法一：使用 Makefile

```bash
# 查看所有可用命令
make help

# 构建所有平台
make build-all

# 分别构建不同平台
make build-windows    # Windows 版本
make build-linux      # Linux 版本
make build-darwin     # macOS 版本

# 构建当前平台
make build

# 清理构建文件
make clean

# 运行测试
make test

# 完整的CI流程
make ci
```

### 方法二：使用构建脚本

#### Linux/macOS
```bash
# 基础构建脚本
chmod +x scripts/build.sh
./scripts/build.sh

# 增强构建脚本（带详细输出）
chmod +x build-all-platforms.sh
./build-all-platforms.sh

# 创建发布包
chmod +x scripts/release.sh
./scripts/release.sh
```

#### Windows
```cmd
# 基础构建脚本
scripts\build.bat

# 增强构建脚本
build-all-platforms.bat
```

### 方法三：手动编译

```bash
# 设置环境变量
export VERSION="1.0.0"
export BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export GIT_COMMIT=$(git rev-parse --short HEAD)
export LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

# 创建构建目录
mkdir -p release

# 编译各平台版本
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-windows-amd64.exe ./cmd/GatTrace
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-windows-arm64.exe ./cmd/GatTrace
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-linux-amd64 ./cmd/GatTrace
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-linux-arm64 ./cmd/GatTrace
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-darwin-amd64 ./cmd/GatTrace
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-darwin-arm64 ./cmd/GatTrace
```

## 🔧 环境要求

- **Go 1.19+** (推荐 1.21+)
- **Git** (用于获取提交哈希)
- **Make** (可选，用于 Makefile)

### 检查环境
```bash
go version          # 检查 Go 版本
git --version       # 检查 Git 版本
make --version      # 检查 Make 版本
```

## 📦 构建选项

### 环境变量
```bash
VERSION=2.0.0       # 设置版本号
GIT_COMMIT=abc123   # 设置Git提交哈希
BUILD_TIME=...      # 设置构建时间（自动生成）
```

### 构建标志
```bash
-ldflags="-s -w"    # 去除符号表和调试信息
-trimpath           # 去除文件路径信息
CGO_ENABLED=0       # 禁用CGO，生成静态二进制
```

## 🔍 验证构建

### 检查生成的文件
```bash
ls -la release/
file release/GatTrace-*    # 查看文件类型
```

### 验证校验和
```bash
# Linux/macOS
cd release && sha256sum -c checksums.txt

# Windows
cd release && powershell "Get-Content checksums.txt | ForEach-Object { $parts = $_ -split '  '; $expected = $parts[0]; $file = $parts[1]; $actual = (Get-FileHash $file).Hash.ToLower(); if ($expected -eq $actual) { Write-Host \"OK: $file\" } else { Write-Host \"FAIL: $file\" } }"
```

### 测试二进制文件
```bash
# 测试版本信息
./release/GatTrace-darwin-amd64 --version
./release/GatTrace-linux-amd64 --version      # 需要Linux环境
wine ./release/GatTrace-windows-amd64.exe --version  # 需要Wine

# 测试帮助信息
./release/GatTrace-darwin-amd64 --help
```

## 📋 构建结果

成功构建后，你将在 `release/` 目录中看到：

```
release/
├── checksums.txt                    # SHA256校验和文件
├── GatTrace-darwin-amd64           # macOS Intel版本
├── GatTrace-darwin-arm64           # macOS Apple Silicon版本
├── GatTrace-linux-amd64            # Linux AMD64版本
├── GatTrace-linux-arm64            # Linux ARM64版本
├── GatTrace-windows-amd64.exe      # Windows AMD64版本
└── GatTrace-windows-arm64.exe      # Windows ARM64版本
```

### 文件大小参考
- Windows: ~3.2-3.4 MB
- Linux: ~3.4-3.7 MB  
- macOS: ~3.5-3.7 MB

## 🚀 发布流程

### 创建完整发布包
```bash
# 使用发布脚本
./scripts/release.sh

# 或使用 Makefile
make release
```

发布包将包含：
- 所有平台的二进制文件
- 安装说明文档
- 示例配置文件
- 版本信息
- 校验和文件

## 🐛 常见问题

### 1. 构建失败
```bash
# 清理并重新构建
make clean
go clean -modcache
go mod download
make build-all
```

### 2. 导入错误
```bash
# 更新依赖
go mod tidy
go mod download
```

### 3. 权限错误
```bash
# 给脚本执行权限
chmod +x scripts/*.sh
chmod +x *.sh
```

### 4. Windows构建失败
```bash
# 确保CGO禁用
export CGO_ENABLED=0
# 或在Windows上
set CGO_ENABLED=0
```

## 🔄 自动化构建

### GitHub Actions
```yaml
name: Build All Platforms
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v3
      with:
        go-version: '1.21'
    - name: Build all platforms
      run: make build-all
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: GatTrace-binaries
        path: release/
```

### Docker构建
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache make git
RUN make build-all

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/release/ /usr/local/bin/
```

## 📚 更多信息

- 查看 `manual-build-guide.md` 了解详细的手动构建步骤
- 查看 `Makefile` 了解所有可用的构建目标
- 查看 `scripts/` 目录了解构建脚本的实现细节