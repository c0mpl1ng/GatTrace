# GatTrace 手动编译指南

## 环境准备

1. **安装 Go 1.19+**
   ```bash
   go version  # 确认版本
   ```

2. **克隆项目**
   ```bash
   git clone <repository>
   cd GatTrace
   ```

3. **安装依赖**
   ```bash
   go mod download
   go mod tidy
   ```

## 手动跨平台编译

### 设置构建变量
```bash
# Linux/macOS
export VERSION="1.0.0"
export BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export GIT_COMMIT=$(git rev-parse --short HEAD)
export LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

# Windows (PowerShell)
$VERSION="1.0.0"
$BUILD_TIME=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$GIT_COMMIT=(git rev-parse --short HEAD)
$LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"
```

### 编译各平台版本

#### Windows 版本
```bash
# Windows AMD64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-windows-amd64.exe ./cmd/GatTrace

# Windows ARM64
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-windows-arm64.exe ./cmd/GatTrace
```

#### Linux 版本
```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-linux-amd64 ./cmd/GatTrace

# Linux ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-linux-arm64 ./cmd/GatTrace
```

#### macOS 版本
```bash
# macOS AMD64 (Intel)
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-darwin-amd64 ./cmd/GatTrace

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$LDFLAGS" -trimpath -o release/GatTrace-darwin-arm64 ./cmd/GatTrace
```

## 构建优化选项

### 基本优化
```bash
-ldflags="-s -w"          # 去除符号表和调试信息
-trimpath                 # 去除文件路径信息
CGO_ENABLED=0            # 禁用CGO，生成静态二进制
```

### 高级优化
```bash
# 更激进的优化
-ldflags="-s -w -buildid="
-gcflags="all=-l -B"     # 禁用内联和边界检查
-asmflags="all=-trimpath=$(pwd)"
```

## 验证构建结果

### 检查文件
```bash
ls -la release/
file release/GatTrace-*     # 查看文件类型
```

### 生成校验和
```bash
# Linux/macOS
cd release && sha256sum * > checksums.txt

# Windows
cd release && powershell "Get-ChildItem | ForEach-Object { (Get-FileHash $_.Name).Hash.ToLower() + '  ' + $_.Name }" > checksums.txt
```

### 测试二进制文件
```bash
# 测试各平台版本
./release/GatTrace-linux-amd64 --version
./release/GatTrace-darwin-amd64 --version
wine ./release/GatTrace-windows-amd64.exe --version  # 如果有wine
```

## 构建脚本示例

### 一键构建脚本
```bash
#!/bin/bash
set -e

VERSION=${VERSION:-"1.0.0"}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

mkdir -p release

platforms=(
    "windows/amd64"
    "windows/arm64"
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

for platform in "${platforms[@]}"; do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    output="release/GatTrace-$GOOS-$GOARCH"
    if [ "$GOOS" = "windows" ]; then
        output="$output.exe"
    fi
    
    echo "Building $GOOS/$GOARCH..."
    env GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build \
        -ldflags="$LDFLAGS" \
        -trimpath \
        -o "$output" \
        ./cmd/GatTrace
done

echo "Build complete!"
ls -la release/
```

## 常见问题

### 1. 构建失败
```bash
# 清理模块缓存
go clean -modcache
go mod download

# 更新依赖
go mod tidy
```

### 2. 交叉编译错误
```bash
# 确保CGO禁用
export CGO_ENABLED=0

# 检查Go版本
go version  # 需要1.19+
```

### 3. 文件大小过大
```bash
# 使用UPX压缩（可选）
upx --best release/GatTrace-*
```

## 自动化构建

### GitHub Actions 示例
```yaml
name: Build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v3
      with:
        go-version: '1.21'
    - run: make build-all
    - uses: actions/upload-artifact@v3
      with:
        name: binaries
        path: release/
```

### Docker 构建
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN make build-all

FROM scratch
COPY --from=builder /app/release/ /binaries/
```