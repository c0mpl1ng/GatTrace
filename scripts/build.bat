@echo off
REM GatTrace Windows 构建脚本

setlocal enabledelayedexpansion

REM 项目信息
set PROJECT_NAME=GatTrace
if "%VERSION%"=="" set VERSION=1.0.0
for /f "tokens=*" %%i in ('powershell -Command "Get-Date -UFormat '%%Y-%%m-%%dT%%H:%%M:%%SZ'"') do set BUILD_TIME=%%i
if "%GIT_COMMIT%"=="" (
    for /f "tokens=*" %%i in ('git rev-parse --short HEAD 2^>nul') do set GIT_COMMIT=%%i
    if "!GIT_COMMIT!"=="" set GIT_COMMIT=unknown
)

REM 构建目录
set BUILD_DIR=release
set BINARY_NAME=GatTrace

REM 清理构建目录
echo 🧹 清理构建目录...
if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
mkdir %BUILD_DIR%

REM 构建标志
set LDFLAGS=-s -w -X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%

echo 🚀 开始跨平台构建...
echo 版本: %VERSION%
echo 构建时间: %BUILD_TIME%
echo Git提交: %GIT_COMMIT%
echo.

REM 构建各平台版本
echo 🔨 构建 windows/amd64...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%/%BINARY_NAME%-windows-amd64.exe ./cmd/GatTrace
if errorlevel 1 (
    echo ❌ 构建失败: windows/amd64
    exit /b 1
)
echo    ✅ 完成

echo 🔨 构建 windows/arm64...
set GOOS=windows
set GOARCH=arm64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%/%BINARY_NAME%-windows-arm64.exe ./cmd/GatTrace
if errorlevel 1 (
    echo ❌ 构建失败: windows/arm64
    exit /b 1
)
echo    ✅ 完成

echo 🔨 构建 linux/amd64...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%/%BINARY_NAME%-linux-amd64 ./cmd/GatTrace
if errorlevel 1 (
    echo ❌ 构建失败: linux/amd64
    exit /b 1
)
echo    ✅ 完成

echo 🔨 构建 linux/arm64...
set GOOS=linux
set GOARCH=arm64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%/%BINARY_NAME%-linux-arm64 ./cmd/GatTrace
if errorlevel 1 (
    echo ❌ 构建失败: linux/arm64
    exit /b 1
)
echo    ✅ 完成

echo 🔨 构建 darwin/amd64...
set GOOS=darwin
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%/%BINARY_NAME%-darwin-amd64 ./cmd/GatTrace
if errorlevel 1 (
    echo ❌ 构建失败: darwin/amd64
    exit /b 1
)
echo    ✅ 完成

echo 🔨 构建 darwin/arm64...
set GOOS=darwin
set GOARCH=arm64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%/%BINARY_NAME%-darwin-arm64 ./cmd/GatTrace
if errorlevel 1 (
    echo ❌ 构建失败: darwin/arm64
    exit /b 1
)
echo    ✅ 完成

echo.
echo 🎉 所有平台构建完成！
echo 构建文件位于: %BUILD_DIR%/
dir %BUILD_DIR%

echo.
echo 🔐 生成校验和文件...
cd %BUILD_DIR%
powershell -Command "Get-ChildItem | ForEach-Object { $hash = Get-FileHash $_.Name -Algorithm SHA256; $hash.Hash.ToLower() + '  ' + $_.Name } | Out-File -Encoding ASCII checksums.txt"
cd ..

echo ✅ 构建完成！