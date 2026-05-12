#!/bin/bash

# 切换到脚本所在目录
cd "$(dirname "$0")"

echo "==================================="
echo "  开始交叉编译 Agent 探针客户端包  "
echo "==================================="

# 定义输出目录
OUT_DIR="../static/downloads"

# 确保输出目录存在
mkdir -p "$OUT_DIR"

echo "[1/4] 正在编译 Windows (x86_64) 版本..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$OUT_DIR/agent_windows_x86_64.exe" main.go
if [ $? -eq 0 ]; then echo "  ✓ 成功"; else echo "  ✗ 失败"; fi

echo "[2/4] 正在编译 Linux (x86_64) 版本..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$OUT_DIR/agent_linux_x86_64" main.go
if [ $? -eq 0 ]; then echo "  ✓ 成功"; else echo "  ✗ 失败"; fi

echo "[3/4] 正在编译 macOS ARM64 (M系列芯片) 版本..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "$OUT_DIR/agent_mac_arm64" main.go
if [ $? -eq 0 ]; then echo "  ✓ 成功"; else echo "  ✗ 失败"; fi

echo "[4/4] 正在编译 macOS AMD64 (Intel芯片) 版本..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o "$OUT_DIR/agent_mac_amd64" main.go
if [ $? -eq 0 ]; then echo "  ✓ 成功"; else echo "  ✗ 失败"; fi

echo "==================================="
echo "全部编译完成！分发包已输出至: $OUT_DIR"
echo "文件列表："
ls -lh "$OUT_DIR" | grep agent_
echo "==================================="
