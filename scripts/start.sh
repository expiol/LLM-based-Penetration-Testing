#!/bin/bash

# 启动脚本
set -e

echo "🚀 启动LLM-based Penetration Testing Platform"

# 检查Python版本
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python版本需要 >= $required_version，当前版本: $python_version"
    exit 1
fi

# 检查依赖
echo "📦 检查依赖..."
if [ ! -f "requirements.txt" ]; then
    echo "❌ requirements.txt 文件不存在"
    exit 1
fi

# 安装依赖
echo "📦 安装依赖..."
pip install -r requirements.txt

# 创建必要的目录
echo "📁 创建目录..."
mkdir -p logs pentest_events/files pentest_events/db

# 检查配置文件
echo "⚙️ 检查配置..."
if [ ! -f "configs/hot_swaps.yaml" ]; then
    echo "⚠️ 配置文件不存在，使用默认配置"
fi

# 设置环境变量
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# 启动服务
echo "🚀 启动服务..."
python starter.py --model_name "${MODEL_NAME:-PenTest-LLM}" --service_port "${SERVICE_PORT:-8080}"
