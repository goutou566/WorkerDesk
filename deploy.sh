#!/bin/bash

# WorkerDesk Cloudflare Workers 部署脚本

echo "开始部署 WorkerDesk 到 Cloudflare Workers..."

# 检查 wrangler 是否已安装
if ! command -v wrangler &> /dev/null; then
    echo "错误: wrangler 未安装，请先运行 npm install -g wrangler"
    exit 1
fi

# 检查配置文件
if [ ! -f "wrangler.toml" ]; then
    echo "错误: wrangler.toml 配置文件不存在"
    exit 1
fi

# 检查 Worker 脚本
if [ ! -f "workerdesk.mjs" ]; then
    echo "错误: workerdesk.mjs 脚本文件不存在"
    exit 1
fi

echo "配置文件检查通过"

# 部署 Worker
echo "正在部署 Worker..."
wrangler deploy

if [ $? -eq 0 ]; then
    echo "✅ 部署成功！"
    echo "Worker 名称: workerdesk"
    echo "请在 Cloudflare Dashboard 查看访问地址"
else
    echo "❌ 部署失败"
    exit 1
fi
