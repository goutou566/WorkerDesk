# WorkerDesk

[English](#english) | [中文](#中文)

---

## English

### 📌 Introduction
**WorkerDesk** is a **serverless helpdesk system** built with **Cloudflare Workers** and **D1 Database**.  
It allows small businesses and teams to **collect feedback, manage support requests, and embed a ticket form** directly into websites or applications.  
Thanks to Cloudflare's free tier, it runs at **virtually zero cost** while remaining reliable and scalable.

---

### ✨ Features
- 🛠️ **Serverless & Scalable** – Powered by Cloudflare Workers, no server maintenance needed.  
- 💸 **Zero Cost** – Fits within Cloudflare's monthly free quota.  
- 🧩 **Embeddable** – Drop-in widget for websites or apps.  
- 🔒 **Reliable** – Runs on Cloudflare's global edge network.  
- 📊 **Persistent Storage** – Ticket data stored securely in D1 Database.  
- 📧 **Email Notifications** – Automatic email alerts when new tickets are created.  
- 🔐 **Email-based Auth** – Users log in with just their email, no password required.  
- 👨‍🔧 **Worker Panel** – Separate interface for support staff to claim and manage tickets.  

---

### 🚀 Getting Started

#### Prerequisites
- [Cloudflare account](https://dash.cloudflare.com/)  
- [Resend API Key](https://resend.com/) (for email notifications)  

#### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Resend API Key (for sending emails)
RESEND_API_KEY=your-resend-api-key

# Admin Token (reserved, currently unused)
ADMIN_TOKEN=your-admin-token

# Worker Code (for staff registration)
WORKER_CODE=your-worker-code

# Service Name (optional)
SERVICE_NAME=WorkerDesk
```

#### Deployment via Cloudflare Dashboard

1. Go to **Workers & Pages** → **Create Application** → **Upload Worker**
2. Upload `workerdesk.mjs` as the script
3. In **Settings** → **Variables**, add the environment variables above as **Secret Text** bindings
4. Add the following bindings:
   - `DB` (D1 Database)
   - `SESSIONS` (KV Namespace)
   - `CODES` (KV Namespace)
   - `SERVICE_NAME` (Plain Text)

#### Deployment via API

```bash
# Upload script
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/workerdesk/versions" \
  -H "Authorization: Bearer {api_token}" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-03-01"}' \
  -F 'worker.js=@workerdesk.mjs;type=application/javascript+module'

# Deploy
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/workerdesk/deployments" \
  -H "Authorization: Bearer {api_token}" \
  -H "Content-Type: application/json" \
  -d '{"versions":[{"version_id":"{version_id}","percentage":100}]}'
```

---

### 🗺️ Roadmap
- ✅ Email notifications for new tickets
- ✅ Email-based authentication
- ✅ Worker panel for support staff
- 🔲 Admin dashboard for managing tickets
- 🔲 Multi-language support
- 🔲 Analytics & reporting

---

## 中文

### 📌 简介

WorkerDesk 是一个基于 Cloudflare Workers 与 D1 数据库构建的无服务器工单系统。
它帮助中小企业和团队收集用户反馈、管理支持请求，并可将工单表单直接嵌入到网站或应用中。
借助 Cloudflare 免费额度，该系统能以几乎零成本运行，同时具备高可靠性与可扩展性。

---

### ✨ 功能
- 🛠️ 无服务器 & 可扩展 —— 基于 Cloudflare Workers，无需服务器维护。
- 💸 几乎零成本 —— 运行在 Cloudflare 每月的免费配额内。
- 🧩 可嵌入 —— 简单集成到任何网页或应用。
- 🔒 可靠安全 —— 依托 Cloudflare 全球边缘网络。
- 📊 持久存储 —— 工单数据安全保存于 D1 数据库。
- 📧 邮件通知 —— 新工单创建时自动发送邮件提醒。
- 🔐 邮箱登录 —— 用户仅需输入邮箱即可登录/注册，无需密码。
- 👨‍🔧 接单后台 —— 独立的接单员界面，用于接单和管理工单。

---

### 🚀 快速开始

#### 环境要求
- Cloudflare 账号
- Resend API Key（用于邮件通知）

#### 环境变量

复制 `.env.example` 为 `.env` 并配置：

```bash
# Resend API Key（用于发送邮件）
RESEND_API_KEY=your-resend-api-key

# 管理员令牌（预留，当前未使用）
ADMIN_TOKEN=your-admin-token

# 接单员认证码
WORKER_CODE=your-worker-code

# 服务名称（可选）
SERVICE_NAME=WorkerDesk
```

#### 通过 Cloudflare 控制台部署

1. 进入 **Workers & Pages** → **创建应用程序** → **上传 Worker**
2. 上传 `workerdesk.mjs` 作为脚本
3. 在 **设置** → **变量** 中，将上述环境变量添加为 **Secret Text** 绑定
4. 添加以下绑定：
   - `DB`（D1 数据库）
   - `SESSIONS`（KV 命名空间）
   - `CODES`（KV 命名空间）
   - `SERVICE_NAME`（纯文本）

#### 通过 API 部署

```bash
# 上传脚本
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/workerdesk/versions" \
  -H "Authorization: Bearer {api_token}" \
  -F 'metadata={"main_module":"worker.js","compatibility_date":"2025-03-01"}' \
  -F 'worker.js=@workerdesk.mjs;type=application/javascript+module'

# 部署
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/workerdesk/deployments" \
  -H "Authorization: Bearer {api_token}" \
  -H "Content-Type: application/json" \
  -d '{"versions":[{"version_id":"{version_id}","percentage":100}]}'
```

---

### 🗺️ 计划
- ✅ 新工单邮件通知
- ✅ 邮箱登录
- ✅ 接单员后台
- 🔲 管理工单的后台面板
- 🔲 多语言支持
- 🔲 数据分析与报表

---