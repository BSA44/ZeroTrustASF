# ZeroTrustASF Hackathon Platform

<div align="center">

**🏆 1st Place Winner - Rector's Cup Hackathon (Cybersecurity Track)**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Redis](https://img.shields.io/badge/Redis-6+-red.svg)](https://redis.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📖 About

> "ZeroTrustASF takes its name after its founding members: [Amir](https://github.com/Delinester), [Sarvar](https://github.com/BSA44), and [Farrukh](https://github.com/farruhilhamov). We are a team of three students from Inha University in Tashkent, Uzbekistan, passionate about cybersecurity and software development."

**ZeroTrustASF** is a comprehensive multi-service cybersecurity platform that demonstrates how a Zero Trust security perimeter can protect real-world applications. By combining device/session attestation, continuous verification, and role-based policy enforcement, this platform integrates four distinct applications with Redis-backed session state and an Nginx reverse proxy into a unified, production-ready security stack.

## ✨ Key Features

- 🔐 **Zero Trust Access Gateway**
  Binds sessions to request context (IP, User-Agent, timestamps) and recalculates HMAC signatures on every verification check

- 🧠 **AI-Driven Security Analysis**
  Vulnerability scanner for Solidity smart contracts with Smol Agents security co-pilot integration

- 📊 **Corporate Dashboard**
  Demonstrates downstream application integration with shared session state and Redis-sourced authorization

- 🧰 **Invite-Based Onboarding**
  IP-based RBAC rules enforced centrally in Flask and mirrored at the Nginx edge

- ⚙️ **Production-Ready Deployment**
  Complete setup with TLS termination, geo-based ACLs, secure proxy headers, and extensible policy hooks

## 🏗️ Architecture Overview

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Nginx (Reverse Proxy + TLS)        │
│  - Geo IP filtering                 │
│  - Session verification handshake   │
│  - Request routing                  │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Session Manager (Flask)            │
│  - HMAC-signed session envelopes    │
│  - Context binding (IP, UA, time)   │
│  - TTL refresh on each request      │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Redis (Session Store)              │
│  - Session state persistence        │
│  - Authorization data cache         │
└─────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Downstream Applications            │
│  - Dashboard                        │
│  - SAST Scanner                     │
│  - Smol Agents Co-pilot             │
│  - AI Vulnerability Analyzer        │
└─────────────────────────────────────┘
```

### Core Components

- **Session Manager (`session_manager.py`)**
  Creates cryptographically signed session envelopes, binds them to request context, refreshes TTL on each access, and provides login/logout/admin APIs

- **Nginx Reverse Proxy**
  First line of defense in the Zero Trust flow: performs geo-based IP gating, TLS termination, and session verification before routing traffic or redirecting to login

- **Downstream Applications**
  Read session data directly from Redis (dashboard) or trust security headers injected by Nginx after successful verification (SAST, SmolAgents, AI scanner)

## 📋 Prerequisites

- **Python** 3.10 or higher
- **Redis** 6.0+ server
- **Nginx** with SSL support (OpenSSL 1.1+)
- **API Keys:**
  - OpenAI or DeepSeek API key (for SAST and Smol Agents features)
  - Telegram bot token (optional, for SmolAgents integration)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ZeroTrustASF.git
cd ZeroTrustASF
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root:

```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

OPENAI_API_KEY=your_openai_api_key_here
# OR
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Optional
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
```

### 4. Start Redis

```bash
redis-server
```

### 5. Run the Application

```bash
python app.py
```

### 6. Configure Nginx (Production)

See the [Deployment Guide](#-deployment) section below for Nginx configuration details.

## 🔧 Configuration

### Session Management

Configure session parameters in `session_manager.py`:

- **Session TTL**: Default 3600 seconds (1 hour)
- **HMAC Algorithm**: SHA-256
- **Context Binding**: IP address, User-Agent, timestamp

### Access Control

Define role-based access policies in your configuration:

- **Admin**: Full access to all services
- **Analyst**: Access to SAST and vulnerability scanner
- **Viewer**: Dashboard access only

## 🌐 Deployment

### Nginx Deployment

1. Setup Nginx:
```bash
sudo rm -rf /etc/nginx
sudo cp nginx /etc -r 
sudo nginx -t
sudo systemctl restart nginx.service

```

2. Install python dependencies:
```bash
pip install -r ZeroTrustASF/requirements.txt
pip install -r SAST_SC/requirements.txt
pip install -r smolagents_chat2/requirements.txt
```

3. Start the applications:
```bash
python ZeroTrustASF/app.py
python SAST_SC/app.py
python smolagents_chat2/app.py
```
___

## 👥 Team

- **[Amir](https://github.com/Delinester)** - Backend & Security Architecture
- **[Sarvar](https://github.com/BSA44)** - Infrastructure & DevOps
- **[Farrukh](https://github.com/farruhilhamov)** - Frontend & Integration


## 📬 Contact

For questions or collaboration opportunities, reach out to our team members via GitHub.

