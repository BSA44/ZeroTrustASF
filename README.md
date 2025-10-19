# ZeroTrustASF Hackathon Platform

ZeroTrustASF is a multi-service cybersecurity platform built during the Rector's Cup hackathon (1st place, Cybersecurity track). It demonstrates how a Zero Trust perimeter can front real applications by combining device/session attestation, continuous verification, and role-based policy enforcement. The project stitches together four apps, Redis-backed session state, and an Nginx reverse proxy into a cohesive demo stack you can run locally.

## Highlights
- 🔐 **Zero Trust access gateway** that binds sessions to request context (IP, UA, timestamps) and recalculates HMAC signatures on every check.
- 🧠 **AI-driven vulnerability analysis** for Solidity contracts plus a Smol Agents security co-pilot protected behind the same controls.
- 📊 **Corporate dashboard** showcasing downstream app integration with shared session state and Redis-sourced authorization data.
- 🧰 **Invite-based onboarding** and IP-based RBAC rules enforced centrally in Flask and mirrored at the edge by Nginx.
- ⚙️ **Production-style deployment** guidance with TLS termination, geo ACLs, proxy headers, and extensible policy hooks.

## Repository Layout



## Architecture Overview



Key concepts:
- **Session Manager ()** creates signed session envelopes, ties them to request context, refreshes TTL on each hit, and exposes , , , , and admin tooling.
- **Nginx** performs the first hop of the Zero Trust flow: geo-based IP gating, TLS termination, and the  handshake that either routes traffic or redirects users to .
- **Downstream apps** read Redis directly (dashboard) or trust the headers injected by Nginx after successful verification (SAST, SmolAgents, AI scanner).

## Prerequisites

- Python 3.10+
- Redis server (tested with Redis 6+)
- Nginx with SSL support (OpenSSL 1.1+)
- OpenAI (or DeepSeek) API key for SAST and Smol Agents features
- Optional: Telegram bot token for the SmolAgents  tool
