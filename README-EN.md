# NyaaRink

[简体中文](README.md)

便捷式远程 SSH 控制协助服务。

Portable remote SSH control assistance service.

Use a single-use invitation page to obtain the invited user's explicit authorization for remote SSH assistance. Supports CLI, REST API, and MCP for both manual operation and AI Agent integration.

## 1. S-side Users: Deployment and Usage

The **S-side (inviting machine)** deploys NyaaRink and initiates assistance. The **C-side (invited machine)** accepts the invitation and runs the connection program to grant SSH access to its system.

### Deployment Prerequisites

- Deploy with Docker Compose. The default public endpoint uses **HTTPS/WSS on port 5116**. The C-side connects outbound, so its SSH port does not need port forwarding.
- Prepare a reachable domain and obtain a **Let's Encrypt certificate**. Configure the public URL, management API key, certificate directory, and data directories using [`.env.example`](.env.example).
- Prepare the service images and matching signed client release packages. Building and publishing these yourself is currently required. See the [Deployment Standard](.docs/技术标准-部署与验收.md) for details and the [Operations Manual](.docs/运维手册.md) for maintenance and backups.

Keep `.env`, certificate private keys, session keys, and authorization data private. Do not upload them to Git repositories or include them in images. Backups must protect the independent authorization ledger, key store, and master key in addition to the application database.

### Usage Workflow

1. The S-side creates an invitation through CLI, API, or MCP and shares the link with the C-side user.
2. The C-side reviews the permission notice, clicks “Accept Access,” downloads the connection package, and runs it as instructed. **Opening the page alone does not grant access.**
3. Once the C-side is online, the S-side can execute commands, use an interactive terminal, or transfer files. The page displays connection status, duration, traffic, and other information.
4. When assistance is complete, the C-side clicks “Disconnect,” or the S-side invokes the disconnect command to revoke authorization and confirms the cleanup status. The C-side then deletes the downloaded package and extracted copies.

The MCP endpoint is `https://<your-domain>:5116/mcp`, authenticated with `Authorization: Bearer <MCP_API_KEY>`. Stdio integration is also supported. See the [User Guide](.docs/使用指南.md) for CLI commands, integration examples, and operating instructions.

### Usage Notes

- **An invitation is consumed when the C-side successfully accepts it.** Invitations that have not been accepted can be canceled. Authorization that has been accepted, even before a connection is established, must be revoked through “Disconnect.”
- **Network loss, closing the page, exiting the program, or restarting does not revoke authorization.** The program supports automatic recovery after user login. Only an explicit disconnect initiated by either side permanently revokes access. If the C-side is offline, local cleanup may need to wait until it reconnects.
- Access is granted to a regular user account by default, and SSH capabilities follow that account's operating system permissions. Arrange and confirm any administrator or root access with the C-side user in advance. The C-side page discloses that the assistant may use AI Agents.
- Command contents, output, and transferred files are not persistently recorded by default. File transfer interfaces are restricted to the account's home directory; this does not sandbox SSH commands.
- Restoring an older application database does not restore revoked access. Access is frozen if the independent authorization data is missing or its integrity is uncertain.

### C-side Support Scope

| System | Connection Method |
| --- | --- |
| Windows 11 / Server 2022+ x64 | Extract the ZIP, open the enclosed folder, and run `start.bat`. No preinstalled Node.js or .NET is required. Bundled Microsoft OpenSSH components listen independently on a loopback address without modifying system SSH. |
| Ubuntu 22.04 / 24.04, Debian 12 / 13 x64 | Uses the native client and system OpenSSH. If the service is missing, follow the prompts to confirm preparation. Existing SSH installations are not automatically upgraded. |

The bundled Windows components are pinned to Microsoft's **OpenSSH 10.4.0.0p1-Preview**, officially marked as not production-ready. Deployers should understand this limitation and track updates. The systems above are the V1 target scope; see the [Acceptance Record](.docs/验收记录.md) for actual verification and outstanding untested items.

## 2. Developers: Project and Development Notes

The server and CLI use TypeScript / Node.js 24, the web interface uses React, and the C-side connection program uses Go. Nginx provides the unified HTTPS/WSS endpoint.

Install dependencies and run the basic checks:

```sh
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

The main source code is in `apps/` and `packages/`. Client releases are built with `scripts/client-release.py`; service images are built and published with `rebuild.py`. Building and publishing are separate from starting containers.

Preserve the following constraints when developing:

- Invitation consumption, explicit revocation, authorization retention during network loss, and access freezing during recovery are core behaviors. Read the [Design Decisions](.docs/设计决策.md) and [Development Plan SSOT](.docs/开发计划-SSOT.md) before changing them.
- Client releases must undergo signature verification. Independent publishers should generate their own signing keys and replace the release verification public keys in both the server and client. Do not disable verification to deploy. The current Windows release build also verifies Microsoft component signatures.
- Keep private configuration, release signing private keys, authorization data, and client release artifacts out of the source repository. Back up databases before modifying them, and clean up temporary data after testing.
- See the [Product Usage Skill](.agents/skills/nyaarink-assist/SKILL.md) for operating conventions for AI Agents, and the [API, MCP, and CLI Standard](.docs/技术标准-API-MCP与CLI.md) for interface contracts.

This project is licensed under [AGPL-3.0](LICENSE).

Nyaa be with you.
