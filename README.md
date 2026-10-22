# NyaaRink

便捷式远程ssh控制协助服务。

Portable remote SSH control assistance service.

V1 已按批准的 SSOT 完成 P1–P8，并部署至 macmini。按 A17 保留未测试的平台和交互场景，实测范围见验收记录。

需求见 [.docs/初始设计.md](.docs/初始设计.md)，审计见 [.docs/设计审计.md](.docs/设计审计.md)。

批准状态见 [.docs/设计决策.md](.docs/设计决策.md)，开发阶段与技术标准入口见 [.docs/开发计划-SSOT.md](.docs/开发计划-SSOT.md)，当前交接见 [.docs/阶段交接-014.md](.docs/阶段交接-014.md)。

操作说明见 [.docs/使用指南.md](.docs/使用指南.md)，维护与恢复见 [.docs/运维手册.md](.docs/运维手册.md)，实测证据和待验项目见 [.docs/验收记录.md](.docs/验收记录.md)。

采用一次性邀请网页、C端明确授权、本地连接程序、HTTPS/WSS 5116 和 API/MCP 接入。网络中断保留授权，只有主动断开才撤销。C用户登录后自动恢复；业务数据库恢复保留有效授权，权威数据不明时冻结访问。

采用 [AGPL-3.0](LICENSE) 许可证，保留远端已有 LICENSE 原文。

Nyaa be with you.

开发校验：`npm ci`、`npm run lint`、`npm run typecheck`、`npm test`、`npm run build`。存活检查为 `/health/live`；`/health/ready` 仅在权威与生产子系统可用、正常接入时返回 200。浏览器测试可通过 `NYAARINK_TEST_CHROMIUM` 指定已安装的 Chrome。

## C端精简连接包

新 Windows 连接包采用 Go 原生客户端与微软官方 OpenSSH-Win64.zip 的六个必需组件，保留可读 start.bat，无需 Node 或 .NET。独立 sshd 只监听随机回环端口，不改系统 SSH；Linux 使用系统 SSH。旧 Node 会话继续使用原程序。微软组件固定 10.4.0.0p1-Preview（官方标记非生产就绪），维护者须跟踪更新。完整包约 5.9 MiB；未测平台和普通账户登录场景见验收记录，不代表完整兼容认证。
