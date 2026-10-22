# NyaaRink

便捷式远程ssh控制协助服务。

Portable remote SSH control assistance service.

设计审计、实施基线、SSOT与C端GUI已获批准；进入P1–P8连续开发，尚无可部署服务。

需求见 [.docs/初始设计.md](.docs/初始设计.md)，审计见 [.docs/设计审计.md](.docs/设计审计.md)。

批准状态见 [.docs/设计决策.md](.docs/设计决策.md)，开发阶段与技术标准入口见 [.docs/开发计划-SSOT.md](.docs/开发计划-SSOT.md)，当前交接见 [.docs/阶段交接-001.md](.docs/阶段交接-001.md)。

规划采用一次性邀请网页、C端明确授权、本地连接程序、HTTPS/WSS 5116 和 API/MCP 接入。网络中断保留授权，只有主动断开才撤销。C用户登录后自动恢复；业务数据库恢复保留有效授权，权威数据不明时冻结访问。

采用 [AGPL-3.0](LICENSE) 许可证，保留远端已有 LICENSE 原文。

Nyaa be with you.
