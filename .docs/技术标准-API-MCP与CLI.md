# 技术标准：API、MCP与CLI

2026-10-22，已批准设计基线1，对应R07、R08。全部公网入口从PUBLIC_BASE_URL派生，推荐端口已由用户确认为5116。REST、MCP与CLI共用业务层、schema和错误码，不维护三套权限判断。

## 1. 鉴权与输入约束

- 管理接口：`Authorization: Bearer <MCP_API_KEY>`，管理Key来自S.env，至少32随机字节，恒定时间比较，禁止URL query传Key。服务缺Key拒绝启动。CLI从用户环境变量读取，不默认写命令行参数，不把Key交模型打印。
- 浏览器：HttpOnly Cookie、严格Origin与CSRF，不能调用S管理接口。浏览器WS只读事件使用Cookie并严格核验Origin。
- 设备：登记后nonce签名和设备绑定，设备身份不能调用管理API；数据ticket只用于一条流。仅清理的撤销设备身份不能恢复SSH访问。
- OpenSSH本地代理：S私有Unix socket，0700目录、0600 socket，校验OS访问身份和会话状态，不监听公网或默认TCP端口。
- JSON body默认上限32KiB；命令字段最大16KiB；创建邀请的名称128字符、目的1024字符，文本仅作为文本渲染。文件独立流接口，不能用JSON/base64绕过限额。
- 所有请求有requestId；错误返回 `{error:{code,message,retryable,requestId}}`，不带密钥/栈/底层完整命令。HTTP401未鉴权、403越权、404无效资源、409状态冲突、410已撤销（仅已鉴权对象可见）、413超限、429限流、503冻结/离线。
- 幂等写接口使用Idempotency-Key与主体hash，最长保留至相关授权撤销；同Key不同主体409。限流失败不消耗邀请。

## 2. REST v1 契约

| 方法与路径 | 身份 | 行为 |
| --- | --- | --- |
| POST /api/v1/invitations | S | 创建邀请；返回inviteId、单次展示inviteUrl、expiresAt |
| GET /api/v1/invitations/{id} | S | 仅元数据，不返回完整邀请码 |
| POST /api/v1/invitations/{id}/cancel | S | 取消未接受邀请，不影响已授权会话 |
| POST /api/v1/invitations/accept | C浏览器 | body邀请码、CSRF、幂等ID；原子接受与绑定 |
| GET /api/v1/browser/session | C浏览器 | 原浏览器恢复页面；撤销后404 |
| POST /api/v1/browser/bootstrap | C浏览器 | 仅未登记设备时签发/替换引导Key，敏感下载响应no-store |
| POST /api/v1/browser/disconnect | C浏览器 | 显式撤销、返回两端清理状态 |
| GET /api/v1/browser/events | C浏览器 | 只读WSS状态/指标事件，不承载原始终端 |
| POST /api/v1/browser/recovery | 新浏览器 | 创建短时配对挑战，无会话信息泄漏 |
| POST /api/v1/device/enroll | 引导Key+本地设备证明 | 一次绑定设备；相同登记ID可安全幂等重取 |
| POST /api/v1/device/challenge | 设备 | 生成受限nonce，无凭据泄漏 |
| GET /api/v1/device/control | 设备 | WSS认证、控制、心跳 |
| GET /api/v1/device/streams/{id} | 一次ticket | WSS原始SSH数据 |
| POST /api/v1/device/recover-browser | 设备签名 | 本地确认后认领浏览器恢复挑战 |
| POST /api/v1/device/disconnect | 设备签名 | 本地主动撤销/离线补交 |
| POST /api/v1/device/cleanup-ack | 设备签名 | 撤销后仅允许提交清理结果 |
| GET /api/v1/sessions | S | 分页列出会话摘要，不包含秘密 |
| GET /api/v1/sessions/{id} | S | 授权/在线/账户/冻结/清理状态 |
| GET /api/v1/sessions/{id}/metrics | S | 技术标准定义的指标与采样时间 |
| POST /api/v1/sessions/{id}/disconnect | S | 主动撤销，与C断开相同业务函数 |
| POST /api/v1/sessions/{id}/executions | S | 创建exec异步任务，返回executionId，不自动重放 |
| GET /api/v1/executions/{id} | S | 状态及限额内内存输出，含truncated与expiresAt |
| POST /api/v1/executions/{id}/cancel | S | 取消任务，不撤销授权 |
| POST /api/v1/sessions/{id}/shells | S | 创建交互终端，获得30秒一次shell连接ticket |
| GET /api/v1/shells/{id}/stream | S+ticket | WSS终端数据及resize/close，不在URL放ticket |
| PUT /api/v1/sessions/{id}/files | S | 流式上传，目标路径经结构化元数据传递 |
| GET /api/v1/sessions/{id}/files | S | 流式下载，通过编码path参数定位，不接收凭据 |
| GET /api/v1/sessions/{id}/ssh-config | S | 返回仅S容器内可用的config路径和安全用法，不含私钥 |
| GET /healthz | 无 | 仅ready/frozen及版本，无会话数、主机或配置 |

所有S接口在被冻结时拒绝新SSH/执行。撤销、状态和修复类操作可按完整性情况继续；撤销未持久化必须报告未确认。任何接口都不能通过设置expiresAt绕过“只有主动断开撤权”。

## 3. 执行、终端与文件

exec输入sessionId、command、shell枚举、可选cwd、timeoutSeconds；默认60秒、最大3600秒。命令是**有意在C账户执行的代码**，不能假称做通用命令白名单沙箱。POSIX使用登记的shell，Windows显式PowerShell或cmd，不能猜测语法；cwd和路径不得拼接进未转义命令。超时终止跟踪到的任务/SSH通道，不撤权，不保证杀掉自行脱离会话的后台进程。

exec在REST与MCP均快速返回executionId，再轮询/CLI等待。HTTP重试不重复执行同一幂等任务；控制连接丢失时标interrupted、结果可能未知，**绝不自动重放**。输出总计最多1MiB，超出继续排空并标truncated，最多内存保存10分钟；S进程重启不恢复输出和执行，不影响授权恢复。

交互终端用于CLI，默认80x24、限制resize和输入帧尺寸，每流独立撤销和配额。MCP不返回实时原始终端无限输出；Agent使用exec/轮询即可，工具不假称可识别人或AI。

SFTP默认路径限制为C确认的账户home及其子路径，每文件上限100MiB。规范化路径、拒绝`..`和根外路径、逐级lstat拒绝符号链接/重解析点、上传临时文件后原子rename，不能将未检查路径拼shell。它是文件API防误操作边界；目标账户可通过SSH shell访问OS授予的其他路径，并非安全沙箱，不承诺抵御同账户恶意并发替换文件的所有竞态。需要更强隔离应在C系统配置专门受限账户。

## 4. MCP工具

`/mcp`使用鉴权的无状态Streamable HTTP，SDK v1.x命名与导入，sessionIdGenerator=undefined；MCP传输会话与产品授权会话绝不混用。MCP关闭不撤销C授权。拒绝伪造Host/跨站Origin，不启用通配CORS。

| 工具 | 功能 |
| --- | --- |
| rink_create_invitation | 创建邀请，返回一次性邀请URL及有效期 |
| rink_cancel_invitation | 取消未接受邀请 |
| rink_list_sessions / rink_get_session | 列举和查询授权、连接、账户、清理状态 |
| rink_get_metrics | 获取明确单位的指标 |
| rink_exec / rink_get_execution / rink_cancel_execution | 发起、查询、取消命令任务 |
| rink_upload_file / rink_download_file | 小文件base64适配，最大1MiB；大文件走CLI/REST流接口 |
| rink_get_ssh_config | S容器内配置位置与cli用法，不返回私钥 |
| rink_disconnect | 明确主动断开，检查持久化撤销及清理结果 |

工具schema严格校验并标明写入/破坏性操作性质；不把工具annotations当真实权限控制。源码路径、stdout等C返回内容属于不可信数据，不能自动变成Agent新指令。

每个可能建立SSH的工具description都说明：断网/exit不撤权；任务完成后显式调用rink_disconnect并检查结果；默认普通账户，提升须C明确授权。断开前Agent须考虑仍在运行的操作，不悄悄结束其他会话。

## 5. CLI与四客户端兼容

统一CLI名`nyaarink`：`invite create/cancel`、`session list/status/metrics/disconnect`、`exec`、`execution status/cancel`、`shell`、`upload/download`、`ssh-config`、`mcp stdio`。`session disconnect --session <id>`为主动撤销命令；S端CLI在明确指定对象时可由已授权Agent直接调用，说明不能用Ctrl+C/SSH exit代替。

CLI HTTPS/WSS到S，管理Key读取环境变量，不把Key写到配置示例。`mcp stdio`桥把本地stdio翻译成经鉴权的S调用，stdout仅MCP消息、日志stderr；桥进程停止不撤权。不能将本地文件路径当成S或C路径，上传CLI明确读取协助者本机文件。

Codex、Claude Code、OpenCode、zcode分别建立验收行：准确版本、stdio桥实测、可用时StreamableHTTP+Bearer实测、工具发现、未鉴权拒绝、创建邀请、执行/轮询、显式断开。V1要求四者至少一个通用路径实测通过；若某工具名称、可安装渠道或版本不明确，先确认，不能虚构通过。未实测前都标未验证，不因用户曾安装某工具就标通过。
