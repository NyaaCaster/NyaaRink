# 技术文档：NyaaRink 猫猫远程协助

本文从 AstrBot 中的猫猫 Bot 视角，说明如何通过 NyaaRink MCP 申请并使用 SSH 远程协助，并记录 NyaaRink 的用户流程、工程架构和可复用设计方法。

## 文档范围与状态

本文依据 NyaaRink 当前工程源码、README、使用指南、设计决策、接口与生命周期标准及验收记录整理。AstrBot 侧的 `astrbot_plugin_nyaa_rink` 插件目录、GitHub 仓库和原有文档已删除；因此，猫猫侧章节描述的是应遵循的 MCP 接入与对话操作方法，不表示已有可安装的 AstrBot 专用插件实现，也不复原已删除的插件代码。

NyaaRink 服务端实现 MCP，但这不等于当前 AstrBot 已完成直连或全流程验收。要让猫猫实际调用，运行环境仍须配置一个能把 NyaaRink Streamable HTTP 或 stdio 工具提供给 AstrBot LLM 的 MCP 适配层，并把管理 Key 存在受保护配置中。现有验收记录没有 AstrBot 的实际连接和完整工具调用证据；本文件说明工具契约和交互方法，不替代那项集成验收。

项目交付状态与测试边界以 [NyaaRink 验收记录](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/验收记录.md) 为准。完成本期开发验收不等于所有操作系统、客户端和故障场景均已认证。

## 术语与信任边界

| 名称 | 含义 |
| --- | --- |
| 猫猫 / Bot | 运行在 AstrBot 对话中的 AI 助手。MCP 工具可用时，猫猫可以在授权范围内请求 NyaaRink 执行操作。 |
| S端 / 邀请机 | 运行 NyaaRink 服务的一端，持有 MCP 管理凭据，负责接受管理请求并代理 SSH。 |
| C端 / 受邀机 | 用户自己的电脑。用户在浏览器接受邀请、在本机运行连接程序后，才会向 S端建立受控 SSH 通道。 |
| 邀请链接 | 含一次性邀请秘密的地址。知道链接可以预览邀请；只有 C端主动接受并成功持久化后，邀请才被消费并建立授权。 |
| 授权 / 在线 | “已授权”表示 C端已接受访问且权限尚未主动撤销；“在线”表示当前连接通道及 SSH 能力已通过核验。二者不是同一状态。 |

远程 SSH 权限受 C端实际确认的操作系统账户约束。SSH 命令可以使用该账户本来拥有的权限；文件 API 的主目录限制不构成 SSH 命令沙箱。默认使用普通账户。管理员或 root 权限必须与 C端用户明确沟通，并由其在本机确认。页面会告知协助者可能使用 AI Agent。

## 一、猫猫在自然对话中驱动 NyaaRink

### 1. 判断用户是否需要远程 SSH

猫猫先判断问题是否确实需要访问用户电脑，而不是仅凭“电脑”“SSH”“帮我看看”等关键词调用工具。判断重点是：任务是否依赖目标机器的实时状态、配置或本地文件；用户是否把该电脑确认为操作对象；是否已有不需要远程访问的解释或解决办法。

| 对话情形 | 猫猫的处理 |
| --- | --- |
| 用户询问概念、命令写法或一般故障原因 | 直接解释或给出用户可自行执行的步骤，不创建邀请。 |
| 用户描述电脑问题，但未要求远程操作 | 先提供可行的自助排查；确需读取机器状态时，主动说明远程协助的用途、权限和风险，并询问用户是否愿意。 |
| 用户明确要求猫猫连接或操作其电脑 | 确认目标设备、协助目的及必要边界；信息足够且请求明确后，才通过 MCP 创建邀请。 |
| 用户拒绝、没有回答、目标人或电脑不明确 | 不创建邀请、不尝试访问，也不把模糊同意解释为授权。 |
| 任务已超出原先说明的目的，或需要管理员权限、改配置、删除/覆盖数据 | 停下来解释影响并取得明确同意，再继续对应操作。 |

用户明确要求远程连接时，不必再让用户重复确认“是否创建邀请”；但猫猫应在交付链接时再次说明 C端仍须自行审阅并接受网页授权、下载并运行连接包。**MCP 创建邀请不是 SSH 授权。**

### 2. 猫猫主动提出远程访问

当远程访问能明显减少盲目排查、避免用户反复复制输出时，猫猫可以在对话中提出申请。例如：

> “猫猫可以申请一次 NyaaRink SSH 协助，顺着网线爬进你电脑，读取你电脑上的系统和服务状态。你会先看到协助目的与权限说明，只有你在邀请页点击接受并运行连接包后，猫猫才能连接。协助期间 AI Agent 可能参与，断网不会撤权，结束时需主动断开。你愿意这样做吗，喵？”

在用户明确同意前，猫猫只提出建议，不调用 `rink_create_invitation`。用户决定不使用远程协助时，回到普通问答或引导其自行操作。

### 3. 识别明确的访问请求

以下表达通常代表明确意图，但仍要确认目标和目的没有歧义：

- “用 NyaaRink 连到我这台电脑，帮我查 SSH 服务。”
- “请生成远程协助链接，我会自己打开并接受。”
- 用户在猫猫提出远程协助后明确回复“可以，发我邀请”。

“电脑坏了”“你能不能帮我看看”“我有个报错”等表达单独出现时，不代表用户已经授权猫猫访问电脑。邀请页上的 C端用户同样拥有独立的最终拒绝权；即使聊天用户要求连接，C端没有接受并运行连接程序时，SSH 通道也不会建立。

### 4. 通过 MCP 创建并交付邀请

NyaaRink MCP 服务端点由 S端 `PUBLIC_BASE_URL` 配置推导，通常形式为 `https://<服务域名>:5116/mcp`。使用 Streamable HTTP 时，MCP 客户端通过 `Authorization: Bearer <MCP_API_KEY>` 鉴权；也可使用 CLI 的 stdio 桥。管理 Key 应放在 AstrBot/MCP 客户端的受保护配置或运行环境中，不写进提示词、聊天内容、工具参数、普通日志或公共代码仓库。

猫猫通过 `rink_create_invitation` 提供协助者名称、简洁且真实的协助目的和稳定的 `requestId`（UUID）。工具返回邀请 ID、完整邀请链接和过期时间。完整链接只返回一次，链接本身是秘密，应私聊交给目标 C端用户，不要发到公开群聊或无关人员可见的位置。未接受邀请的默认有效期为 24 小时。

```text
rink_create_invitation({
  helperName: "猫猫",
  purpose: "经用户同意，检查该电脑的 SSH 服务状态并读取系统版本",
  requestId: "<本次创建操作的 UUID>"
})
```

若调用结果不确定，重试同一次创建时复用原 `requestId`，不要新建另一个邀请。链接交付时，猫猫应告诉用户：

1. 打开链接，核对协助者名称、目的和访问说明。
2. 自己勾选知情确认并点击“接受访问”。
3. 下载连接包；Windows 解压后进入包内文件夹并运行 `start.bat`，按本机提示确认。
4. 等页面显示在线并核实本机账户后，猫猫才开始 SSH 操作。
5. 协助结束时由任一方主动断开，并删除下载包及解压副本。

猫猫不应声称仅打开网页即可授权，也不应把“接受访问”描述成无风险的只读授权：实际 SSH 权限由 C端确认的账户决定。

### 5. MCP 查询和远程 SSH 操作

邀请被接受后，猫猫使用 `rink_list_sessions` 查找本次协助会话，并用 `rink_get_session` 核验目标会话。若名称、目的、时间或设备信息有歧义，不操作任何会话，应先请用户确认。执行前至少检查：

- `authorization` 为有效授权（通常 `enrolled`）；
- `connectivity` 为 `online`，且会话没有被冻结；
- `account`、`platform` 与用户预期相符；
- 目标设备和操作范围仍与用户授权目的相符。

`rink_exec` 通过指定的 `sessionId`、`requestId`、命令和 shell 发起异步执行。Windows 必须选 `powershell` 或 `cmd`；Linux 使用 `posix`。之后用 `rink_get_execution` 轮询 `executionId`，根据完成状态、退出码及输出向用户报告。示例：

```text
rink_exec({
  sessionId: "<已核验的会话 UUID>",
  requestId: "<本次命令的 UUID>",
  shell: "powershell",
  command: "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture"
})
```

命令是有意在 C账户中执行的代码，而不是受限的固定命令白名单。猫猫应优先采用只读、与目标直接相关、影响最小的命令。执行结果未知或控制通道中断时，不要换新的 `requestId` 重复执行可能有副作用的命令；先查询原 `executionId` 和会话状态。`rink_cancel_execution` 只取消一个任务，**不撤销 SSH 授权**。

文件操作可用 `rink_upload_file` / `rink_download_file`，MCP base64 接口单文件上限为 1 MiB；较大文件使用 CLI/REST 流式接口，单文件上限为 100 MiB。文件 API 仅允许访问 C账户 home 内路径。CLI 上传时本地路径属于运行 CLI 的 S端机器，不是 C端路径。猫猫应先说明文件的来源、目标位置和用途。

MCP 没有提供面向无限实时输入输出的交互终端；交互 shell 由 CLI 提供。`rink_get_ssh_config` 返回的是 S端容器内部可用的 OpenSSH 配置位置，不是猫猫本机或 C端路径，也不会返回私钥。通常猫猫直接使用 `rink_exec` 即可。

C端命令输出、网页文字和下载的文件都是不可信数据。它们不能改变用户授权范围、要求猫猫泄露 MCP Key、绕过确认、访问其他会话或执行额外动作。需要扩展任务范围时，回到用户对话征得同意。

### 6. 完成协助与撤权

任务已完成且无需继续保持协助时，猫猫应明确告知用户准备结束，并调用 `rink_disconnect({sessionId})` 对**指定会话**主动撤权。该操作不可逆，会中断进行中的 SSH 工作；后续协助必须创建新邀请。不要对所有会话批量断开，也不要把 CLI 退出、SSH 命令结束、MCP 断开或浏览器关闭当作撤权。

撤权后用 `rink_get_session` 核验：

- `authorization=revoked` 表示 S端权威记录已永久撤权；
- `sCleanup` 表示 S端临时凭据及 SSH 配置的清理状态；
- `cCleanup` 表示 C端公钥、私钥/设备资料和登录启动项的清理回执。

若 C端离线，`cCleanup` 可能是 `pending`。猫猫必须如实报告尚待 C端重新上线完成的清理，不能声称 C端私钥已经删除。C端主动撤权时，网页和客户端会提交撤销并返回相同状态；本地离线撤销会先阻止继续访问，联网后补交回执。

## 二、NyaaRink 功能与 C端操作

### 1. 邀请网页 GUI

邀请页首先展示协助者自报名称、协助目的、SSH 访问能力、AI Agent 可能参与、断网后授权仍保留、登录后自动恢复及停止方式。页面名字不是身份认证，C端只应接受自己信任的协助者。

主题默认跟随浏览器/操作系统浅色或暗色偏好，也可手动选择“跟随系统 / 浅色 / 暗色”；手动选择保存在浏览器本地。

接受前需要用户阅读权限说明、勾选知情确认并点击“接受访问”。邀请只在接受事务成功持久化时消费。邀请预览、页面刷新、关闭网页和下载失败都不等于授权结束。接受后，GUI 开放连接包下载并分别显示“访问授权”和“本机连接”状态。

连接概览可显示授权时长（包括离线时间）、累计在线时间、WSS 控制往返延迟、受控 SSH 连接当前/累计数、双向 SSH 字节量和受控 API 操作数。页面指标含义：

- `rttMs` 是 S端控制 WSS ping/pong 的往返毫秒数，不是浏览器到服务器延迟，也不是单条 SSH 命令延迟。
- SSH 字节量统计隧道中的 SSH 数据，不含 TLS 开销；受控操作数代表 API 操作，不是命令条数。
- SSH 连接数仅代表由服务管理的认证连接；通过 S端原生 OpenSSH 代理的连接会计入流量，但不一定计入该连接数。
- NyaaRink 不把无法准确解释的底层包数量称为“SSH 请求次数”。

若页面 WebSocket 断开或状态无法读取，GUI 会显示“状态待核实”。这时不得推断授权已撤销；用户可重新核实状态。连接在线的前提是设备已完成签名控制通道、SSH 主机身份及所需 SSH 能力检查，不是“脚本窗口打开”这么简单。

### 2. Windows 连接 ZIP 包

接受邀请后，在页面选择 Windows 并点击“下载连接脚本”。实际下载的是带单层目录的 ZIP：

```text
NyaaRink-<会话ID>/
├── start.bat
├── bootstrap.json
├── client-runtime.zip
└── README.txt
```

- `start.bat` 是可读入口；用户可以先用文本编辑器查看。它通过 Windows 自带 PowerShell 在本地校验、展开并启动程序，不下载可执行程序、不新增 `.ps1` 文件、不修改 PowerShell 执行策略。
- `bootstrap.json` 包含本次会话的短时引导凭据和服务信息，是秘密材料。不得分享、放入工单、发到群聊或上传到公开扫描网站。
- `client-runtime.zip` 是单独签名的运行时发行包，包含 Go 原生客户端、签名清单、许可证和便携 SSH 组件。
- `README.txt` 记录使用和注意事项。解压后先进入 `NyaaRink-<会话ID>` 目录，再运行 `start.bat`，不要直接在 ZIP 预览器中启动。

启动器先校验内层发行包的摘要、清单与程序；Go 客户端再次校验 Ed25519 签名和发行文件完整性，并验证微软 OpenSSH 组件的 Authenticode 信任。校验失败时停止运行，不应关闭安全软件或添加排除项。

当前 Windows 客户端不需要预装 Node.js 或 .NET。它从微软官方便携包中使用 `sshd.exe`、`sshd-auth.exe`、`sshd-session.exe`、`ssh-shellhost.exe`、`sftp-server.exe`、`libcrypto.dll` 六个必要组件。组件版本固定为 **OpenSSH 10.4.0.0p1-Preview**；微软标记为非生产就绪，部署者须了解此限制并跟踪安全更新。

### 3. Windows 连接程序具体做什么

`start.bat` 将引导配置交给原生客户端。客户端在当前 Windows 用户上下文中：

1. 展开并核验签名发行包，将程序复制到当前账户的私密持久运行目录；后续恢复不依赖 Downloads 或解压目录。
2. 展示 NyaaRink 服务地址、访问风险和撤权规则，请用户明确确认本次配置，并核实实际账户及本机连接设置。默认使用运行程序的普通账户；管理员账户需要额外确认。
3. 为该会话准备独立 SSH 主机身份、配置和 `authorized_keys`，启动随包便携 `sshd`。它只监听随机分配的 `127.0.0.1` 回环端口，不安装或修改 Windows 系统 SSH 服务，不增加防火墙规则。
4. 使用设备 Ed25519 身份向 S端登记，再建立出站 WSS 控制通道。C端不开放公网 SSH 监听、不需要路由器端口映射。
5. 创建当前用户登录后恢复所需的计划任务，并运行连接服务。前台进程意外退出或网络中断不会撤销授权；用户登录后程序可恢复连接。

SSH 使用密钥认证，不把 Windows 登录密码发送给 S端。S端的每会话 SSH 私钥留在 S端私密存储中。S端获得的 SSH 能力与 C端实际授权账户一致；SSH 命令并不限于网页文件接口的 home 目录。

连接状态要结合多处判断：

- ZIP/启动器显示发行文件校验结果，只说明本地包通过完整性检查，不代表 SSH 已连接。
- 客户端本地 `status --session <会话UUID>` 可用于检查本地会话阶段、清理状态和回执状态；状态字段以该版本客户端输出为准。
- C端网页的“访问授权”表示授权生命周期；“本机连接”在线/等待/离线显示 S端观测到的连接状态。断网、页面失联会显示离线或待核实，但不会自动撤权。
- S端猫猫通过 `rink_get_session` 可查授权、平台/账户、冻结和两端清理状态，通过 `rink_get_metrics` 查连接指标。

Windows 用户结束协助时，最直接的方式是在 C端网页点击“断开连接”，阅读二次确认并确认。客户端也提供对指定会话执行 `disconnect --session <会话UUID>` 的主动撤权入口。确认后客户端持久化撤销标记，终止便携 SSH 与活动流，删除本次公钥授权和登录恢复任务，之后向 S端报告清理结果。离线撤销先本地阻断访问，网络恢复后补交；清理失败会保留可重试状态，不会假报完成。

S端猫猫则通过 MCP 调用 `rink_disconnect`。该工具会停止该会话正在执行的 SSH 工作、销毁 S端有效凭据并通知 C端清理。C端离线时，S端会保留 `cCleanup=pending` 等真实状态；C端恢复连接后完成清理与回执。撤销不可逆，继续协助需重新发邀请。

**删除 ZIP、`start.bat` 或解压目录本身不会撤销 SSH 权限。**主动断开后，C端应按网页提示删除下载的 ZIP 和所有解压副本。若仅删除文件、关闭网页、关机、退出客户端或断网，可能留下有效但离线的授权。

### 4. Linux 客户端简述

Ubuntu/Debian 使用 Go 原生客户端，并复用 C端系统 OpenSSH。若检测到缺少或停止的 SSH 服务，客户端先解释拟进行的本机服务准备并要求确认；不会自动升级已有 SSH。默认通过普通用户的 systemd user 服务在用户登录后恢复，不自动启用 linger 或改用 root。缺少可用 user manager 时应明确报告无法建立登录恢复，不应伪称已配置成功。

## 三、NyaaRink 框架设计与技术细节

### 1. 工程布局

| 路径 | 职责 |
| --- | --- |
| `apps/web` | React 邀请/授权 GUI：展示权限说明、接受邀请、下载连接包、显示状态和指标、由 C端发起撤权。 |
| `apps/server` | Node.js/TypeScript 服务：REST 路由、MCP、邀请/授权、浏览器身份、设备登记、WSS 隧道、SSH 操作、文件传输、指标和权威存储。 |
| `apps/cli` | S端 CLI 和 MCP stdio 桥；可创建邀请、查询会话、exec、终端、传文件和显式断开。 |
| `apps/client-native` | 新会话使用的 Go 原生 C端程序：签名验证、设备身份、WSS、SSH 准备、登录恢复、本地及远端撤权。 |
| `apps/client` | 旧版 Node C端会话客户端。新 Go 发行不会自动迁移或撤销已建立的旧会话。 |
| `apps/server/src/mcp.ts` | 定义 NyaaRink MCP 工具名、严格输入 schema、只读/破坏性标记和统一错误处理。 |
| `packages/contracts` | REST、设备、执行任务和隧道共享的 Zod schema 与传输约束，避免各入口各自定义权限行为。 |
| `packages/version` | 项目版本和运行时标记等共享元数据。 |
| `packages/windows-openssh.json` | 固定微软 Windows OpenSSH 发行来源和构建校验信息。 |
| `nginx/nginx.conf`、Dockerfile、Compose | HTTPS/WSS 边缘入口和 app/gateway 双容器部署。 |
| `scripts/`、`backup.py`、`restore.py`、`restart.py`、`rebuild.py` | 客户端发行、证书同步、备份恢复、镜像构建发布和部署重启。 |
| `.docs/` | 初始设计、决策、接口/部署/生命周期标准、SSOT、使用指南和验收记录。 |

工作区使用 npm workspaces、TypeScript strict/ESM、Node.js 24、Express、React/Vite、SQLite/better-sqlite3、MCP SDK、`ssh2` 与 `ws`；C端 Go 原生程序独立编译。依赖版本由 `package-lock.json` 和 Go module 文件锁定。

### 2. 部署拓扑与网络边界

```mermaid
flowchart LR
  CAT["AstrBot 猫猫 / Agent"] -->|"MCP Streamable HTTP + Bearer Key"| GW
  BROWSER["C端浏览器 GUI"] -->|"HTTPS / Cookie / CSRF"| GW
  CCLIENT["C端原生连接程序"] -->|"出站 WSS 控制通道"| GW
  CCLIENT -->|"独立出站 WSS 数据流"| GW
  subgraph S["S端 Docker Compose"]
    GW["nginx TLS gateway :5116"] -->|"内部 HTTP :3000"| APP["Node.js app"]
    APP --> MCP["REST / MCP / CLI 业务层"]
    APP --> AUTH["独立授权账本 + 加密密钥库"]
    APP --> DB["SQLite 投影与运行数据"]
  end
  CCLIENT -->|"本机回环 SSH"| SSHD["C端 sshd：127.0.0.1 / ::1"]
```

公网只有 nginx gateway 的 HTTPS/WSS 端口（默认 **5116**）映射到宿主机；Node app 的 3000 端口仅在 Compose 内部网络。C端主动向 S端建立 WSS，不要求 C端开放入站 SSH、防火墙端口或路由转发。普通 SSH 数据通过 WSS 数据流传输；NyaaRink 不提供任意 TCP 目标代理。

HTTPS 证书由部署者自行申请 Let's Encrypt 证书，并通过受保护的只读证书目录挂载给 gateway/app。MCP 管理 Key、证书私钥、32 字节主密钥、授权账本、会话密钥和发行私钥均不应写入 Git 跟踪文件或镜像。

当前 Compose 部署基线在容器内以 root 运行 app/gateway，并为特定 Docker/AppArmor 环境取消 `no-new-privileges` 与 AppArmor 限制；这会降低一层容器隔离。配置仍保留只读根文件系统、移除能力（gateway 仅保留所需 `SETGID`）、资源限制和私密独立挂载，并且不使用 `privileged`、host 网络或 Docker socket。部署者应把 bind mount 和私密目录作为高权限资产保护；具体变更须对照当前 Compose 和部署标准核验。

### 3. MCP 与业务执行路径

NyaaRink 提供 12 个 MCP 工具，名称均以 `rink_` 开头：

| 工具 | 用途 |
| --- | --- |
| `rink_create_invitation` | 创建邀请并返回一次性秘密链接。 |
| `rink_cancel_invitation` | 取消尚未被 C端接受的邀请。 |
| `rink_list_sessions`、`rink_get_session` | 分页列出或查询授权、设备、在线及清理状态。 |
| `rink_get_metrics` | 查询 SSH 字节、连接数、API 操作数、授权/在线时长和 RTT。 |
| `rink_exec`、`rink_get_execution`、`rink_cancel_execution` | 提交异步命令、轮询任务或取消单个任务。 |
| `rink_upload_file`、`rink_download_file` | 在 C账户 home 范围传输小文件；MCP base64 上限 1 MiB。 |
| `rink_get_ssh_config` | 返回 S容器内原生 OpenSSH 配置路径，不返回私钥。 |
| `rink_disconnect` | 对指定会话永久撤权并启动双方清理。 |

MCP 工具不另建授权系统；它们调用与 REST/CLI 共用的服务层。输入采用严格 schema，工具 metadata 只是客户端提示，不是安全边界。真正鉴权依靠 MCP Bearer Key、浏览器 Cookie/CSRF、设备签名和每流短时 ticket。

命令路径可概括为：

1. 猫猫调用经过管理 Key 鉴权的 MCP 工具。
2. app 验证 session 授权、在线状态、输入 schema、操作范围及幂等 ID。
3. `Operations` 使用 `ssh2` 建立 SSH 认证连接；数据经过 `TunnelHub` 对应的数据 WSS 流到达 C端。
4. C端连接程序只把 SSH socket 接到本机登记时核验的回环 sshd。服务端不给 C端任意目标地址，C端也不会把该连接开放到 LAN 或公网。
5. exec 返回 `executionId`，猫猫用轮询工具读取有限保留期内的结果。连接中断时结果可能是 `interrupted` 或未知，服务端不会自动重放命令。

命令最长 16 KiB，默认超时 60 秒、上限 3600 秒；输出最多缓存在内存 1 MiB、最长 10 分钟。MCP 任务取消与会话撤权是两种独立动作。C端 shell 权限来自操作系统账户，不能把 API 路径限制说成系统权限隔离。

### 4. 邀请和授权生命周期

| 状态/事件 | 含义 |
| --- | --- |
| 邀请 `issued` | S端已生成邀请；预览不消费，默认 24 小时后过期，未接受时可由 S端取消。 |
| 授权 `accepted` | C端点击接受，S端把消费和浏览器绑定写入权威记录；还可能尚未下载或运行程序。 |
| 授权 `enrolled` | C端程序以一次性 bootstrap 完成本机账户/设备登记，S端已绑定设备公钥与 SSH 公钥。bootstrap 默认约 10 分钟有效。 |
| 连接 `online` | C端设备通过 WSS、签名挑战、generation 和 SSH 能力核验。 |
| 连接 `offline` / `reconnecting` | 网络或程序暂时中断。只改变可达状态，**不撤销授权**；旧任务不可盲目重放。 |
| 授权 `revoked` | C端网页、本地客户端或 S端通过主动断开持久化撤权。不可逆，必须重新邀请才能访问。 |

主动撤权后，服务先把 `revoked` 写入权威账本，再关闭 SSH/WSS、执行任务和 S端临时凭据，向在线 C端发送 revoke 并等待清理回执。离线 C端时，本地清理状态可以保持 pending；服务不会因为超时谎报完成。C端离线主动撤权则先在本地持久化 revoked 并阻止恢复，连网后补交。

服务重启、容器升级、SSH 退出、MCP 断开、关闭浏览器、关机、超时、清理失败均不等价于主动撤权。重新打开已撤销邀请页不会恢复有效邀请信息。

### 5. 隧道握手和 SSH 代理

控制通道与 SSH 数据流分开：

1. C端连接 `/api/v1/device/control` 建立控制 WSS，向 S端发送 `hello` 与登记设备公钥。
2. S端发出限时随机 nonce；C端使用设备 Ed25519 私钥对挑战签名。S端校验签名、实例 ID、epoch、sessionId 和设备绑定。
3. 授权有效后，S端发放新的 connection generation。旧 generation 下的数据流和任务不会被复用。C端还要启动本地 SSH 并完成回环、host key 和能力校验，S端探测 SSH 认证和必要能力后才报告 verified/online。
4. 每一条 SSH 流由 S端创建单次 stream ticket，再通过控制通道通知 C端。C端向 `/api/v1/device/streams/<streamId>` 发起独立 WSS，在 Authorization header 提交 ticket；ticket 绑定 session、generation 和用途，约 30 秒内只能消费一次。
5. 数据流承载 SSH 原始二进制数据，服务端通过有界缓冲、背压及配额进行双向桥接。握手失败、旧 ticket 或旧 generation 都不能变成授权。

服务默认每会话最多 4 条 SSH 流，并限制每会话聚合带宽与全局排队；超限时结束对应操作/数据流或返回可重试错误，不自动撤销整份授权。具体数值以 [隧道生命周期标准](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/技术标准-授权生命周期与隧道.md) 为准。

Windows Go 客户端使用单会话便携 sshd，`ListenAddress 127.0.0.1`、随机高位端口、会话独立 hostkey 和 `authorized_keys`，固定实际账户，关闭密码认证和各类 SSH 转发，保留 PTY/SFTP。Linux 客户端复用系统 sshd，需验证有效配置、账户公钥和回环代理能力；发现服务缺失/停止时须本机确认，不自动升级已有 OpenSSH。

### 6. 数据、密钥与恢复

NyaaRink 把 SQLite 视为可重建的业务投影，而非 SSH 权限的最终权威：

- **`AUTHORITY_DIR`**：独立追加事件账本，保存 instance/epoch、邀请接受、设备登记、撤权、幂等和必要授权元数据；每条事件含序号、前序摘要和 HMAC。账本旁的加密 vault 保存需要跨重启恢复的会话密钥包。
- **`SESSION_MASTER_KEY_FILE`**：恰好 32 字节的主密钥文件，用于加解密秘密和校验权威文件；与账本分开保护和备份。不可随意重生替代原密钥。
- **`STATE_DIR`**：SQLite/WAL、索引、任务/指标投影。服务启动时先验证并重放权威事件，再恢复/校准 SQLite。

受保护写操作先提交权威事件，再更新 SQLite 投影。撤销事件提交后，即使进程在删除旧密钥包前崩溃，重启也只能继续清理，不能恢复 SSH 访问。数据库恢复时保留最新权威账本状态：旧数据库中已撤销的会话不会复活，数据库尚未记录的新有效会话仍可重建。账本损坏、主密钥缺失、实例/世代不符或完整性无法证明时进入 frozen，拒绝新 SSH 访问；不得通过初始化空账本、恢复旧账本或假定“全撤销”绕过冻结。

S端 SSH 私钥只留在服务私密存储和其受控临时运行目录；MCP 不返回私钥。会话密钥包用主密钥加密。浏览器 Cookie、bootstrap key、设备私钥和 SSH 密钥用途相互分离。MCP 管理 Key 本身等于 S端管理权限，应按高敏感凭据保护。

默认不持久保存命令正文、命令输出、终端内容、文件内容或连接脚本。执行结果只在内存内限额、限时保留。持久审计以操作元数据、撤销事件和流量指标为主；系统级 nginx/sshd 仍可能自行记录日志，部署者应独立审查。历史加密备份中的旧秘密不能宣称已被物理擦除。

### 7. 构建、发行、运维和验证

- 服务端基础为 Node.js 24 Debian Bookworm 镜像，Docker Compose 启动 `app` 与 `gateway`；`nginx` 终止 TLS、转发 HTTPS/WSS，Node 服务不直接暴露公网端口。
- C端客户端发行由 `scripts/client-release.py` 构建。版本必须与项目版本一致，生成双平台发行目录和 Ed25519 manifest 签名。独立发行者需自己生成发行密钥，并把公钥同步配置到客户端和服务端再重编译；私钥不可提交。Windows 构建还要核验固定来源的微软 ZIP 哈希与 Authenticode 发布者。
- `rebuild.py` 负责构建/推送服务镜像，不负责启动容器。生产部署由发布 Compose、`restart.py` 和私密 `.env` 完成；上线前校验证书、授权权威完整性、发行签名和 health/readiness。
- 证书由部署者自行申请 Let's Encrypt DNS-01。续期需要安全地把最新证书同步到 NyaaRink 的只读挂载目录并 reload gateway；不要覆盖共享证书服务中的其他消费者 hook。
- 备份时，SQLite 使用一致性备份；权威账本/密钥库和主密钥需要独立保护。只备份数据库不能在整机丢失时恢复授权。
- 源码基础检查包括 `npm ci`、`npm run typecheck`、`npm run lint`、`npm test`、`npm run build`；原生程序在 `apps/client-native` 运行 Go test/vet。真实 SSH、Windows、Linux和生产测试是 opt-in 验收，不应把单元测试通过当成全矩阵支持证明。

### 8. 当前已知验收边界

NyaaRink 的开发阶段和当前交付已完成；公开说明仍应遵循验收记录中保留的未测试项。已实测的 Windows 普通账户流程覆盖：运行连接包、由 MCP 执行 SSH 命令、在用户指定目录创建/读取文件、C端主动断开，以及 S端凭据清理确认。其他证据按验收记录逐项限定。

不要把以下未覆盖范围宣称为全面通过：完整 Windows 登录注销/重启自动恢复矩阵、Windows Server 全平台验证、所有缺少/停止 SSH 服务组合、所有目标 Linux 发行版的原生完整生命周期、未逐个实测的 MCP 客户端完整工作流、独立异网 WSS 与自然到期续期、杀毒厂商误报复核。Windows Preview 组件仍需维护者持续跟踪。

## 四、可升级为方法论的设计要点

### 1. 双重同意：对话意图不等于设备授权

把授权拆成两道：聊天用户明确要求猫猫申请协助；C端用户再在信任边界上审核并接受。模型的意图识别只用于决定是否提出申请或创建待处理邀请，不能替用户执行最后的设备授权。

### 2. 先提案，再邀请，再操作

将流程设计成“解释需求与权限 → 用户同意申请 → 创建邀请 → C端本机接受并运行 → 验证在线身份/范围 → 执行明确任务 → 双方显式撤权”。每一步都产生清晰状态，避免把自然语言同意、链接访问、脚本运行和 SSH 在线混为一谈。

### 3. 会话状态分离

分别表示邀请状态、授权状态、设备登记状态、在线连接状态和两侧清理状态。网络可达性是暂态，授权撤销是不可逆的业务事件；因此“离线”不能自动等于“结束”，“连接失败”不能自动等于“撤权成功”。

### 4. 管理控制面和远程数据面分离

MCP/REST 负责创建有界操作和检查状态；SSH 字节只通过经设备签名认证、会话绑定、限时单次票据授权的 WSS 数据流。C端只连本机回环 sshd，避免开放 C端公网 SSH 和通用内网代理。

### 5. 能力边界要诚实

“文件 API 限制在 home”不代表 SSH 命令被限制在 home；“密钥认证”不代表命令只读；“容器化”不代表每层默认隔离都存在。文档和 GUI 必须把实际账户权限、撤权效果、数据保留以及部署例外说清楚。

### 6. 安全失败时冻结，不推测授权

权威数据缺失或状态不一致时，系统不能猜测数据库备份是否新、不能默认为全部撤销，也不能恢复旧记录造成权限复活。冻结访问并等待权威数据校验，是安全可审计的失效策略。

### 7. 幂等和未知结果的操作纪律

对创建邀请、接受、设备登记和执行命令使用稳定幂等 ID。结果未知时查询原对象、复用原请求标识；不通过换 ID 来重放有副作用的命令。取消一条任务与撤销整份会话应是不同操作。

### 8. 让撤权成为一等操作

邀请、运行、指标和命令工具之外，必须有醒目、不可歧义的显式断开入口；撤权先写权威状态，再中断数据流、销毁服务端凭据并收集设备清理回执。pending/failed 不能伪装为 confirmed，且撤权后的访问不能由旧脚本或自动重连恢复。

### 9. 验收与产品声明保持同一粒度

按“操作系统 × 账户类型 × 登录/断网/恢复场景 × MCP 客户端 × 部署条件”记录证据。某一 Windows 普通账户链路通过，不等于 Windows Server、Linux 全矩阵或全部 MCP 客户端通过。保留未测项并在界面、README 和技术文档中使用一致边界。

### 10. 区分可复用能力与一次性集成

NyaaRink MCP 是稳定的服务接口；AstrBot 猫猫属于调用方。对话策略负责理解意图、沟通风险、保持范围并正确收尾，服务端负责鉴权、授权状态、隧道和凭据清理。将两者通过明确工具契约衔接，避免把服务权限判断只放在 LLM 提示词或某个已删除的单体插件里。

## 参考文档

- [NyaaRink 仓库与 README](https://github.com/NyaaCaster/NyaaRink)
- [使用指南](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/使用指南.md)
- [API、MCP 与 CLI 标准](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/技术标准-API-MCP与CLI.md)
- [授权生命周期与隧道标准](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/技术标准-授权生命周期与隧道.md)
- [C端部署、自动恢复与撤销标准](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/技术标准-C端部署与撤销.md)
- [凭据持久化与恢复标准](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/技术标准-凭据持久化与恢复.md)
- [部署与验收标准](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/技术标准-部署与验收.md)
- [设计决策](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/设计决策.md)
- [验收记录](https://github.com/NyaaCaster/NyaaRink/blob/main/.docs/验收记录.md)
