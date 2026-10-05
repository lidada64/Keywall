# Keywall

本地 CLI 密钥保险库与上传前检查工具，命令可简写为 `kw`。将 key 存入加密保险库，通过别名使用，并在 Git 推送或文件上传前检查密钥泄露。独立运行，不需要 1Password、云账户或第三方密码管理器。

当前版本：**0.1.4** · [更新记录](CHANGELOG.md) · [安全说明](SECURITY.md) · [MIT 许可证](LICENSE)

适合以终端和代码 Agent 为主的工作流：隐藏输入 key、按名称查找、向可信子程序提供指定 key，以及为普通 `git push` 安装全局或单仓库检查。

**当前版本未经独立安全审计。它防范通过受控入口发生的误泄露，不是全系统防火墙。**

## 下载即用（Windows x64）

Windows 发布包为包含 .NET 运行时的独立程序，无需安装 SDK。二进制发布后可在 [Releases](https://github.com/lidada64/Keywall/releases) 下载 ZIP 和 SHA-256 清单；也可以按下方步骤自行构建。解压发布包后，在该目录的 PowerShell 中运行：

```powershell
.\kw.exe init
.\kw.exe add service/dev --note "开发环境 API"
.\kw.exe find service
.\kw.exe info service/dev
.\kw.exe hook install --global
```

`init` 设置至少 8 字符的主密码；输入主密码与 key 时不显示字符，也不把 key 放进命令参数或命令历史。Windows 下初始化后保持会话解锁，后续命令无需重复输入主密码。

所有命令都可以将 `keywall` 简写为 `kw`；发布包包含等价的 `kw.exe`，共享同一个默认保险库。例如：`kw init`、`kw add service/dev`、`kw find service`。

```powershell
kw login       # 已有保险库：第一次输入主密码，后续命令无需重复输入
kw status      # 查看解锁状态
kw lock        # 立即锁定；下次使用时重新输入主密码
kw add --help  # 查看 add 的参数，不需要解锁
```

解锁状态由当前 Windows 登录会话中的后台进程在内存中保持，主密码不会缓存到磁盘。注销 Windows、重启、`kw lock`、后台进程结束或更新程序后，需要重新解锁。关闭终端通常不结束后台会话。`--no-session` 可对单次命令恢复每次输入密码的行为；它不会清除其他命令已建立的会话，严格使用前先 `kw lock`。同一 Windows 用户与登录会话中的程序可以使用已解锁保险库，包括 Agent；这不构成同账户进程之间的隔离。

默认保险库路径为 `%LOCALAPPDATA%\Keywall\vault.json`。名称、备注、上传目标与 key 均在加密内容中。可以用 `--vault D:\private\vault.json` 指定其他位置；不要把保险库放进要上传的目录。

发布包包含 .NET 运行时，无需安装 SDK。第一次运行需要创建保险库并添加自己的 key，软件不预置任何凭据。源码构建也可在支持 .NET 8 的系统运行；Windows 账户模式仅限 Windows。

## 搜索、查看与使用

```powershell
keywall find github
keywall info github/personal
keywall reveal github/personal
keywall run --key service/dev --env SERVICE_TOKEN -- python app.py
keywall add service/dev --replace
keywall remove service/dev
```

- `list`、`find`、`info` 默认不输出明文。备注只用于说明用途，避免在其中填写其他敏感信息。
- `reveal` 必须在自己的交互终端中输入 `REVEAL`，禁止重定向与管道输出；明文会留在终端滚动记录中。
- `run` 只给子进程注入指定环境变量，不修改全局环境、不隐式启动 shell；标准输出与错误输出中的已存密钥及常见编码会被遮盖。超过 64 KiB 的输出行会终止子进程。
- **子进程能够读取 key，也能写文件或发网络请求。只能对可信程序使用 `run`。输出遮盖不是隔离。** 交互程序可能因管道与逐行检查而改变行为；本版本不保证兼容所有 TUI。
- 默认没有自动复制到剪贴板的功能，避免增加明文副本。

将解压目录加入用户 PATH 后，可以从任意目录运行 `kw`；未加入 PATH 时，请使用程序的完整路径或在解压目录使用 `.\kw.exe`。普通保险库命令不会修改全局 Git 配置。`hook install --global` 是主动启用全局 Git 检查的命令。

从源码生成发布包后，还可以运行安装脚本：

```powershell
pwsh -File scripts/install.ps1
# 安装已有解压包时指定其目录
pwsh -File scripts/install.ps1 -SourceDirectory "C:\Downloads\keywall-win-x64"
```

安装脚本将程序复制到 `%LOCALAPPDATA%\Programs\Keywall` 并加入用户 PATH。更新会结束当前解锁会话，但保留保险库；更新后执行 `kw login`。安装本身不会启用 Git hooks，需另行执行 `kw hook install --global`。

## 上传前的墙

检查文件、目录、ZIP（包括 ZIP 格式的 DOCX、APK 等）：

```powershell
keywall scan .\release.zip
keywall scan .\src
```

检查包括：保险库中的密钥原文、UTF-16、Base64、URL 编码、十六进制表示，以及部分 GitHub/AWS/API/Slack token、私钥头和凭据赋值模式。报告只显示文件和规则，不打印命中的 key。匹配规则有误报和漏报；**扫描通过不等于不存在敏感数据**。

限制：32 MiB/文件、128 MiB/扫描、10000 文件、最多三层 ZIP。超过限制、读取失败、损坏或无法解压的 ZIP 会阻止操作。RAR、7z、gzip、tar、PDF、旧 Office 容器等明确不支持的格式会阻止操作。目录中的符号链接和重解析点不会跟随。目录扫描不自动跳过 `.git`、`node_modules` 或其他文件夹，建议只扫描实际产物目录。

### Git 推送

在仓库目录中运行：

```powershell
keywall push origin main
# 或指定仓库
keywall push origin main --repo D:\projects\my-project
```

只接受已配置的 remote 名称及一个分支。检查该提交相对于远端当前引用新增的完整 blob；远端已有的对象不重复阻止干净推送。尚未推送的历史里出现过密钥，即使后来删除或加入 `.gitignore`，仍会阻止推送。未跟踪、被忽略的本地 `.env` 不在 Git 扫描范围内。固定已检查的提交 ID，并用远端引用租约避免检查期间发生变化。不推送额外 tags 或子模块，不允许非快进更新；若远端旧对象在本地不存在，先自行 fetch。新建远端引用没有基线，检查全部可达历史。

Git 认证依赖你已有的 Git/SSH 凭据设置，本版不会将保险库 key 注入 Git 的 URL。新增 Git LFS 指针会被拒绝，因为真实内容在外部存储中。扫描受 30000 Git 对象限制。`.gitignore` 不会移除已跟踪文件或历史内容，不能用忽略规则放行尚未推送的泄露。已经到过远端的 key 仍需要撤销或轮换；放行后续干净推送并不表示历史泄露已消除。

若希望所有仓库默认启用（包含以后新建的仓库），只需全局安装一次：

```powershell
kw hook install --global
kw hook status --global
kw login
```

全局模式设置用户级 `core.hooksPath`，保留原全局钩子目录的执行；原来没有全局目录时，转发到各仓库默认的 hooks，包括已有 pre-push 和 pre-commit。只在 pre-push 中增加 kw 检查。`kw hook remove --global` 恢复安装前的全局配置。仓库本地 `core.hooksPath` 会覆盖全局设置，需要在该仓库的钩子中另行接入；全局模式不能强制覆盖这些配置，也不能防止主动禁用 hooks。

只保护单个仓库时：

```powershell
kw hook install --repo "D:\你的项目"
kw hook status --repo "D:\你的项目"
kw login
git -C "D:\你的项目" push origin main
```

安装后 `pre-push` 会按 Git 提供的远端当前对象 ID，检查每个非删除引用的新增对象（含尚未推送的历史）；发现密钥、保险库锁定、程序缺失或检查异常都会阻止推送。密码模式先在交互终端执行 `kw login`，不要把主密码写在 hook 内。可用 `--vault PATH` 绑定其他保险库，随后也要用相同路径登录。

已有 `pre-push` 会备份为 `pre-push.keywall-original`，检查通过后执行，并传递相同的参数和引用输入；其他 hooks 不修改。`kw hook remove --repo PATH` 恢复原钩子。钩子绑定安装时的可执行文件和保险库路径；搬迁后应卸载再安装。此设置只作用于当前仓库（包括共享 Git 目录的 worktrees），新仓库需单独安装。若已配置 `core.hooksPath`，命令拒绝自动修改共享或工具管理的目录；可自行将 `kw git-check --stdin` 接入现有 pre-push，并保留输入供其他检查使用。

这是本地防误传措施。`git push --no-verify`、覆盖 `core.hooksPath`、删除钩子都可以绕过；若需要强制约束，应在 Git 服务端增加密钥检查。Git 官方协议说明：[pre-push](https://git-scm.com/docs/githooks#_pre_push)。

### HTTPS 文件上传

先登记固定目标，再上传。当前协议为 **HTTPS PUT**，不通用于任意云平台的 multipart、SFTP 或部署 CLI：

```powershell
keywall target add artifacts https://uploads.example.com/releases/build.zip --key upload/prod
keywall target list
keywall upload .\release.zip --target artifacts
# X-API-Key 形式
keywall target add api https://uploads.example.com/blob --key upload/prod --header X-API-Key --prefix ""
```

上述域名是示例，你需要自己的支持 PUT 的接口。默认鉴权头为 `Authorization: Bearer <key>`。目标 URL 不允许用户名、查询参数或片段；不得在 URL 中塞 key。TLS 使用系统证书验证，禁用重定向、禁用 Cookie，不输出响应正文。

上传前将文件读取到有大小上限的内存副本，检查后发送**同一份字节**，源文件被改动也不会替换上传内容。输出 SHA-256 方便核对。密钥由 Keywall 添加到目标的请求头，调用方无需收到明文。失败没有自动重试；服务端可能已部分或完整接收请求，请自行核查。

**直接使用 curl、scp、浏览器或其他发布工具会绕过这道墙。** 要强制所有 Agent 上传经过受控入口，需要另行配置 OS 沙箱、服务身份和网络出口，本版本没有全局拦截能力。

## 保险库与恢复

- 默认：PBKDF2-HMAC-SHA256（600000 次、随机 16 字节 salt）派生 256 位 key；AES-GCM、随机 12 字节 nonce、16 字节认证 tag。使用 .NET 自带实现，不自创算法。格式固定版本与认证关联数据。
- Windows 会话代理仅在内存中持有派生 key，通过限定当前用户的命名管道提供解锁；范围绑定当前用户 SID、Windows 登录会话和保险库路径。每条命令重新读取并验证加密保险库，不缓存条目副本。不同保险库的会话分别解锁和锁定。
- 保存使用临时加密文件、落盘 flush 和原子替换；独占锁避免并发覆盖。Windows 上依赖文件系统与账号权限，不会自动重写 ACL。
- `keywall init --windows`：Windows 用户范围 DPAPI。无需每次输入主密码，但同一用户权限的程序可能解密；不能宣称 Agent 看不到 key。该模式仅绑定当前 Windows 用户环境，不提供可移植备份。
- 主密码模式支持加密备份。备份不覆盖已有文件；路径含空格时应加引号。

```powershell
keywall backup D:\backup\keywall.kwvault
```

恢复时，将加密备份复制到新的路径，然后使用 `keywall --vault "D:\restore\vault.json" list` 并输入原主密码。主密码丢失没有后门；旧备份仍含旧 key，删除条目不会销毁既有备份，泄露应在上游撤销。

主密码和 key 不通过环境变量或命令参数接收。仅为受信程序管道提供显式 `--password-stdin`、`add --stdin`；组合时先一行主密码，再一行 key。`--password-stdin` 默认绕过会话缓存且不建立会话，显式 `login` 除外。不要使用包含真实密钥的 `echo` 命令、脚本常量或 shell 历史来提供这些输入。

## 与 Agent 配合

让 Agent 处理代码和查看别名，自己在交互终端解锁。不要将主密码、key 或 `reveal` 输出贴入聊天。上传凭据可以由 `upload` 内部使用，Agent 只需知道目标别名。

本版未实现通用 API 代理/MCP，也不把任意程序的身份当成安全证明。同账户进程、管理员、恶意依赖、内存抓取、修改本程序或直接上传均超出保护范围。会话解锁期间，不要把“首次输入过密码”当成后续调用者认证。详见 [SECURITY.md](SECURITY.md)。

## 构建、验证与打包

需要 .NET 8 或兼容的更新 SDK；打包脚本需要 PowerShell 7。Python 回归脚本使用标准库。

```powershell
git clone https://github.com/lidada64/Keywall.git
cd Keywall
dotnet restore tests/Keywall.Tests/Keywall.Tests.csproj --configfile NuGet.Config
dotnet run --project tests/Keywall.Tests/Keywall.Tests.csproj -c Release
pwsh -File scripts/package.ps1
python tests/smoke.py dist/keywall-win-x64/keywall.exe
python tests/hook-smoke.py dist/keywall-win-x64/kw.exe
python tests/global-hook-smoke.py dist/keywall-win-x64/kw.exe
python tests/ignored-env-smoke.py dist/keywall-win-x64/kw.exe
```

打包脚本查询 Microsoft 官方 .NET 8 发布元数据，选择最新运行时补丁，生成独立 Windows x64 可执行文件、ZIP 和 SHA-256 清单。下载来源为 Microsoft/NuGet。核心源码没有第三方 NuGet 包依赖；发布包包含微软运行时，保留其许可与第三方声明。

回归脚本使用假密钥、临时保险库、隔离的 Git 配置和本地 bare 远端，不上传真实凭据。测试包含加密存储、输出遮盖、上传快照、全局钩子转发，以及忽略 `.env` 与尚未推送的历史泄露的区别。

`.github/workflows/ci.yml` 负责构建和回归测试；release workflow 由版本 tag 触发。打包产物在 `dist/`，保险库、缓存、测试输出和本机专用文档不进入源码仓库。公开发布前请阅读安全边界，并让独立人员审阅。
