# MythwareGuard · 极域学生端守护 + 退出取证

两个原生 Windows 程序，无控制台、无运行时依赖、无安装框架。

| 文件 | 大小 | 作用 |
|---|---|---|
| `MythwareGuard.exe` | 229 KB | 装在学生机：守护极域双进程，每次极域被结束都记一条事件并发到局域网 |
| `MwReceiver.exe` | 100 KB | 装在管理机：只接收退出事件，落盘持久化，可随时查询导出 |

**实测（Windows Server 2025）**：杀掉极域进程 → 新进程出现 **48 ms**（另有 57 ms / 107 ms 样本），一次击杀只产生一个进程、一条事件。

---

## 一、快速开始

双击 `MythwareGuard.exe` → UAC 确认 → 点「是」。装到 `C:\ProgramData\MythwareGuard\`。

```cmd
MythwareGuard.exe --install      :: 静默安装（机房推包用）
MythwareGuard.exe --status       :: 查看守护与目标状态
MythwareGuard.exe --uninstall    :: 卸载
```

管理机双击 `MwReceiver.exe` 即可，端口冲突时 `MwReceiver.exe --port 17900`。

---

## 二、守护结构

| 层 | 进程 | 权限 | 职责 |
|---|---|---|---|
| L1 | `mwcore.exe --role warden` | SYSTEM | 守护 L2/L3，兼管 session 0 目标 |
| L2 | `mwsync.exe --role shadow` | SYSTEM | 只保住 L1，**不碰目标、不上报** |
| L3 | `mwhost.exe --role node` | 用户会话 | 守护本会话的极域进程 |
| L4 | 计划任务 `--role revive` | SYSTEM | 每分钟自检，缺失即复活 L1/L2 |

**响应机制**：监管句柄常驻内核，进程退出的瞬间内核就 signal，守护在同一轮内重建
（检测 0 ms + `CreateProcess` ~30 ms）。同时监管极域目标、对端守护、会话 node 三类进程，
任一消失立即唤醒同一个等待。兜底轮询 200 ms，正常运行时 CPU ≈ 0。

**会话归属**：node 只管自己会话的目标；session 0（服务态）以及 node 已死的会话由 SYSTEM 层接管。
取不到目标会话 token 时降级到当前桌面启动，不会把目标丢在半死状态。

**镜像冗余**：三个不同文件名的副本 + `mirror\bin.dat`，删掉一个文件不影响已加载的进程，
重建时自动从镜像恢复。

### 极域目标

```ini
target:TopDomain.exe=required       ; 必须存活，找不到时自动发现
target:MasterHelper.exe=required
target:StudentMain.exe=              ; 出现过才守护
target:Student.exe=
target:MythwareStudent.exe=
```

`required` 找不到 exe 时按「运行中进程 → 注册表 Uninstall → Program Files 目录」三级发现，
失败后退避 2 分钟重试。

---

## 三、事件上报

**平时零流量**，只有极域进程消失的那一刻才发一条。

### 可靠性：先落盘，再投递

事件先写入 `C:\ProgramData\MythwareGuard\queue\<role>\*.json`，收到 HTTP 200 才删除；
断网、接收端不在线、机器重启都不丢。失败按 1→2→4→8→16→30 秒指数退避重试，上限 30 秒。
队列上限 2000 条，超出丢最旧。

### 加密：RSA-2048 / OAEP-SHA256

RSA 单块只能加密 190 字节（2048 位密钥 + OAEP-SHA256 的 66 字节开销），而一条事件约 300 字节，
因此**按 190 字节分块逐块加密**，密文 base64 后传输。接收端用私钥逐块解回。
全链路只用 RSA，不掺对称算法。

公钥由接收端首次运行时生成，客户端用 `GET /api/v1/pubkey` 自动获取并缓存到
`%ProgramData%\MythwareGuard\keys\collector.pub`。

### 传输：HTTP/1.1，端口 17800

```
GET  /api/v1/pubkey          取收集端公钥
POST /api/v1/events          上报事件（body 为 base64 密文）
GET  /api/v1/health          健康检查
GET  /api/v1/events?limit=N  读取最近事件（JSON 数组）
```

发现走 UDP 17800：客户端先发受限广播 `255.255.255.255`，再按每张网卡的子网广播地址各发一次
（应对禁广播的网络），接收端回 `MWGD!1`，源地址即为收集端 IP。2 秒无应答则下轮重试。

不使用 80/443，不跑 HTTP 服务框架。

### 事件格式

```json
{"v":1,"ev":"exit","ts":1793886903,"id":"<MachineGuid>","host":"PC-001",
 "user":"student01","group":"A机房","ip":"192.168.1.23","mac":"AA-BB-CC-DD-EE-FF",
 "name":"MasterHelper.exe","pid":964,"ok":1,"newpid":9576}
```

- `name` 被结束的进程，`pid` 死前 PID，`newpid` 重新拉起后的 PID，`ok=0` 表示没拉起来；
- `user` 取控制台登录用户（`WTSQuerySessionInformation`），SYSTEM 身份下也准确；
- `id` 为注册表 `MachineGuid`，换 IP 也能对上同一台机器。

---

## 四、接收端

窗口是一张按时间倒序的取证表：时间 / 电脑 / 用户 / IP / 分组 / 被退出的进程 / PID / 自动恢复。
恢复失败整行标红。顶部输入框实时筛选，一键导出 Excel 可直接打开的 UTF-8 CSV。

```
C:\ProgramData\MwReceiver\
├── events\2026-11-05.jsonl      每天一个文件，只追加不覆盖
├── keys\private.blob            私钥（首次运行自动生成）
├── keys\public.blob
├── receiver.log
└── export-*.csv
```

启动时自动载入历史（内存上限 8000 条，最旧先淘汰，磁盘不动）。关掉重开数据还在，
换机器把 `events` 目录整个拷走即可。

首次运行 Windows 会弹防火墙提示，允许「专用网络」；被策略拦下时管理员执行：

```cmd
netsh advfirewall firewall add rule name="MwReceiver" dir=in action=allow protocol=TCP localport=17800
netsh advfirewall firewall add rule name="MwReceiverUDP" dir=in action=allow protocol=UDP localport=17800
```

---

## 五、配置

`C:\ProgramData\MythwareGuard\config.ini`，改完重启守护生效：

```ini
debug=1                   ; 调试日志（默认开，排查完可设 0 降噪）
poll_ms=200
peer_timeout=12
harden=0                  ; 1 = 给极域进程加 deny-TERMINATE ACL
critical=0                ; 1 = 守护进程设为 critical（被强杀会蓝屏）

report_enable=1
report_port=17800
report_crypto=1
report_server=            ; 留空自动发现，填 IP 则直连
report_group=A机房
```

`harden=1` 会让极域进程连任务管理器都杀不掉，但副作用是**极域自身的「退出」和在线升级也会失败**，
所以默认关闭。需要更强保护时再打开，并接受这个代价。

---

## 六、构建

需要 [zig](https://ziglang.org)（自带 mingw 交叉工具链，Linux/macOS/Windows 都能构建）：

```bash
./build_all.sh          # 产出 dist/MythwareGuard.exe 与 dist/MwReceiver.exe
```

产物为 x86_64、`subsystem=2`（无控制台）、静态链接 mingw 运行时，
仅依赖系统 DLL（KERNEL32 / USER32 / ADVAPI32 / WTSAPI32 / USERENV / SHELL32 / WS2_32 / IPHLPAPI / BCRYPT + UCRT），
已启用 ASLR(DYNAMICBASE) 与 DEP(NXCOMPAT)，内嵌图标与版本资源。

源码结构：

```
src/common.c     路径、日志、key/value 文档
src/win.c        进程/会话/提权/ACL 封装
src/guard.c      配置、exe 发现、共享状态、角色启动
src/engine.c     监护循环、目标归属、角色入口
src/report.c     落盘队列、RSA 信封、HTTP 投递
src/crypto.c     RSA-2048 分段加解密、base64
src/setup.c      安装/卸载/状态
src/main.c       WinMain 与命令行分发
receiver/core.c  事件存储、JSONL、HTTP 服务、密钥管理
receiver/gui.c   Win32 列表界面、筛选、导出
```

---

## 七、已知限制

- 仅在 **Windows Server 2025** 上做过真机验证；Windows 8.1/10/11 应当可用（同 ABI），Win7 需 KB2999226 且抓不到极域原始命令行；
- 未做代码签名，个别杀软对「结束即拉起」敏感，加白名单即可；**不建议再套 UPX**，压缩壳会显著提高误报率；
- 升级安装时旧 exe 会被轮换为 `*.old`（运行中的映像不能覆盖、只能改名），残留文件可随时删除；
- 事件为明文 JSON 的 RSA 密文，面向可信内网；需要收敛范围时用 `report_server` 指定单台接收端；
- 不做公网中继/远程兜底——设计场景是机房局域网内部署。

---

## 八、许可

MIT License，见 `LICENSE`。
