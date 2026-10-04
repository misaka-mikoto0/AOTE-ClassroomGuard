# AOTE - 实力主义至上的一体机管控系统

> All-in-One of the Elite (AOTE) Classroom Guardian System

班级大屏幕一体机非上课时段使用管控系统。作为后台守护程序，在非上课时间自动限制设备使用（通过**浏览器内容管控**拦截视频、游戏等无关网站 + **弱网管控**限制黑名单站点访问），仅允许通过**热键密码豁免**或**授权U盘**临时解锁，引导学生合理使用设备。

> 本版本已彻底移除所有基于进程的操作（进程冻结、杀进程、双进程守护、WMI/注册表自启动等），管控完全基于浏览器层面实现（Playwright 浏览器沙盒）。

---

## 📖 目录

- [项目背景](#-项目背景)
- [功能特性](#-功能特性)
- [技术架构](#-技术架构)
- [安装指南](#-安装指南)
- [使用说明](#-使用说明)
- [CDP 调试浏览器（推荐）](#-cdp-调试浏览器推荐)
- [配置说明](#-配置说明)
- [项目结构](#-项目结构)
- [测试](#-测试)
- [贡献方式](#-贡献方式)
- [许可证](#-许可证)
- [免责声明](#-免责声明)

---

## 🎯 项目背景

班级配备的大屏幕一体机（交互式电子白板/教学一体机）在非上课时间常被用于播放与学习无关的视频内容。本系统作为后台守护程序，在非上课时段自动限制设备使用，仅允许通过特定方式（热键密码豁免或授权U盘）临时解锁。

系统核心理念：**实力主义至上** —— 想用电脑？先证明你有权限（管理员密码豁免 / 授权U盘）。

---

## ✨ 功能特性

### 核心模块

| 模块 | 说明 |
|------|------|
| ⏰ **时间调度 (Time Guard)** | 根据课程表自动判断上课/下课时间，切换严格/宽松/紧急三种模式；支持节假日例外配置 |
| 🌐 **浏览器沙盒 (Browser Sandbox)** | 基于 Playwright 直接控制浏览器内容：域名黑/白名单拦截、`route.fulfill` 返回拦截页、`page.evaluate` 内容控制、**非上课时间全面禁止视频播放** |
| 📶 **弱网管控 (Weak Network)** | **持续监控每个访问请求**，命中黑名单域名即时切换弱网（CDP 模拟延迟+限速 + 请求级附加延迟）；离开黑名单站点自动恢复，不影响非黑名单网站正常访问 |
| 🔑 **U盘授权 (USB Guard)** | 双因素认证（硬件ID + 密钥文件SHA-256）；支持「即拔即禁 / 定时解锁 / 维护模式」 |
| 🛡️ **防绕过 (Anti-Tamper)** | 管理员密码验证 + 浏览器沙盒心跳监控（无任何进程操作） |
| 🌐 **HTTP服务** | 本地 `127.0.0.1:8765`；`/ping` 心跳、浏览器违禁内容上报（调沙盒拦截） |
| 📊 **系统托盘** | 状态显示（含弱网状态）、临时解锁、密码豁免、紧急退出入口 |
| 📝 **日志系统** | 控制台 + 按天轮转文件双输出；记录模式切换/浏览器拦截/弱网切换/U盘事件/防绕过触发 |

### 弱网管控亮点

- **持续监控**：路由层拦截每一个访问请求，实时判定是否命中黑名单
- **命中即切换**：访问黑名单域名/URL 的瞬间，该页面立即切换为弱网
  - CDP `Network.emulateNetworkConditions`：模拟延迟 800ms + 下载限速 128KB/s + 上传限速 64KB/s
  - 请求级附加延迟 3000ms：每个命中黑名单的请求额外延迟，视频/下载彻底卡顿
- **互不影响**：弱网为 per-page 生效，只限速命中黑名单的页面，非黑名单网站不受任何影响
- **自动恢复**：离开黑名单站点超过最短时长（默认15秒）自动恢复全速，防止频繁抖动
- **密码豁免**：按热键 `Ctrl+Shift+Alt+G` 输入管理员密码即可豁免（临时/永久解锁），无需做题

---

## 🏗️ 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                      main.py (主进程)                        │
│   GuardianApp - 协调整合所有模块（单进程架构，无守护子进程） │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐   ┌────────────────┐   ┌──────────────┐   │
│  │  TimeGuard   │   │BrowserSandbox  │   │ WeakNetwork  │   │
│  │  时间调度    │──▶│ 浏览器内容管控 │──▶│  弱网管控    │   │
│  └──────────────┘   └────────────────┘   └──────────────┘   │
│         ▲                   │    ▲                │           │
│         │                   │    │                ▼           │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐      │
│  │ AntiTamper   │   │  USBGuard    │   │ HTTPServer   │      │
│  │  防绕过      │   │  U盘授权     │   │  内容上报    │      │
│  └──────────────┘   └──────────────┘   └──────────────┘      │
│         │                                       │              │
│  ┌──────────────┐                      ┌──────────────┐      │
│  │  SystemTray  │                      │   Logger     │      │
│  │  系统托盘    │                      │ 控制台+轮转  │      │
│  └──────────────┘                      └──────────────┘      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 浏览器沙盒两种运行模式

| 模式 | 说明 |
|------|------|
| **自主启动模式** | 程序自己启动一个独立浏览器实例（独立 `--user-data-dir`，不污染主浏览器），携带 `--disable-web-security` / `--proxy-server` / `--remote-debugging-port=9222` |
| **CDP 接管模式（调试推荐）** | 通过桌面快捷方式启动带调试端口的 Edge，主程序用 `connect_over_cdp` 接管该浏览器；断线自动重连，关闭沙盒不关浏览器 |

### 技术栈

- **语言**：Python 3.10+
- **浏览器控制**：`playwright`（chromium/msedge channel，`route.fulfill`、`page.evaluate`、CDP Session）
- **GUI**：`tkinter`（U盘模式选择、密码验证）
- **托盘**：`pystray` + `Pillow`
- **配置**：`PyYAML`（支持热重载）

### 运行模式

| 模式 | 触发条件 | 行为 |
|------|---------|------|
| 严格模式 | 非上课时间 | 浏览器黑名单域名全部拦截（`route.fulfill` 返回拦截页）；**全面禁止视频播放**（无论什么网站，含学习站点内嵌视频）；访问违禁站点自动切换弱网 |
| 宽松模式 | 上课时间 | 不拦截，仅记录访问日志与违禁内容上报 |
| 已解锁（豁免） | 密码验证 / 授权U盘 | 全部放行 + 恢复网络，直到临时解锁到期或重新拔插 |

### 视频播放管控（非上课时间全面禁视频）

严格模式期间，**双管齐下**禁止一切视频播放，不区分网站（学习网站内嵌视频同样禁）：

1. **JS 层禁用播放逻辑**：向每个页面注入管控脚本
   - 覆盖 `HTMLMediaElement.prototype.play/load/canPlayType`
   - 拦截 `src` 属性赋值（播放器拿不到视频源）
   - `MutationObserver` 兜底：新插入的 `<video>/<audio>` 自动暂停清空
   - 页面顶部弹出提示浮层：`当前为非上课时间段，视频播放已被管控`
   - 全局开关控制，切换上课/下课模式**无需刷新页面**即时生效
2. **网络层拦截视频资源**：路由层对视频请求（`.mp4/.m3u8/.flv/...` 或 `media` 资源类型）直接 `fulfill 403`，杜绝漏网之鱼

> 配置开关：`config/config.yaml` → `browser_rules.video_block_enabled: true`（默认开启；设为 `false` 可关闭）

---

## 📦 安装指南

### 环境要求

- **操作系统**：Windows 10/11 x64
- **Python**：3.10+
- **浏览器**：本机已安装 Microsoft Edge 或 Google Chrome（自动探测复用，无需额外下载浏览器）

### 安装步骤

1. **克隆仓库**

   ```bash
   git clone https://github.com/<your-account>/AOTE-ClassroomGuard.git
   cd AOTE-ClassroomGuard
   ```

2. **创建虚拟环境（推荐）**

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **安装依赖**

   ```powershell
   pip install -r requirements.txt
   ```

4. **（可选）创建 CDP 调试浏览器桌面快捷方式**

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\create_cdp_shortcut.ps1
   ```

5. **（可选）接管任务栏/状态栏等所有启动入口**

   想让学生**无论从任务栏固定图标、开始菜单还是点击网页链接**打开的 Edge 都自动带调试端口、纳入 CDP 管控，可执行：

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\hijack_browser_entries.ps1
   ```

   它会：① 在 `HKCU\Software\Classes\MSEdgeHTM\shell\open\command` 写入带 `--remote-debugging-port=9222` 的 URL 关联命令（无需管理员权限，对当前用户生效）；② 给任务栏/开始菜单/桌面上固定的 Edge 快捷方式追加 CDP 参数。

   还原方式：`...\hijack_browser_entries.ps1 -Revert`（原注册表值/快捷方式自动备份于 `%LOCALAPPDATA%\AOTE\`）。

5. **运行测试**（可选，验证安装）

   ```powershell
   python test_suite.py
   ```

> **注意**：系统**不再自动打开/拉起浏览器**，改为通过 CDP 接管用户手动打开的调试浏览器。直接复用本机已安装的 Edge/Chrome，**无需**执行 `python -m playwright install chromium` 下载浏览器。

---

## 🚀 使用说明

### 启动系统

```powershell
python main.py
```

启动后：
- 系统托盘出现蓝色盾牌图标
- 控制台与 `aote.log` 同步输出运行日志（含浏览器访问记录）
- 进入 CDP 接管模式，等待用户手动打开调试浏览器后接管（系统不自动打开浏览器）

### 命令行参数

| 参数 | 说明 |
|------|------|
| `python main.py` | 标准模式（单进程，浏览器内容管控） |
| `python main.py --install-autostart` | 设置开机自启动（写入 HKCU Run 键，无需管理员） |
| `python main.py --remove-autostart` | 取消开机自启动 |
| `python main.py --autostart-status` | 查询开机自启动状态 |
| `python uninstall.py` | 卸载清理（仅删除本程序数据文件，不做任何系统修改） |

> exe 版本同样支持以上参数，例如 `AOTE.exe --autostart-status`。

### 打包为 exe 并设置开机自启动

将项目打包为**单文件免 Python 环境**的可执行程序（Python 运行时、全部依赖、playwright 驱动、config 配置全部内嵌），并注册开机自启动：

```powershell
# 一键打包 + 设置开机自启动（产物: dist\AOTE.exe，约 62MB）
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -SetAutostart

# 其他常用命令
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1            # 仅重新打包
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -NoBuild   # 跳过打包，仅处理自启动
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -RemoveAutostart      # 取消开机自启动
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -AutostartStatus      # 查询自启动状态
```

打包要点：
- 使用 `aote.spec`（PyInstaller **onefile** 单文件模式，`console=False` 无窗口托盘应用），`collect_all("playwright")` 完整收集 playwright 驱动（`node.exe`），整个程序只需一个 exe 即可运行，无需安装 Python/playwright/浏览器下载
- **配置内嵌 + 可覆盖**：`config\config.yaml` 已打进 exe；同时脚本会复制一份到 exe 旁的 `dist\config\`，exe 优先读取旁置配置（可编辑、热重载生效），删除旁置配置后自动回退到内嵌配置
- 自启动项写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`（值名 `AOTE_Guardian`），仅当前用户生效、无需管理员权限
- 重打包时使用 `--clean` 清理旧产物；发布时只需拷贝 `dist\AOTE.exe` 一个文件

### 解锁方式

#### 方式一：热键密码豁免

按热键 `Ctrl + Shift + Alt + G`（或托盘「密码豁免」）：
1. 弹出管理员密码验证窗口
2. 输入正确密码 → 可选择「临时解锁（5/30分钟）」或「永久解锁」
3. 豁免期间全部放行、网络恢复；到期自动回到严格模式

> 黑名单站点命中后自动切换弱网，同样可通过热键密码豁免恢复正常。

#### 方式二：授权U盘

插入授权U盘后弹出模式选择：
- **即拔即禁**：U盘拔出前保持解锁，拔出后3秒内恢复严格模式
- **定时解锁**：30分钟 / 1小时 / 2小时，到期自动恢复
- **维护模式**：需管理员密码二次确认，解锁至下次重启

### 紧急退出

- 快捷键：`Ctrl + Shift + Alt + G`
- 或托盘右键 → 「紧急退出系统」
- 输入管理员密码验证通过后完全退出

---

## 🔌 CDP 调试浏览器（推荐）

通过 CDP 接管模式，你可以在**自己常用的 Edge** 里浏览，主程序实时记录每一个访问的网站。

### 使用步骤

1. **确保配置**（`config/config.yaml`）：
   ```yaml
   browser_sandbox:
     connect_cdp_url: "http://127.0.0.1:9222"   # 非空 = CDP 接管模式
   ```

2. **创建桌面快捷方式**（只需一次）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\create_cdp_shortcut.ps1
   ```
   桌面生成「AOTE CDP Debug Browser」，它用**独立配置目录**启动 Edge 并开启调试端口 9222。

3. **启动主程序**：
   ```powershell
   python main.py
   ```

4. **双击桌面「AOTE CDP Debug Browser」** 打开浏览器，正常访问网站即可。

5. **查看日志**：控制台实时输出（也写入 `logs\aote.log`）：
   ```
   [Sandbox] 已连接外部浏览器（CDP），正在接管页面...
   [Sandbox] 访问页面 [200] https://www.example.com/
   [Sandbox] 资源 [200] script https://www.example.com/xxx.js
   ```

### 常见问题

| 现象 | 原因与解决 |
|------|-----------|
| 日志一直提示"等待调试浏览器连接" | 没有双击调试快捷方式，或已有普通 Edge 在运行（Edge 会把调试参数转发给旧实例而忽略）。**先关闭所有普通 Edge，再双击调试快捷方式** |
| 浏览器是 Chrome / 其它内核 | 无需修改配置：调试快捷方式已复用本机 Edge/Chrome；如自行创建快捷方式，确保带 `--remote-debugging-port=9222` 参数即可 |

---

## ⚙️ 配置说明

所有配置集中在 [config/config.yaml](config/config.yaml)，支持**热重载**（修改后5秒内生效，无需重启）。

关键配置项：

```yaml
# 浏览器沙盒（核心模块）：仅 CDP 接管，不自动打开浏览器
browser_sandbox:
  enabled: true
  connect_cdp_url: "http://127.0.0.1:9222"   # 接管在此调试端口启动的外部浏览器
  monitor_browser_processes: true  # 未带调试参数的浏览器进程一律终止接管
  user_data_dir: ""                # 独立用户数据目录（不污染主浏览器）

# 浏览器内容管控规则
browser_rules:
  block_domains: []                # 黑名单域名（严格模式拦截 + 命中自动弱网）
  allowed_domains: []              # 白名单域名（宽松模式豁免）
  video_block_enabled: true        # 非上课时间全面禁止视频播放（JS禁用+网络拦截双通道）
  weak_network:                    # 弱网管控（命中黑名单即时切换）
    enabled: true                  # 是否启用弱网管控
    delay_ms: 3000                 # 命中黑名单的每个请求附加延迟（毫秒）
    latency_ms: 800                # CDP 模拟网络延迟（毫秒）
    download_kbps: 128             # 下载限速（KB/s）
    upload_kbps: 64                # 上传限速（KB/s）
    min_duration: 15               # 弱网最短持续时间（秒），防止频繁抖动

# 课程表（按星期配置时间段）
schedule:
  weekday:
    1: [["08:00", "12:00"], ["14:00", "17:30"]]

# U盘授权（需替换为实际值）
usb_guard:
  whitelist_serials: ["你的U盘序列号"]
  key_hash_sha256: "密钥文件的SHA-256哈希"

# 管理员密码（SHA-256哈希）
emergency:
  admin_password_hash: "你的密码SHA-256哈希"
```

### 生成密钥哈希

```python
import hashlib
print(hashlib.sha256("你的密码".encode()).hexdigest())
print(hashlib.sha256(open("U盘密钥文件路径","rb").read()).hexdigest())
```

---

## 📁 项目结构

```
AOTE-ClassroomGuard/
├── main.py                  # 主程序入口（单进程）
├── uninstall.py             # 卸载清理（仅清理本程序数据）
├── test_suite.py            # 测试套件
├── requirements.txt         # Python 依赖
├── README.md                # 项目文档
├── LICENSE                  # 许可证
├── config/
│   └── config.yaml          # 全部可配置项
├── scripts/
│   ├── create_cdp_shortcut.ps1   # 创建桌面 CDP 调试浏览器快捷方式
│   └── hijack_browser_entries.ps1# 接管任务栏/开始菜单/URL关联，全入口带 CDP 参数（支持 -Revert）
└── aote/                    # 核心模块包
    ├── __init__.py
    ├── config.py            # 配置加载（热重载）
    ├── logger.py            # 日志（控制台+按天轮转）
    ├── time_guard.py        # 时间调度（三模式）
    ├── browser_sandbox.py   # 浏览器沙盒（内容管控/弱网管控/CDP接管）
    ├── usb_guard.py         # U盘授权（双因素认证）
    ├── anti_tamper.py       # 防绕过（密码验证+沙盒心跳）
    ├── http_server.py       # 本地HTTP服务
    └── system_tray.py       # 系统托盘
```

---

## 🧪 测试

```powershell
python test_suite.py
```

测试内容：
1. ✅ 配置加载模块（含弱网管控参数）
2. ✅ 日志模块
3. ✅ 弱网管控逻辑（域名匹配 / 弱网状态 / 参数动态调整）
4. ✅ 时间调度逻辑

---

## 🤝 贡献方式

欢迎贡献代码！请遵循以下流程：

1. **Fork** 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature`
3. 提交更改：`git commit -m "feat: 添加xxx功能"`
4. 推送分支：`git push origin feature/your-feature`
5. 提交 **Pull Request**

### 提交规范

| 前缀 | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档更新 |
| `refactor` | 重构 |
| `test` | 测试相关 |
| `chore` | 构建/工具相关 |

### 开发建议

- 修改配置相关代码时注意热重载兼容性
- 浏览器路由/内容管控/弱网改动请在独立 profile 中充分测试
- 弱网参数修改后务必运行 `test_suite.py` 验证

---

## 📄 许可证

本项目采用 [MIT License](LICENSE)。

---

## ⚠️ 免责声明

- 本系统为**设备管理辅助工具**，不能替代学校规章制度
- 部署前**务必在虚拟机或备用机器上完整测试**所有功能
- 本系统仅基于浏览器层面做内容管控，不涉及任何进程终止/系统级修改
- 请合理使用，确保符合相关法律法规与学校管理规定
