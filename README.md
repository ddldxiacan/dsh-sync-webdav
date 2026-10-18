# dsh-sync · WebDAV 配置同步插件

[![DSH Plugin](https://img.shields.io/badge/DeepSeek%20Harness-Plugin-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

把 `~/.dsh` 的整体配置打包加密后备份到 WebDAV，在新机器上一键恢复——替代「手工搬运配置文件」的做法。

> 适用于 [DeepSeek Harness](https://github.com/deepseek-ai) 的双半区插件（Host + Client），零 npm 依赖。

## 为什么需要它

换机器或换账号时，DSH 的配置散落在 `~/.dsh` 里：模型路由、凭据、任务板、插件设置……手工搬运容易漏、容易错，而且**这些文件里有 API key，直接扔网盘不安全**。

dsh-sync 把这件事变成两个按钮：**备份**（加密上传）和**恢复**（解密还原，且自动先做本地快照）。

## 功能

在**设置页**新增一张「配置同步（WebDAV）」卡片（与 general / account / models / plugins 并列，全新 id `sync`，不替换任何现有页面）：

| 功能 | 说明 |
|---|---|
| 服务器配置 | WebDAV URL、用户名、密码、远程目录；「保存并测试连接」会真实发起 PROPFIND/MKCOL 验证 |
| 状态区 | 远端可达性、备份条目（名称/大小/时间）、最近一次本地快照 |
| 备份 | 输入口令 → 打包 `~/.dsh` → AES-256-GCM 加密 → PUT 上传 |
| 恢复 | 选一个备份（或「恢复最新」）→ 确认 → 自动先做本地快照 → 解密覆盖 |
| 回滚 | 从本地快照列表还原 |
| 插件重装 | 恢复后检测到插件依赖缺失 → 点「重装插件」→ 自动改写 `link:` 依赖并执行 pnpm install |
| 版本升级 | 打开设置页自动检查新版本；有新版时一键升级本插件自身（升级前自动备份，失败可回滚） |

**触发方式：纯手动。** 插件不做任何定时或后台自动同步。

## 换机器迁移（A 机 → B 机）完整流程

备份**不含 `node_modules/`**，所以恢复后**只有插件的配置、没有插件的代码**。DSH 启动时对缺失的 bundle 只是**警告跳过、不会崩溃，也不会自动重装**——结果是所有插件静默消失。因此迁移分两步：

**在 A 机**
1. 安装本插件，在设置卡片填好 WebDAV 并保存（会真实测试连接）
2. 输入口令 → 点「备份」

**在 B 机**
1. **先装上本插件**（`github:ddldxiacan/dsh-sync-webdav`，或本地路径），重启 DSH
2. 在设置卡片填入**同一套** WebDAV 配置
3. 输入**同一个口令** → 选备份 → 点「恢复」
4. 恢复完成后，卡片会提示「插件依赖未安装」→ 点「**重装插件**」
5. 重启 DSH

第 4 步会自动处理 A 机的本地路径依赖：A 机若用 `link:E:\…\dsh-sync-release` 这种写法装了本插件，这个绝对路径在 B 机**并不存在**，直接 `pnpm install` 会失败。插件在**备份时**就把这类依赖的仓库地址采集进备份包，恢复时自动改写为 `github:ddldxiacan/dsh-sync-webdav` 之类的可移植 spec 再安装。

> 恢复流程**不会**自动跑 pnpm install——重装由你点按钮触发，因为安装可能耗时数分钟且会改动 `package.json`。

> B 机前置条件：**Git 必须在 `PATH` 中**（`link:` 依赖改写后的 `github:` spec 需要 git 解析），且能访问 registry。实测 7 个插件冷安装约 2 分钟。

### 恢复为什么“看起来没反应”？逐项自查

恢复是写文件，不会自动刷新界面或重启，**恢复成功后必须重启 DeepSeek Harness 才生效**。若点了「恢复」后什么都没发生，按顺序检查：

| 现象 | 最可能的原因 | 处理 |
|---|---|---|
| 设置页里根本没有「配置同步（WebDAV）」卡片 | 本机没装本插件；或装的版本与备份不匹配（v0.1.0 只注册 3 个端点，无插件重装卡片） | 装与 A 机**同版本**的插件，重启 DSH |
| 卡片显示「插件服务未就绪：请确认本机已安装 dsh-sync-webdav…」 | 插件 Host 半区未加载或端点未注册 | 同上；确认 `cordis.patch.yml` 里 `ui-settings` 未被禁用 |
| 点了「恢复」出现「口令错误」类红字 | passphrase 与备份时不一致 | 用回备份时的口令 |
| 恢复提示「有 N 个条目被跳过」 | 备份内容异常（含不安全路径），或 AppData 路径在新机无法解析 | 反馈该提示给插件作者；被跳过的文件未落地 |
| 提示「恢复成功」但界面没有变化 | 正常现象——配置已写入，但 DSH 未重启 | 重启 DeepSeek Harness |
| 远端列表为空 / 「远端没有备份」 | WebDAV 配置与 A 机不一致，或远程目录填错 | 核对 url/username/password/remoteDir |

**v0.3.1 起**：恢复成功后提示会明确报告「已恢复 N 个文件（逐文件校验通过）+ 快照名 + 需重启」，被跳过/校验失败的文件会逐个列出，不再静默。

## 版本升级

插件自带升级模块，安装过的用户不必重装即可跟进新版本。

**打开设置页时自动检查一次**（结果在宿主内缓存 10 分钟），卡片上直接显示当前版本与是否有新版。也可随时点「检查更新」强制刷新。

| 当前安装方式 | 升级行为 |
|---|---|
| `github:` / `registry:`（受管安装） | 显示「发现新版本」+ 更新摘要 + 「立即升级」按钮 |
| `link:` / `file:`（开发态） | 显示「开发态安装，不受版本升级管理；更新请在该目录执行 `git pull`」，**不提供**升级按钮 |

点「立即升级」后：先把 `package.json` 备份为 `package.json.bak-dsh-sync-<时间戳>`，再把依赖声明改写为**带 tag 的确定性 spec**（`github:<owner>/<repo>#vX.Y.Z`），然后执行 `pnpm install` 并重启 DSH 生效。**升级过程只改写这一个依赖键**，profile 里其它插件依赖与 `dsh.profile.bundles` 原样不动。

### 判定「有没有新版本」用 commit sha，不是版本号

这一点与直觉相反，但对本插件是必须的：**发新提交可以不改 `package.json` 的 `version`**（本仓库的 `4da85ef` 与 `b503783` 两个提交版本号都是 `0.1.0`）。实测若只比 semver，判定会 100% 失效。

因此：

- **本地已装 sha**：从 profile 的 `pnpm-lock.yaml` 中提取（用「任意 40 位 hex」匹配——同一条 `github:` specifier 会产出 codeload / `git+ssh` / `git+https` 三种锁文件形态，字段名不统一）
- **远端最新 sha**：优先 GitHub API `commits/main`；API 限流或连不上时回退到 `git ls-remote <repo> HEAD`（tag 同样从 `refs/tags/*` 解析）。changelog 仍只走 compare API，限流时摘要可以为空，但「有没有更新」不再被锁死
- 两者不等即为「有更新」；`latest` 字段优先取最高的 `v*` tag，无 tag 时退化为 sha 前 7 位

> 注意：`node_modules/<包名>/` 里的文件**不含** sha，不能从那里读本地版本。

### 两个安全取舍

1. **registry 安装不自动升级。** `dsh-sync-plugin` 这个包名在 npm 上**属于另一位作者的另一个项目**（`dpskk2/dsh-sync-plugin`）。若检测到当前是 registry 安装，插件会拒绝自动升级并提示改用 `github:` 方式——否则会把别人的项目装到你机器上。（本插件的包名已改为 `dsh-sync-webdav` 以避开该冲突。）
2. **升级通道强制走 HTTPS。** pnpm 解析 `github:` 依赖时，HTTPS 走不通会**静默回退到 SSH**；在没配 SSH key 的机器上会以难懂的鉴权错误告终。本插件在升级时显式固定 HTTPS 通道。

### 从旧版本（`dsh-sync-plugin`）升级

**v0.2.0 起包名从 `dsh-sync-plugin` 改为 `dsh-sync-webdav`**，原因是前者在 npm 上属于别人的项目。改包名意味着它在本机 profile 里是**另一个依赖**，所以：

1. 先装新名（`github:ddldxiacan/dsh-sync-webdav#v0.2.0`）
2. **再卸掉旧名**，否则同一个 `id: dsh-sync` 会注册两次导致启动报错：

```powershell
dsh plugin --profile desktop remove dsh-sync-plugin
```

3. 重启 DSH

升级到 v0.2.0 之后，后续版本就都能在设置页里一键升级了。

## 发版流程（维护者）

```powershell
# 1. 改完代码，跑自测（必须全绿）
node tools-selftest.mjs

# 2. bump 版本号（package.json 的 version）
# 3. 提交并打标签 —— tag 是升级模块的版本锚点，必须打
git add -A
git commit -m "feat: ..."
git tag -a v0.2.0 -m "v0.2.0: ..."
git push origin main --tags
```

**打 tag 是发版的必要步骤**：升级功能以 `v*` tag 作为「最新版本」的来源，并把它作为安装锚点（`github:<owner>/<repo>#vX.Y.Z`）。只提交不打 tag，已安装用户的「检查更新」会退化为按 commit sha 比较——仍能发现更新，但看不到版本号。

若要让安装路径也解析出具体提交，pnpm 会把 `#vX.Y.Z` 钉到该 tag 指向的 sha 并记进锁文件（实测确认）。

## 同步范围与排除规则

打包 `~/.dsh` 下**除以下之外**的全部内容：

- `dsh-runtimes/`（按目录名整棵排除。Node 运行时体积大且与机器架构相关，**不是**靠单文件大小上限排除的）
- `node_modules/`（插件依赖，**实测 800MB+**，可由 pnpm 重装）
- `sessions/`（会话历史，属可再生的使用记录，**这是唯一不同步的对话数据**）
- `logs/`、`npm-cache/`、`tmp*/`、`cache*/`
- 上述目录之外，单个大于 50MB 的文件

远端目录只保留最近 **5** 份 `.bundle`，更旧的在备份成功后自动 `DELETE`。备份结果会带上打包范围（每个顶层目录有多少文件），体积异常时能直接看出来。

**v0.3.0 起额外同步 Electron 应用级设置**：`%APPDATA%\@deepseek-ai\dsh-desktop\desktop\settings.json` 等用户配置文件，以 `__appdata__/` 前缀并入同一加密备份，恢复/回滚时自动写回原位（Chromium 缓存类目录与 >2MB 文件仍排除，不撑大备份）。

账号凭据（`.credentials.yaml`）、各插件配置（`cordis.yml`/`package.json`/`.plugin-manager`）、agent-presets、task-board、skins、附件等**全部在同步范围内**——只有聊天对话（`sessions/`）与可重建产物（`node_modules/`、运行时）不打包。

> 排除 `node_modules` 与 `sessions` 不只是为了省空间：它们在 base64 封装后会让 payload 达到 350MB+，加上序列化副本会**直接把 Node 堆撑爆**（实测 OOM）。这两项都是可重建的产物，不属于配置。

> 备份**包含** `~/.dsh/dsh-sync.json` 自身（里面存着 WebDAV 的 url/username/password），这属有意设计——配置整体迁移。备份内容受口令加密保护。

## 安全模型

- **加密**：`scrypt(passphrase, salt, 32)` 派生密钥 + `AES-256-GCM`；带 SHA-256 内容校验，篡改或口令错误都会明确报错
- **口令**：只在内存中存在，绝不落盘、绝不写入日志
- **覆盖策略**：恢复与回滚**都只覆盖、不删除**——备份里没有的现有文件（尤其 `dsh-runtimes/` 等排除项）一律原样保留。这是关键安全设计：否则一次回滚会删掉运行时导致 DSH 起不来。

## 安装

### 方式一：通过 DSH 插件管理器安装（推荐）

在 DSH 的**插件管理**界面填入仓库地址安装：

```
github:ddldxiacan/dsh-sync-webdav
```

或使用 CLI：

```powershell
dsh plugin --profile desktop install github:ddldxiacan/dsh-sync-webdav
```

DSH 会通过 pnpm 拉取本仓库，读取 `package.json` 里的 `dsh.bundle.patch`，自动把 `dsh-sync` 注册进 profile 的 `cordis.patch.yml`，**无需手工改配置**。

> ⚠️ **前置条件：本机必须已安装 Git 且在 `PATH` 中。** pnpm 安装 `github:` 形式的 spec 时会调用 `git ls-remote` 探测远程仓库；找不到 git 会直接报 `Command failed with exit code 1: git ls-remote …`。新版 Windows 的 Git for Windows 默认加入 `PATH`，无需额外配置。
>
> 仓库为 **Public**，因此无需任何凭据即可安装。（若你 fork 后改为 Private，则需确保本机 git 已能访问该仓库：HTTPS 走 Personal Access Token，或配置 SSH key。）

### 方式二：本地目录安装（开发调试）

```powershell
dsh plugin --profile desktop install "E:\完整路径\dsh-sync-release"
```

插件管理器同样支持**绝对路径**安装，适合改完代码立刻验证。

### 安装后

**重启 DeepSeek Harness**，然后在 **设置** 页找到「**配置同步（WebDAV）**」卡片。

### 仓库结构

```
dsh-sync-release/
├── package.json        # name: dsh-sync-webdav，声明 dsh.bundle.patch 与 dsh.client
├── cordis.patch.yml    # 注册 dsh-sync 服务（name 与 package.json 一致）
├── index.js            # Host 半区：打包/加密/WebDAV/恢复/回滚/插件重装 + 7 个 HTTP 端点
├── client.js           # Client 半区：设置页卡片
└── tools-selftest.mjs  # 自测（含 mock WebDAV 服务器与 B 机恢复 E2E）
```

### 手动安装（不使用插件管理器时）

1. 把本目录整个复制到 `<profile>/node_modules/dsh-sync-webdav/`
2. 在 `<profile>/cordis.patch.yml` 追加：

```yaml
- insert:
    - id: dsh-sync
      name: 'dsh-sync-webdav'
      config: {}
```

3. 重启 DSH

> 注意：**不要**同时存在手动安装与插件管理器安装两份——同一个 `id: dsh-sync` 注册两次会导致启动报错。

## HTTP 端点（供脚本/自动化调用）

全部返回 HTTP 200，以 `ok` 字段判断成败；错误统一 `{ ok: false, error }`。

| 方法与路径 | 请求体 | 成功响应 |
|---|---|---|
| `GET /dsh-sync/status` | — | `{ configured, remote: { reachable, backups: [{name,size,modified}], latest? }, lastLocalSnapshot? }` |
| `POST /dsh-sync/config` | `{ url, username, password, remoteDir }` | `{ ok: true }`（先做连通性测试，失败不保存） |
| `POST /dsh-sync/backup` | `{ passphrase }` | `{ ok: true, name, size, fileCount, scope, pruned }` |
| `POST /dsh-sync/restore` | `{ name?, passphrase }` | `{ ok: true, restored, snapshot, meta? }` |
| `POST /dsh-sync/rollback` | `{ snapshot }` | `{ ok: true, restored }` |
| `GET /dsh-sync/plugins` | — | `{ ok: true, profile, profileDir, deps: [{name, spec, kind, installed, rewrite?}], missing, needsInstall, mapped, pnpm: {available, path?}, lastRestore? }` |
| `POST /dsh-sync/plugins/install` | `{}` | `{ ok: true, installed, exitCode, durationMs, rewritten, removed, lockSynced, log }` |

备份文件名：`dsh-sync-<yyyymmdd-HHMMSS>.bundle`

### 备份格式

```
[8 字节 magic "DSHSYNC1"][4 字节 headerLen(LE)][header JSON][AES-256-GCM 密文]
header: { version, salt(b64), iv(b64), tag(b64), payloadSha256 }
明文 payload: { files: [{ path, sha256, data(b64) }], meta?: { dshVersion, profile, createdAt, linkMap, unmapped } }
```

`meta` 是可选的：旧备份没有它，恢复时按「无插件映射信息」处理（不会报错，只是重装插件时无法自动改写 `link:` 依赖）。

## 自测

```powershell
node tools-selftest.mjs
```

预期自测全绿（`0 failed`）。覆盖：排除规则（含 `node_modules`/`sessions` 回归断言）、加解密往返、错误口令与篡改拒绝、打包/解包、备份 `meta` 与旧备份向后兼容、快照与回滚（含「`dsh-runtimes/` 必须在回滚后存活」的回归断言）、路径穿越防护、`link:` → 仓库 spec 改写、**B 机恢复 E2E**（A 机备份 → B 机恢复 → 重装插件依赖）、**异步 runner 不阻塞事件循环**（含「源码中不得出现 `spawnSync(`」防退化护栏），以及一个内置 mock WebDAV 服务器上的 Basic Auth / MKCOL / PUT / GET / PROPFIND 全链路。

## 已知限制

1. **手动触发**，不会自动备份——改完配置记得点一次。
2. **恢复与回滚只覆盖不删除**：回滚不会清除「快照之后新增的文件」。这是为保护 `dsh-runtimes/` 等排除项而做的取舍。
3. Windows 保留设备名（`CON`/`NUL`/`COM1` 等）未被路径校验拦截——它们只会解析到 `~/.dsh` 内部，不构成逃逸，属已评估的低危残余。
4. 插件本身**不处理 `app.asar` 补丁**。第三方模型推理档位修复需在新机器上单独重放，见 `reasoning-effort-fix/README.md`。
5. **版本检查优先走未认证 GitHub API，限额 60 次/小时（按 IP）**。每次成功的 API 检查约花 2~3 个请求，结果在进程内缓存 10 分钟。限额耗尽或 API 连不上时，会改用本机 `git ls-remote` 取 HEAD sha 和 tag，检查不会因此停摆；这时更新摘要可能为空。备份/恢复不依赖这条通道。
6. **仓库改名自动跟随**：若本仓库日后再次改名，GitHub 会对旧地址返回 301。`git`/`pnpm` 会自动跟随（安装不受影响），插件的网络层也已实现 301 跟随（v0.2.1 起），老版本的升级检查不会因此失效。
