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

**触发方式：纯手动。** 插件不做任何定时或后台自动同步。

## 换机器迁移（A 机 → B 机）完整流程

备份**不含 `node_modules/`**，所以恢复后**只有插件的配置、没有插件的代码**。DSH 启动时对缺失的 bundle 只是**警告跳过、不会崩溃，也不会自动重装**——结果是所有插件静默消失。因此迁移分两步：

**在 A 机**
1. 安装本插件，在设置卡片填好 WebDAV 并保存（会真实测试连接）
2. 输入口令 → 点「备份」

**在 B 机**
1. **先装上本插件**（`github:ddldxiacan/dsh-sync-release`，或本地路径），重启 DSH
2. 在设置卡片填入**同一套** WebDAV 配置
3. 输入**同一个口令** → 选备份 → 点「恢复」
4. 恢复完成后，卡片会提示「插件依赖未安装」→ 点「**重装插件**」
5. 重启 DSH

第 4 步会自动处理 A 机的本地路径依赖：A 机若用 `link:E:\…\dsh-sync-release` 这种写法装了本插件，这个绝对路径在 B 机**并不存在**，直接 `pnpm install` 会失败。插件在**备份时**就把这类依赖的仓库地址采集进备份包，恢复时自动改写为 `github:ddldxiacan/dsh-sync-release` 之类的可移植 spec 再安装。

> 恢复流程**不会**自动跑 pnpm install——重装由你点按钮触发，因为安装可能耗时数分钟且会改动 `package.json`。

> B 机前置条件：**Git 必须在 `PATH` 中**（`link:` 依赖改写后的 `github:` spec 需要 git 解析），且能访问 registry。实测 7 个插件冷安装约 2 分钟。

## 同步范围与排除规则

打包 `~/.dsh` 下**除以下之外**的全部内容：

- `dsh-runtimes/`（Node 运行时，体积大且与机器架构相关）
- `node_modules/`（插件依赖，**实测 221MB**，可由 pnpm 重装）
- `sessions/`（会话历史，**实测 27MB**，属可再生的使用记录）
- `logs/`、`npm-cache/`、`tmp*/`、`cache*/`
- 单个大于 10MB 的文件

实测效果：`~/.dsh` 共 258MB / 18918 个文件 → 备份 **11.5MB / 126 个文件**，耗时约 180ms。

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
github:ddldxiacan/dsh-sync-release
```

或使用 CLI：

```powershell
dsh plugin --profile desktop install github:ddldxiacan/dsh-sync-release
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
├── package.json        # name: dsh-sync-plugin，声明 dsh.bundle.patch 与 dsh.client
├── cordis.patch.yml    # 注册 dsh-sync 服务（name 与 package.json 一致）
├── index.js            # Host 半区：打包/加密/WebDAV/恢复/回滚/插件重装 + 7 个 HTTP 端点
├── client.js           # Client 半区：设置页卡片
└── tools-selftest.mjs  # 自测（含 mock WebDAV 服务器与 B 机恢复 E2E）
```

### 手动安装（不使用插件管理器时）

1. 把本目录整个复制到 `<profile>/node_modules/dsh-sync-plugin/`
2. 在 `<profile>/cordis.patch.yml` 追加：

```yaml
- insert:
    - id: dsh-sync
      name: 'dsh-sync-plugin'
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
| `POST /dsh-sync/backup` | `{ passphrase }` | `{ ok: true, name, size, fileCount }` |
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

预期 `88 passed, 0 failed`。覆盖：排除规则（含 `node_modules`/`sessions` 回归断言）、加解密往返、错误口令与篡改拒绝、打包/解包、备份 `meta` 与旧备份向后兼容、快照与回滚（含「`dsh-runtimes/` 必须在回滚后存活」的回归断言）、路径穿越防护、`link:` → 仓库 spec 改写、**B 机恢复 E2E**（A 机备份 → B 机恢复 → 重装插件依赖）、**异步 runner 不阻塞事件循环**（含「源码中不得出现 `spawnSync(`」防退化护栏），以及一个内置 mock WebDAV 服务器上的 Basic Auth / MKCOL / PUT / GET / PROPFIND 全链路。

## 已知限制

1. **手动触发**，不会自动备份——改完配置记得点一次。
2. **恢复与回滚只覆盖不删除**：回滚不会清除「快照之后新增的文件」。这是为保护 `dsh-runtimes/` 等排除项而做的取舍。
3. Windows 保留设备名（`CON`/`NUL`/`COM1` 等）未被路径校验拦截——它们只会解析到 `~/.dsh` 内部，不构成逃逸，属已评估的低危残余。
4. 插件本身**不处理 `app.asar` 补丁**。第三方模型推理档位修复需在新机器上单独重放，见 `reasoning-effort-fix/README.md`。
