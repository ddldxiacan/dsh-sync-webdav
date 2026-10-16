/**
 * DSH Sync · Host 半区
 *
 * 把 ~/.dsh 打包加密备份到 WebDAV，支持恢复与回滚。纯手动触发，
 * Host 不做任何定时/自动行为。无 npm 依赖、fail-soft。
 *
 * 恢复/回滚都只覆盖：两者把备份（或快照）里实际存在的文件挨个拷进 ~/.dsh，
 * 绝不删除备份之外 ~/.dsh 里已有的文件。因此被排除项（dsh-runtimes/、node_modules/、
 * sessions/、logs/、npm-cache、tmp*、cache*、>10MB 文件）在恢复/回滚后原样保留 —— 这是刻意的，
 * 否则 ~/.dsh/dsh-runtimes/ 里的 node 运行时会随回滚被删掉，DSH 无法启动。
 * 同理，node_modules/（可重装的插件依赖）也不会因回滚而丢失。
 *
 * 备份包含 dsh-sync.json 自身的 WebDAV 凭据（url/username/password），属有意设计：
 * 用户要求配置整体同步，故清单与凭据一并进备份；备份本身已用口令加密。
 *
 * 备份文件格式（二进制）：
 *   [8 字节 magic "DSHSYNC1"][4 字节 headerLen(LE)][header JSON utf8][AES-256-GCM ciphertext]
 *   header: { version, salt(b64), iv(b64), tag(b64), payloadSha256 }
 *   明文 payload: JSON { files: [{ path, sha256, data(b64) }] }
 *   密钥 = scrypt(passphrase, salt, 32)，口令只在内存中出现，绝不落盘。
 */

import { spawn } from 'node:child_process'
import {
  createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync,
} from 'node:crypto'
import {
  appendFileSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import http from 'node:http'
import https from 'node:https'
import { fileURLToPath } from 'node:url'

const MAGIC = Buffer.from('DSHSYNC1', 'utf8')
const MAX_FILE_BYTES = 10 * 1024 * 1024
const SNAPSHOT_KEEP = 5
const CONFIG_FILE_NAME = 'dsh-sync.json'
const SNAPSHOT_ROOT_NAME = '.dsh-sync-snapshots'
const RESTORE_STATE_NAME = 'dsh-sync-last-restore.json'
// B 机恢复后重装插件依赖用；pnpm 随 DSH 一起分发在 resources/runtime/ 下
const PNPM_REL_PATH = join('runtime', 'pnpm', 'bin', 'pnpm.mjs')
const INSTALL_TIMEOUT_MS = 15 * 60 * 1000
const LOG_TAIL_CHARS = 4000

// ============================================================
// 可注入内部实现（供 tools-selftest.mjs 复用）
// ============================================================

/** 是否应排除某个相对路径（posix 分隔）。规则：
 *  目录名：dsh-runtimes、node_modules、sessions、logs、npm-cache，以及 tmp 或 cache 开头的目录
 *  单个文件大于 10MB
 *
 * 为何排除 node_modules：`profiles/<name>/node_modules` 是插件依赖，实测占 ~221MB
 * 且可由 pnpm 重装，属可重建产物而非配置。若打包进去，base64 封装后 payload 达
 * 350MB+，加序列化副本会直接把 Node 堆撑爆（实测 OOM）。
 *
 * 为何排除 sessions：会话历史实测 ~27MB，属可再生的使用记录而非配置；
 * 且体积随使用持续增长，不适合每次全量上传。需要时单独同步。 */
export function isExcluded(relPosix, fileSizeBytes) {
  const segs = relPosix.split('/')
  for (const seg of segs) {
    if (seg === 'dsh-runtimes' || seg === 'node_modules' || seg === 'sessions' ||
        seg === 'logs' || seg === 'npm-cache') return true
    if (seg.startsWith('tmp') || seg.startsWith('cache')) return true
  }
  if (fileSizeBytes !== undefined && fileSizeBytes > MAX_FILE_BYTES) return true
  return false
}

/** 遍历 root，收集全部应打包文件（返回 posix 相对路径列表，已排序） */
export function collectFiles(root) {
  const out = []
  const walk = (dir, prefix) => {
    let entries
    try { entries = readdirSync(dir, { withFileTypes: true }) } catch (e) { return }
    for (const ent of entries) {
      const rel = prefix ? prefix + '/' + ent.name : ent.name
      const abs = join(dir, ent.name)
      if (ent.isDirectory()) {
        if (isExcluded(rel)) continue
        walk(abs, rel)
      } else if (ent.isFile()) {
        let size = 0
        try { size = statSync(abs).size } catch (e) { continue }
        if (isExcluded(rel, size)) continue
        out.push(rel)
      }
    }
  }
  walk(root, '')
  out.sort()
  return out
}

/** 打包（未加密）：返回明文 payload Buffer。meta 仅在新版本携带，旧备份不含该字段
 *  （不传 meta 时产物与旧版逐字节一致，保证格式向后兼容） */
export function buildPayload(root, relFiles, meta) {
  const files = []
  for (const rel of relFiles) {
    const buf = readFileSync(join(root, rel))
    files.push({ path: rel, sha256: createHash('sha256').update(buf).digest('hex'), data: buf.toString('base64') })
  }
  const obj = meta ? { files, meta } : { files }
  return Buffer.from(JSON.stringify(obj), 'utf8')
}

/** 加密 payload → 备份文件 Buffer */
export function encryptBundle(payload, passphrase) {
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const key = scryptSync(passphrase, salt, 32)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()])
  const tag = cipher.getAuthTag()
  const header = Buffer.from(JSON.stringify({
    version: 1,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    payloadSha256: createHash('sha256').update(payload).digest('hex'),
  }), 'utf8')
  const len = Buffer.alloc(4)
  len.writeUInt32LE(header.length, 0)
  return Buffer.concat([MAGIC, len, header, ciphertext])
}

/** 解密备份文件 Buffer → 明文 payload；任何不一致都抛错 */
export function decryptBundle(buf, passphrase) {
  if (buf.length < 12 || !buf.subarray(0, 8).equals(MAGIC)) throw new Error('不是有效的 dsh-sync 备份文件')
  const headerLen = buf.readUInt32LE(8)
  const header = JSON.parse(buf.subarray(12, 12 + headerLen).toString('utf8'))
  const ciphertext = buf.subarray(12 + headerLen)
  const key = scryptSync(passphrase, Buffer.from(header.salt, 'base64'), 32)
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(header.iv, 'base64'))
  decipher.setAuthTag(Buffer.from(header.tag, 'base64'))
  const payload = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  const sha = createHash('sha256').update(payload).digest('hex')
  if (sha !== header.payloadSha256) throw new Error('备份内容校验失败（SHA-256 不匹配）')
  return payload
}

/** 相对路径安全校验：只接受干净的相对 posix 路径（无绝对路径、盘符、~、`..` 段） */
function isSafeRelPath(p) {
  if (typeof p !== 'string' || !p || p.includes('\0')) return false
  if (p.startsWith('/') || p.startsWith('\\') || p.startsWith('~')) return false
  if (p.includes(':') || p.includes('\\')) return false                       // 盘符 / UNC / 反斜杠
  if (/^[A-Za-z]:/.test(p)) return false
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.' || seg === '..') return false
  }
  return true
}

/** 把明文 payload 解包写入 root；返回文件数 */
export function extractPayload(payload, root) {
  const parsed = JSON.parse(payload.toString('utf8'))
  let count = 0
  for (const f of (parsed.files || [])) {
    if (!isSafeRelPath(f.path)) continue
    const abs = join(root, f.path)
    mkdirSync(dirname(abs), { recursive: true })
    const buf = Buffer.from(f.data, 'base64')
    const sha = createHash('sha256').update(buf).digest('hex')
    if (sha !== f.sha256) throw new Error('文件 ' + f.path + ' 校验失败')
    writeFileSync(abs, buf)
    count++
  }
  return count
}

/** 备份文件名 */
export function bundleName(date) {
  const d = date || new Date()
  const p = (n) => String(n).padStart(2, '0')
  return 'dsh-sync-' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()) + '.bundle'
}

/** 把 root（按排除规则）快照到 snapshotRoot/<ts>/；返回快照目录名，并保留最近 keep 份 */
export function makeSnapshot(root, snapshotRoot, keep, date) {
  const d = date || new Date()
  const p = (n) => String(n).padStart(2, '0')
  const ts = d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()) + '-' + String(d.getMilliseconds()).padStart(3, '0')
  mkdirSync(snapshotRoot, { recursive: true })
  const dest = join(snapshotRoot, ts)
  mkdirSync(dest, { recursive: true })
  for (const rel of collectFiles(root)) {
    const target = join(dest, rel)
    mkdirSync(dirname(target), { recursive: true })
    copyFileSync(join(root, rel), target)
  }
  // 只保留最近 keep 份
  let olds = readdirSync(snapshotRoot).filter((n) => { try { return statSync(join(snapshotRoot, n)).isDirectory() } catch (e) { return false } }).sort()
  while (olds.length > keep) {
    try { rmSync(join(snapshotRoot, olds.shift()), { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
  return ts
}

/** 从快照目录回滚到 root：先快照现状，再只覆盖式还原快照里实际存在的文件。
 *  root 中不被快照覆盖的路径（dsh-runtimes/、logs/ 等排除项，以及快照之后新增的文件）
 *  一律原样保留 —— 绝不删除快照之外的文件。与 extractPayload 的“只覆盖”语义一致。 */
export function rollbackFromSnapshot(snapshotDir, root, snapshotRoot, keep) {
  const taken = makeSnapshot(root, snapshotRoot, keep)
  let count = 0
  const walk = (dir, prefix) => {
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? prefix + '/' + ent.name : ent.name
      const abs = join(dir, ent.name)
      if (ent.isDirectory()) walk(abs, rel)
      else if (ent.isFile()) {
        if (!isSafeRelPath(rel)) continue
        const target = join(root, rel)
        mkdirSync(dirname(target), { recursive: true })
        copyFileSync(abs, target)   // 已存在则覆盖；不存在则新建。root 里其余条目不动。
        count++
      }
    }
  }
  walk(snapshotDir, '')
  return { count, taken }
}

// ============================================================
// WebDAV 客户端（http/https + Basic Auth，无依赖）
// ============================================================

function basicAuth(username, password) {
  return 'Basic ' + Buffer.from(username + ':' + password, 'utf8').toString('base64')
}

/** 发起一次 WebDAV 请求。返回 { status, headers, body(Buffer) } */
export function davRequest(urlStr, method, opts) {
  const o = opts || {}
  return new Promise((resolve, reject) => {
    let u
    try { u = new URL(urlStr) } catch (e) { return reject(new Error('无效的 URL: ' + urlStr)) }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return reject(new Error('仅支持 http/https'))
    const mod = u.protocol === 'https:' ? https : http
    const headers = { ...(o.headers || {}) }
    if (o.username !== undefined) headers['Authorization'] = basicAuth(o.username, o.password || '')
    let body = o.body
    if (body !== undefined && body !== null) {
      if (!Buffer.isBuffer(body)) body = Buffer.from(body, 'utf8')
      headers['Content-Length'] = String(body.length)
    }
    const req = mod.request(u, { method, headers, timeout: o.timeoutMs || 15000 }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('timeout', () => { req.destroy(new Error('请求超时')) })
    req.on('error', reject)
    if (body !== undefined && body !== null) req.write(body)
    req.end()
  })
}

/** 远端目录 URL（保证以 / 结尾） */
function remoteDirUrl(cfg, extra) {
  let base = String(cfg.url || '')
  if (!base.endsWith('/')) base += '/'
  const dir = String(cfg.remoteDir || '').replace(/^\/+|\/+$/g, '')
  let u = dir ? base + dir + '/' : base
  if (extra !== undefined) u += extra
  return u
}

const PROPFIND_BODY = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:displayname/></d:prop></d:propfind>`

/** 探测远端目录（不存在则 MKCOL）。成功返回 null，失败返回错误消息 */
export async function ensureRemoteDir(cfg) {
  const url = remoteDirUrl(cfg)
  let res
  try {
    res = await davRequest(url, 'PROPFIND', {
      username: cfg.username, password: cfg.password,
      headers: { Depth: '0', 'Content-Type': 'application/xml' },
      body: PROPFIND_BODY,
    })
  } catch (e) { return '无法连接 WebDAV: ' + e.message }
  if (res.status === 207 || res.status === 200) return null
  if (res.status === 404) {
    // 逐级 MKCOL（远端目录可能有多层）
    let partial = String(cfg.url || '')
    if (!partial.endsWith('/')) partial += '/'
    for (const seg of String(cfg.remoteDir || '').split('/').filter(Boolean)) {
      partial += seg + '/'
      let mk
      try {
        mk = await davRequest(partial, 'MKCOL', { username: cfg.username, password: cfg.password })
      } catch (e) { return 'MKCOL 失败: ' + e.message }
      if (mk.status !== 201 && mk.status !== 405) {
        return '创建远端目录失败（HTTP ' + mk.status + '）: ' + partial
      }
    }
    return null
  }
  if (res.status === 401 || res.status === 403) return '认证失败（HTTP ' + res.status + '）'
  return 'PROPFIND 返回 HTTP ' + res.status
}

/** XML 转义 */
function xmlEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/** 解析 PROPFIND 多状态响应，列出目录内容 [{ name, size, modified, isDir }] */
export function parsePropfind(xmlText) {
  const out = []
  // 按 <d:response>…</d:response>（命名空间前缀任意）切分
  const respRe = /<(?:[A-Za-z0-9_-]+:)?response[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?response>/g
  let m
  while ((m = respRe.exec(xmlText)) !== null) {
    const block = m[1]
    const href = (block.match(/<(?:[A-Za-z0-9_-]+:)?href[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?href>/) || [])[1]
    if (!href) continue
    const isDir = /<(?:[A-Za-z0-9_-]+:)?collection\s*\/?\s*>/.test(block)
    const sizeRaw = (block.match(/<(?:[A-Za-z0-9_-]+:)?getcontentlength[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?getcontentlength>/) || [])[1]
    const modRaw = (block.match(/<(?:[A-Za-z0-9_-]+:)?getlastmodified[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?getlastmodified>/) || [])[1]
    let name
    try { name = decodeURIComponent(href.replace(/\/$/, '').split('/').pop() || '') } catch (e) { name = href }
    if (!name) continue
    out.push({
      name,
      isDir,
      size: Number(sizeRaw) || 0,
      modified: modRaw || null,
    })
  }
  return out
}

/** 列出远端目录里的 .bundle 备份（按名字排序，新在后） */
export async function listRemoteBackups(cfg) {
  const url = remoteDirUrl(cfg)
  const res = await davRequest(url, 'PROPFIND', {
    username: cfg.username, password: cfg.password,
    headers: { Depth: '1', 'Content-Type': 'application/xml' },
    body: PROPFIND_BODY,
  })
  if (res.status !== 207 && res.status !== 200) {
    throw new Error('PROPFIND 返回 HTTP ' + res.status)
  }
  const entries = parsePropfind(res.body.toString('utf8'))
  return entries
    .filter((e) => !e.isDir && /\.bundle$/.test(e.name))
    .map((e) => ({ name: e.name, size: e.size, modified: e.modified }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
}

// ============================================================
// 恢复后重装插件依赖（B 机）
//
// 背景：备份刻意排除 node_modules（~221MB，可重装），因此 B 机恢复后只拿到
// 插件配置（package.json / cordis.patch.yml / pnpm-lock.yaml）而拿不到插件代码。
// DSH 加载 profile 时对每个 bundle 都是 try/catch（告警跳过，不崩），也绝不自动
// 跑 pnpm install —— 于是插件静默消失。更糟的是 A 机的 package.json 里可能有
// `"<包名>": "link:E:/..."` 这种绝对路径依赖，在 B 机上根本不存在，
// 直接 pnpm install 必然失败。故此处：把 link:/file: 依赖改写成其仓库地址后再装。
// ============================================================

/** 从仓库地址（package.json repository.url）推导 pnpm 可解析的 spec */
export function repoSpecFromUrl(url) {
  const raw = String(url || '').trim()
  if (!raw) return null
  const s = raw.replace(/^git\+/, '').replace(/\.git$/, '').replace(/\/+$/, '')
  const m1 = /^(?:https?|ssh|git):\/\/(?:[^@/]+@)?([^/:]+)[/:](.+)$/.exec(s)
  const m2 = /^[^@/]+@([^:/]+):(.+)$/.exec(s)
  const host = (m1 && m1[1]) || (m2 && m2[1]) || null
  const repo = ((m1 && m1[2]) || (m2 && m2[2]) || '').replace(/\.git$/, '').replace(/^\/+/, '')
  if (!host || !repo || repo.split('/').length < 2) return null
  // 三大托管服务用简写，其余主机回退成原始 https 地址
  if (/^(www\.)?github\.com$/i.test(host)) return 'github:' + repo
  if (/^(www\.)?gitlab\.com$/i.test(host)) return 'gitlab:' + repo
  if (/^(www\.)?bitbucket\.org$/i.test(host)) return 'bitbucket:' + repo
  return 'https://' + host + '/' + repo
}

/** 读某个已安装包的 package.json 并推导 spec；读不到返回 null */
export function specFromInstalledPackage(pkgDir) {
  try {
    const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'))
    const url = (pkg.repository && (pkg.repository.url || (typeof pkg.repository === 'string' ? pkg.repository : null))) || null
    const spec = repoSpecFromUrl(url)
    return spec ? { spec, reason: 'repository.url' } : null
  } catch (e) { return null }
}

/** 找 pnpm 的入口脚本（随 DSH 分发，位于 resources/runtime/pnpm/bin/pnpm.mjs） */
export function findPnpmPath(resourcesPath) {
  const roots = []
  if (resourcesPath) roots.push(resourcesPath)
  try { roots.push(join(dirname(process.execPath), 'resources')) } catch (e) { /* ignore */ }
  for (const r of roots) {
    const p = join(r, PNPM_REL_PATH)
    if (existsSync(p)) return p
  }
  return null
}

/** 判断 package.json 里某条依赖的类别 */
export function depKind(spec) {
  const s = String(spec || '')
  if (/^(link|file|portal):/i.test(s)) return 'link'
  if (/^(github|gitlab|bitbucket|gist):/i.test(s) || /^(git\+|git:|ssh:\/\/)/i.test(s) || /\.git(#|$)/i.test(s)) return 'git'
  if (/^(https?:|file:)/i.test(s) && /\.(t|tar\.gz|zip)$/i.test(s)) return 'tarball'
  if (/^https?:/i.test(s)) return 'tarball'
  return 'registry'
}

/** 覆盖式写 JSON 文件，保留 2 空格缩进与末尾换行（与 pnpm 风格一致） */
function writeJsonFile(file, obj) {
  writeFileSync(file, JSON.stringify(obj, null, 2) + '\n', 'utf8')
}

// ============================================================
// 版本检查（只读远端；不改任何文件）
//
// 为何以 git commit sha 为主判据、而不是 semver：实测本仓库两个提交
// （4da85ef / b503783）的 package.json version 都是 0.1.0 —— 发布新提交
// 完全不必改版本号，只看 semverGt 会 100% 漏判。semver 只在拿不到 sha 时兜底。
// ============================================================

const VERSION_CACHE_TTL_MS = 10 * 60 * 1000
const GITHUB_API = 'https://api.github.com'
const GITHUB_UA = 'dsh-sync'
const COMPARE_MAX_MESSAGES = 8

/** registry 安装一律拒绝：实测 npm 上的同名包属于另一个作者（不同 owner 的同名项目），
 *  按 `name@version` 自动升级会装成别人的代码。包名从 package.json 读，不写死。 */
export function registryRejectError(pkgName) {
  return '检测到 registry 安装（' + pkgName + ' 在 npm 上属于其他作者的项目），出于安全考虑不自动升级；请改用 github: 方式安装'
}

/** 解析 semver：返回 { nums:[major,minor,patch], pre:string[]|null }，非法返回 null。
 *  只接受 SemVer 允许的字符集，因此分支名（main/HEAD）必然解析失败 —— 这是有意的：
 *  远端 tag 列表里混入非 semver 名字时不得被当成版本号参与比较。 */
export function parseSemver(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(v === undefined || v === null ? '' : v).trim())
  if (!m) return null
  return { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split('.') : null }
}

function cmpPre(a, b) {
  if (a === null && b === null) return 0
  if (a === null) return 1      // 有预发布段 < 无预发布段（1.0.0-alpha < 1.0.0）
  if (b === null) return -1
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = a[i]
    const y = b[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      if (Number(x) !== Number(y)) return Number(x) > Number(y) ? 1 : -1
    } else if (xn !== yn) {
      return xn ? -1 : 1        // 数字标识符优先级低于字母标识符
    } else if (x !== y) {
      return x > y ? 1 : -1
    }
  }
  return 0
}

/** semver 比较：a > b → 1，a < b → -1，相等 → 0；任一不可解析 → null。
 *  必须按数值比较，字符串比较会把 '0.10.0' 判成小于 '0.9.0'。 */
export function cmpSemver(a, b) {
  const x = parseSemver(a)
  const y = parseSemver(b)
  if (!x || !y) return null
  for (let i = 0; i < 3; i++) {
    if (x.nums[i] !== y.nums[i]) return x.nums[i] > y.nums[i] ? 1 : -1
  }
  return cmpPre(x.pre, y.pre)
}

/** a 是否严格高于 b（任一不可解析 → false） */
export function semverGt(a, b) {
  return cmpSemver(a, b) === 1
}

/** 从 GitHub /tags 的返回里挑最高版本 tag；只比较 semver，不依赖数组顺序
 *  （GitHub 按创建时间倒序返回，与版本高低无关）。无 v* tag → null */
export function latestTagOf(tags) {
  let best = null
  let bestVer = null
  for (const t of Array.isArray(tags) ? tags : []) {
    const name = String((t && t.name !== undefined ? t.name : t) || '')
    if (!/^v\d/.test(name)) continue
    if (!parseSemver(name)) continue
    if (bestVer === null || cmpSemver(name, bestVer) > 0) { bestVer = name; best = t }
  }
  return best
}

/** 在锁文件文本里定位 `name:` 依赖条目，返回其后第一条 40 位 hex 提交 sha。
 *  不做字段名解析是刻意的：同一个 `github:` specifier 实测会产出三种锁文件形态
 *  （codeload 的 version/tarball、git 形态的 resolution.commit），字段名不统一；
 *  缩进深度也随 importer 不同而不同，故按「所属条目 + 后续若干行」定位。
 *  node_modules/<pkg>/ 下的文件不含 sha（实测 7 个文件全无），不能作为来源。 */
export function shaOfDependency(text, pkgName) {
  const lines = String(text || '').split('\n')
  const nameRe = new RegExp('^\\s*' + String(pkgName).replace(/[.*+?^${}()|[\]\\/]/g, '\\$&') + ':\\s*$')
  for (let i = 0; i < lines.length; i++) {
    if (!nameRe.test(lines[i])) continue
    const total = /^\s*specifier:/.test(String(lines[i + 1] || '')) ? 4 : 14
    const end = Math.min(lines.length, i + 1 + total)
    for (let j = i + 1; j < end; j++) {
      const m = /([0-9a-f]{40})/.exec(lines[j])
      if (m) return m[1]
    }
  }
  return null
}

/** 从 profile 的 pnpm-lock.yaml 取自身依赖被锁定的 commit sha；
 *  兜底看 node_modules/.pnpm/lock.yaml（内容一致）。取不到返回 null。 */
export function localShaFromLock(profileDir, pkgName) {
  for (const f of [join(profileDir, 'pnpm-lock.yaml'), join(profileDir, 'node_modules', '.pnpm', 'lock.yaml')]) {
    let text
    try { text = readFileSync(f, 'utf8') } catch (e) { continue }
    const hit = shaOfDependency(text, pkgName)
    if (hit) return hit
  }
  return null
}

/** 本插件自身的包目录：用 import.meta.url 定位，绝不用 process.cwd() */
export function selfPackageDir() {
  try { return dirname(fileURLToPath(import.meta.url)) } catch (e) { return null }
}

/** 读自身 package.json（随包发布，必然存在）；读不到返回 null */
export function readSelfPackage() {
  const dir = selfPackageDir()
  if (!dir) return null
  try {
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
    return { dir, file: join(dir, 'package.json'), pkg }
  } catch (e) { return null }
}

/** 自身版本（读不到时给 0.0.0，避免上游拿到 undefined） */
export function selfVersion() {
  const s = readSelfPackage()
  return (s && s.pkg && s.pkg.version) ? String(s.pkg.version) : '0.0.0'
}

/** 自身包名 —— 绝不硬编码：包名可能随时改动以避开 npm 同名占用。
 *  读不到时返回 null（调用方报错退出），而不是猜一个名字 —— 猜错会把
 *  「指向别的包」的 spec 写进 profile。profile 依赖键名同样按此匹配。 */
export function selfPackageName() {
  const s = readSelfPackage()
  const n = s && s.pkg && s.pkg.name
  return (typeof n === 'string' && n) ? n : null
}

/** 解析自身 package.json 的 repository.url → 'owner/repo'（用既有的 repoSpecFromUrl，避免两处判断分叉）；
 *  解析不出返回 null。repository 也可能是裸字符串。 */
export function parseRepoSlug(url) {
  const spec = repoSpecFromUrl(url)
  return spec ? spec.replace(/^[a-z]+:/i, '') : null
}

/**
 * 给一次「装 github: 依赖」的子进程注入 git URL 重写：SSH → HTTPS。
 *
 * 为什么必须做：pnpm 解析 github: 依赖时会 shell out 到 git；HTTPS 走不通时
 * （企业网/代理/防火墙）git 会静默回退到 git@github.com: 的 SSH 形式，在没配
 * SSH key 的机器上就报鉴权错——这个错和「升级失败」毫无关联，是装给别人用时
 * 的首要故障模式。用 insteadOf 把 SSH 形式强行拉回 HTTPS 才是对的手段
 * （~/.npmrc 里的 proxy 会覆盖我们传的 HTTP(S)_PROXY，代理变量解决不了）。
 *
 * 作用域：只挂在这一次安装的子进程 env 上，绝不写进 process.env ——
 * GIT_CONFIG_COUNT 会被子进程继承，泄漏出去会污染用户其它 git 操作。
 */
export function githubHttpsOnlyEnv(base) {
  return {
    ...base,
    GIT_CONFIG_COUNT: '2',
    GIT_CONFIG_KEY_0: 'url.https://github.com/.insteadOf',
    GIT_CONFIG_VALUE_0: 'git@github.com:',
    GIT_CONFIG_KEY_1: 'url.https://github.com/.insteadOf',
    GIT_CONFIG_VALUE_1: 'ssh://git@github.com/',
  }
}

/** 读 URL 上的布尔查询开关（如 ?force=1 / ?force=true）。 */
export function queryFlag(url, name) {
  try {
    const u = new URL(String(url || ''), 'http://localhost')
    const v = u.searchParams.get(name)
    return v !== null && /^(1|true|yes|on)$/i.test(v)
  } catch (e) { return false }
}

/**
 * 校验「只改了目标依赖」：除 dependencies[target] 外的所有字段必须与原对象逐字节一致。
 * 这是安全红线的最后一道闸 —— dsh.profile.bundles 等字段一旦被改动就会拒绝落盘。
 */
export function nonTargetFieldsIntact(before, after, target) {
  const strip = (o) => {
    const c = JSON.parse(JSON.stringify(o || {}))
    if (c.dependencies && typeof c.dependencies === 'object') {
      delete c.dependencies[target]
      if (!Object.keys(c.dependencies).length) delete c.dependencies
    }
    return JSON.stringify(c)
  }
  return strip(before) === strip(after)
}

/** 自身仓库 slug（owner/repo），取自自身 package.json 的 repository.url */
export function selfRepoSlug() {
  const s = readSelfPackage()
  const r = s && s.pkg && s.pkg.repository
  const url = (r && (r.url || (typeof r === 'string' ? r : null))) || null
  return parseRepoSlug(url)
}

/** GitHub compare 响应 → changelog 行：commits[].commit.message 的首行。
 *  整个数组最多 8 条（含末尾的统计行）—— total_commits 超过可显示条数时，
 *  末行补「还有 N 个提交」，N 是尚未显示的数量。 */
export function summaryFromCompare(json) {
  const c = json && typeof json === 'object' ? json : {}
  const msgs = []
  for (const item of Array.isArray(c.commits) ? c.commits : []) {
    const raw = item && item.commit && item.commit.message ? String(item.commit.message) : ''
    const first = raw.split('\n')[0].trim()
    if (first) msgs.push(first)
  }
  const total = Number(c.total_commits)
  const overflow = Number.isFinite(total) && total > 0 ? total : msgs.length
  if (overflow > COMPARE_MAX_MESSAGES) {
    const shown = msgs.slice(0, COMPARE_MAX_MESSAGES - 1)
    shown.push('还有 ' + (overflow - shown.length) + ' 个提交')
    return shown
  }
  return msgs.slice(0, COMPARE_MAX_MESSAGES)
}

/** 算出重定向的下一跳；地址非法返回 null。抽成纯函数便于离线自测。 */
export function nextRedirectUrl(base, location) {
  try { return new URL(String(location), new URL(String(base))).toString() } catch (e) { return null }
}

/** 默认网络通道：node:https，15 秒超时，失败收敛成 { status:null, error }，绝不抛异常。
 *  必须带 User-Agent —— 不带时 GitHub 会 403。
 *
 *  必须自己跟随重定向：仓库改名后，GitHub 对旧 owner/repo 路径下的**所有** API 端点
 *  返回 301 + Location 指向新仓库（实测 /tags、/commits、/compare 全如此），而 node:https
 *  不会自动跟随（curl -L / git / pnpm 都会，所以安装照常，只有 API 层会静默失败）。
 *  不处理就会以「GitHub API 返回 HTTP 301」这种与升级毫无关联的错阻断版本检查。
 *
 *  为什么这件事对升级模块是必需的：老用户装的是改名前的版本，其 package.json 里的
 *  repository.url 仍是旧仓库名，自省得到的 slug 也就是旧名 —— 全靠这里跟随 301 自愈。
 */
export function defaultHttpsGet(url, opts) {
  const o = opts || {}
  const maxRedirects = Number.isFinite(o.maxRedirects) ? o.maxRedirects : 5
  const request = o.request || https.request // 可注入，便于离线验证重定向链
  return new Promise((resolve) => {
    const go = (target, hop) => {
      let u
      try { u = new URL(target) } catch (e) { return resolve({ status: null, body: '', error: '无效的 URL: ' + target }) }
      const req = request(u, {
        method: 'GET',
        headers: { 'User-Agent': GITHUB_UA, Accept: 'application/vnd.github+json' },
        timeout: 15000,
      }, (res) => {
        const code = res.statusCode
        const loc = res.headers ? res.headers.location : null
        if (code >= 300 && code < 400 && loc) {
          res.resume() // 放掉重定向响应体，否则连接不释放
          if (hop >= maxRedirects) {
            return resolve({ status: code, body: '', error: '重定向次数超过 ' + maxRedirects + ' 次：' + target })
          }
          const next = nextRedirectUrl(target, loc)
          if (!next) return resolve({ status: code, body: '', error: '无效的重定向地址：' + loc })
          return go(next, hop + 1)
        }
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => resolve({ status: code, body: Buffer.concat(chunks).toString('utf8'), error: null }))
      })
      req.on('timeout', () => req.destroy(new Error('请求超时')))
      req.on('error', (e) => resolve({ status: null, body: '', error: e && e.message ? e.message : String(e) }))
      req.end()
    }
    go(url, 0)
  })
}

/**
 * 检查远端最新版本：以 commit sha 为主判据，semver 兜底。
 * 任何网络失败都收敛成 error 字符串，绝不抛异常、绝不影响既有端点。
 * opts 全部可注入（httpsGet/cache/now），因此自测无需真实联网。
 * @returns {{ current, repo, hasUpdate, latest, latestTag, remoteSha, changelog, checkedAt, checked, error }}
 */
export async function performVersionCheck(current, slug, opts) {
  const o = opts || {}
  const httpsGet = o.httpsGet || defaultHttpsGet
  const key = JSON.stringify(['version', slug, o.pkgName || '', current, o.localSha || '', !!o.force])
  if (!o.force && o.cache && typeof o.cache.get === 'function') {
    const hit = o.cache.get(key)
    if (hit && (o.now ? o.now() : Date.now()) - hit.at < VERSION_CACHE_TTL_MS) {
      return { ...hit.value, checked: false }
    }
  }
  const out = {
    current: current || null, repo: slug || null, hasUpdate: false, latest: null,
    latestTag: null, remoteSha: null, changelog: [], checkedAt: null, checked: true, error: null,
  }
  let tags = []
  let tag = null
  const api = (p) => GITHUB_API + '/repos/' + slug + p

  // 传输层失败（status 为 null）时优先回报真实原因（ENOTFOUND/超时），
  // 否则会退化成毫无信息量的「HTTP null」
  const describeFail = (r) => {
    if (r && r.error) return '无法连接 GitHub：' + r.error
    if (r && (r.status === 403 || r.status === 429)) return 'GitHub API 限流（HTTP ' + r.status + '），请稍后重试'
    return 'GitHub API 返回 HTTP ' + (r ? r.status : 'null')
  }

  // 远端版本 tag（只比较 semver，不依赖返回顺序）
  try {
    const r = await httpsGet(api('/tags'))
    if (r.status === 403 || r.status === 429) {
      out.error = 'GitHub API 限流（HTTP ' + r.status + '），请稍后重试'
    } else if (r.status !== 200) {
      out.error = describeFail(r)
    } else {
      let parsed = null
      try { parsed = JSON.parse(r.body || '[]') } catch (e) { parsed = null }
      if (!Array.isArray(parsed)) out.error = 'GitHub API 返回了非预期内容'
      else { tags = parsed; tag = latestTagOf(parsed) }
    }
  } catch (e) {
    out.error = '无法连接 GitHub：' + (e && e.message ? e.message : String(e))
  }

  // 远端 HEAD sha（与本地锁文件里的 sha 同一命名空间，可直接同真值比较）
  try {
    const r = await httpsGet(api('/commits/' + (o.branch || 'main')))
    if (r.status === 200) {
      try { out.remoteSha = JSON.parse(r.body || '{}').sha || null } catch (e) { out.remoteSha = null }
    } else if (r.status === 403 || r.status === 429) {
      if (!out.error) out.error = 'GitHub API 限流（HTTP ' + r.status + '），请稍后重试'
    } else if (!out.error && !tags.length) {
      // tags 已成功时不必因 commits 的 404 报错（分支名可能不是 main）
      out.error = describeFail(r)
    }
  } catch (e) {
    if (!out.error) out.error = '无法连接 GitHub：' + (e && e.message ? e.message : String(e))
  }

  out.latestTag = tag ? String(tag.name) : null
  // latest：优先最高 tag；无 tag 时退化为远端 sha 前 7 位（UI 原样显示，不再格式化）
  if (out.latestTag) out.latest = out.latestTag
  else if (out.remoteSha) out.latest = out.remoteSha.slice(0, 7)
  const remoteVer = out.latestTag ? out.latestTag.replace(/^v/, '') : null
  const cur = typeof current === 'string' ? current.replace(/^v/, '') : current
  if (o.localSha && out.remoteSha) out.hasUpdate = String(o.localSha) !== String(out.remoteSha)
  else if (remoteVer) out.hasUpdate = semverGt(remoteVer, cur)
  else out.hasUpdate = false

  // 更新摘要：以本地 sha 为 compare 基线（tag 可能不存在；sha 是唯一始终可得的真值）。
  // compare 失败只让 changelog 退化为 []，绝不影响 hasUpdate 这个主判据。
  const base = o.localSha || o.localTag
  const head = out.remoteSha || out.latestTag
  if (out.hasUpdate && base && head) {
    try {
      const r = await httpsGet(api('/compare/' + encodeURIComponent(base) + '...' + encodeURIComponent(head)))
      if (r.status === 200) {
        let parsed = null
        try { parsed = JSON.parse(r.body || '{}') } catch (e) { parsed = null }
        out.changelog = summaryFromCompare(parsed)
      }
    } catch (e) { out.changelog = [] }
  }

  out.checkedAt = new Date().toISOString()
  if (o.cache && typeof o.cache.set === 'function') o.cache.set(key, { at: Date.now(), value: out })
  return { ...out }
}

/**
 * 读取 profile 的 package.json，生成安装方案（不改文件）。
 * @returns {{ ok:boolean, error?:string, profileDir?, file?, deps?:Array, rewrite?, remove?:Array }}
 */
export function planProfileInstall(profileDir, linkMap) {
  const file = join(profileDir, 'package.json')
  let pkg, raw
  try {
    raw = readFileSync(file, 'utf8')
    pkg = JSON.parse(raw)
  } catch (e) {
    return { ok: false, error: '无法读取 profile 的 package.json：' + (e && e.message ? e.message : String(e)) }
  }
  const deps = pkg.dependencies && typeof pkg.dependencies === 'object' ? pkg.dependencies : {}
  const rewrite = Object.create(null)
  const remove = Object.create(null)
  const items = []
  for (const [name, spec] of Object.entries(deps)) {
    const kind = depKind(spec)
    const item = { name, spec, kind }
    if (kind === 'link') {
      // 相对路径（在 B 机上可能同样有效）保持原样；只改绝对路径等无法解析的
      const target = String(spec).replace(/^(link|file|portal):/i, '')
      const localish = !isAbsolute(target) && !/^[A-Za-z]:/.test(target)
      if (localish && existsSync(join(profileDir, target))) {
        item.kept = true
      } else {
        // 优先用备份里记录的映射：B 机上 node_modules 尚未重建，本地推导不出仓库地址。
        // 仅在记录的 from 与当前 spec 一致时才采用，避免陈旧映射改写掉了别的写法。
        const rec = linkMap && linkMap[name]
        const recSpec = rec ? (typeof rec === 'string' ? rec : rec.spec) : null
        const usable = recSpec && (!rec.from || String(rec.from) === String(spec))
        const found = usable ? { spec: recSpec, reason: (rec.reason || 'last-restore') }
          : specFromInstalledPackage(join(profileDir, 'node_modules', name)) ||
            specFromInstalledPackage(join(dshRootOf(profileDir), 'commonl-workspace', name))
        if (found) {
          item.rewrite = found.spec
          item.reason = found.reason
          rewrite[name] = found.spec
        } else {
          item.removed = true
          remove[name] = String(spec)
        }
      }
    }
    items.push(item)
  }
  return { ok: true, file, profileDir, deps: items, rewrite, remove, pkg }
}

/** 由 profiles/<name> 推回 ~/.dsh 根（仅用于兼容旧布局的兜底查找） */
function dshRootOf(profileDir) {
  try { return dirname(dirname(profileDir)) } catch (e) { return profileDir }
}

/** 把 ~/.dsh 里记录的「上次恢复」信息读出来（可能不存在） */
export function readLastRestore(dshRoot) {
  try {
    const obj = JSON.parse(readFileSync(join(dshRoot, RESTORE_STATE_NAME), 'utf8'))
    return obj && typeof obj === 'object' ? obj : null
  } catch (e) { return null }
}

/** 写「上次恢复」信息，供设置卡片在恢复完成后展示可安装的插件 */
export function writeLastRestore(dshRoot, info) {
  try {
    writeJsonFile(join(dshRoot, RESTORE_STATE_NAME), info)
    return true
  } catch (e) { return false }
}

/** 从明文 payload 里取出 meta（旧备份没有该字段时返回 null） */
export function extractPayloadMeta(payload) {
  try {
    const parsed = JSON.parse(payload.toString('utf8'))
    return parsed && typeof parsed.meta === 'object' && parsed.meta ? parsed.meta : null
  } catch (e) { return null }
}

/** 采集 A 机安装元信息（哪些插件是 link: 依赖、其仓库地址是什么），随备份一起带走 */
export function collectInstallMeta(dshRoot, profileName) {
  const name = profileName || 'desktop'
  const profileDir = join(dshRoot, 'profiles', name)
  let pkg = null
  try { pkg = JSON.parse(readFileSync(join(profileDir, 'package.json'), 'utf8')) } catch (e) { pkg = null }
  const deps = (pkg && pkg.dependencies) || {}
  const linkMap = Object.create(null)
  const unmapped = Object.create(null)
  for (const [dep, spec] of Object.entries(deps)) {
    if (!/^(link|file|portal):/i.test(String(spec))) continue
    const found = specFromInstalledPackage(join(profileDir, 'node_modules', dep))
    if (found) linkMap[dep] = { from: String(spec), spec: found.spec, reason: found.reason }
    else unmapped[dep] = String(spec)
  }
  let dshVersion = null
  let pnpmVersion = null
  try {
    // resources/version 是 Electron 版本文件，仅用于标识安装来源；pnpm 版本取自 runtime
    const resDir = dirname(process.execPath) + '/resources'
    const v = readFileSync(join(resDir, 'version'), 'utf8').trim()
    if (v && v.length < 40) dshVersion = v
    pnpmVersion = JSON.parse(readFileSync(join(resDir, 'runtime', 'versions.json'), 'utf8')).pnpm || null
  } catch (e) { /* 版本信息缺失不影响安装，忽略 */ }
  return { dshVersion, pnpmVersion, profile: name, createdAt: new Date().toISOString(), linkMap, unmapped }
}

// ============================================================
// 插件入口
// ============================================================

function resolveService(ctx, name) {
  try {
    if (ctx && typeof ctx.get === 'function') {
      const s = ctx.get(name)
      if (s !== undefined) return s
    }
  } catch (e) { /* ignore */ }
  try {
    if (ctx && ctx[name] !== undefined) return ctx[name]
  } catch (e) { /* ignore */ }
  return undefined
}

export function apply(ctx, config) {
  const cfg = { ...(config || {}) }
  const home = homedir()
  const dshRoot = cfg.root || join(home, '.dsh')
  const snapshotRoot = cfg.snapshotRoot || join(home, SNAPSHOT_ROOT_NAME)
  const configFile = join(dshRoot, CONFIG_FILE_NAME)
  const cleanupFns = []

  const log = (message) => {
    try {
      mkdirSync(dshRoot, { recursive: true })
      const logPath = join(dshRoot, 'dsh-sync-host.log')
      try { if (statSync(logPath).size > 256 * 1024) writeFileSync(logPath, '', 'utf8') } catch (e) { /* first */ }
      appendFileSync(logPath, '[' + new Date().toISOString() + '] ' + message + '\n', 'utf8')
    } catch (e) { /* ignore */ }
  }

  const loadPluginConfig = () => {
    try {
      const raw = readFileSync(configFile, 'utf8')
      const c = JSON.parse(raw)
      return (c && typeof c === 'object' && typeof c.url === 'string' && c.url) ? c : null
    } catch (e) { return null }
  }

  const savePluginConfig = (c) => {
    mkdirSync(dshRoot, { recursive: true })
    writeFileSync(configFile, JSON.stringify({ url: c.url, username: c.username, password: c.password, remoteDir: c.remoteDir }, null, 2), 'utf8')
  }

  const json = (res, obj) => {
    const body = JSON.stringify(obj)
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(Buffer.byteLength(body)),
      'Cache-Control': 'no-store',
    })
    res.end(body)
  }

  const readBody = (req) => new Promise((resolve) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')) } catch (e) { resolve({}) }
    })
    req.on('error', () => resolve({}))
  })

  let lastLocalSnapshot = null
  let installing = false
  try {
    const olds = readdirSync(snapshotRoot).filter((n) => { try { return statSync(join(snapshotRoot, n)).isDirectory() } catch (e) { return false } }).sort()
    if (olds.length) lastLocalSnapshot = olds[olds.length - 1]
  } catch (e) { /* ignore */ }

  // ---- 各端点处理逻辑（与路由解耦，便于复用） ----

  const handleStatus = async () => {
    const c = loadPluginConfig()
    if (!c) return { configured: false, remote: { reachable: false, backups: [] }, lastLocalSnapshot: lastLocalSnapshot || undefined }
    try {
      const err = await ensureRemoteDir(c)
      if (err) {
        return { configured: true, remote: { reachable: false, backups: [] }, lastLocalSnapshot: lastLocalSnapshot || undefined, error: err }
      }
      const backups = await listRemoteBackups(c)
      return {
        configured: true,
        remote: { reachable: true, backups, latest: backups.length ? backups[backups.length - 1].name : undefined },
        lastLocalSnapshot: lastLocalSnapshot || undefined,
      }
    } catch (e) {
      return {
        configured: true, remote: { reachable: false, backups: [] },
        lastLocalSnapshot: lastLocalSnapshot || undefined,
        error: e && e.message ? e.message : String(e),
      }
    }
  }

  const handleConfig = async (body) => {
    const c = {
      url: String(body.url || '').trim(),
      username: String(body.username || ''),
      password: String(body.password || ''),
      remoteDir: String(body.remoteDir || '').trim(),
    }
    if (!c.url) return { ok: false, error: 'url 不能为空' }
    const err = await ensureRemoteDir(c)
    if (err) return { ok: false, error: err }
    savePluginConfig(c)
    return { ok: true }
  }

  const handleBackup = async (body) => {
    const c = loadPluginConfig()
    if (!c) return { ok: false, error: '尚未配置 WebDAV（先 POST /dsh-sync/config）' }
    const passphrase = String(body.passphrase || '')
    if (!passphrase) return { ok: false, error: 'passphrase 不能为空' }
    const relFiles = collectFiles(dshRoot)
    const payload = buildPayload(dshRoot, relFiles, collectInstallMeta(dshRoot, cfg.profile))
    const bundle = encryptBundle(payload, passphrase)
    const name = bundleName()
    const url = remoteDirUrl(c, name)
    const res = await davRequest(url, 'PUT', {
      username: c.username, password: c.password,
      headers: { 'Content-Type': 'application/octet-stream' },
      body: bundle, timeoutMs: 120000,
    })
    if (res.status !== 200 && res.status !== 201 && res.status !== 204) {
      return { ok: false, error: 'PUT 失败（HTTP ' + res.status + '）' }
    }
    log('backup uploaded: ' + name + ' (' + bundle.length + ' bytes, ' + relFiles.length + ' files)')
    return { ok: true, name, size: bundle.length, fileCount: relFiles.length }
  }

  const handleRestore = async (body) => {
    const c = loadPluginConfig()
    if (!c) return { ok: false, error: '尚未配置 WebDAV' }
    const passphrase = String(body.passphrase || '')
    if (!passphrase) return { ok: false, error: 'passphrase 不能为空' }
    let name = body.name ? String(body.name) : null
    if (!name) {
      const backups = await listRemoteBackups(c)
      if (!backups.length) return { ok: false, error: '远端没有备份' }
      name = backups[backups.length - 1].name
    }
    const url = remoteDirUrl(c, name)
    const res = await davRequest(url, 'GET', { username: c.username, password: c.password, timeoutMs: 120000 })
    if (res.status !== 200) return { ok: false, error: 'GET 失败（HTTP ' + res.status + '）' }
    const payload = decryptBundle(res.body, passphrase)
    // 恢复前先本地快照（安全性快照，本身就是回滚目标）
    lastLocalSnapshot = makeSnapshot(dshRoot, snapshotRoot, SNAPSHOT_KEEP)
    // 只覆盖：备份里没有的现有文件（含 dsh-runtimes/ 等排除项）一律保留
    const count = extractPayload(payload, dshRoot)
    // 记录本次恢复的插件依赖映射，供设置卡片上的「重装插件依赖」按钮使用。
    // 刻意不在此处自动跑 pnpm install：恢复流程只做文件覆盖，安装由用户点击触发。
    const meta = extractPayloadMeta(payload)
    if (meta) {
      writeLastRestore(dshRoot, {
        at: new Date().toISOString(), bundle: name,
        profile: meta.profile || cfg.profile, linkMap: meta.linkMap || {},
      })
    }
    log('restored ' + name + ': ' + count + ' files (snapshot ' + lastLocalSnapshot + ')' +
        (meta ? ', install meta captured' : ', no install meta in bundle'))
    return { ok: true, restored: count, snapshot: lastLocalSnapshot, meta: meta ? { profile: meta.profile, linkCount: Object.keys(meta.linkMap || {}).length } : undefined }
  }

  const handleRollback = async (body) => {
    const snapshot = String(body.snapshot || '')
    if (!snapshot || snapshot.includes('..') || /[\\/]$/.test(snapshot) || snapshot.includes('/') || snapshot.includes('\\')) {
      return { ok: false, error: 'snapshot 名称非法' }
    }
    const dir = join(snapshotRoot, snapshot)
    if (!existsSync(dir)) return { ok: false, error: '快照不存在: ' + snapshot }
    // 只覆盖式还原快照内的文件；快照未覆盖的现有文件（dsh-runtimes/ 等）原样保留
    const { count } = rollbackFromSnapshot(dir, dshRoot, snapshotRoot, SNAPSHOT_KEEP)
    lastLocalSnapshot = snapshot
    log('rolled back to snapshot ' + snapshot + ': ' + count + ' files')
    return { ok: true, restored: count }
  }

  /**
   * 默认 runner：用异步 spawn 跑子进程。
   *
   * 必须异步 —— 实测冷装 7 个插件依赖耗时 2 分 6.7 秒，最坏要等满 INSTALL_TIMEOUT_MS。
   * 路由 handler 就跑在 DSH 主进程的事件循环上，若在此处用 spawnSync 同步等待，
   * 这十几分钟里整个 DSH 的 web 服务（含所有其他插件与 UI 请求）都会被钉住；
   * 客户端的 doInstall() 也按异步设计（置 busy、等响应），双方才对得齐。
   * 输出按 LOG_TAIL_CHARS 限长累积，避免长日志把内存撑爆。
   */
  const defaultRunner = (opt) => new Promise((resolve) => {
    let child
    try {
      child = spawn(opt.cmd, opt.args, {
        cwd: opt.cwd, env: opt.env, timeout: opt.timeout,
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (e) {
      resolve({ status: null, stdout: '', stderr: '', error: e })
      return
    }
    // stdout/stderr 各自按 LOG_TAIL_CHARS 限长累积（超限丢最早的部分，只留末尾诊断信息）
    const tails = { stdout: '', stderr: '' }
    const collect = (key) => (buf) => {
      const s = tails[key] + buf.toString('utf8')
      tails[key] = s.length > LOG_TAIL_CHARS ? s.slice(s.length - LOG_TAIL_CHARS) : s
    }
    child.stdout.on('data', collect('stdout'))
    child.stderr.on('data', collect('stderr'))
    let settled = false
    const done = (val) => { if (!settled) { settled = true; resolve(val) } }
    child.on('error', (e) => done({ status: null, stdout: tails.stdout, stderr: tails.stderr, error: e }))
    child.on('close', (code, signal) => done({
      status: code,
      stdout: tails.stdout,
      stderr: tails.stderr,
      error: signal ? new Error('子进程被信号终止：' + signal) : undefined,
    }))
  })

  // ---- 恢复后重装插件依赖 ----

  /** 解析实际使用的 profile：优先 cfg.profile，其次看哪个 profiles/<n> 里有 bundle 配置 */
  const resolveProfile = () => {
    const wanted = String(cfg.profile || 'desktop')
    const direct = join(dshRoot, 'profiles', wanted)
    try {
      if (existsSync(join(direct, 'package.json'))) return { name: wanted, dir: direct }
    } catch (e) { /* ignore */ }
    try {
      for (const n of readdirSync(join(dshRoot, 'profiles'))) {
        const dir = join(dshRoot, 'profiles', n)
        try {
          const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
          if (pkg.dsh && pkg.dsh.profile && pkg.dsh.profile.bundles) return { name: n, dir }
        } catch (e) { /* 跳过没有 package.json 的目录 */ }
      }
    } catch (e) { /* ignore */ }
    return { name: wanted, dir: direct }
  }

  /** 组合「插件依赖现状」：已装/缺失、可否改写、能否安装。
   *  字段形状遵循 client.js 头部契约：missing 是包名数组，deps[].installed 是布尔值。 */
  const buildPluginsReport = () => {
    const prof = resolveProfile()
    // 恢复时记录的映射必须先读：B 机上 node_modules 尚未重建，只能靠备份里的 linkMap
    const last = readLastRestore(dshRoot)
    const plan = planProfileInstall(prof.dir, last && last.linkMap)
    const pnpmPath = findPnpmPath(process.resourcesPath)
    const nodeModules = join(prof.dir, 'node_modules')
    const deps = []
    const missing = []
    const mapped = {}
    if (plan.ok) {
      for (const it of plan.deps) {
        const installed = existsSync(join(nodeModules, it.name, 'package.json'))
        if (!installed) missing.push(it.name)
        const row = { name: it.name, spec: it.spec, kind: it.kind, installed }
        if (it.rewrite) row.rewrite = it.rewrite
        if (it.reason) row.reason = it.reason
        if (it.removed) row.removed = true
        if (it.kept) row.kept = true
        deps.push(row)
        if (it.rewrite) mapped[it.name] = { spec: it.rewrite, reason: it.reason || 'repository.url' }
      }
    }
    return {
      profile: prof.name,
      profileDir: prof.dir,
      found: plan.ok,
      error: plan.ok ? undefined : plan.error,
      deps,
      missing,
      missingCount: missing.length,
      needsInstall: missing.length > 0,
      mapped,
      pnpm: { available: !!pnpmPath, path: pnpmPath || undefined },
      lastRestore: last ? { at: last.at, bundle: last.bundle } : undefined,
    }
  }

  /** 实测：改写 spec → 备份 package.json → 跑 pnpm install（可注入 runner 供测试） */
  const runProfileInstall = async (runner, pnpmPathOpt, opts) => {
    if (installing) return { ok: false, error: '安装正在进行中，请稍候' }
    const prof = resolveProfile()
    const file = join(prof.dir, 'package.json')
    // 区分「未提供」与「显式传入空值」：测试用 null 模拟找不到 pnpm，不能被 || 吞掉
    const pnpmPath = pnpmPathOpt === undefined ? findPnpmPath(process.resourcesPath) : pnpmPathOpt
    if (!pnpmPath) return { ok: false, error: '未找到 pnpm（期望 resources/runtime/pnpm/bin/pnpm.mjs）' }

    // 1) 把 link:/file: 改写成仓库地址；无法推导的直接移除（宁可少装一个插件也不能让整条 install 失败）
    //    改写规则与 /plugins 报告共用 planProfileInstall，避免两处判断分叉
    const last = readLastRestore(dshRoot)
    const plan = planProfileInstall(prof.dir, last && last.linkMap)
    if (!plan.ok) return { ok: false, error: plan.error }
    const pkg = plan.pkg
    const deps = pkg.dependencies && typeof pkg.dependencies === 'object' ? pkg.dependencies : {}
    const rewritten = Object.create(null)
    const removed = Object.create(null)
    // 返回值形状对齐 client.js 契约：rewritten 是 { 包名: 改写后的声明 }，
    // removed 是包名数组，installed 是本次成功安装的包名数组
    for (const it of plan.deps) {
      if (it.rewrite) { rewritten[it.name] = { from: it.spec, to: it.rewrite }; deps[it.name] = it.rewrite }
      else if (it.removed) { removed[it.name] = it.spec; delete deps[it.name] }
    }
    const mapped = (last && last.linkMap) || {}

    const changed = Object.keys(rewritten).length || Object.keys(removed).length
    if (changed) {
      const bak = file + '.bak-dsh-sync-' + new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
      try {
        copyFileSync(file, bak)
        writeJsonFile(file, pkg)
        log('plugin install: rewrote ' + Object.keys(rewritten).length + ' link deps, removed ' + Object.keys(removed).length + ' (backup ' + bak + ')')
      } catch (e) {
        return { ok: false, error: '改写 package.json 失败：' + (e && e.message ? e.message : String(e)) }
      }
    } else if (!existsSync(file)) {
      return { ok: false, error: 'profile 的 package.json 不存在' }
    }

    // 2) 跑 pnpm install（普通模式：顺带把锁文件里遗留的 link: specifier 一并同步，否则后续
    //    DSH 自己的 pnpm install --frozen-lockfile 会因为 package.json 与锁文件不一致而失败）
    const args = [pnpmPath, 'install']
    installing = true
    const startedAt = Date.now()
    // 升级路径装的是 github: 依赖，必须把 git 的 SSH 回退拉回 HTTPS（见 githubHttpsOnlyEnv）
    const baseEnv = { ...process.env, ELECTRON_RUN_AS_NODE: '1' }
    const childEnv = opts && opts.githubHttpsOnly ? githubHttpsOnlyEnv(baseEnv) : baseEnv
    let r
    try {
      r = await runner({ cmd: process.execPath, args, cwd: prof.dir, env: childEnv, timeout: INSTALL_TIMEOUT_MS })
    } catch (e) {
      installing = false
      return { ok: false, error: 'pnpm install 启动失败：' + (e && e.message ? e.message : String(e)), log: '' }
    }
    installing = false
    const durationMs = Date.now() - startedAt
    const tail = (String(r.stdout || '') + String(r.stderr || '')).slice(-LOG_TAIL_CHARS)
    const ok = r.status === 0
    let lockSynced = null
    // 本次真正就位的包（以 node_modules 里是否有 package.json 为准）
    const installedNames = []
    if (ok) {
      for (const it of plan.deps) {
        if (existsSync(join(prof.dir, 'node_modules', it.name, 'package.json'))) installedNames.push(it.name)
      }
    }
    const rewrittenOut = {}
    for (const [n, v] of Object.entries(rewritten)) rewrittenOut[n] = v.to
    const removedOut = Object.keys(removed)
    if (ok) {
      // 锁文件里是否还残留 link: specifier —— 残留会让 DSH 自己的 --frozen-lockfile 失败
      lockSynced = lockSyncedOf(prof.dir)
      writeLastRestore(dshRoot, {
        at: new Date().toISOString(), profile: prof.name,
        linkMap: mapped, rewritten, removed, lockSynced,
      })
      log('plugin install ok in ' + durationMs + 'ms (rewritten ' + Object.keys(rewritten).length + ', removed ' + Object.keys(removed).length + ', lockSynced ' + lockSynced + ')')
    } else {
      log('plugin install failed: exit ' + r.status + ' / ' + (r.error ? String(r.error) : 'see log'))
    }
    return {
      ok, installed: installedNames, exitCode: r.status, durationMs,
      rewritten: rewrittenOut, removed: removedOut, lockSynced: ok ? lockSynced : undefined,
      log: tail, error: ok ? undefined : 'pnpm install 退出码 ' + r.status,
    }
  }

  /** 读取锁文件是否仍有 link: specifier（同步校验，供返回值使用） */
  const lockSyncedOf = (profileDir) => {
    try { return !/link:/.test(readFileSync(join(profileDir, 'pnpm-lock.yaml'), 'utf8')) } catch (e) { return null }
  }

  /** 供测试直接调用的纯函数包装：不传 runner 时用默认异步实现 */
  const handlePlugins = async () => {
    try {
      return { ok: true, ...buildPluginsReport() }
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : String(e) }
    }
  }

  const handlePluginInstall = async (body, runner, pnpmPathOpt) => {
    try {
      return await runProfileInstall(runner || defaultRunner, pnpmPathOpt)
    } catch (e) {
      installing = false
      return { ok: false, error: e && e.message ? e.message : String(e) }
    }
  }

  // ---------- 版本检查 / 自我升级（模块整体 fail-soft：任何网络失败都不得影响既有端点） ----------

  const versionCache = new Map()
  let lastCheckedAt = null

  /** 只读本机自身的安装态：版本、原始声明、kind/mode、锁文件 sha。全部来自磁盘，不联网。 */
  const inspectSelf = () => {
    const pkgName = selfPackageName()
    if (!pkgName) return { ok: false, error: '无法读取自身 package.json（name 缺失）' }
    const prof = resolveProfile()
    if (!prof || !prof.dir) return { ok: false, error: '未找到 profile 目录', pkgName }
    let pkg = null
    try { pkg = JSON.parse(readFileSync(join(prof.dir, 'package.json'), 'utf8')) } catch (e) { pkg = null }
    const deps = (pkg && pkg.dependencies && typeof pkg.dependencies === 'object') ? pkg.dependencies : {}
    // 依赖键名用读到的包名匹配，绝不写死旧名
    const spec = Object.prototype.hasOwnProperty.call(deps, pkgName) ? String(deps[pkgName]) : null
    const kind = depKind(spec)
    // link:/file:/portal: 一律视为开发态（本机指向源码目录），其余算受管安装
    const mode = kind === 'link' ? 'dev' : 'managed'
    let installed = null
    try { installed = JSON.parse(readFileSync(join(prof.dir, 'node_modules', pkgName, 'package.json'), 'utf8')) } catch (e) { installed = null }
    const current = (installed && installed.version) ? String(installed.version) : selfVersion()
    return { ok: true, pkgName, prof, spec, kind, mode, current, localSha: localShaFromLock(prof.dir, pkgName), hasProfPkg: !!pkg }
  }

  const emptyVersionShape = (extra) => ({
    ok: true, current: selfVersion(), mode: 'managed', kind: 'unknown', spec: null,
    repo: selfRepoSlug(), hasUpdate: false, latest: null, changelog: [],
    checkedAt: lastCheckedAt, checked: false, error: null, ...extra,
  })

  /** GET /dsh-sync/version（?force=1 跳过缓存）。契约形状见任务书；失败也返回 200 + ok:true + error */
  const handleVersion = async (body, req, opts) => {
    const o = opts || {}
    try {
      const info = inspectSelf()
      const slug = selfRepoSlug()
      const base = emptyVersionShape({
        current: info.ok ? info.current : selfVersion(),
        mode: info.ok ? info.mode : 'managed',
        kind: info.ok ? info.kind : 'unknown',
        spec: info.ok ? info.spec : null,
        repo: slug || null,
      })
      if (!slug) return { ...base, error: '无法从自身 package.json 的 repository.url 解析出仓库地址' }
      // registry 安装一律不自动升级：npm 上同名包属于另一个作者
      if (info.ok && info.kind === 'registry') return { ...base, error: registryRejectError(info.pkgName) }
      let result
      try {
        result = await (o.check || performVersionCheck)(base.current, slug, {
          httpsGet: o.httpsGet, cache: versionCache, now: o.now,
          force: !!(o.force || queryFlag(req && req.url, 'force')),
          localSha: info.ok ? info.localSha : null,
          pkgName: info.ok ? info.pkgName : null,
        })
      } catch (e) {
        // performVersionCheck 本身已 fail-soft；这里兜住注入替身抛出的异常，端点仍返回 200
        return { ...base, error: '版本检查失败：' + (e && e.message ? e.message : String(e)) }
      }
      if (result && result.checkedAt) lastCheckedAt = result.checkedAt
      return {
        ...base,
        hasUpdate: !!result.hasUpdate,
        latest: result.latest || null,
        changelog: Array.isArray(result.changelog) ? result.changelog.slice(0, COMPARE_MAX_MESSAGES) : [],
        checkedAt: result.checkedAt || null,
        checked: result.checked !== false,
        error: result.error || null,
      }
    } catch (e) {
      return emptyVersionShape({ repo: selfRepoSlug(), error: '版本检查失败：' + (e && e.message ? e.message : String(e)) })
    }
  }

  /**
   * POST /dsh-sync/upgrade。把 profile 的 dependencies[<自身包名>] 改写成指向目标 ref 的
   * 确定性 spec（github:<owner>/<repo>#<tag|sha>），备份 package.json，再复用既有的
   * runProfileInstall() 跑一次 pnpm install（单飞护栏/超时/日志截断都在里面）。
   *
   * 为什么复用裸 `pnpm install` 就够：pnpm 的「锁文件已最新 → 跳过 resolution」只对裸 install 生效；
   * 一旦 specifier 本身变了（link: → github:#tag）它就必然重新解析该依赖。这也是这里必须
   * 先断言 spec 真的变了的原因 —— 没变就别白跑一次安装。
   *
   * 安全红线：只改写 dependencies[<name>] 这一个键，其它依赖键与 dsh.profile.bundles 等字段原样保留。
   */
  const handleUpgrade = async (body, req, opts) => {
    const o = opts || {}
    const started = Date.now()
    try {
      const info = inspectSelf()
      if (!info.ok) return { ok: false, error: info.error || '无法读取本机插件信息' }
      const { pkgName } = info
      const slug = selfRepoSlug()
      if (!slug) return { ok: false, error: '无法从自身 package.json 的 repository.url 解析出仓库地址' }

      // 1) 开发态拒绝：本机指向源码目录，升级的正确做法是 git pull
      if (info.kind === 'link') {
        return { ok: false, error: '开发态安装（link:）：本机指向源码目录，请用 git pull 更新' }
      }
      // 2) registry 安装拒绝：npm 同名包属于另一个作者
      if (info.kind === 'registry') return { ok: false, error: registryRejectError(pkgName) }

      // 3) 版本检查（force：升级前必须拿最新结果，不受 10 分钟缓存影响）
      const direct = o.check || performVersionCheck
      const ver = await direct(info.current, slug, {
        httpsGet: o.httpsGet, cache: versionCache, now: o.now, force: true,
        localSha: info.localSha, pkgName,
      })
      if (ver && ver.checkedAt) lastCheckedAt = ver.checkedAt
      if (ver && ver.error) return { ok: false, error: ver.error }
      if (!ver || !ver.hasUpdate) {
        return { ok: true, upgraded: false, alreadyLatest: true, from: info.current, to: info.current, spec: info.spec, exitCode: 0, durationMs: Date.now() - started, needRestart: false, before: { version: info.current, spec: info.spec }, backup: null, log: '', error: null }
      }
      const ref = ver.latestTag || ver.remoteSha
      if (!ref) return { ok: false, error: '远端最新版本没有可用的 tag 或 commit，无法生成确定性 spec' }

      // 4) 改写 spec（备份 package.json → 写回）。只动这一个键。
      const file = join(info.prof.dir, 'package.json')
      let pkg
      try { pkg = JSON.parse(readFileSync(file, 'utf8')) } catch (e) {
        return { ok: false, error: 'profile 的 package.json 读取失败：' + (e && e.message ? e.message : String(e)) }
      }
      const before = JSON.parse(JSON.stringify(pkg))
      pkg.dependencies = (pkg.dependencies && typeof pkg.dependencies === 'object') ? pkg.dependencies : {}
      const newSpec = 'github:' + slug + '#' + ref
      const oldSpec = pkg.dependencies[pkgName]
      // spec 未变 → 已在该 ref 上，直接返回，不白跑一次 pnpm install
      if (String(oldSpec) === newSpec) {
        return { ok: true, upgraded: false, from: info.current, to: ver.latest, spec: newSpec, exitCode: 0, durationMs: Date.now() - started, needRestart: false, before: { version: info.current, spec: oldSpec === undefined ? null : String(oldSpec) }, backup: null, log: '', error: null }
      }
      pkg.dependencies[pkgName] = newSpec
      const backup = file + '.bak-dsh-sync-' + new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
      try {
        copyFileSync(file, backup)
        writeJsonFile(file, pkg)
      } catch (e) {
        return { ok: false, error: '改写 profile package.json 失败：' + (e && e.message ? e.message : String(e)), durationMs: Date.now() - started }
      }
      if (!nonTargetFieldsIntact(before, pkg, pkgName)) {
        return { ok: false, error: '改写后校验失败：目标依赖之外的字段发生变化，已终止（备份见 ' + backup + '）', durationMs: Date.now() - started }
      }
      log('upgrade: ' + (oldSpec === undefined ? '(none)' : String(oldSpec)) + ' -> ' + newSpec + ' (backup ' + backup + ')')

      // 5) 复用既有安装路径（绝不新写第二条 pnpm install 分支）
      const install = o.install || ((r, p, op) => runProfileInstall(r || defaultRunner, p, op))
      const ir = await install(o.runner, o.pnpmPath, { githubHttpsOnly: true })
      const logTail = (ir && ir.log) ? String(ir.log) : ''
      if (!ir || !ir.ok) {
        return { ok: false, error: (ir && ir.error) ? ir.error : 'pnpm install 失败', log: logTail, durationMs: Date.now() - started, backup, from: info.current, to: ver.latest, spec: newSpec }
      }
      // 6) 重新读 profile package.json 确认 spec 已落地；to = 目标版本，needRestart 恒为 true
      //    （插件代码在 DSH 启动时加载，生效必须重启 —— 已实测确认）
      let confirmed = null
      try {
        const after = JSON.parse(readFileSync(file, 'utf8'))
        confirmed = after.dependencies ? after.dependencies[pkgName] : null
      } catch (e) { confirmed = null }
      if (String(confirmed) !== newSpec) {
        return { ok: false, error: '安装后校验失败：profile 里仍是 ' + String(confirmed), log: logTail, durationMs: Date.now() - started, backup, from: info.current, to: ver.latest, spec: newSpec }
      }
      log('upgrade ok: ' + info.current + ' -> ' + ver.latest + ' in ' + (Date.now() - started) + 'ms')
      return {
        ok: true, from: info.current, to: ver.latest, upgraded: true, spec: newSpec,
        exitCode: (ir && typeof ir.exitCode === 'number') ? ir.exitCode : 0, durationMs: Date.now() - started,
        needRestart: true, before: { version: info.current, spec: oldSpec === undefined ? null : String(oldSpec) },
        backup, log: logTail, error: null,
      }
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : String(e), durationMs: Date.now() - started }
    }
  }

  const handlers = {
    'GET /dsh-sync/status': handleStatus,
    'GET /dsh-sync/plugins': handlePlugins,
    'GET /dsh-sync/version': handleVersion,
    'POST /dsh-sync/config': handleConfig,
    'POST /dsh-sync/backup': handleBackup,
    'POST /dsh-sync/restore': handleRestore,
    'POST /dsh-sync/rollback': handleRollback,
    'POST /dsh-sync/plugins/install': (body) => handlePluginInstall(body),
    'POST /dsh-sync/upgrade': handleUpgrade,
  }

  /** 供 tools-selftest.mjs 直接调用的内部句柄（不启动 DSH、不注册路由） */
  apply._internals = {
    handlePlugins, handlePluginInstall, buildPluginsReport, resolveProfile, defaultRunner,
    handleVersion, handleUpgrade, inspectSelf, versionCache, runProfileInstall,
  }

  const setupRoutes = (routeCtx) => {
    try {
      const webServer = resolveService(routeCtx, 'webServer')
      if (!webServer || typeof webServer.register !== 'function') {
        log('webServer service unavailable; HTTP endpoints disabled')
        return
      }
      for (const [route, handler] of Object.entries(handlers)) {
        const [method, path] = route.split(' ')
        const dispose = webServer.register({
          kind: 'exact',
          path,
          handler: async (req, res) => {
            try {
              if (req.method !== method) {
                return json(res, { ok: false, error: '方法不允许：需要 ' + method })
              }
              const body = method === 'POST' ? await readBody(req) : {}
              const result = await handler(body, req)
              json(res, result)
            } catch (e) {
              json(res, { ok: false, error: e && e.message ? e.message : String(e) })
            }
          },
        })
        if (typeof dispose === 'function') cleanupFns.push(dispose)
      }
      log('HTTP endpoints ready: /dsh-sync/{status,config,backup,restore,rollback,plugins,plugins/install,version,upgrade}')
    } catch (e) {
      log('route registration failed: ' + (e && e.message ? e.message : String(e)))
    }
  }

  try {
    if (ctx && typeof ctx.inject === 'function') {
      const off = ctx.inject(['webServer'], setupRoutes)
      if (typeof off === 'function') cleanupFns.push(off)
    } else {
      setupRoutes(ctx)
    }
  } catch (e) {
    log('inject(webServer) failed: ' + (e && e.message ? e.message : String(e)))
    try { setupRoutes(ctx) } catch (e2) { /* ignore */ }
  }

  if (ctx && typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      for (const fn of cleanupFns) {
        try { fn() } catch (e) { /* ignore */ }
      }
      log('host half disposed')
    })
  }
}

/** 供 tools-selftest.mjs 使用的测试句柄：每次 apply 后指向最新实例（软引用，不参与运行时逻辑）。
 *  必须在模块加载时就存在，才能由自测以 `Object.keys(indexJs)` 断言导出面未被破坏。 */
export let selftest = null

/** 以测试配置启动一份 host 半区实例并拿到内部句柄（不注册路由，无副作用）。
 *  cfg.enableRoutes=false 时连 webServer 注入都跳过，便于在纯 node 下验证端点逻辑。 */
export function createTestHarness(config) {
  const fakeCtx = { inject: () => () => {}, effect: () => () => {} }
  apply(fakeCtx, { ...(config || {}), __test: true })
  selftest = apply._internals
  return selftest
}
