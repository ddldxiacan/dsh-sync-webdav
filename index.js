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
// `"dsh-sync-plugin": "link:E:/..."` 这种绝对路径依赖，在 B 机上根本不存在，
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
  const runProfileInstall = async (runner, pnpmPathOpt) => {
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
    let r
    try {
      r = await runner({ cmd: process.execPath, args, cwd: prof.dir, env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, timeout: INSTALL_TIMEOUT_MS })
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

  const handlers = {
    'GET /dsh-sync/status': handleStatus,
    'GET /dsh-sync/plugins': handlePlugins,
    'POST /dsh-sync/config': handleConfig,
    'POST /dsh-sync/backup': handleBackup,
    'POST /dsh-sync/restore': handleRestore,
    'POST /dsh-sync/rollback': handleRollback,
    'POST /dsh-sync/plugins/install': (body) => handlePluginInstall(body),
  }

  /** 供 tools-selftest.mjs 直接调用的内部句柄（不启动 DSH、不注册路由） */
  apply._internals = { handlePlugins, handlePluginInstall, buildPluginsReport, resolveProfile, defaultRunner }

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
              const result = await handler(body)
              json(res, result)
            } catch (e) {
              json(res, { ok: false, error: e && e.message ? e.message : String(e) })
            }
          },
        })
        if (typeof dispose === 'function') cleanupFns.push(dispose)
      }
      log('HTTP endpoints ready: /dsh-sync/{status,config,backup,restore,rollback,plugins,plugins/install}')
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
