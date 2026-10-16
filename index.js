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

import {
  createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync,
} from 'node:crypto'
import {
  appendFileSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import http from 'node:http'
import https from 'node:https'

const MAGIC = Buffer.from('DSHSYNC1', 'utf8')
const MAX_FILE_BYTES = 10 * 1024 * 1024
const SNAPSHOT_KEEP = 5
const CONFIG_FILE_NAME = 'dsh-sync.json'
const SNAPSHOT_ROOT_NAME = '.dsh-sync-snapshots'

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

/** 打包（未加密）：返回明文 payload Buffer */
export function buildPayload(root, relFiles) {
  const files = []
  for (const rel of relFiles) {
    const buf = readFileSync(join(root, rel))
    files.push({ path: rel, sha256: createHash('sha256').update(buf).digest('hex'), data: buf.toString('base64') })
  }
  return Buffer.from(JSON.stringify({ files }), 'utf8')
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
    const payload = buildPayload(dshRoot, relFiles)
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
    log('restored ' + name + ': ' + count + ' files (snapshot ' + lastLocalSnapshot + ')')
    return { ok: true, restored: count, snapshot: lastLocalSnapshot }
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

  const handlers = {
    'GET /dsh-sync/status': handleStatus,
    'POST /dsh-sync/config': handleConfig,
    'POST /dsh-sync/backup': handleBackup,
    'POST /dsh-sync/restore': handleRestore,
    'POST /dsh-sync/rollback': handleRollback,
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
              const result = await handler(body)
              json(res, result)
            } catch (e) {
              json(res, { ok: false, error: e && e.message ? e.message : String(e) })
            }
          },
        })
        if (typeof dispose === 'function') cleanupFns.push(dispose)
      }
      log('HTTP endpoints ready: /dsh-sync/{status,config,backup,restore,rollback}')
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
