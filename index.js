/**
 * DSH Sync · Host 半区
 *
 * 把 ~/.dsh 打包加密备份到 WebDAV，支持恢复与回滚。纯手动触发，
 * Host 不做任何定时/自动行为。无 npm 依赖、fail-soft。
 *
 * 恢复/回滚把「配置范围」对齐到所选备份或快照，但恢复有**三种模式**（0.4.2 起由用户在确认弹窗里选）：
 *   merge（默认）  只补本机没有的文件；本机已有的配置一律不动，内容不同的列成「冲突」回报。
 *   overwrite      备份里的文件全部覆盖写入，但本机多出来的配置不删。
 *   mirror         覆盖写入 + 删掉备份里没有的配置（0.3.5~0.4.1 的旧行为，即「完全覆盖」）。
 * 为什么默认 merge：换机场景里 B 机往往已经装好插件、配了皮肤，旧版一律对齐会把用户在 B 机的
 * 改动默默冲掉，还会删掉备份里没有的配置文件。全新机器上 merge 与 mirror 结果相同（本机没有
 * 多余配置可冲突），所以默认取保守的一端，由想「一模一样」的用户显式选完全覆盖。
 * 回滚语义不变：仍是对齐到快照（快照是同一台机器的历史状态，保留冲突没有意义）。
 * 配置范围就是 collectFiles / collectAppDataFiles 会打包的路径。
 * 排除项一律不动：dsh-runtimes/、node_modules/、sessions/、logs/、npm-cache、
 * tmp*、cache*、单文件 >50MB，以及 AppData 里的缓存目录。这些不在备份里，
 * 删掉会让 DSH 无法启动，或丢掉聊天记录和可重装的插件代码。
 * 旧备份若完全没有 __appdata__ 条目、也没有 meta.appDataIncluded，说明它没采集
 * 应用级设置，恢复时不删除本机 AppData 配置。
 *
 * 备份包含 dsh-sync.json 自身的 WebDAV 凭据（url/username/password），属有意设计：
 * 用户要求配置整体同步，故清单与凭据一并进备份；备份本身已用口令加密。
 *
 * 0.3.0 起，Electron 应用级设置（%APPDATA%\@deepseek-ai\dsh-desktop\desktop\settings.json 等
 * 小型配置文件）也一并打包：以 __appdata__/ 前缀并入同一 payload，恢复/回滚时自动写回原位；
 * Chromium 缓存类目录（Cache/Local Storage/blob_storage 等）与 >2MB 文件仍排除。
 *
 * 备份文件格式（二进制）：
 *   [8 字节 magic "DSHSYNC1"][4 字节 headerLen(LE)][header JSON utf8][AES-256-GCM ciphertext]
 *   header: { version, salt(b64), iv(b64), tag(b64), payloadSha256 }
 *   明文 payload: JSON { files: [{ path, sha256, data(b64) }] }
 *   密钥 = scrypt(passphrase, salt, 32)。口令可以记在本机 dsh-sync.json，方便下次备份/恢复留空使用；
 *   打包时会从 dsh-sync.json 里剥掉口令，备份内容本身不含口令。状态接口只回报「已记住」，不回传口令。
 */

import { spawn } from 'node:child_process'
import {
  createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync,
} from 'node:crypto'
import {
  appendFileSync, chmodSync, closeSync, copyFileSync, existsSync, mkdirSync, openSync, readdirSync,
  readFileSync, readSync, realpathSync, renameSync, rmdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { delimiter, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import http from 'node:http'
import https from 'node:https'
import { fileURLToPath } from 'node:url'

const MAGIC = Buffer.from('DSHSYNC1', 'utf8')
const MAX_FILE_BYTES = 50 * 1024 * 1024
const SNAPSHOT_KEEP = 5
const REMOTE_KEEP = 5
const CONFIG_FILE_NAME = 'dsh-sync.json'
const SNAPSHOT_ROOT_NAME = '.dsh-sync-snapshots'
const RESTORE_STATE_NAME = 'dsh-sync-last-restore.json'
// 远程目录的默认值。空字符串在历史上表示「网盘根目录」，是个有意义的取值，
// 不能拿它当「没填」——所以默认值只在字段**完全缺失**时补上（见 applyDefaultRemoteDir）。
// 为什么要有默认值：根目录下会跟网盘里其它文件混在一起，删/找备份都不方便；
// 给个固定子目录既清爽，也避免两台机器各自往根目录堆东西。
const DEFAULT_REMOTE_DIR = 'dsh-sync'
// Electron 应用级用户数据（settings.json 等）：不在 ~/.dsh 下，单独收集后以 __appdata__/ 前缀入库。
// 只取稳定的小型配置文件，排除 Chromium 缓存类目录（体积大且可再生）。
const APPDATA_ROOT_NAME = '@deepseek-ai'
const APPDATA_PREFIX = '__appdata__/'
const APPDATA_MAX_FILE_BYTES = 2 * 1024 * 1024

// —— home 级挂载点 ——
// DSH 插件与相邻工具的自定义模型配置并不总在 ~/.dsh 下：模型目录、价表、provider
// 切换器散落在 home 根下。只按白名单收「配置」，绝不收可重建产物（venv / .git /
// 备份 / 日志 / 会话），并同样以挂载前缀并入同一 payload，恢复/回滚时写回原位。
const HOME_PREFIX = '__home__/'
// 单文件上限比 AppData 宽（.cc-switch 的 sqlite 就是 1.2MB），但仍设上限防止误收大文件。
const HOME_MAX_FILE_BYTES = 8 * 1024 * 1024
// name  home 下的顶层名；include 非空时只收这些相对路径（目录则整棵收）；
// excludeDirs / excludeFiles 是逐项黑名单（可再生的备份、日志、诊断产物）。
const HOME_MOUNTS = [
  { name: '.dsh-freetap' },
  { name: '.dsh-opencode-free' },
  { name: '.opencode2dsh' },
  { name: '.dsh-wallpaper-engine', excludeDirs: ['diag', 'cache', 'thumbs', 'uploads', 'avatars', 'ffmpeg'] },
  { name: '.cc-switch', excludeDirs: ['backups', 'logs'], excludeFiles: ['crash.log'] },
  { name: '.claude', include: ['settings.json', 'settings.local.json', 'skills', 'cc-haha', 'plugins/known_marketplaces.json'] },
]
// 任何挂载点内都不收的目录名：可重建 / 可再生 / 仓库元数据 / 机器本地运行态。
const HOME_SKIP_DIR_NAMES = new Set(['node_modules', '.git', '.runtime', 'cache', 'Cache', 'logs', 'tmp'])
// ~/.dsh 里被 cache*/tmp* 规则误伤的「配置性质」路径前缀：显式白名单放行。
// peakrate.json 是模型分时费率表，属于模型数据，不是可再生缓存。
const CACHE_KEEP_PREFIXES = [
  'cache/dsh-claude-style/',
]
export function isExcludedAppData(relPosix, fileSizeBytes, isDir) {
  // 采用「缓存目录黑名单 + 顶层文件白名单」：Chromium/Electron 的 userData 下绝大多数是
  // 缓存类可再生内容，只同步已知承载用户配置的文件与目录。
  const segs = relPosix.split('/')
  const APPDATA_CACHE_DIRS = new Set([
    'blob_storage', 'Cache', 'Cache_Data', 'Code Cache', 'Crashpad', 'DawnGraphiteCache',
    'DawnWebGPUCache', 'Dictionaries', 'DIPS', 'GPUCache', 'GPUPersistentCache', 'GrShaderCache',
    'Local Storage', 'Network', 'Partitions', 'Session Storage', 'ShaderCache', 'Shared Dictionary',
    'shared_proto_db', 'VideoDecodeStats', 'WebStorage', 'logs', 'old',
  ])
  for (const seg of segs) {
    if (APPDATA_CACHE_DIRS.has(seg)) return true
    if (/^Cache/.test(seg) || /^Dawn(GPU|Graphite|WebGPU)Cache$/.test(seg)) return true
  }
  // 顶层（dsh-desktop 直下）只同步白名单文件：.updaterId、lockfile、Local State、
  // Preferences、DIPS 等均为 Chromium 运行态，不属于用户配置且机器相关
  if (!isDir && segs.length === 2) {
    const KNOWN_TOP = new Set(['settings.json'])
    if (!KNOWN_TOP.has(segs[1])) return true
  }
  if (fileSizeBytes !== undefined && fileSizeBytes > APPDATA_MAX_FILE_BYTES) return true
  return false
}
/**
 * Electron 应用级用户数据的根目录（「Roaming」那一级）。按平台取真实位置：
 *   Windows  %APPDATA%                      → C:\Users\x\AppData\Roaming
 *   macOS    ~/Library/Application Support
 *   Linux    $XDG_CONFIG_HOME 或 ~/.config   （Electron 在 Linux 上的标准位置）
 *
 * 为什么必须按平台分：旧实现无脑拼 ~/AppData/Roaming。那在 Linux/macOS 上是个
 * **并不存在**的虚构目录 —— 后果是恢复一份 Windows 备份时，会在用户 home 下
 * 凭空创建 ~/AppData/Roaming/@deepseek-ai/... 这棵假目录树，而且预览里还会把它
 * 报成「本机缺少的配置」。宁可解析不到（返回 null）也不要造一个假路径。
 *
 * 备份里的键名仍然统一用 Windows 那套（dsh-desktop/desktop/settings.json），
 * 换到别的平台只是挂载点不同，靠这里切换根目录即可，不必改备份格式。
 */
function appDataRoamingRoot() {
  const platform = (appDataPlatformOverride() || process.platform)
  if (platform === 'win32') {
    if (process.env.APPDATA) return process.env.APPDATA
    try { return join(homedir(), 'AppData', 'Roaming') } catch (e) { return null }
  }
  if (platform === 'darwin') {
    try { return join(homedir(), 'Library', 'Application Support') } catch (e) { return null }
  }
  // Linux 及其它类 Unix：Electron 遵循 XDG
  if (process.env.XDG_CONFIG_HOME) return process.env.XDG_CONFIG_HOME
  try { return join(homedir(), '.config') } catch (e) { return null }
}
// 仅供自测注入「当前平台」，避免为了验证 Linux 分支而在 Windows 上造一整套环境。
// 生产路径永远返回 null，行为完全由 process.platform 决定。
let APP_DATA_PLATFORM_OVERRIDE = null
export function __setAppDataPlatformForTest(p) { APP_DATA_PLATFORM_OVERRIDE = p || null }
function appDataPlatformOverride() { return APP_DATA_PLATFORM_OVERRIDE }
export function collectAppDataFiles() {
  const roaming = appDataRoamingRoot()
  if (!roaming) return []
  const root = join(roaming, APPDATA_ROOT_NAME)
  const out = []
  const walk = (dir, prefix) => {
    let entries
    try { entries = readdirSync(dir, { withFileTypes: true }) } catch (e) { return }
    for (const ent of entries) {
      const rel = prefix ? prefix + '/' + ent.name : ent.name
      const abs = join(dir, ent.name)
      if (ent.isDirectory()) {
        if (isExcludedAppData(rel, undefined, true)) continue
        walk(abs, rel)
      } else if (ent.isFile()) {
        let size = 0
        try { size = statSync(abs).size } catch (e) { continue }
        if (isExcludedAppData(rel, size, false)) continue
        out.push(APPDATA_PREFIX + rel)
      }
    }
  }
  walk(root, '')
  out.sort()
  return out
}
/** AppData 相对路径（带 __appdata__/ 前缀）→ 绝对路径；非法或前缀不符返回 null */
export function appDataAbsPath(relPosix) {
  if (typeof relPosix !== 'string' || !relPosix.startsWith(APPDATA_PREFIX)) return null
  const rel = relPosix.slice(APPDATA_PREFIX.length)
  if (!isSafeRelPath(rel)) return null
  const roaming = appDataRoamingRoot()
  if (!roaming) return null
  return join(roaming, APPDATA_ROOT_NAME, ...rel.split('/'))
}
// home 根目录：默认 **未启用**（返回 null，不收集任何 home 文件）。
// 由插件入口 apply() 显式启用（生产 = homedir()），自测由 createTestHarness 注入隔离目录。
// 为什么不能默认 homedir()：模块层直接调用 makeSnapshot / rollback / buildPayload 的代码
// 会去读、甚至按 mirror 删用户真实的 ~/.cc-switch、~/.claude —— 那是删用户数据。
// 不隔离的话，自测会读到用户真实的 ~/.cc-switch、~/.claude，而 mirror 用例会按
// payload 删掉 home 里「备份没有」的配置 —— 直接删用户数据。
let HOME_ROOT_OVERRIDE = null
export function __setHomeRootForTest(p) { HOME_ROOT_OVERRIDE = p || null }
function homeRoot() { return HOME_ROOT_OVERRIDE }
/** 挂载点表（副本，调用方改不到内部常量）。 */
export function homeMounts() { return HOME_MOUNTS.map((m) => ({ ...m })) }
/**
 * 一个挂载点内的相对路径是否应收集。
 * include 对目录判「是否为某条目的祖先」，否则 plugins 这种中间目录会被整棵剪掉，
 * 底下的 plugins/known_marketplaces.json 永远收不到。
 */
function homeMountKeeps(mount, rel, isDir) {
  const segs = rel.split('/')
  for (const seg of segs) {
    if (HOME_SKIP_DIR_NAMES.has(seg)) return false
    if (seg.startsWith('tmp') || seg.startsWith('cache')) return false
  }
  if (Array.isArray(mount.excludeDirs)) {
    const dirSegs = isDir ? segs : segs.slice(0, -1)
    if (dirSegs.some((s) => mount.excludeDirs.includes(s))) return false
  }
  if (!isDir && Array.isArray(mount.excludeFiles) && mount.excludeFiles.includes(segs[segs.length - 1])) return false
  if (Array.isArray(mount.include)) {
    const ok = isDir
      ? mount.include.some((p) => p === rel || rel.startsWith(p + '/') || p.startsWith(rel + '/'))
      : mount.include.some((p) => rel === p || rel.startsWith(p + '/'))
    if (!ok) return false
  }
  return true
}
/** 遍历 home 挂载点，收集全部应打包文件（返回带 __home__ 前缀的 posix 路径，已排序）。 */
export function collectHomeFiles() {
  const home = homeRoot()
  if (!home) return []
  const out = []
  for (const mount of HOME_MOUNTS) {
    const seen = new Set()
    const walk = (dir, prefix) => {
      let real
      try { real = realpathSync(dir) } catch (e) { return }
      if (seen.has(real)) return
      seen.add(real)
      let entries
      try { entries = readdirSync(dir, { withFileTypes: true }) } catch (e) { return }
      for (const ent of entries) {
        const rel = prefix ? prefix + '/' + ent.name : ent.name
        const abs = join(dir, ent.name)
        let kind = null
        if (ent.isDirectory()) kind = 'dir'
        else if (ent.isFile()) kind = 'file'
        else if (ent.isSymbolicLink()) {
          let st
          try { st = statSync(abs) } catch (e) { continue }
          kind = st.isDirectory() ? 'dir' : (st.isFile() ? 'file' : null)
        }
        if (kind === 'dir') {
          if (!homeMountKeeps(mount, rel, true)) continue
          walk(abs, rel)
        } else if (kind === 'file') {
          if (!homeMountKeeps(mount, rel, false)) continue
          let size = 0
          try { size = statSync(abs).size } catch (e) { continue }
          if (size > HOME_MAX_FILE_BYTES) continue
          out.push(HOME_PREFIX + mount.name + '/' + rel)
        }
      }
    }
    walk(join(home, mount.name), '')
  }
  out.sort()
  return out
}
/** home 挂载路径（带 __home__/ 前缀）→ 绝对路径；非法、前缀不符或非白名单挂载点返回 null */
export function homeAbsPath(relPosix) {
  if (typeof relPosix !== 'string' || !relPosix.startsWith(HOME_PREFIX)) return null
  const rel = relPosix.slice(HOME_PREFIX.length)
  if (!isSafeRelPath(rel)) return null
  const top = rel.split('/')[0]
  if (!HOME_MOUNTS.some((m) => m.name === top)) return null
  const home = homeRoot()
  if (!home) return null
  return join(home, ...rel.split('/'))
}
/** 备份内路径 → 本机绝对路径：root 内条目直连，带挂载前缀的交给对应挂载点解析。 */
export function resolvePayloadAbs(relPath, root) {
  if (typeof relPath !== 'string' || !relPath) return null
  if (relPath.startsWith(APPDATA_PREFIX)) return appDataAbsPath(relPath)
  if (relPath.startsWith(HOME_PREFIX)) return homeAbsPath(relPath)
  return join(root, relPath)
}

// B 机恢复后重装插件依赖用。桌面版把运行时放在 primary-runtime/dependencies/ 下
// （runtime.json 的 pnpm 字段），旧布局 runtime/pnpm/ 仍保留作兼容。
const PNPM_CANDIDATES = [
  join('runtime', 'primary-runtime', 'dependencies', 'pnpm', 'bin', 'pnpm.mjs'),
  join('runtime', 'pnpm', 'bin', 'pnpm.mjs'),
  join('runtime', 'primary-runtime', 'dependencies', 'pnpm', 'bin', 'pnpm.cjs'),
]
const INSTALL_TIMEOUT_MS = 15 * 60 * 1000
const LOG_TAIL_CHARS = 4000

// ============================================================
// 可注入内部实现（供 tools-selftest.mjs 复用）
// ============================================================

// 备份策略：**除「工作区聊天数据」和「可重建产物」之外，~/.dsh 里的一切都同步**。
// 排除清单是白纸黑字的四类，其余一律收录——新增的目录默认进备份，不会静默漏掉。
//
// 1) 聊天数据（用户要求不同步）：sessions/（会话正文）、attachments/（聊天里上传的文件对象）。
//    注意 attachments 在 0.4.1 之前是被打包的，这次一并排除。
// 2) 可重建产物：dsh-runtimes/（DSH 运行时二进制，实测 257MB）、node_modules（插件依赖，实测 996MB）。
//    两者都能靠重启/「重装插件」恢复，且全量打包会让 payload 达 1.25GB —— 当前实现把整个
//    payload 读进内存再加密，实测 350MB 就 OOM。
// 3) 日志与缓存：logs、npm-cache、tmp*/cache* 前缀目录，可再生且无配置价值。
// 4) 单个文件大于 50MB。
const CHAT_DIR_NAMES = new Set(['sessions', 'attachments'])
const REBUILDABLE_DIR_NAMES = new Set(['dsh-runtimes', 'node_modules'])
const EPHEMERAL_DIR_NAMES = new Set(['logs', 'npm-cache'])
// 聊天派生数据：session_projcache 存每个会话的标题与首条输入原文，
// workspace.json 的 archivedSessionIds 存会话 id 索引。都不属于「配置」，一并排除。
const CHAT_DERIVED_PATHS = new Set([
  'storages/session_projcache',
  'storages/workspace.json',
])

/** 是否应排除某个相对路径（posix 分隔）。规则见上方注释的四类。 */
export function isExcluded(relPosix, fileSizeBytes) {
  const rel = String(relPosix || '')
  if (CHAT_DERIVED_PATHS.has(rel)) return true
  const segs = rel.split('/')
  // 白名单：被 cache*/tmp* 规则误伤的配置性质路径照收（模型费率表等）
  const keepByPrefix = CACHE_KEEP_PREFIXES.some((p) => rel.startsWith(p) || p.startsWith(rel + '/'))
  for (const seg of segs) {
    if (CHAT_DIR_NAMES.has(seg) || REBUILDABLE_DIR_NAMES.has(seg) || EPHEMERAL_DIR_NAMES.has(seg)) return true
    if (keepByPrefix) continue
    if (seg.startsWith('tmp') || seg.startsWith('cache')) return true
  if (fileSizeBytes !== undefined && fileSizeBytes > MAX_FILE_BYTES) return true
  }
  return false
}

/** 某一类排除原因（无则 undefined）。供 describeScope 与界面文案共用。 */
export function exclusionReason(rel) {
  if (CHAT_DERIVED_PATHS.has(rel)) return '聊天派生数据'
  // 白名单内的路径不算排除项，否则范围卡片会把它同时报成「已同步」和「已排除」。
  if (CACHE_KEEP_PREFIXES.some((p) => rel.startsWith(p) || p.startsWith(rel + '/'))) return undefined
  for (const seg of rel.split('/')) {
    if (seg === 'sessions') return '聊天记录'
    if (seg === 'attachments') return '聊天文件'
    if (seg === 'dsh-runtimes') return '可重建：DSH 运行时'
    if (seg === 'node_modules') return '可重建：插件依赖'
    if (seg === 'logs' || seg === 'npm-cache') return '日志/缓存'
    if (seg.startsWith('tmp') || seg.startsWith('cache')) return '临时/缓存'
  }
  return undefined
}

/**
 * 让用户看清「这次到底同步了什么」：返回 { included, excluded, totals }。
 * included/excluded 都是 [{ name, files, bytes, reason? }]，按体积倒序。
 *
 * opts.measureExcluded 默认 false：统计被排除目录的体积要递归整棵 node_modules
 * （实测 5.8 万个文件、3.6 秒），不能放在每次 /status 都要跑的热路径上。
 * 只有备份结果这类一次性展示才传 true。
 */
export function describeScope(root, opts) {
  const o = opts || {}
  const measureExcluded = o.measureExcluded === true;
  const included = new Map()
  const excluded = new Map()
  // 同一个顶层项可能由多种原因拼成（如 profiles 下既有 node_modules 也有 logs），
  // 归纳时按体积取占主导的那个原因，避免给出「日志/缓存」这种误导性的标签。
  const bump = (map, name, files, bytes, reason) => {
    let row = map.get(name)
    if (!row) { row = { name, files: 0, bytes: 0, reasons: new Map() }; map.set(name, row) }
    row.files += files
    row.bytes += bytes
    if (reason) row.reasons.set(reason, (row.reasons.get(reason) || 0) + bytes)
    return row
  }
  const walk = (dir, prefix) => {
    let entries
    try { entries = readdirSync(dir, { withFileTypes: true }) } catch (e) { return }
    for (const ent of entries) {
      const rel = prefix ? prefix + '/' + ent.name : ent.name
      const abs = join(dir, ent.name)
      const top = rel.includes('/') ? rel.split('/')[0] : '(files)'
      const reason = exclusionReason(rel)
      if (ent.isDirectory()) {
        if (reason) {
          // 顶层目录整块排除时记一行；嵌套的（如 profiles/x/node_modules）折算到顶层。
          // 只有显式要求时才递归量体积——见函数头注释。
          const size = measureExcluded ? dirSize(abs) : { files: 0, bytes: 0 }
          bump(excluded, prefix ? top : ent.name, size.files, size.bytes, prefix ? exclusionReason(top) || reason : reason)
          continue
        }
        walk(abs, rel)
      } else if (ent.isFile()) {
        let size = 0
        try { size = statSync(abs).size } catch (e) { continue }
        const why = reason || (size > MAX_FILE_BYTES ? '单个文件 >50MB' : undefined)
        if (why) { bump(excluded, top, 1, size, top === '(files)' ? why : (exclusionReason(top) || why)); continue }
        bump(included, top, 1, size)
      }
    }
  }
  walk(root, '')
  // home 挂载点也算「本次同步范围」的一部分，单独列出来，
  // 否则用户在范围卡片里看不到它们，只能靠信。
  for (const rel of collectHomeFiles()) {
    const segs = rel.split('/')
    const name = HOME_PREFIX + (segs[1] || '')
    let size = 0
    const abs = homeAbsPath(rel)
    if (abs) { try { size = statSync(abs).size } catch (e) { size = 0 } }
    bump(included, name, 1, size)
  }
  const bySize = (a, b) => b.bytes - a.bytes
  const inc = [...included.values()].sort(bySize).map((r) => ({ name: r.name, files: r.files, bytes: r.bytes }))
  const exc = [...excluded.values()].sort(bySize).map((r) => {
    let top = null
    let topScore = -1
    for (const [reason, bytes] of r.reasons) {
      // 没量体积（bytes 全是 0）时按固定优先级取原因，保证结果稳定可读：
      // 聊天 > 可重建 > 日志缓存 > 单文件过大
      const score = bytes * 1000 + REASON_PRIORITY(reason)
      if (score > topScore) { top = reason; topScore = score }
    }
    return { name: r.name, files: r.files, bytes: r.bytes, reason: top || undefined }
  })
  return {
    included: inc,
    excluded: exc,
    totals: {
      files: inc.reduce((n, r) => n + r.files, 0),
      bytes: inc.reduce((n, r) => n + r.bytes, 0),
      excludedCount: exc.length,
      // 未量体积时这两项为 undefined（客户端据此显示「未统计」而不是 0）
      excludedFiles: measureExcluded ? exc.reduce((n, r) => n + r.files, 0) : undefined,
      excludedBytes: measureExcluded ? exc.reduce((n, r) => n + r.bytes, 0) : undefined,
    },
  }
}

/** 排除原因的展示优先级（数值越大越优先），仅在没量体积时用来打破平局。 */
function REASON_PRIORITY(reason) {
  if (reason === '聊天记录' || reason === '聊天文件' || reason === '聊天派生数据') return 4
  if (reason === '可重建：DSH 运行时' || reason === '可重建：插件依赖') return 3
  if (reason === '日志/缓存' || reason === '临时/缓存') return 2
  return 1
}

/** 递归统计一个目录的体积（excluded 清单用，不做 isExcluded 过滤）。 */
function dirSize(dir) {
  const out = { files: 0, bytes: 0 }
  let entries
  try { entries = readdirSync(dir, { withFileTypes: true }) } catch (e) { return out }
  for (const ent of entries) {
    const abs = join(dir, ent.name)
    if (ent.isDirectory()) {
      const sub = dirSize(abs)
      out.files += sub.files
      out.bytes += sub.bytes
    } else if (ent.isFile()) {
      try { out.bytes += statSync(abs).size; out.files++ } catch (e) { /* ignore */ }
    }
  }
  return out
}

/** 遍历 root，收集全部应打包文件（返回 posix 相对路径列表，已排序）。
 *
 *  符号链接必须跟随：Linux/macOS 上把配置目录软链到别处很常见
 *  （dotfiles 管理、`skins/` 指向独立仓库、pnpm 风格的目录布局）。
 *  readdir 的 dirent 对软链只有 isSymbolicLink()，既不算 isFile 也不算 isDirectory，
 *  旧实现会把它们**静默跳过** —— 备份看着成功，其实少了整棵皮肤/配置目录。
 *  跟随的同时必须防环（链接回祖父目录会无限递归），用 realpath 记录已访问目录。 */
export function collectFiles(root) {
  const out = []
  const seenDirs = new Set()
  const walk = (dir, prefix) => {
    let real
    try { real = realpathSync(dir) } catch (e) { return }
    if (seenDirs.has(real)) return          // 防环：同一个真实目录只走一次
    seenDirs.add(real)
    let entries
    try { entries = readdirSync(dir, { withFileTypes: true }) } catch (e) { return }
    for (const ent of entries) {
      const rel = prefix ? prefix + '/' + ent.name : ent.name
      const abs = join(dir, ent.name)
      let kind = null
      if (ent.isDirectory()) kind = 'dir'
      else if (ent.isFile()) kind = 'file'
      else if (ent.isSymbolicLink()) {
        // 链接指向什么，要以链接目标为准（断链就跳过，绝不抛错）
        let st
        try { st = statSync(abs) } catch (e) { continue }
        kind = st.isDirectory() ? 'dir' : (st.isFile() ? 'file' : null)
      }
      if (kind === 'dir') {
        if (isExcluded(rel)) continue
        walk(abs, rel)
      } else if (kind === 'file') {
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

/** 打包进备份前去掉本机口令。WebDAV 账号密码仍按原设计一并迁移，口令不进备份内容。 */
export function redactBackupBytes(rel, buf) {
  if (rel !== CONFIG_FILE_NAME) return buf
  let obj
  try { obj = JSON.parse(buf.toString('utf8')) } catch (e) { return buf }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj) || !Object.prototype.hasOwnProperty.call(obj, 'passphrase')) return buf
  delete obj.passphrase
  return Buffer.from(JSON.stringify(obj, null, 2) + '\n', 'utf8')
}

/** 打包（未加密）：返回明文 payload Buffer。meta 仅在新版本携带，旧备份不含该字段
 *  （不传 meta 时产物与旧版逐字节一致，保证格式向后兼容） */
export function buildPayload(root, relFiles, meta, appDataFiles, homeFiles) {
  const files = []
  for (const rel of relFiles) {
    const buf = redactBackupBytes(rel, readFileSync(join(root, rel)))
    files.push({ path: rel, sha256: createHash('sha256').update(buf).digest('hex'), data: buf.toString('base64') })
  }
  // AppData 应用设置：以 __appdata__/ 前缀并入同一 payload，恢复时由 extractPayload 写回原位
  for (const rel of (appDataFiles || [])) {
    const abs = appDataAbsPath(rel)
    if (!abs) continue
    let buf
    try { buf = readFileSync(abs) } catch (e) { continue }
    files.push({ path: rel, sha256: createHash('sha256').update(buf).digest('hex'), data: buf.toString('base64') })
  }
  // home 级配置（模型目录/价表/provider 切换器）：同一 payload，恢复时写回 home 原位
  for (const rel of (homeFiles || [])) {
    const abs = homeAbsPath(rel)
    if (!abs) continue
    let buf
    try { buf = readFileSync(abs) } catch (e) { continue }
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

/**
 * 把明文 payload 解包写入 root。返回 { count, skipped, verified, mismatches }：
 *   count      实际写入的文件数
 *   skipped    因路径不安全/无法解析而跳过的条目 [{ path, reason }]（正常备份恒为空，
 *              出现即表示备份内容异常，调用方必须向用户明示，不得当作无事发生）
 *   verified   写入后逐文件回读并通过 SHA-256 校验的数量
 *   mismatches 写入后回读校验失败的条目 [{ path, reason }]（写入层异常，极罕见）
 * 单个条目内容校验失败仍抛错：那是备份损坏/被篡改的信号，必须中断而不是静默跳过。
 */
export function extractPayloadDetailed(payload, root) {
  const parsed = JSON.parse(payload.toString('utf8'))
  const files = Array.isArray(parsed.files) ? parsed.files : []
  let count = 0
  const skipped = []
  for (const f of files) {
    if (!f || typeof f.path !== 'string' || !f.path) {
      skipped.push({ path: (f && f.path) ? String(f.path) : '(无路径)', reason: '条目缺少有效路径' })
      continue
    }
    if (!isSafeRelPath(f.path)) {
      skipped.push({ path: f.path, reason: '路径不安全（含 ..、盘符或绝对路径）' })
      continue
    }
    const abs = resolvePayloadAbs(f.path, root)
    if (!abs) {
      skipped.push({ path: f.path, reason: '无法解析到本地路径' })
      continue
    }
    mkdirSync(dirname(abs), { recursive: true })
    const buf = Buffer.from(f.data, 'base64')
    const sha = createHash('sha256').update(buf).digest('hex')
    if (sha !== f.sha256) throw new Error('文件 ' + f.path + ' 校验失败')
    writeFileSync(abs, buf)
    count++
  }
  let verified = 0
  const mismatches = []
  for (const f of files) {
    if (!f || typeof f.path !== 'string' || !f.path || !isSafeRelPath(f.path)) continue
    const abs = resolvePayloadAbs(f.path, root)
    if (!abs) continue
    let onDisk
    try {
      onDisk = readFileSync(abs)
    } catch (e) {
      mismatches.push({ path: f.path, reason: '回读失败: ' + e.message })
      continue
    }
    const sha = createHash('sha256').update(onDisk).digest('hex')
    if (sha === f.sha256) verified++
    else mismatches.push({ path: f.path, reason: '写入后内容不一致' })
  }
  return { count, skipped, verified, mismatches }
}

/** 把明文 payload 解包写入 root；返回文件数（旧调用方兼容入口） */
export function extractPayload(payload, root) {
  return extractPayloadDetailed(payload, root).count
}

/** payload 里路径合法的条目。这些路径构成恢复后应存在的配置集合。 */
function payloadKeepPaths(payload) {
  const parsed = JSON.parse(payload.toString('utf8'))
  const files = Array.isArray(parsed.files) ? parsed.files : []
  const keep = new Set()
  for (const f of files) {
    if (!f || typeof f.path !== 'string' || !isSafeRelPath(f.path)) continue
    keep.add(f.path)
  }
  return keep
}

/** 这份备份是否声明了 AppData 应用设置。没声明的旧备份不能用来清空本机设置。 */
function payloadIncludesAppData(payload, keep) {
  for (const p of keep) {
    if (p.startsWith(APPDATA_PREFIX)) return true
  }
  const meta = extractPayloadMeta(payload)
  return !!(meta && meta.appDataIncluded)
}

/** 这份备份是否声明了 home 级配置。没声明的旧备份不能用来清空本机 home 配置。 */
function payloadIncludesHome(payload, keep) {
  for (const p of keep) {
    if (p.startsWith(HOME_PREFIX)) return true
  }
  const meta = extractPayloadMeta(payload)
  return !!(meta && meta.homeIncluded)
}

// ============================================================
// 恢复模式：完全覆盖 / 只补缺失
// ============================================================
// 换机恢复的两种诉求互相冲突，必须由用户选，不能替用户猜：
//   1) 「要一台和 A 机一模一样的机器」→ mirror：按备份对齐，备份里没有的配置删掉。
//   2) 「B 机已经配好了皮肤/插件/自定义设置，别把我改过的覆盖掉」→ merge：只补本机没有的
//      文件；本机已有且内容不同的文件原样保留，并在结果里列成「冲突」让用户自己看。
// 中间态 overwrite 用于「要 A 机的官方配置，但保留我在 B 机额外装的插件配置」。
export const RESTORE_MODES = ['merge', 'overwrite', 'mirror']
/** 默认走保守策略：只补缺失。全新机器上它与 mirror 结果完全相同（本机没有多余配置可冲突）。 */
export const DEFAULT_RESTORE_MODE = 'merge'
export function normalizeRestoreMode(mode) {
  const m = String(mode === undefined || mode === null ? '' : mode).trim().toLowerCase()
  return RESTORE_MODES.includes(m) ? m : DEFAULT_RESTORE_MODE
}

/** payload 解析成对象；内容不是合法 JSON 时返回 null（备份损坏，调用方必须明确报错）。 */
function parsePayloadObject(payload) {
  try {
    const o = JSON.parse(payload.toString('utf8'))
    if (!o || typeof o !== 'object' || Array.isArray(o)) return null
    if (!Array.isArray(o.files)) return null
    return o
  } catch (e) { return null }
}

// ============================================================
// profile 名重映射（v0.4.6，跨平台恢复的关键）
// ============================================================
// 背景：profile 名是**跟平台绑定的**——Windows 桌面版固定用 profiles/desktop，
// Linux/macOS 的 `dsh web` 用 profiles/web。备份里存的是源机器那一套相对路径
// （profiles/desktop/package.json …），目标机上如果直接按原路径落地：
//
//   1) Desktop 备份 → Web 机器：写进 profiles/desktop/，而目标机实际加载的是 profiles/web，
//      于是「恢复成功」但配置一个都没生效；更糟的是 mirror 模式会把目标机自己的
//      profiles/web/* 当成「备份里没有的多余配置」**整棵删掉**（插件依赖、cordis.patch.yml
//      全没了，DSH 起来后插件全部消失）。
//   2) Web 备份 → Desktop 机器：同样写进 profiles/web/，桌面版不认。
//   3) desktop ↔ desktop、web ↔ web：名字相同，映射为恒等，行为与旧版完全一致。
//
// 因此恢复时必须把备份里的 profiles/<源名>/... 换成本机**正在使用**的 profile 名。
// 只重映射 profiles/<name>/ 这一层，其余路径（含 __appdata__/ 挂载点）原样不动；
// 本机不使用 desktop/web 这套名字（自定义 profile）时，退化为按名字匹配，绝不乱猜。
const PROFILE_DIR_RE = /^profiles\/([^/]+)\/(.*)$/

/** 备份里出现的 profile 名（去重、排序），供界面提示与测试断言用。 */
export function payloadProfileNames(payload) {
  const parsed = parsePayloadObject(payload)
  if (!parsed) return []
  const names = new Set()
  for (const f of parsed.files) {
    if (!f || typeof f.path !== 'string') continue
    const m = PROFILE_DIR_RE.exec(f.path)
    if (m) names.add(m[1])
  }
  return [...names].sort()
}

/**
 * 决定「备份里的 profile 名 → 本机 profile 名」的映射。
 *
 * targetProfile 是本机实际在跑的 profile 名（调用方传 resolveProfile().name）。
 *
 * 判定顺序（关键，v0.5.0 修正）：
 *   1) **优先用备份 meta 里记录的「源机器当时在用的 profile」**（meta.profile）。
 *      它才是这份备份真正代表的那套配置。多 profile 的机器上尤其重要：
 *      实测事故（2026-10-20）Windows 机器同时有 desktop（22 个插件，日常在用）
 *      和 web（4 个插件，备用）两个 profile，备份里两个都在。旧逻辑看到
 *      「备份里有 web」就直接取恒等，于是 Windows 的 web 覆盖了 Linux 的 web，
 *      而真正在用的 desktop 被写到 Linux 的 profiles/desktop —— `dsh web` 根本不加载它，
 *      用户看到的仍是 4 个插件的空壳配置。
 *   2) 没有 meta（旧备份）时退化为按名字判断：
 *      - 备份含本机目标名 → 恒等
 *      - 只有「源名与目标名都是平台标准名（desktop / web）」才重映射
 *   3) 自定义 profile 名（如 alpha→beta）永不猜测：备份里没有信息能断定这是
 *      「同一套配置换了名字」，强行改名会把配置写进用户没打算用的 profile。
 *
 * 返回的 skip 是「本次不落地」的 profile 名：当源 profile 被映射到 target 时，
 * 备份里那个与 target 同名的 profile 会写到同一个目录造成互相覆盖，因此跳过它。
 */
export function planProfileRemap(payload, targetProfile) {
  const target = String(targetProfile || '').trim()
  const names = payloadProfileNames(payload)
  const isPlatformName = (n) => n === 'desktop' || n === 'web'
  const none = { map: {}, from: null, to: null, names, skip: [] }
  if (!target || names.length === 0) return none

  // 1) meta.profile 优先：那是源机器备份时真正在跑的 profile
  const meta = extractPayloadMeta(payload)
  const metaProfile = meta && meta.profile ? String(meta.profile).trim() : ''
  if (metaProfile && names.includes(metaProfile) && metaProfile !== target &&
      isPlatformName(metaProfile) && isPlatformName(target)) {
    // 与目标同名的那个 profile 来自源机器的另一套配置，会覆盖到同一目录 → 跳过
    const skip = names.filter((n) => n !== metaProfile && n === target)
    return { map: { [metaProfile]: target }, from: metaProfile, to: target, names, skip, reason: 'meta' }
  }

  // 2) 无 meta 或 meta 不可用时的旧规则
  if (names.includes(target)) return { map: {}, from: target, to: target, names, skip: [] }
  if (names.length === 1) {
    const from = names[0]
    if (isPlatformName(from) && isPlatformName(target)) {
      return { map: { [from]: target }, from, to: target, names, skip: [] }
    }
    return none
  }
  const platformNames = names.filter(isPlatformName)
  if (platformNames.length === 1 && isPlatformName(target)) {
    const from = platformNames[0]
    const skip = names.filter((n) => n !== from && n === target)
    return { map: { [from]: target }, from, to: target, names, skip }
  }
  return none
}

/** 按映射改写一条备份内相对路径；不需要改写时原样返回。 */
export function remapPayloadPath(relPath, remap) {
  const m = remap && remap.map ? remap : null
  if (!m) return relPath
  const hit = PROFILE_DIR_RE.exec(relPath)
  if (!hit) return relPath
  const next = m.map[hit[1]]
  if (!next || next === hit[1]) return relPath
  return 'profiles/' + next + '/' + hit[2]
}

/** 解析 payload 里路径合法、能落到本机的条目 [{ path, sha256, buffer, abs }]，附带非法条目清单。
 *  payload 本身不合法时抛错，且错误信息是给用户看的（不是 at position ... 这种）。
 *
 *  v0.4.6：opts.remap 给出 profile 名映射后，条目额外带 srcPath（备份里的原始路径）
 *  与 destPath（实际落地路径），二者不同即表示这次恢复发生了跨 profile 迁移。 */
function payloadValidEntries(payload, root, opts) {
  const o = opts || {}
  const remap = o.remap || null
  const parsed = parsePayloadObject(payload)
  if (!parsed) throw new Error('备份内容不是有效的配置清单（JSON 解析失败或缺少 files 数组），无法恢复')
  const files = Array.isArray(parsed.files) ? parsed.files : []
  const entries = []
  const invalid = []
  const skippedProfiles = []
  for (const f of files) {
    if (!f || typeof f.path !== 'string' || !f.path) {
      invalid.push({ path: (f && f.path) ? String(f.path) : '(无路径)', reason: '条目缺少有效路径' })
      continue
    }
    if (!isSafeRelPath(f.path)) {
      invalid.push({ path: f.path, reason: '路径不安全（含 ..、盘符或绝对路径）' })
      continue
    }
    // 重映射只改 profiles/<name>/ 这一段。改完必须再过一次 isSafeRelPath：
    // 目标名来自本机 profile 解析，理论上安全，但绝不能因为多一层字符串拼接就放松校验。
    //
    // remap.skip 里的 profile：源 profile 已映射到本机目标名，备份里同名的那份若也落地
    // 会写到同一个目录互相覆盖，所以本次直接不写（不是错误，属于有意的取舍）。
    const srcHit = PROFILE_DIR_RE.exec(f.path)
    if (srcHit && Array.isArray(remap && remap.skip) && remap.skip.includes(srcHit[1])) {
      skippedProfiles.push({ path: f.path, profile: srcHit[1], reason: '该 profile 已被映射到本机目标 profile，避免互相覆盖' })
      continue
    }
    const destPath = remapPayloadPath(f.path, remap)
    if (destPath !== f.path && !isSafeRelPath(destPath)) {
      invalid.push({ path: f.path, reason: '重映射后的路径不安全' })
      continue
    }
    const abs = resolvePayloadAbs(destPath, root)
    if (!abs) {
      invalid.push({ path: destPath, reason: '无法解析到本地路径' })
      continue
    }
    entries.push({ path: destPath, srcPath: f.path, sha256: f.sha256, buffer: Buffer.from(f.data, 'base64'), abs })
  }
  return { entries, invalid, skippedProfiles }
}

/**
 * 恢复预览（不写盘）：这份备份在这台电脑上会新增什么、和本机一致什么、冲突什么、本机多什么。
 * 恢复确认弹窗用它把「会改动哪些配置」摊开给用户，让模式选择有依据。
 * 冲突 = 本机已有该文件、但内容与备份不同；localOnly = 本机配置范围内、备份里没有的文件（mirror 会删掉它们）。
 */
export function planPayloadApply(payload, root, parsedEntries, opts) {
  const o = opts || {}
  // 第三个参数是内部优化（复用已解析条目）。传进来的东西不对就自己重解析，
  // 不能让一个可选优化参数把整次预览打崩。
  let parsed = parsedEntries
  if (!parsed || !Array.isArray(parsed.entries) || !Array.isArray(parsed.invalid)) {
    parsed = payloadValidEntries(payload, root, { remap: o.remap })
  }
  const { entries, invalid, skippedProfiles } = parsed
  const added = []
  const unchanged = []
  const conflicts = []
  for (const e of entries) {
    let onDisk = null
    try { onDisk = readFileSync(e.abs) } catch (err) { onDisk = null }
    if (onDisk === null) { added.push(e.path); continue }
    // 插件自带配置（dsh-sync.json）在备份里被有意剥掉了口令：本机那份比备份多一个 passphrase 字段，
    // 直接比字节会让「自己的备份恢复回自己机器」也报冲突。这里按「剥掉口令后」比较。
    const cmp = redactBackupBytes(e.path, onDisk)
    const sha = createHash('sha256').update(cmp).digest('hex')
    if (sha === e.sha256) unchanged.push(e.path)
    else conflicts.push({ path: e.path, localBytes: onDisk.length, bundleBytes: e.buffer.length })
  }
  const keep = new Set(entries.map((e) => e.path))
  const localOnly = []
  for (const rel of collectFiles(root)) {
    if (!keep.has(rel)) localOnly.push(rel)
  }
  const homeIncluded = payloadIncludesHome(payload, keep)
  const appDataIncluded = payloadIncludesAppData(payload, keep)
  if (appDataIncluded) {
    for (const rel of collectAppDataFiles()) {
      if (!keep.has(rel)) localOnly.push(rel)
    }
  }
  if (homeIncluded) {
    for (const rel of collectHomeFiles()) {
      if (!keep.has(rel)) localOnly.push(rel)
    }
  }
  return {
    homeIncluded,
    appDataIncluded,
    added, unchanged, conflicts, localOnly, invalid,
    profileSkipped: Array.isArray(skippedProfiles) ? skippedProfiles : [],
    totals: {
      bundle: entries.length,
      added: added.length,
      unchanged: unchanged.length,
      conflicts: conflicts.length,
      localOnly: localOnly.length,
      invalid: invalid.length,
    },
  }
}

/**
 * 写 dsh-sync.json 时保留本机记住的口令。
 * 备份里这份配置按设计是剥掉 passphrase 的（口令不进备份内容），直接覆盖会把用户
 * 在这台电脑上记好的口令抹掉，下次备份/恢复又得重填。口令属于「这台电脑的东西」，
 * 不属于从别的机器搬来的配置，所以始终以本机为准。
 */
function keepLocalPassphrase(rel, abs, incoming) {
  if (rel !== CONFIG_FILE_NAME) return incoming
  let local = null
  try { local = JSON.parse(readFileSync(abs, 'utf8')) } catch (e) { return incoming }
  const pass = local && typeof local.passphrase === 'string' ? local.passphrase : ''
  if (!pass) return incoming
  let next = null
  try { next = JSON.parse(incoming.toString('utf8')) } catch (e) { return incoming }
  if (!next || typeof next !== 'object' || Array.isArray(next)) return incoming
  if (typeof next.passphrase === 'string' && next.passphrase) return incoming
  next.passphrase = pass
  return Buffer.from(JSON.stringify(next, null, 2) + '\n', 'utf8')
}

/**
 * 按所选模式把 payload 落到本机。返回实际写入/冲突/删除明细。
 *   merge     只写本机没有的文件；本机已有（内容相同或不同）一律不动 —— 冲突列进 keptConflicts
 *   overwrite 备份里的文件全部覆盖写入，但**不删**本机多出来的配置
 *   mirror    覆盖写入 + 删掉备份里没有的配置（v0.3.5~v0.4.1 的旧行为，界面标注为「完全覆盖」）
 * 排除项（sessions/、node_modules/ 等）在任何模式下都不写也不删。
 */
export function applyPayloadMode(payload, root, mode, opts) {
  const o = opts || {}
  const m = normalizeRestoreMode(mode)
  const parsed = payloadValidEntries(payload, root, { remap: o.remap })
  const entries = parsed.entries
  const plan = planPayloadApply(payload, root, parsed)
  // 跨 profile 迁移的条目：备份里叫 profiles/desktop/x，本机落到 profiles/web/x。
  // 必须逐条回报——否则用户只看到「恢复成功 N 个文件」，却不知道该去哪个 profile 下找。
  const remapped = entries.filter((e) => e.srcPath && e.srcPath !== e.path).map((e) => ({ from: e.srcPath, to: e.path }))
  const held = new Set()
  if (m === 'merge') {
    for (const p of plan.unchanged) held.add(p)
    for (const c of plan.conflicts) held.add(c.path)
  }
  let count = 0
  let verified = 0
  const mismatches = []
  for (const e of entries) {
    if (held.has(e.path)) continue
    try {
      mkdirSync(dirname(e.abs), { recursive: true })
      writeFileSync(e.abs, keepLocalPassphrase(e.path, e.abs, e.buffer))
      count++
    } catch (err) {
      mismatches.push({ path: e.path, reason: '写入失败: ' + (err && err.message ? err.message : String(err)) })
      continue
    }
    try {
      const sha = createHash('sha256').update(readFileSync(e.abs)).digest('hex')
      if (sha === e.sha256) verified++
      else mismatches.push({ path: e.path, reason: '写入后内容不一致' })
    } catch (err) {
      mismatches.push({ path: e.path, reason: '回读失败: ' + (err && err.message ? err.message : String(err)) })
    }
  }
  let removed = []
  let failed = []
  if (m === 'mirror') {
    const keep = new Set(entries.map((e) => e.path))
    const pruneAppData = o.pruneAppData === false ? false : payloadIncludesAppData(payload, keep)
    const pruneHome = o.pruneHome === false ? false : payloadIncludesHome(payload, keep)
    const pruned = removeConfigNotInSet(root, keep, { pruneAppData, pruneHome })
    removed = pruned.removed
    failed = pruned.failed
  }
  return {
    mode: m,
    count,
    verified,
    // 非法条目与「因模式保留」是两件事：前者是备份异常，后者是用户选择的结果
    skipped: plan.invalid,
    mismatches,
    removed,
    failed,
    conflicts: plan.conflicts,
    keptConflicts: m === 'merge' ? plan.conflicts.map((c) => c.path) : [],
    keptLocalOnly: m === 'mirror' ? [] : plan.localOnly,
    unchanged: plan.unchanged,
    added: plan.added,
    remapped,
    profileSkipped: plan.profileSkipped,
    totals: plan.totals,
  }
}

/** 删掉文件后，向上移除已经空掉的目录，停在 stopDir（不含）本身。 */
function pruneEmptyParents(absFile, stopDir) {
  const stop = resolve(stopDir)
  let dir = dirname(resolve(absFile))
  while (dir !== stop) {
    const rel = relative(stop, dir)
    if (!rel || rel.startsWith('..') || isAbsolute(rel)) break
    let names
    try { names = readdirSync(dir) } catch (e) { break }
    if (names.length) break
    try { rmdirSync(dir) } catch (e) { break }
    dir = dirname(dir)
  }
}

/**
 * 删除 root 配置范围内、不在 keep 里的文件，并清掉因此变空的目录。
 * keep 使用与 collectFiles / collectAppDataFiles 相同的 posix 相对路径。
 * 排除项不在 collect 结果里，因此运行时、插件代码、会话、日志和缓存不会被删。
 * opts.pruneAppData === false 时不动 AppData（自测用来避开本机真实设置）。
 * 返回 { removed, failed }。失败通常是文件被占用，调用方必须告诉用户对齐没有完成。
 */
export function removeConfigNotInSet(root, keep, opts) {
  const o = opts || {}
  const removed = []
  const failed = []
  const drop = (rel, abs, stopDir) => {
    try {
      rmSync(abs, { force: true })
      removed.push(rel)
      pruneEmptyParents(abs, stopDir)
    } catch (e) {
      failed.push({ path: rel, reason: e && e.message ? e.message : String(e) })
    }
  }
  for (const rel of collectFiles(root)) {
    if (keep.has(rel)) continue
    drop(rel, join(root, rel), root)
  }
  if (o.pruneAppData !== false) {
    const roaming = appDataRoamingRoot()
    const stop = roaming ? join(roaming, APPDATA_ROOT_NAME) : null
    for (const rel of collectAppDataFiles()) {
      if (keep.has(rel)) continue
      const abs = appDataAbsPath(rel)
      if (!abs || !stop) continue
      drop(rel, abs, stop)
    }
  }
  // home 挂载点：只在备份明确声明了 home 配置时才对齐，避免旧备份清空本机配置。
  if (o.pruneHome) {
    const home = homeRoot()
    for (const rel of collectHomeFiles()) {
      if (keep.has(rel)) continue
      const abs = homeAbsPath(rel)
      if (!abs || !home) continue
      drop(rel, abs, home)
    }
  }
  return { removed, failed }
}

/**
 * 把 root 的配置对齐到 payload：先写入备份里的文件，再删掉配置范围内多出来的文件。
 * 排除项保持原样。返回 extractPayloadDetailed 的字段，外加 removed / failed。
 */
export function applyPayloadMirror(payload, root, opts) {
  const written = extractPayloadDetailed(payload, root)
  const keep = payloadKeepPaths(payload)
  const pruneAppData = opts && opts.pruneAppData === false
    ? false
    : payloadIncludesAppData(payload, keep)
  const pruneHome = opts && opts.pruneHome === false
    ? false
    : payloadIncludesHome(payload, keep)
  const pruned = removeConfigNotInSet(root, keep, { pruneAppData, pruneHome })
  return { ...written, removed: pruned.removed, failed: pruned.failed }
}

/** 备份文件名 */
export function bundleName(date) {
  const d = date || new Date()
  const p = (n) => String(n).padStart(2, '0')
  return 'dsh-sync-' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()) + '.bundle'
}

/** 把 root（按排除规则）快照到 snapshotRoot/<ts>/；返回快照目录名，并保留最近 keep 份。
 *  opts.protect 指定一个快照目录名在本轮保留时不被删除：回滚会先拍一份新快照，
 *  若回滚目标恰好是最旧的那份，它会被保留策略清掉，接着再去读它就是 ENOENT。 */
export function makeSnapshot(root, snapshotRoot, keep, date, opts) {
  const o = opts || {}
  const d = date || new Date()
  const p = (n) => String(n).padStart(2, '0')
  const ts = d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds()) + '-' + String(d.getMilliseconds()).padStart(3, '0')
  mkdirSync(snapshotRoot, { recursive: true })
  // 毫秒级时间戳仍可能撞名（并发恢复、或快速连点两次回滚）：撞上就加到唯一为止。
  // 不处理的话第二份会写进同一个目录，与第一份混在一起，回滚出来的内容是两次的混合。
  let finalTs = ts
  let n = 0
  while (existsSync(join(snapshotRoot, finalTs))) {
    n++
    finalTs = ts + '-' + n
  }
  const dest = join(snapshotRoot, finalTs)
  mkdirSync(dest, { recursive: true })
  for (const rel of collectFiles(root)) {
    const target = join(dest, rel)
    mkdirSync(dirname(target), { recursive: true })
    copyFileSync(join(root, rel), target)
  }
  // AppData 应用设置一并进快照，保证回滚语义与备份一致
  for (const rel of collectAppDataFiles()) {
    const abs = appDataAbsPath(rel)
    if (!abs) continue
    const target = join(dest, rel)
    try {
      mkdirSync(dirname(target), { recursive: true })
      copyFileSync(abs, target)
    } catch (e) { /* 单文件失败不阻断快照 */ }
  }
  // home 级配置一并进快照，保证回滚语义与备份一致
  for (const rel of collectHomeFiles()) {
    const abs = homeAbsPath(rel)
    if (!abs) continue
    const target = join(dest, rel)
    try {
      mkdirSync(dirname(target), { recursive: true })
      copyFileSync(abs, target)
    } catch (e) { /* 单文件失败不阻断快照 */ }
  }
  // 只保留最近 keep 份；opts.protect 指定的那份不参与删除
  let olds = readdirSync(snapshotRoot).filter((n) => { try { return statSync(join(snapshotRoot, n)).isDirectory() } catch (e) { return false } }).sort()
  const protectedName = o.protect ? String(o.protect) : null
  while (olds.length > keep) {
    const victim = olds.shift()
    if (victim === protectedName) continue
    try { rmSync(join(snapshotRoot, victim), { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
  return finalTs
}

/** 取路径最后一段（快照目录名），用于保留策略里的保护名单。 */
function basenameSafe(p) {
  const s = String(p || '').replace(/[\\/]+$/, '')
  const i = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  return i >= 0 ? s.slice(i + 1) : s
}

/** 从快照目录回滚到 root：先快照现状，再把配置范围对齐到该快照。
 *  快照里的文件覆盖写回；配置范围内、快照里没有的文件删掉。
 *  排除项（dsh-runtimes/、node_modules/、sessions/、logs/、缓存、超大文件）原样保留。
 *  opts.pruneAppData === false 时不清理 AppData，避免自测误删本机设置。 */
export function rollbackFromSnapshot(snapshotDir, root, snapshotRoot, keep, opts) {
  const o = opts || {}
  // 回滚目标必须保护起来：下面 makeSnapshot 会按保留策略清旧快照，
  // 若目标正好是最旧的一份，它会先被删掉，紧接着 walk 就是 ENOENT。
  const protect = basenameSafe(snapshotDir)
  const taken = makeSnapshot(root, snapshotRoot, keep, undefined, { protect })
  let count = 0
  const keepSet = new Set()
  const walk = (dir, prefix) => {
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? prefix + '/' + ent.name : ent.name
      const abs = join(dir, ent.name)
      if (ent.isDirectory()) walk(abs, rel)
      else if (ent.isFile()) {
        if (!isSafeRelPath(rel)) continue
        const target = resolvePayloadAbs(rel, root)
        if (!target) continue
        mkdirSync(dirname(target), { recursive: true })
        copyFileSync(abs, target)
        keepSet.add(rel)
        count++
      }
    }
  }
  walk(snapshotDir, '')
  let pruneAppData = false
  for (const p of keepSet) {
    if (p.startsWith(APPDATA_PREFIX)) { pruneAppData = true; break }
  }
  if (o.pruneAppData === false) pruneAppData = false
  let pruneHome = false
  for (const p of keepSet) {
    if (p.startsWith(HOME_PREFIX)) { pruneHome = true; break }
  }
  if (o.pruneHome === false) pruneHome = false
  const pruned = removeConfigNotInSet(root, keepSet, { pruneAppData, pruneHome })
  return { count, taken, removed: pruned.removed, failed: pruned.failed }
}

// ============================================================
// WebDAV 客户端（http/https + Basic Auth，无依赖）
// ============================================================

function basicAuth(username, password) {
  return 'Basic ' + Buffer.from(username + ':' + password, 'utf8').toString('base64')
}

/** 发起一次 WebDAV 请求。返回 { status, headers, body(Buffer), error? }。
 *  只自动跟随 GET/HEAD 的 3xx：PUT/PROPFIND 被重放到别的主机会丢请求体或打错机器。
 *  跨主机（对象存储签名直链）时去掉 Authorization——直链自带签名，多带 Basic 会被拒。 */
export function davRequest(urlStr, method, opts) {
  const o = opts || {}
  const maxRedirects = Number.isFinite(o.maxRedirects) ? o.maxRedirects : 5
  const followRedirects = o.followRedirects !== undefined ? o.followRedirects : (method === 'GET' || method === 'HEAD')

  const go = (target, hop, originHost) => new Promise((resolve, reject) => {
    let u
    try { u = new URL(target) } catch (e) { return reject(new Error('无效的 URL: ' + target)) }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return reject(new Error('仅支持 http/https'))
    const mod = u.protocol === 'https:' ? https : http
    const headers = { ...(o.headers || {}) }
    if (u.host !== originHost) delete headers['Authorization']
    // 跨主机（跳到对象存储直链）时不携带 WebDAV 凭据
    if (o.username !== undefined && u.host === originHost) {
      headers['Authorization'] = basicAuth(o.username, o.password || '')
    }
    const hopMethod = hop === 0 ? method : (method === 'HEAD' ? 'HEAD' : 'GET')
    let body = hop === 0 ? o.body : undefined
    if (body !== undefined && body !== null) {
      if (!Buffer.isBuffer(body)) body = Buffer.from(body, 'utf8')
      headers['Content-Length'] = String(body.length)
    } else {
      delete headers['Content-Length']
    }
    const req = mod.request(u, { method: hopMethod, headers, timeout: o.timeoutMs || 15000 }, (res) => {
      const code = res.statusCode
      const loc = res.headers ? res.headers.location : null
      if (followRedirects && code >= 300 && code < 400 && loc) {
        res.resume()
        if (hop >= maxRedirects) {
          return resolve({ status: code, headers: res.headers, body: Buffer.alloc(0), error: '重定向超过 ' + maxRedirects + ' 次' })
        }
        const next = nextRedirectUrl(target, loc)
        if (!next) return resolve({ status: code, headers: res.headers, body: Buffer.alloc(0), error: '无效重定向：' + loc })
        return go(next, hop + 1, originHost).then(resolve, reject)
      }
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: code, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('timeout', () => { req.destroy(new Error('请求超时')) })
    req.on('error', reject)
    if (body !== undefined && body !== null) req.write(body)
    req.end()
  })

  try {
    const host = new URL(urlStr).host
    return go(urlStr, 0, host)
  } catch (e) {
    return Promise.reject(new Error('无效的 URL: ' + urlStr))
  }
}

/** 远端目录 URL（保证以 / 结尾）。remoteDir 为空时就是网盘根目录。 */
function remoteDirUrl(cfg, extra) {
  let base = String(cfg.url || '')
  if (!base.endsWith('/')) base += '/'
  const dir = normalizeRemoteDir(cfg && cfg.remoteDir)
  let u = dir ? base + dir.split('/').map((seg) => encodeURIComponent(seg)).join('/') + '/' : base
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
    for (const seg of normalizeRemoteDir(cfg.remoteDir).split('/').filter(Boolean)) {
      partial += encodeURIComponent(seg) + '/'
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
    // collection 后面可能紧跟属性（<D:collection xmlns:D="DAV:"/>），不能要求立刻闭合
    const isDir = /<(?:[A-Za-z0-9_-]+:)?collection[\s/>]/.test(block)
    const sizeRaw = (block.match(/<(?:[A-Za-z0-9_-]+:)?getcontentlength[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?getcontentlength>/) || [])[1]
    const modRaw = (block.match(/<(?:[A-Za-z0-9_-]+:)?getlastmodified[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?getlastmodified>/) || [])[1]
    let name
    try { name = decodeURIComponent(href.replace(/\/$/, '').split('/').pop() || '') } catch (e) { name = href }
    if (!name) continue
    // 空标签 / 缺失长度是「未知」，不是 0 字节。目录的 getcontentlength 经常挂在 404 propstat 里。
    let size = null
    if (sizeRaw !== undefined && String(sizeRaw).trim() !== '') {
      const n = Number(String(sizeRaw).trim())
      size = Number.isFinite(n) ? n : null
    }
    out.push({
      name,
      isDir,
      size,
      modified: modRaw || null,
    })
  }
  return out
}

/** 远程目录规范化：空字符串表示网盘根目录。 */
export function normalizeRemoteDir(dir) {
  return String(dir || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '')
}

/** 只允许相对目录，避免恢复/删除时把路径拼出账号之外。空目录（根目录）合法。 */
export function isSafeRemoteDir(dir) {
  const d = normalizeRemoteDir(dir)
  if (!d) return true
  if (d.includes('\0') || d.includes(':') || d.includes('\\')) return false
  const segs = d.split('/')
  return segs.every((seg) => seg && seg !== '.' && seg !== '..')
}

/**
 * 同一账号要一起看的目录。
 * 实测会出现「输入框写着 dsh-sync，但保存下来的仍是根目录」：
 * 备份写进根目录，另一台保存成 dsh-sync 的电脑就列出空目录。
 * 所以列表固定覆盖：当前保存的目录、网盘根目录、约定目录 dsh-sync。
 */
export function backupSearchDirs(cfg) {
  const dirs = []
  const add = (dir) => {
    const n = normalizeRemoteDir(dir)
    if (!isSafeRemoteDir(n) || dirs.includes(n)) return
    dirs.push(n)
  }
  add(cfg && cfg.remoteDir)
  add('')
  add('dsh-sync')
  return dirs
}

/** 本机已记住的口令，或这一次输入的口令。remember=false 时不回落到已保存的口令。 */
export function resolvePassphrase(saved, body) {
  const typed = body && typeof body.passphrase === 'string' ? body.passphrase : ''
  const remember = !body || body.remember !== false
  if (typed) return { passphrase: typed, typed: true, remember }
  const stored = saved && typeof saved.passphrase === 'string' ? saved.passphrase : ''
  if (remember && stored) return { passphrase: stored, typed: false, remember }
  return { passphrase: '', typed: false, remember }
}

/**
 * 请求体里「没给 remoteDir」时补上默认目录；**显式给的（哪怕空字符串）一律尊重**。
 *
 * 这里必须区分「字段缺失」和「字段为空」：
 *   - 字段缺失（老客户端、脚本只传 url/username/password）→ 用默认 dsh-sync，省得往根目录堆。
 *   - 显式空字符串 → 用户就是要用网盘根目录（0.4.6 及更早版本里这是「留空=根目录」的语义，
 *     且已有用户的配置里就存着 ''）。若把它当「没填」补成 dsh-sync，老用户下次备份会
 *     写到新目录，而他们以为备份还在原处——等于让人觉得「备份全丢了」。
 */
export function applyDefaultRemoteDir(body) {
  const b = (body && typeof body === 'object') ? body : {}
  if (Object.prototype.hasOwnProperty.call(b, 'remoteDir')) return b
  return { ...b, remoteDir: DEFAULT_REMOTE_DIR }
}

/** 保存服务器配置时保留本机口令，并忽略请求体里夹带的口令（口令走单独接口）。 */
export function configForDisk(prev, body) {
  const c = {
    url: String((body && body.url) || '').trim(),
    username: String((body && body.username) || ''),
    password: String((body && body.password) || ''),
    remoteDir: normalizeRemoteDir(body && body.remoteDir),
  }
  if (prev && typeof prev.passphrase === 'string' && prev.passphrase) c.passphrase = prev.passphrase
  return c
}

/** 把 GCM 认证失败翻成用户能看懂的口令错误。其它解密错误原样返回。 */
export function describeDecryptError(err) {
  const msg = err && err.message ? err.message : String(err || '')
  if (/authenticate|bad decrypt/i.test(msg)) {
    return '口令与这份备份不一致。请填写备份当时的口令；本机记住的口令只对用它打出来的备份有效。'
  }
  return msg || '解密失败'
}

/** 列出远端目录里的 .bundle 备份（按名字排序，新在后）。404 视为该目录还没有备份。 */
export async function listRemoteBackups(cfg) {
  const url = remoteDirUrl(cfg)
  const res = await davRequest(url, 'PROPFIND', {
    username: cfg.username, password: cfg.password,
    headers: { Depth: '1', 'Content-Type': 'application/xml' },
    body: PROPFIND_BODY,
  })
  if (res.status === 404) return []
  if (res.status !== 207 && res.status !== 200) {
    throw new Error('PROPFIND 返回 HTTP ' + res.status)
  }
  const entries = parsePropfind(res.body.toString('utf8'))
  return entries
    .filter((e) => !e.isDir && /\.bundle$/.test(e.name) && isSafeBackupName(e.name))
    .map((e) => ({ name: e.name, size: e.size, modified: e.modified, encrypted: true }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
}

/** 合并同一账号下根目录、dsh-sync 和当前保存目录里的备份。每条带上真实 remoteDir。 */
export async function listAccountBackups(cfg) {
  const backups = []
  const errors = []
  for (const remoteDir of backupSearchDirs(cfg)) {
    try {
      const items = await listRemoteBackups({ ...cfg, remoteDir })
      for (const item of items) {
        backups.push({ ...item, remoteDir, encrypted: item.encrypted !== false })
      }
    } catch (e) {
      errors.push({ remoteDir, error: e && e.message ? e.message : String(e) })
    }
  }
  backups.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : (a.remoteDir < b.remoteDir ? -1 : a.remoteDir > b.remoteDir ? 1 : 0)))
  return { backups, errors }
}

/** 备份打包了哪些顶层目录（文件数），用来一眼看出体积是不是被非配置内容撑大。 */
export function summarizePackedScope(relFiles, appDataFiles, homeFiles) {
  const counts = Object.create(null)
  for (const rel of relFiles || []) {
    const top = String(rel).includes('/') ? String(rel).split('/')[0] : '(files)'
    counts[top] = (counts[top] || 0) + 1
  }
  const topLevel = Object.keys(counts).sort().map((name) => ({ name, files: counts[name] }))
  const homeCounts = Object.create(null)
  for (const rel of homeFiles || []) {
    const segs = String(rel).split('/')
    const name = segs[0] + '/' + (segs[1] || '')
    homeCounts[name] = (homeCounts[name] || 0) + 1
  }
  const homeMounts = Object.keys(homeCounts).sort().map((name) => ({ name, files: homeCounts[name] }))
  return { topLevel, appDataFiles: (appDataFiles || []).length, homeFiles: (homeFiles || []).length, homeMounts, fileCount: (relFiles || []).length }
}

/** 远端只保留最近 keep 份 .bundle（按文件名排序，旧的在前）。失败抛错，由调用方决定是否吞掉。 */
export async function pruneRemoteBackups(cfg, keep) {
  const n = Number.isFinite(keep) ? keep : REMOTE_KEEP
  const backups = await listRemoteBackups(cfg)
  if (backups.length <= n) return { deleted: [], kept: backups.map((b) => b.name) }
  const excess = backups.slice(0, backups.length - n)
  const deleted = []
  for (const b of excess) {
    const url = remoteDirUrl(cfg, b.name)
    const res = await davRequest(url, 'DELETE', { username: cfg.username, password: cfg.password })
    if (res.status === 200 || res.status === 204 || res.status === 404) deleted.push(b.name)
    else throw new Error('删除旧备份失败（HTTP ' + res.status + '）：' + b.name)
  }
  return { deleted, kept: backups.slice(backups.length - n).map((b) => b.name) }
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

/** 读文件头判断是 JS 脚本还是原生可执行文件。
 *  为什么必须判断：pnpm >= 10 的 npm 包里 \`pnpm\` 本体是原生启动器（ELF/Mach-O/PE），
 *  只有 bin/pnpm.mjs 是脚本。用 node 去执行原生二进制必然 SyntaxError。 */
export function isNativeExecutable(file) {
  try {
    const fd = openSync(file, 'r')
    const head = Buffer.alloc(4)
    const n = readSync(fd, head, 0, 4, 0)
    closeSync(fd)
    if (n < 2) return false
    return head.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||        // ELF
           (head[0] === 0x4d && head[1] === 0x5a)                       // MZ (PE)
  } catch (e) { return false }
}

/** 在 PATH 里找 pnpm（Windows 补 PATHEXT）。返回真实路径或 null。
 *  Web 版是纯 npm 安装的 CLI，没有 Electron 内置运行时，只有 PATH 这条路可用。
 *  opts.platform 仅供自测注入（在 Windows 上验证 Linux 分支，反之亦然）。 */
export function findPnpmOnPath(env, opts) {
  const e = env || process.env
  const platform = (opts && opts.platform) || process.platform
  const exts = platform === 'win32'
    ? String(e.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean)
    : ['']
  for (const dir of String(e.PATH || e.Path || '').split(delimiter)) {
    if (!dir) continue
    for (const ext of exts) {
      const cand = join(dir, 'pnpm' + ext)
      try {
        if (statSync(cand).isFile()) return realpathSync(cand)
      } catch (err) { /* 继续找 */ }
    }
  }
  return null
}

/** 解析出「怎么调用 pnpm」。返回 { cmd, args, env?, via } 或 null。
 *  关键约束：cmd 是 node 时 args 必须指向 .mjs/.cjs 脚本；cmd 是原生二进制时不得带 --expose-internals。
 *  优先级：宿主给的 packageManager > 桌面版 resources 布局 > PATH。 */
export function resolvePnpmInvocation(resourcesPath, opts) {
  const o = opts || {}
  const platform = o.platform || process.platform
  // 1) 宿主提供的 packageManager（桌面版 Electron 内置运行时走这条）
  const pm = o.packageManager
  if (pm && typeof pm.command === 'string' && pm.command) {
    return { cmd: pm.command, args: [...(pm.args || [])], env: pm.env, via: 'host' }
  }
  // 2) 桌面版 resources/ 布局（保持原有优先级，桌面版行为不变）
  const bundled = findPnpmPath(resourcesPath, o)
  if (bundled) return { cmd: process.execPath, args: ['--expose-internals', bundled], via: 'bundled' }
  // 3) PATH 上的 pnpm（Web 版 / CLI 安装的正解）
  const onPath = findPnpmOnPath(o.env, { platform })
  if (!onPath) return null
  // npm 安装的 pnpm 包里，启动器旁一定有 bin/pnpm.mjs，优先用它（脚本才认 --expose-internals）
  const sibling = join(dirname(onPath), 'bin', 'pnpm.mjs')
  if (existsSync(sibling)) return { cmd: process.execPath, args: ['--expose-internals', sibling], via: 'path-script' }
  // Windows 上 npm / corepack 装的 pnpm 是 .CMD / .BAT 批处理外壳，spawn 直接跑会 EINVAL，
  // 必须经 cmd.exe 转一手（见 buildPnpmCommand）。
  if (platform === 'win32' && /\.(cmd|bat)$/i.test(onPath)) return { cmd: onPath, args: [], via: 'path-cmd-shim' }
  if (!isNativeExecutable(onPath)) return { cmd: process.execPath, args: ['--expose-internals', onPath], via: 'path-script' }
  return { cmd: onPath, args: [], via: 'path-binary' }   // 原生二进制：直接执行
}

/** 把 resolvePnpmInvocation 的结果 + 额外参数拼成可以真的 spawn 的命令行。
 *  .CMD/.BAT 外壳走 cmd.exe /d /s /c ""<path>" <args>"，并置 windowsVerbatimArguments，
 *  否则 node 的 spawn 要么 EINVAL，要么在带空格的路径上把 "C:\Program" 当成命令。 */
export function buildPnpmCommand(inv, extraArgs) {
  const extra = Array.isArray(extraArgs) ? extraArgs : []
  if (!inv) return null
  if (inv.via === 'path-cmd-shim') {
    const quoted = [inv.cmd, ...extra].map((a) => (/[\s"]/.test(a) ? '"' + String(a).replace(/"/g, '') + '"' : a))
    return {
      cmd: process.env.ComSpec || 'cmd.exe',
      args: ['/d', '/s', '/c', '"' + quoted.join(' ') + '"'],
      windowsVerbatimArguments: true,
    }
  }
  return { cmd: inv.cmd, args: [...inv.args, ...extra] }
}

/** 找 pnpm 的入口脚本。按候选列表探测，并兜底扫 ~/.dsh/dsh-runtimes/<版本>/。
 *  opts.homeRoot 仅供测试注入，避免扫到本机真实运行时。 */
export function findPnpmPath(resourcesPath, opts) {
  const o = opts || {}
  const roots = []
  if (resourcesPath) roots.push(resourcesPath)
  try { roots.push(join(dirname(process.execPath), 'resources')) } catch (e) { /* ignore */ }
  for (const r of roots) {
    for (const rel of PNPM_CANDIDATES) {
      const p = join(r, rel)
      if (existsSync(p)) return p
    }
  }
  if (o.homeRoot === null) return null
  const home = o.homeRoot !== undefined ? o.homeRoot : join(homedir(), '.dsh', 'dsh-runtimes')
  try {
    for (const n of readdirSync(home)) {
      for (const rel of PNPM_CANDIDATES) {
        const p = join(home, n, rel)
        if (existsSync(p)) return p
      }
    }
  } catch (e) { /* ignore */ }
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

/** 解析 `git ls-remote` 的 stdout。带 ^{} 的剥离开行优先（那是 commit sha，和锁文件同一命名空间）。 */
export function parseGitLsRemote(text) {
  const byName = new Map()
  let head = null
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^([0-9a-f]{40})\t(\S+)$/i.exec(line.trim())
    if (!m) continue
    const sha = m[1]
    const ref = m[2]
    if (ref === 'HEAD') { head = sha; continue }
    if (!ref.startsWith('refs/tags/')) continue
    const peeled = ref.endsWith('^{}')
    const name = ref.slice('refs/tags/'.length).replace(/\^\{\}$/, '')
    if (!name) continue
    if (!byName.has(name) || peeled) byName.set(name, sha)
  }
  const tags = []
  for (const [name, sha] of byName) tags.push({ name, commit: { sha } })
  return { head, tags }
}

/** `git ls-remote <repo> HEAD refs/tags/*`。失败收敛成 { error }，不抛。opts.spawn 可注入。 */
export function defaultGitLsRemote(slug, opts) {
  const o = opts || {}
  const spawnFn = o.spawn || spawn
  const url = 'https://github.com/' + slug + '.git'
  const args = ['ls-remote', url, 'HEAD', 'refs/tags/*']
  const env = githubHttpsOnlyEnv({ ...process.env })
  return new Promise((resolve) => {
    let child
    try {
      child = spawnFn('git', args, { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], timeout: 20000 })
    } catch (e) {
      resolve({ head: null, tags: [], error: e && e.message ? e.message : String(e) })
      return
    }
    let stdout = ''
    let stderr = ''
    const cap = (key) => (buf) => {
      if (key === 'stdout') stdout += buf.toString('utf8')
      else stderr += buf.toString('utf8')
    }
    if (child.stdout) child.stdout.on('data', cap('stdout'))
    if (child.stderr) child.stderr.on('data', cap('stderr'))
    let settled = false
    const done = (val) => { if (!settled) { settled = true; resolve(val) } }
    child.on('error', (e) => done({ head: null, tags: [], error: e && e.message ? e.message : String(e) }))
    child.on('close', (code) => {
      if (code !== 0) {
        done({ head: null, tags: [], error: 'git ls-remote 退出码 ' + code + (stderr ? '：' + stderr.slice(0, 200) : '') })
        return
      }
      done({ ...parseGitLsRemote(stdout), error: null })
    })
  })
}

/**
 * 检查远端最新版本：以 commit sha 为主判据，semver 兜底。
 * 任何网络失败都收敛成 error 字符串，绝不抛异常、绝不影响既有端点。
 * GitHub API 被限流或连不上时，用 git ls-remote 补 sha 与 tag（changelog 仍只走 API）。
 * opts 全部可注入（httpsGet/cache/now/gitLsRemote），因此自测无需真实联网。
 * 传 gitLsRemote:false 可关掉兜底。
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

  // API 失败时用 git ls-remote 补 sha / tag，避免 60 次/小时的未认证限额把检查锁死。
  // changelog 仍只走 compare API：限流时摘要为空，但不挡住 hasUpdate。
  if (out.error && o.gitLsRemote !== false) {
    try {
      const probe = o.gitLsRemote || defaultGitLsRemote
      const git = await probe(slug)
      if (git && !git.error && (git.head || (git.tags && git.tags.length))) {
        if (git.head && !out.remoteSha) out.remoteSha = git.head
        if ((!tag || !tags.length) && git.tags && git.tags.length) {
          tags = git.tags
          tag = latestTagOf(git.tags)
        }
        if (out.remoteSha || tag) {
          out.error = null
          out.source = 'git-ls-remote'
        }
      }
    } catch (e) { /* 保留原来的 API 错误 */ }
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

/** 云端备份文件名。只允许插件自己写出的名字，避免 DELETE 打到目录里的其它对象。 */
export function isSafeBackupName(name) {
  return typeof name === 'string' && /^dsh-sync-\d{8}-\d{6}\.bundle$/.test(name)
}

/** 从绝对路径里取出 `/.dsh/` 之后的那段（换电脑后用户名、盘符都变了，只有这段还在）。 */
export function dshPathSuffix(absPath) {
  const norm = String(absPath || '').replace(/\\/g, '/')
  const key = '/.dsh/'
  const idx = norm.toLowerCase().lastIndexOf(key)
  if (idx < 0) return null
  return norm.slice(idx + key.length)
}

function specKindAndTarget(spec) {
  const m = /^(link|file|portal):(.*)$/i.exec(String(spec || ''))
  if (!m) return null
  return { kind: m[1].toLowerCase(), target: m[2] }
}

/** link:/file:/portal: 的目标落到本机的绝对路径。相对路径相对 profile 目录。 */
export function resolveDepTarget(spec, profileDir) {
  const parsed = specKindAndTarget(spec)
  if (!parsed) return null
  const target = parsed.target
  if (isAbsolute(target) || /^[A-Za-z]:[\\/]/.test(target)) return target
  return join(profileDir, ...target.split(/[\\/]/).filter((s) => s && s !== '.'))
}

function isInsideDir(root, target) {
  const rel = relative(resolve(root), resolve(target))
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))
}

/**
 * 把指向「某台电脑 ~/.dsh 里面」的 file:/link: 改成相对当前 profile 的路径。
 * 文件必须已经在这台电脑的 ~/.dsh 里（恢复刚写完，或本来就在）。
 * 指到 ~/.dsh 外面的 link:（例如开发目录）不在这里改，交给 linkMap。
 * 改不了时返回 null。
 */
export function retargetDependencySpec(spec, profileDir, dshRoot) {
  const parsed = specKindAndTarget(spec)
  if (!parsed) return null
  const suffix = dshPathSuffix(parsed.target)
  if (!suffix) return null
  if (suffix.split('/').some((s) => s === '' || s === '.' || s === '..')) return null
  const abs = join(dshRoot, ...suffix.split('/'))
  if (!isInsideDir(dshRoot, abs) || !existsSync(abs)) return null
  const rel = relative(profileDir, abs).replace(/\\/g, '/')
  if (!rel || isAbsolute(rel)) return null
  const next = parsed.kind + ':' + rel
  const prev = String(spec).replace(/\\/g, '/')
  return next === prev ? null : next
}

function yamlUnquote(raw) {
  let body = String(raw || '').trim()
  const hash = body.indexOf(' #')
  if (hash >= 0) body = body.slice(0, hash).trim()
  if (body.length >= 2 && ((body.startsWith("'") && body.endsWith("'")) || (body.startsWith('"') && body.endsWith('"')))) {
    return body.slice(1, -1).replace(/''/g, "'")
  }
  return body
}

function yamlSingleQuote(s) {
  return "'" + String(s).replace(/'/g, "''") + "'"
}

/** 路径比较用的规范化：统一分隔符、去掉尾斜杠。
 *  大小写只在 Windows/macOS（默认不区分大小写）上折叠；Linux 上 /Home 与 /home
 *  是两个不同目录，一律 toLowerCase 会把它们判成同一个，导致该改写的没改写、
 *  该保留的被误改。 */
const CASE_INSENSITIVE_FS = process.platform === 'win32' || process.platform === 'darwin'
function normPathForCompare(p, caseInsensitive) {
  const s = String(p || '').replace(/\\/g, '/').replace(/\/+$/, '')
  const fold = caseInsensitive === undefined ? CASE_INSENSITIVE_FS : !!caseInsensitive
  return fold ? s.toLowerCase() : s
}

/** 路径是否相等。opts.caseInsensitive 仅供自测注入跨平台语义（默认按本机平台）。 */
export function pathsEqual(a, b, opts) {
  const ci = opts && opts.caseInsensitive !== undefined ? opts.caseInsensitive : undefined
  return normPathForCompare(a, ci) === normPathForCompare(b, ci)
}

export function isUnderDir(file, dir, opts) {
  const ci = opts && opts.caseInsensitive !== undefined ? opts.caseInsensitive : undefined
  const a = normPathForCompare(file, ci)
  const d = normPathForCompare(dir, ci)
  return !!d && (a === d || a.startsWith(d + '/'))
}

function readStoreDirFromModules(profileDir) {
  try {
    const text = readFileSync(join(profileDir, 'node_modules', '.modules.yaml'), 'utf8')
    const m = /^storeDir:\s*(.+)$/m.exec(text)
    return m ? yamlUnquote(m[1]) : null
  } catch (e) { return null }
}

/**
 * 把一个 profile 里「只在源机器上成立」的路径改成这台电脑能用的路径。
 * - package.json / pnpm-lock.yaml 里指向 ~/.dsh 内部的 file:、link:
 * - pnpm-workspace.yaml 的 storeDir。源机器写死的 store 会让这台电脑的
 *   `pnpm install` 整批失败（路径不存在，或和已有 node_modules 的 store 不一致），
 *   于是 package.json 里列出的插件全部变成「包不可用」。
 * 已有 node_modules/.modules.yaml 时，storeDir 以它为准，避免 ERR_PNPM_UNEXPECTED_STORE。
 */
export function portabilizeProfile(profileDir, dshRoot, opts) {
  const o = opts || {}
  const home = o.home || homedir()
  const rewritten = []
  const replacements = []
  const pkgFile = join(profileDir, 'package.json')
  let pkg = null
  try { pkg = JSON.parse(readFileSync(pkgFile, 'utf8')) } catch (e) { pkg = null }
  if (pkg && pkg.dependencies && typeof pkg.dependencies === 'object') {
    let changed = false
    for (const [name, spec] of Object.entries(pkg.dependencies)) {
      const next = retargetDependencySpec(spec, profileDir, dshRoot)
      if (!next) continue
      replacements.push({ from: String(spec), to: next })
      rewritten.push({ name, from: String(spec), to: next })
      pkg.dependencies[name] = next
      changed = true
    }
    if (changed) writeJsonFile(pkgFile, pkg)
  }
  try {
    const lockFile = join(profileDir, 'pnpm-lock.yaml')
    let lock = readFileSync(lockFile, 'utf8')
    let lockChanged = false
    for (const r of replacements) {
      if (!lock.includes(r.from)) continue
      lock = lock.split(r.from).join(r.to)
      lockChanged = true
    }
    if (lockChanged) writeFileSync(lockFile, lock, 'utf8')
  } catch (e) { /* 没有锁文件就跳过 */ }

  let storeDir = null
  try {
    const wsFile = join(profileDir, 'pnpm-workspace.yaml')
    const text = readFileSync(wsFile, 'utf8')
    const m = /^storeDir:\s*(.+)$/m.exec(text)
    if (m) {
      const current = yamlUnquote(m[1])
      const fromModules = readStoreDirFromModules(profileDir)
      let next = null
      if (fromModules && !pathsEqual(fromModules, current)) next = fromModules
      else if (!fromModules && (!isUnderDir(current, home) || !existsSync(current))) {
        next = join(home, '.pnpm', 'store', 'v11')
      }
      if (next && !pathsEqual(next, current)) {
        writeFileSync(wsFile, text.replace(/^storeDir:\s*.+$/m, 'storeDir: ' + yamlSingleQuote(next)), 'utf8')
        storeDir = { from: current, to: next }
      }
    }
  } catch (e) { /* 没有 workspace 文件就跳过 */ }
  return { rewritten, storeDir }
}

/** 恢复之后扫一遍每个 profile，把源机器的绝对路径改到这台电脑。 */
export function portabilizeRestoredTree(dshRoot, opts) {
  const profilesDir = join(dshRoot, 'profiles')
  const profiles = []
  let names = []
  try { names = readdirSync(profilesDir) } catch (e) { names = [] }
  for (const name of names) {
    const dir = join(profilesDir, name)
    try { if (!statSync(dir).isDirectory()) continue } catch (e) { continue }
    if (!existsSync(join(dir, 'package.json'))) continue
    profiles.push({ name, ...portabilizeProfile(dir, dshRoot, opts) })
  }
  return { profiles }
}

/**
 * 恢复后自保：确保**本插件自己**仍在目标 profile 的 dependencies 与 bundles 里。
 *
 * 为什么必须有这一步（v0.4.8）：
 * 恢复会把备份里的 profiles/<name>/package.json 整个覆盖过来。若那份备份来自一台
 * 「没装本插件」或「插件装在别的 profile」的机器，覆盖后目标机的 profile 里就没有
 * 本插件了。紧接着设置页会自动触发 pnpm install（按新的 package.json 收敛
 * node_modules），于是本插件的代码被删掉；DSH 一重启就加载不到这个 bundle，
 * 设置页的「配置同步」卡片和 /dsh-sync/* 端点一起消失 —— 用户此时**连回滚按钮都点不到**，
 * 只能手工重装插件才能救回来。
 *
 * 实测事故（2026-10-20）：Windows 机器备份里的 profiles/web 恰好没装本插件，在 Linux 上
 * 用「完全覆盖」恢复后，插件的依赖、bundle 注册与 node_modules 三者全被清掉。
 *
 * 所以恢复完成后把自身补回去（依赖 + bundle 注册），并把结果回报给界面。
 * 只补自己这一个包名，其它依赖与字段一律不动。
 */
export function ensureSelfRegistered(profileDir, pkgName, spec) {
  if (!profileDir || !pkgName) return { ok: false, reason: 'no-profile' }
  const file = join(profileDir, 'package.json')
  let pkg
  try { pkg = JSON.parse(readFileSync(file, 'utf8')) } catch (e) { return { ok: false, reason: 'no-package-json' } }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) return { ok: false, reason: 'bad-package-json' }
  let changed = false
  let depAdded = false
  let bundleAdded = false
  // 1) dependencies：没这个键就补上（值由调用方给，即恢复前本机的声明）
  const deps = (pkg.dependencies && typeof pkg.dependencies === 'object' && !Array.isArray(pkg.dependencies))
    ? pkg.dependencies : {}
  if (spec && !Object.prototype.hasOwnProperty.call(deps, pkgName)) {
    deps[pkgName] = spec
    pkg.dependencies = deps
    depAdded = true
    changed = true
  }
  // 2) bundles：DSH 只加载 bundles 里列出的包，缺了等同于没装
  const prof = (pkg.dsh && typeof pkg.dsh === 'object') ? pkg.dsh.profile : null
  if (prof && typeof prof === 'object') {
    if (!Array.isArray(prof.bundles)) prof.bundles = []
    if (!prof.bundles.includes(pkgName)) {
      prof.bundles.push(pkgName)
      bundleAdded = true
      changed = true
    }
  }
  if (!changed) return { ok: true, depAdded: false, bundleAdded: false, changed: false }
  try {
    writeJsonFile(file, pkg)
  } catch (e) {
    return { ok: false, reason: 'write-failed: ' + (e && e.message ? e.message : String(e)) }
  }
  return { ok: true, depAdded, bundleAdded, changed: true }
}

/** 按名字删除远端 .bundle。条目可以是字符串，或 { name, remoteDir }。非法名字拒绝，404 视为已经不在。 */
export async function deleteRemoteBackups(cfg, names) {
  const deleted = []
  const failed = []
  const list = Array.isArray(names) ? names : []
  for (const item of list) {
    const name = typeof item === 'string' ? item : (item && item.name)
    const remoteDir = typeof item === 'string' || !item || item.remoteDir === undefined
      ? normalizeRemoteDir(cfg && cfg.remoteDir)
      : normalizeRemoteDir(item.remoteDir)
    if (!isSafeBackupName(name)) {
      failed.push({ name: String(name), error: '备份名称非法' })
      continue
    }
    if (!isSafeRemoteDir(remoteDir)) {
      failed.push({ name, error: '远程目录非法' })
      continue
    }
    let res
    try {
      res = await davRequest(remoteDirUrl({ ...cfg, remoteDir }, name), 'DELETE', { username: cfg.username, password: cfg.password })
    } catch (e) {
      failed.push({ name, error: e && e.message ? e.message : String(e) })
      continue
    }
    if (res.status === 200 || res.status === 204 || res.status === 404) deleted.push(name)
    else failed.push({ name, error: 'HTTP ' + res.status })
  }
  return { deleted, failed }
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
      // 目标在这台电脑上真实存在就保留（含恢复后改写好的 file:../../local-packages/…）。
      // 不能因为包里写了 repository.url 就改成 github:——那会丢掉本机打过补丁的 tarball，
      // 而且一个失效的绝对路径会让整次 pnpm install 失败，其它插件一起变成「包不可用」。
      const resolved = resolveDepTarget(spec, profileDir)
      if (resolved && existsSync(resolved)) {
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

/**
 * 从 pnpm 输出里抓被拦下的构建脚本包名。
 * 为什么必须处理：git 托管的插件靠 prepare 脚本构建，pnpm 默认拦下它们，
 * 只报「退出码 1」。不把这层翻译给用户，恢复别人备份时就卡在这里无从下手。
 * 实测输出形如：\`Ignored build scripts: esbuild@0.21.5, sharp.\`
 */
export function parseIgnoredBuildScripts(text) {
  const m = /Ignored build scripts:([^\n]*)/i.exec(String(text || ''))
  if (!m) return []
  const seen = new Set()
  for (const raw of m[1].split(/[,、]/)) {
    // 每段先取第一个空白前的 token（pnpm 会在后面接 "Run pnpm approve-builds …" 这类注解），
    // 再去掉结尾标点与 @版本号
    const name = String(raw).trim().split(/\s+/)[0]
      .replace(/[.。:;]+$/, '')
      .replace(/@[^@/]+$/, '')
    if (!name || !/^(@[\w.-]+\/)?[\w.-]+$/.test(name)) continue
    seen.add(name)
  }
  return [...seen]
}

/** 读 profile 的 pnpm-workspace.yaml 里已经声明的 allowBuilds 包名（missing 时为空表）。 */
export function readAllowBuilds(profileDir) {
  try {
    const file = join(profileDir, 'pnpm-workspace.yaml')
    return parsePnpmAllowBuilds(readFileSync(file, 'utf8'))
  } catch (e) { return [] }
}

/** 从 pnpm-workspace.yaml 文本解析 allowBuilds（支持块列表与行内数组两种写法）。 */
export function parsePnpmAllowBuilds(text) {
  const lines = String(text || '').split(/\r?\n/)
  const out = []
  let active = false
  for (const line of lines) {
    const block = /^allowBuilds\s*:\s*(.*)$/.exec(line)
    if (block) {
      const inline = block[1].trim()
      if (inline.startsWith('[')) {
        for (const raw of inline.replace(/^\[|\]$/g, '').split(',')) {
          const name = yamlUnquote(raw.trim())
          if (name) out.push(name)
        }
        active = false
      } else {
        active = inline === ''
      }
      continue
    }
    if (!active) continue
    const item = /^\s+-\s*(.+)$/.exec(line)
    if (item) {
      const name = yamlUnquote(item[1].trim())
      if (name) out.push(name)
    } else if (/^\S/.test(line)) {
      active = false        // 顶层另一个键，allowBuilds 块结束
    }
  }
  return out
}

/**
 * 把包名写进 profile 的 pnpm-workspace.yaml 的 allowBuilds，供「允许并重试」使用。
 * 已有条目一律保留；写到临时文件再改名，避免半截文件把 profile 写坏。
 */
export function approveBuilds(profileDir, names) {
  const wanted = (Array.isArray(names) ? names : []).filter((n) => typeof n === 'string' && n.trim())
  if (!wanted.length) return { ok: true, added: [], allowBuilds: readAllowBuilds(profileDir) }
  const file = join(profileDir, 'pnpm-workspace.yaml')
  let text = ''
  try { text = readFileSync(file, 'utf8') } catch (e) { text = '' }
  const existing = parsePnpmAllowBuilds(text)
  const added = wanted.filter((n) => !existing.includes(n))
  if (!added.length) return { ok: true, added: [], allowBuilds: existing }
  const block = 'allowBuilds:\n' +
    [...existing, ...added].map((n) => '  - ' + yamlSingleQuote(n)).join('\n') + '\n'
  // 已有 allowBuilds 就整段换成块列表（顺带把行内数组写法归一），否则追加到文件末尾
  const next = /^allowBuilds\s*:/m.test(text)
    ? text.replace(/^allowBuilds\s*:[^\n]*(?:\n[ \t]+[^\n]*)*\n?/m, block)
    : (text ? (text.endsWith('\n') ? text : text + '\n') : '') + block
  const tmp = file + '.tmp-dsh-sync'
  writeFileSync(tmp, next, 'utf8')
  renameSyncSafe(tmp, file)
  return { ok: true, added, allowBuilds: [...existing, ...added] }
}

/** 改名失败的兜底（Windows 上目标被占用时先删再改）。 */
function renameSyncSafe(from, to) {
  try { renameSync(from, to) } catch (e) {
    try { rmSync(to, { force: true }); renameSync(from, to) } catch (e2) { throw e }
  }
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
  return {
    dshVersion, pnpmVersion, profile: name, createdAt: new Date().toISOString(), linkMap, unmapped,
    appDataIncluded: true,
    homeIncluded: true,
  }
}

// ============================================================
// 插件入口
// ============================================================

/** 是否来自本机 loopback（connection 服务缺失时的 fail-closed 判据：只看 Host 与来源地址）。 */
export function isLoopbackRequest(req) {
  const host = String((req && req.headers && req.headers.host) || '')
  const name = host.replace(/^\[|\](?=:)/, '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase()
  if (name && name !== 'localhost' && name !== '127.0.0.1' && name !== '::1' && name !== '[::1]') return false
  const remote = String((req && req.socket && req.socket.remoteAddress) || '')
  if (!remote) return false
  return remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1'
}

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
  // home 级挂载点默认开启（生产 = homedir()）。放在 apply() 里而不是模块层：
  // 模块层默认 homedir() 会让任何直接调用 makeSnapshot/rollback 的代码读到并可能删用户真实 home。
  __setHomeRootForTest(cfg.homeRoot !== undefined ? cfg.homeRoot : home)
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
    const obj = {
      url: String(c.url || ''),
      username: String(c.username || ''),
      password: String(c.password || ''),
      remoteDir: normalizeRemoteDir(c.remoteDir),
    }
    if (typeof c.passphrase === 'string' && c.passphrase) obj.passphrase = c.passphrase
    // 文件里有 WebDAV 密码与（记住时的）备份口令，必须只有本用户可读：
    // 默认 umask 落盘实测是 0664，同机其他用户能直接读走。
    writeFileSync(configFile, JSON.stringify(obj, null, 2), { encoding: 'utf8', mode: 0o600 })
    try { chmodSync(configFile, 0o600) } catch (e) { /* Windows 上 chmod 基本无效，忽略 */ }
  }

  /** 统一出口。状态码与宿主 /api 对齐：方法不匹配 405、body 解析失败 400、内部异常 500。 */
  const json = (res, obj, status) => {
    const body = JSON.stringify(obj)
    res.writeHead(Number.isFinite(status) ? status : 200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': String(Buffer.byteLength(body)),
      'Cache-Control': 'no-store',
    })
    res.end(body)
  }

  /** 读请求体。解析失败时 parseFailed=true —— 调用方要回 400，不能当成空 body 继续。 */
  const readBody = (req) => new Promise((resolve) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim()
      if (!raw) return resolve({ body: {}, parseFailed: false })
      try { resolve({ body: JSON.parse(raw), parseFailed: false }) } catch (e) { resolve({ body: {}, parseFailed: true }) }
    })
    req.on('error', () => resolve({ body: {}, parseFailed: false }))
  })

  let lastLocalSnapshot = null
  let installing = false
  // 恢复/回滚互斥：两者都会改写整个配置范围并各自拍快照。并发执行时两次写入会交错，
  // 最后的配置是两份备份的混合体，而两份快照都「看起来正常」——这种半合并状态极难排查。
  // 后到的请求直接拒绝，让用户等前一个跑完（每次恢复也就几秒）。
  let restoring = null
  const withRestoreLock = async (label, fn) => {
    if (restoring) {
      return { ok: false, error: '已有一次' + restoring + '正在进行，请等它完成后再试（同一时间只允许一个操作改写配置）' }
    }
    restoring = label
    try {
      return await fn()
    } catch (e) {
      // 不能把异常冒成 500：Linux 上快照/写入可能因权限或磁盘满失败（EACCES、ENOSPC），
      // 用户需要知道是哪一步、为什么，而不是笼统的「HTTP 500」。
      const msg = (e && e.message) ? e.message : String(e)
      log(label + ' failed: ' + msg)
      return { ok: false, error: label + '失败：' + msg + '。配置可能只写入了一部分，可用本地快照回滚。' }
    } finally {
      restoring = null
    }
  }
  // 路由注册时拿到的 ctx（fail-closed 兜底要用它再取一次 connection）
  let routeCtxRef = ctx
  try {
    const olds = readdirSync(snapshotRoot).filter((n) => { try { return statSync(join(snapshotRoot, n)).isDirectory() } catch (e) { return false } }).sort()
    if (olds.length) lastLocalSnapshot = olds[olds.length - 1]
  } catch (e) { /* ignore */ }

  // ---- 各端点处理逻辑（与路由解耦，便于复用） ----

  // 设置页回显已保存的配置，但绝不回传明文密码：只回 hasPassword，页面留空表示「沿用已保存的」。
  // 密码本来就在本机 dsh-sync.json 里，没有任何必要再经一次 HTTP 往返暴露。
  const savedConfigView = (c) => {
    if (!c) return null
    return {
      url: String(c.url || ''),
      username: String(c.username || ''),
      password: '',
      remoteDir: normalizeRemoteDir(c.remoteDir),
      hasPassword: !!c.password,
      hasPassphrase: typeof c.passphrase === 'string' && !!c.passphrase,
    }
  }

  /** 备份范围的实时快照（本地磁盘统计，不联网）。设置页与备份结果都用它。 */
  const localCoverage = () => {
    try { return describeScope(dshRoot) } catch (e) { return null }
  }

  const handleStatus = async () => {
    const c = loadPluginConfig()
    const config = savedConfigView(c)
    // 备份范围随状态一起给出：用户在点「立即备份」之前就能看到这次会同步什么、排除什么。
    const coverage = localCoverage()
    if (!c) return { configured: false, config, coverage, remote: { reachable: false, backups: [] }, lastLocalSnapshot: lastLocalSnapshot || undefined }
    try {
      const err = await ensureRemoteDir(c)
      if (err) {
        return { configured: true, config, coverage, remote: { reachable: false, backups: [] }, lastLocalSnapshot: lastLocalSnapshot || undefined, error: err }
      }
      const listed = await listAccountBackups(c)
      const backups = listed.backups
      if (!backups.length && listed.errors.length) {
        throw new Error(listed.errors.map((e) => (e.remoteDir || '根目录') + '：' + e.error).join('；'))
      }
      return {
        configured: true,
        config,
        coverage,
        remote: {
          reachable: true,
          backups,
          latest: backups.length ? backups[backups.length - 1].name : undefined,
          listErrors: listed.errors.length ? listed.errors : undefined,
        },
        lastLocalSnapshot: lastLocalSnapshot || undefined,
      }
    } catch (e) {
      return {
        configured: true, config, coverage, remote: { reachable: false, backups: [] },
        lastLocalSnapshot: lastLocalSnapshot || undefined,
        error: e && e.message ? e.message : String(e),
      }
    }
  }

  const handleConfig = async (body) => {
    const prev = loadPluginConfig()
    // 状态接口不再回传明文密码，所以页面留空表示「沿用已保存的」；点「清除密码」才会真的清空。
    if (prev && prev.password && body && (body.password === undefined || body.password === null || body.password === '')) {
      body = { ...body, password: prev.password }
    }
    // 请求体没带 remoteDir 就用默认 dsh-sync；带了（含空字符串）一律照用户的来。
    body = applyDefaultRemoteDir(body)
    const c = configForDisk(prev, body)
    if (!c.url) return { ok: false, error: 'url 不能为空' }
    const err = await ensureRemoteDir(c)
    if (err) return { ok: false, error: err }
    savePluginConfig(c)
    return { ok: true }
  }

  const handlePassphrase = async (body) => {
    const c = loadPluginConfig()
    if (!c) return { ok: false, error: '尚未配置 WebDAV（先保存服务器配置）' }
    if (body && body.clear) {
      const next = { ...c }
      delete next.passphrase
      savePluginConfig(next)
      return { ok: true, hasPassphrase: false }
    }
    const passphrase = body && typeof body.passphrase === 'string' ? body.passphrase : ''
    if (!passphrase) return { ok: false, error: '口令不能为空' }
    savePluginConfig({ ...c, passphrase })
    return { ok: true, hasPassphrase: true }
  }

  // 备份也参与同一把锁：恢复进行到一半时拍的备份，会是两份配置混合的半成品，
  // 而且这种坏备份看起来完全正常，等到下次恢复才会暴露。
  const handleBackup = (body) => withRestoreLock('备份', () => doBackupLocked(body))

  const doBackupLocked = async (body) => {
    const c = loadPluginConfig()
    if (!c) return { ok: false, error: '尚未配置 WebDAV（先 POST /dsh-sync/config）' }
    const resolved = resolvePassphrase(c, body)
    const passphrase = resolved.passphrase
    if (!passphrase) return { ok: false, error: '请先输入口令。勾选「在本机记住」后，这台电脑以后可以留空。' }
    if (resolved.typed && resolved.remember) {
      c.passphrase = passphrase
      savePluginConfig(c)
    }
    const relFiles = collectFiles(dshRoot)
    const appDataFiles = collectAppDataFiles()
    const homeFiles = collectHomeFiles()
    const payload = buildPayload(dshRoot, relFiles, collectInstallMeta(dshRoot, resolveProfile().name), appDataFiles, homeFiles)
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
    const scope = summarizePackedScope(relFiles, appDataFiles, homeFiles)
    let pruned = []
    let pruneError = null
    try {
      const pr = await pruneRemoteBackups(c, REMOTE_KEEP)
      pruned = pr.deleted
      if (pruned.length) log('remote prune: deleted ' + pruned.join(', '))
    } catch (e) {
      pruneError = e && e.message ? e.message : String(e)
      log('remote prune failed: ' + pruneError)
    }
    // 「到底同步了什么、排除了什么」要能被用户看见，否则「其他全部同步」只能靠信。
    let coverage = null
    // 备份结果是一次性展示，这里量出被排除目录的真实体积
    try { coverage = describeScope(dshRoot, { measureExcluded: true }) } catch (e) { coverage = null }
    log('backup uploaded: ' + name + ' (' + bundle.length + ' bytes, ' + relFiles.length + ' files + ' + appDataFiles.length + ' appdata files + ' + homeFiles.length + ' home files; scope ' + scope.topLevel.map((t) => t.name + '=' + t.files).join(',') + ')')
    return {
      ok: true, name, size: bundle.length, fileCount: relFiles.length, appDataCount: appDataFiles.length, homeCount: homeFiles.length,
      scope,
      coverage: coverage ? { included: coverage.included, excluded: coverage.excluded, totals: coverage.totals } : undefined,
      pruned, pruneError,
    }
  }

  // 恢复缓存：预览与紧接着的恢复共用同一份已解密 payload，避免为同一份备份下载两次。
  // 只留一份；键里含备份名、远程目录与口令，任何不一致都不算命中。
  let restoreCache = null
  const RESTORE_CACHE_TTL_MS = 2 * 60 * 1000
  const restoreCacheKey = (name, remoteDir, passphrase) =>
    createHash('sha256').update(String(name) + '\u0000' + String(remoteDir) + '\u0000' + String(passphrase)).digest('hex')

  /**
   * 恢复的公共前半段：定位备份 → 下载 → 解密。恢复与预览共用，保证两者判断的是同一份备份。
   * 成功返回 { ok:true, payload, name, remoteDir, c }，失败返回 { ok:false, error }。
   */
  const fetchRestorePayload = async (body) => {
    const c = loadPluginConfig()
    if (!c) return { ok: false, error: '尚未配置 WebDAV' }
    const resolved = resolvePassphrase(c, body)
    const passphrase = resolved.passphrase
    if (!passphrase) return { ok: false, error: '请先输入口令。勾选「在本机记住」后，这台电脑以后可以留空。' }
    // 注意：这里**不能**先落盘。口令打错一次就覆盖掉本机记住的那份，会让后续每次恢复都失败，
    // 用户还得重新输入正确的口令才能恢复。只在解密成功后持久化（见下方 rememberPassphrase）。
    let name = body.name ? String(body.name) : null
    const hasDir = body && Object.prototype.hasOwnProperty.call(body, 'remoteDir')
    let remoteDir = hasDir ? normalizeRemoteDir(body.remoteDir) : null
    if (!name || remoteDir === null) {
      const listed = await listAccountBackups(c)
      const backups = listed.backups
      if (!name) {
        if (!backups.length) return { ok: false, error: '远端没有备份' }
        const latest = backups[backups.length - 1]
        name = latest.name
        if (remoteDir === null) remoteDir = latest.remoteDir
      } else if (remoteDir === null) {
        const hits = backups.filter((b) => b.name === name)
        remoteDir = hits.length ? hits[hits.length - 1].remoteDir : normalizeRemoteDir(c.remoteDir)
      }
    }
    if (!isSafeBackupName(name)) return { ok: false, error: '备份名称非法' }
    if (!isSafeRemoteDir(remoteDir)) return { ok: false, error: '远程目录非法' }
    // 预览刚下载过、用户几秒内就点「开始恢复」：直接复用，不再下载一次（实测几十 MB）
    const key = restoreCacheKey(name, remoteDir, passphrase)
    if (restoreCache && restoreCache.key === key && (Date.now() - restoreCache.at) < RESTORE_CACHE_TTL_MS) {
      return { ok: true, payload: restoreCache.payload, name, remoteDir, c, cached: true }
    }
    const url = remoteDirUrl({ ...c, remoteDir }, name)
    const res = await davRequest(url, 'GET', { username: c.username, password: c.password, timeoutMs: 120000 })
    if (res.error) return { ok: false, error: '下载备份失败：' + res.error }
    if (res.status !== 200) {
      return { ok: false, error: '下载备份失败（HTTP ' + res.status + '，Content-Type: ' + ((res.headers && res.headers['content-type']) || '-') + '）' }
    }
    // 先解密校验（口令错误/内容损坏在这里就明确报错，绝不在解包中途才炸）
    let payload
    try {
      payload = decryptBundle(res.body, passphrase)
    } catch (e) {
      return { ok: false, error: describeDecryptError(e) }
    }
    // 口令已被证明能解开这份备份，此时才值得存下来
    if (resolved.typed && resolved.remember) {
      c.passphrase = passphrase
      savePluginConfig(c)
    }
    restoreCache = { key: restoreCacheKey(name, remoteDir, passphrase), payload, at: Date.now() }
    return { ok: true, payload, name, remoteDir, c }
  }

  /**
   * 恢复预览（不写盘）：把这份备份在当前机器上的差异摊开，供用户在恢复前选模式。
   * 每个模式各自会做什么也一并算好，界面直接照着显示，避免文案与实现分叉。
   */
  const handleRestorePreview = async (body) => {
    const got = await fetchRestorePayload(body)
    if (!got.ok) return got
    if (!parsePayloadObject(got.payload)) {
      return { ok: false, error: '这份备份的内容不是有效的配置清单，无法比对差异。' }
    }
    // 跨平台恢复的核心：备份里 profiles/<源 profile>/ 要换成本机正在跑的那个 profile。
    // Windows 桌面版固定 desktop、dsh web 固定 web——不换的话配置会落进目标机根本不加载的目录。
    const remap = planProfileRemap(got.payload, resolveProfile().name)
    const plan = planPayloadApply(got.payload, dshRoot, undefined, { remap })
    const meta = extractPayloadMeta(got.payload)
    log('restore preview ' + got.name + ': ' + plan.totals.bundle + ' files, ' +
        plan.totals.added + ' new, ' + plan.totals.conflicts + ' conflicts, ' + plan.totals.localOnly + ' local-only')
    return {
      ok: true,
      name: got.name,
      mode: normalizeRestoreMode(body && body.mode),
      defaultMode: DEFAULT_RESTORE_MODE,
      // 列表只给前 40 条：预览是给人看的，不是全量报告
      added: plan.added.slice(0, 40),
      conflicts: plan.conflicts.slice(0, 40).map((c) => c.path),
      localOnly: plan.localOnly.slice(0, 40),
      unchangedCount: plan.unchanged.length,
      invalid: plan.invalid,
      totals: plan.totals,
      modes: [
        { id: 'merge', label: '只补缺失（推荐）', effect: '本机已有的配置一律不动，只补本机没有的文件。' },
        { id: 'overwrite', label: '覆盖同名配置', effect: '备份里的文件全部覆盖写入；本机多出来的配置保留不删。' },
        { id: 'mirror', label: '完全覆盖（与备份一模一样）', effect: '覆盖写入，并删除本机多出来、备份里没有的配置。' },
      ],
      meta: meta ? { profile: meta.profile, createdAt: meta.createdAt } : undefined,
      // 跨平台提示：备份是 desktop、本机跑 web 时，界面要明确告诉用户「配置会被搬到 web」。
      // 不给这条信息，用户会以为恢复的是另一个 profile，或者疑惑为什么路径对不上。
      profileRemap: remap.from && remap.to && remap.from !== remap.to
        ? { from: remap.from, to: remap.to, note: '备份来自 ' + remap.from + ' profile，本机使用 ' + remap.to + '，恢复时会自动写到本机 profile 下' }
        : null,
      targetProfile: remap.to || null,
    }
  }

  const handleRestore = (body) => withRestoreLock('恢复', () => doRestoreLocked(body))

  const doRestoreLocked = async (body) => {
    const got = await fetchRestorePayload(body)
    if (!got.ok) return got
    const payload = got.payload
    const name = got.name
    const c = got.c
    const mode = normalizeRestoreMode(body && body.mode)
    // payload 不合法就在动任何文件之前拒绝：绝不能在「已经拍了快照、开始写文件」之后才发现。
    if (!parsePayloadObject(payload)) {
      return { ok: false, error: '这份备份的内容不是有效的配置清单，未做任何改动。请换一份备份或检查备份文件是否损坏。' }
    }
    // 恢复前先本地快照（安全性快照，本身就是回滚目标）：任何模式都可回滚
    lastLocalSnapshot = makeSnapshot(dshRoot, snapshotRoot, SNAPSHOT_KEEP)
    // 按模式落地：merge 只补缺失 / overwrite 覆盖但不删 / mirror 完全对齐。排除项一律不动。
    // 与预览用同一套映射规则：预览说会写到哪里，这里就必须写到哪里。
    const remap = planProfileRemap(payload, resolveProfile().name)
    // 先记下「恢复前本插件是怎么声明的」：备份可能来自没装本插件的机器，
    // 覆盖后要靠这份声明把自身补回 profile（否则插件会把自己删掉，见 ensureSelfRegistered）。
    const selfBefore = inspectSelf()
    const r = applyPayloadMode(payload, dshRoot, mode, { remap })
    // 源机器的 file: 绝对路径和 pnpm storeDir 在这台电脑上不存在。不改的话，
    // 接下来的 pnpm install 会整批失败，package.json 里的插件全部显示「包不可用」。
    let portability = { profiles: [] }
    try { portability = portabilizeRestoredTree(dshRoot) } catch (e) {
      log('portabilize failed: ' + (e && e.message ? e.message : String(e)))
    }
    // 恢复可能把本插件自己从 profile 里覆盖掉（备份来自没装插件的机器时）。
    // 必须补回去：插件没了，用户连「回滚」按钮都点不到，只能手工重装。
    // portabilize 跑完之后再补，避免刚写好又被它改写掉。
    let selfRepair = null
    if (selfBefore && selfBefore.ok && selfBefore.pkgName) {
      try {
        const prof = resolveProfile()
        selfRepair = ensureSelfRegistered(prof.dir, selfBefore.pkgName, selfBefore.spec)
        if (selfRepair && selfRepair.changed) {
          log('self-register: restored bundle re-added to profile' +
              (selfRepair.depAdded ? ' (dependencies)' : '') +
              (selfRepair.bundleAdded ? ' (bundles)' : ''))
        }
      } catch (e) {
        selfRepair = { ok: false, reason: e && e.message ? e.message : String(e) }
      }
    }
    // 记录本次恢复的插件依赖映射。安装本身由设置页在恢复成功后自动触发
    // （pnpm 可能要几分钟，不放在这条请求里，避免和「先写完文件」缠在一起）。
    const meta = extractPayloadMeta(payload)
    if (meta) {
      writeLastRestore(dshRoot, {
        at: new Date().toISOString(), bundle: name, mode,
        profile: meta.profile || cfg.profile, linkMap: meta.linkMap || {},
      })
    }
    const rewrittenN = (portability.profiles || []).reduce((n, p) => n + ((p.rewritten && p.rewritten.length) || 0), 0)
    log('restored ' + name + ' [' + mode + ']: ' + r.count + ' files, verified ' + r.verified +
        (r.keptConflicts.length ? ', kept ' + r.keptConflicts.length + ' local conflicts' : '') +
        (r.keptLocalOnly.length ? ', kept ' + r.keptLocalOnly.length + ' local-only' : '') +
        (r.removed.length ? ', removed ' + r.removed.length : '') +
        (r.failed.length ? ', remove failed ' + r.failed.length : '') +
        (r.skipped.length ? ', skipped ' + r.skipped.length : '') +
        (r.mismatches.length ? ', mismatches ' + r.mismatches.length : '') +
        ' (snapshot ' + lastLocalSnapshot + ')' +
        (meta ? ', install meta captured' : ', no install meta in bundle') +
        (rewrittenN ? ', retargeted ' + rewrittenN + ' local specs' : '') +
        (selfRepair && selfRepair.changed ? ', self re-registered in profile' : ''))
    return {
      ok: true, mode, restored: r.count, verified: r.verified,
      removedCount: r.removed.length,
      removed: r.removed.slice(0, 30),
      removeFailed: r.failed,
      skipped: r.skipped, mismatches: r.mismatches,
      // 冲突 = 本机改过、这次按你的选择保留的文件。必须显式回报，否则用户会以为「恢复没生效」
      keptConflicts: r.keptConflicts.slice(0, 40),
      keptConflictsCount: r.keptConflicts.length,
      keptLocalOnlyCount: r.keptLocalOnly.length,
      unchangedCount: r.unchanged.length,
      totals: r.totals,
      snapshot: lastLocalSnapshot,
      portability,
      meta: meta ? { profile: meta.profile, linkCount: Object.keys(meta.linkMap || {}).length } : undefined,
      // 自保结果：备份来自没装本插件的机器时，恢复会把插件自己覆盖掉，这里回报是否补回。
      selfRepair: selfRepair || null,
      // 跨 profile 迁移明细：让界面能说清「备份里的 desktop 配置写到了本机 web」。
      profileRemap: remap.from && remap.to && remap.from !== remap.to
        ? { from: remap.from, to: remap.to, count: (r.remapped || []).length }
        : null,
      remapped: (r.remapped || []).slice(0, 40),
    }
  }

  const handleDelete = async (body) => {
    const c = loadPluginConfig()
    if (!c) return { ok: false, error: '尚未配置 WebDAV' }
    const names = Array.isArray(body.names)
      ? body.names
      : (body.name ? [{ name: String(body.name), remoteDir: Object.prototype.hasOwnProperty.call(body, 'remoteDir') ? body.remoteDir : undefined }] : [])
    if (!names.length) return { ok: false, error: '请指定要删除的备份' }
    const { deleted, failed } = await deleteRemoteBackups(c, names)
    if (deleted.length) log('remote delete: ' + deleted.join(', '))
    if (failed.length) log('remote delete failed: ' + failed.map((f) => f.name + ' ' + f.error).join('; '))
    return {
      ok: failed.length === 0 && deleted.length > 0,
      deleted,
      failed,
      error: failed.length
        ? failed.map((f) => f.name + '：' + f.error).join('；')
        : (deleted.length ? undefined : '没有删除任何备份'),
    }
  }

  const handleRollback = (body) => withRestoreLock('回滚', () => doRollbackLocked(body))

  const doRollbackLocked = async (body) => {
    const snapshot = String(body.snapshot || '')
    if (!snapshot || snapshot.includes('..') || /[\\/]$/.test(snapshot) || snapshot.includes('/') || snapshot.includes('\\')) {
      return { ok: false, error: 'snapshot 名称非法' }
    }
    const dir = join(snapshotRoot, snapshot)
    if (!existsSync(dir)) return { ok: false, error: '快照不存在: ' + snapshot }
    // 配置范围对齐到该快照；排除项（dsh-runtimes/ 等）原样保留
    const rolled = rollbackFromSnapshot(dir, dshRoot, snapshotRoot, SNAPSHOT_KEEP)
    // 「最近一次本地快照」必须是刚拍的那份（回滚前的状态），不是刚回滚到的旧快照。
    // 设成旧快照会让界面显示错乱，并且让「回滚到最近快照」按钮无法撤销这次回滚。
    if (rolled.taken) lastLocalSnapshot = rolled.taken
    log('rolled back to snapshot ' + snapshot + ': ' + rolled.count + ' files' +
        (rolled.removed.length ? ', removed ' + rolled.removed.length : '') +
        (rolled.failed.length ? ', remove failed ' + rolled.failed.length : '') +
        (rolled.taken ? ' (safety snapshot ' + rolled.taken + ')' : ''))
    return {
      ok: true, restored: rolled.count,
      removedCount: rolled.removed.length,
      removed: rolled.removed.slice(0, 30),
      removeFailed: rolled.failed,
      snapshot: rolled.taken,
    }
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
        // .CMD/.BAT 外壳（Windows 上的 pnpm）必须原样透传已转义好的命令行
        windowsVerbatimArguments: opt.windowsVerbatimArguments === true,
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

  /** 宿主给的当前 profile 名（0.2.1 起所有 profile 都有 ctx.profileContext） */
  const hostProfileName = () => {
    try {
      const pc = resolveService(ctx, 'profileContext')
      const name = pc && typeof pc.name === 'string' ? pc.name.trim() : ''
      return name || null
    } catch (e) { return null }
  }

  /**
   * 解析实际使用的 profile：宿主当前 profile > cfg.profile > 扫描 profiles/<n>。
   *
   * 为什么宿主优先：机器上同时有 profiles/desktop 和 profiles/web 时，Web 实例若按
   * 默认值 'desktop' 直取，就会改写 desktop 的 package.json 并往那里装包——当前运行的
   * web profile 一个都修不好，症状是「按钮说成功了，重启后插件还是不可用」。
   */
  const resolveProfile = () => {
    const fromHost = hostProfileName()
    const wanted = String(fromHost || cfg.profile || 'desktop')
    const direct = join(dshRoot, 'profiles', wanted)
    try {
      if (existsSync(join(direct, 'package.json'))) return { name: wanted, dir: direct }
    } catch (e) { /* ignore */ }
    if (fromHost) return { name: wanted, dir: direct }   // 宿主说的就是它，不要再去猜别的 profile
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

  /** 宿主给的 pnpm 调用方式（桌面版 Electron 内置运行时通过它暴露） */
  const hostPackageManager = () => {
    try {
      const pc = resolveService(ctx, 'profileContext')
      const pm = pc && pc.packageManager
      return pm && typeof pm.command === 'string' && pm.command ? pm : null
    } catch (e) { return null }
  }

  /** 解析「怎么调用 pnpm」。测试可显式注入一份（传 null 表示强制找不到）。 */
  const pnpmInvocation = (opts) => {
    const o = opts || {}
    return resolvePnpmInvocation(process.resourcesPath, {
      packageManager: o.packageManager !== undefined ? o.packageManager : hostPackageManager(),
      homeRoot: o.homeRoot,
      env: o.env,
    })
  }

  const PNPM_MISSING_HINT = '未找到 pnpm。请先安装 pnpm（npm i -g pnpm）并确保它在 PATH 中；' +
    '桌面版应用自带运行时，Web 版需要自行安装。'

  /** 组合「插件依赖现状」：已装/缺失、可否改写、能否安装。
   *  字段形状遵循 client.js 头部契约：missing 是包名数组，deps[].installed 是布尔值。 */
  const buildPluginsReport = () => {
    const prof = resolveProfile()
    // 已经恢复过的机器打开设置页时也要改路径，否则用户不重新恢复就一直装不上
    try {
      const fixed = portabilizeProfile(prof.dir, dshRoot)
      if ((fixed.rewritten && fixed.rewritten.length) || fixed.storeDir) {
        log('portabilize ' + prof.name + ': specs ' + fixed.rewritten.length +
          (fixed.storeDir ? ', storeDir retargeted' : ''))
      }
    } catch (e) { /* 改路径失败不挡住状态查询 */ }
    // 恢复时记录的映射必须先读：B 机上 node_modules 尚未重建，只能靠备份里的 linkMap
    const last = readLastRestore(dshRoot)
    const plan = planProfileInstall(prof.dir, last && last.linkMap)
    const inv = pnpmInvocation()
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
      found: plan.ok,
      error: plan.ok ? undefined : plan.error,
      deps,
      missing,
      missingCount: missing.length,
      needsInstall: missing.length > 0,
      mapped,
      // 注意：Web 版靠 PATH 上的 pnpm，available 必须反映「能不能真跑起来」，不能只看桌面版布局。
      // profileDir 绝对路径不再回传（属不必要的暴露），需要时看 profile 名即可。
      pnpm: { available: !!inv, path: inv ? (inv.args[inv.args.length - 1] || inv.cmd) : undefined, via: inv ? inv.via : undefined },
      lastRestore: last ? { at: last.at, bundle: last.bundle } : undefined,
    }
  }

  /**
   * 实测：改写 spec → 备份 package.json → 跑 pnpm install（可注入 runner 供测试）
   *
   * pnpmInv 参数沿用旧签名的位置：调用方传 'C:/fake/pnpm.mjs' 这类路径时按「脚本入口」解释，
   * 传 null 表示强制找不到 pnpm，传 undefined 表示自己解析。
   */
  const runProfileInstall = async (runner, pnpmInv, opts) => {
    if (installing) return { ok: false, error: '安装正在进行中，请稍候' }
    const prof = resolveProfile()
    const file = join(prof.dir, 'package.json')
    // 区分「未提供」与「显式传入空值」：测试用 null 模拟找不到 pnpm，不能被 || 吞掉
    const inv = pnpmInv === undefined
      ? pnpmInvocation()
      : (typeof pnpmInv === 'string' ? { cmd: process.execPath, args: ['--expose-internals', pnpmInv], via: 'injected' } : pnpmInv)
    if (!inv) return { ok: false, error: PNPM_MISSING_HINT }

    // 0) 先把源机器的绝对路径改到这台电脑，再决定哪些依赖要改写成仓库地址
    try { portabilizeProfile(prof.dir, dshRoot) } catch (e) { /* 下面的 plan 仍会去掉装不上的 link: */ }

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
    // 备份句柄提到外层：pnpm 失败时要靠它把 package.json 还原回去（见下）
    let bak = null
    const lockFile = join(prof.dir, 'pnpm-lock.yaml')
    let lockBak = null
    if (changed) {
      bak = file + '.bak-dsh-sync-' + new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
      try {
        copyFileSync(file, bak)
        // 锁文件也留一份：失败时它和 package.json 必须一起回到改动前，
        // 否则 DSH 自己后续的 --frozen-lockfile 会因为两者不一致而整批失败。
        if (existsSync(lockFile)) {
          lockBak = lockFile + '.bak-dsh-sync-' + new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
          try { copyFileSync(lockFile, lockBak) } catch (e) { lockBak = null }
        }
        writeJsonFile(file, pkg)
        log('plugin install: rewrote ' + Object.keys(rewritten).length + ' link deps, removed ' + Object.keys(removed).length + ' (backup ' + bak + ')')
      } catch (e) {
        return { ok: false, error: '改写 package.json 失败：' + (e && e.message ? e.message : String(e)) }
      }
    } else if (!existsSync(file)) {
      return { ok: false, error: 'profile 的 package.json 不存在' }
    }

    /** 安装失败时把 package.json / pnpm-lock.yaml 还原到改写前（没有备份则什么也不做）。 */
    const restoreProfileFiles = () => {
      let restored = false
      if (bak) {
        try { copyFileSync(bak, file); restored = true } catch (e) { /* ignore */ }
      }
      if (lockBak) {
        try { copyFileSync(lockBak, lockFile) } catch (e) { /* ignore */ }
      }
      if (restored) log('plugin install failed; package.json restored from ' + bak)
      return restored
    }

    // 2) 跑 pnpm install（普通模式：顺带把锁文件里遗留的 link: specifier 一并同步，否则后续
    //    DSH 自己的 pnpm install --frozen-lockfile 会因为 package.json 与锁文件不一致而失败）
    // 调用方式由 resolvePnpmInvocation 决定：脚本入口用 node + --expose-internals，
    // 原生启动器（pnpm >= 10 的 npm 包）必须直接执行，否则 node 会把 ELF 当 JS 解析。
    const extra = opts && opts.force ? ['install', '--force'] : ['install']
    const built = buildPnpmCommand(inv, extra) || { cmd: inv.cmd, args: [...inv.args, ...extra] }
    const args = built.args
    installing = true
    const startedAt = Date.now()
    // 升级路径装的是 github: 依赖，必须把 git 的 SSH 回退拉回 HTTPS（见 githubHttpsOnlyEnv）
    const baseEnv = { ...process.env, ELECTRON_RUN_AS_NODE: '1', DSH_DESKTOP_NODE_EXECUTABLE: process.execPath }
    const withGit = opts && opts.githubHttpsOnly ? githubHttpsOnlyEnv(baseEnv) : baseEnv
    const childEnv = inv.env ? { ...withGit, ...inv.env } : withGit
    let r
    try {
      r = await runner({
        cmd: built.cmd, args, cwd: prof.dir, env: childEnv, timeout: INSTALL_TIMEOUT_MS,
        windowsVerbatimArguments: built.windowsVerbatimArguments,
      })
    } catch (e) {
      installing = false
      const restored = restoreProfileFiles()
      return { ok: false, restored, error: 'pnpm install 启动失败：' + (e && e.message ? e.message : String(e)), log: '' }
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
    // 失败必须回滚 package.json：改写与删依赖是在跑 pnpm 之前做的，不还原就会留下一个
    // 依赖被改坏/删掉的 profile，用户手上没有任何回滚点。
    const restored = ok ? false : restoreProfileFiles()
    // pnpm 因构建审批拦下的包名：不译出来的话用户只看到「退出码 1」，无从下手
    const pendingBuilds = ok ? [] : parseIgnoredBuildScripts(tail)
    if (pendingBuilds.length) log('plugin install blocked by build scripts: ' + pendingBuilds.join(', '))
    return {
      ok, installed: installedNames, exitCode: r.status, durationMs, restored,
      rewritten: rewrittenOut, removed: removedOut, lockSynced: ok ? lockSynced : undefined,
      pendingBuilds: pendingBuilds.length ? pendingBuilds : undefined,
      log: tail,
      error: ok
        ? undefined
        : (pendingBuilds.length
            ? 'pnpm 拦下了 ' + pendingBuilds.join('、') + ' 的安装脚本（git 插件靠 prepare 构建）。' +
              '点「允许并重试」把它们写进 profile 的 pnpm-workspace.yaml 的 allowBuilds 后再装一次。'
            : 'pnpm install 退出码 ' + r.status),
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

  const handlePluginInstall = async (body, runner, pnpmInvOpt) => {
    try {
      // 「允许并重试」：先把被拦下的包名写进 profile 的 pnpm-workspace.yaml，再跑一次安装
      const approve = body && Array.isArray(body.approve) ? body.approve.filter((n) => typeof n === 'string' && n) : []
      if (approve.length) {
        const prof = resolveProfile()
        const r = approveBuilds(prof.dir, approve)
        log('approveBuilds: ' + (r.added.length ? r.added.join(', ') : '(already allowed) ' + approve.join(', ')))
      }
      return await runProfileInstall(runner || defaultRunner, pnpmInvOpt)
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
   * 为什么升级要带 --force：pnpm 看到 specifier 字符串没变时会认为锁文件已最新而跳过。
   * 「声明已是 #vX、node_modules 里仍是旧版本」正是这种错位。spec 与已装版本、锁文件 sha
   * 三者一致才跳过安装；否则强制重装。安装失败会把 package.json 从备份还原回去。
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
      // spec 字符串相同还不够：node_modules 里的版本和锁文件 sha 也得对上，
      // 否则「声明已是目标 tag、内容仍是旧提交」会被短路，升级按钮永远空转。
      let installedVer = null
      try {
        installedVer = JSON.parse(readFileSync(join(info.prof.dir, 'node_modules', pkgName, 'package.json'), 'utf8')).version
      } catch (e) { installedVer = null }
      const tagged = ver.latestTag ? String(ver.latestTag).replace(/^v/, '') : null
      const specSame = String(oldSpec) === newSpec
      const versionOk = !tagged || installedVer === tagged
      const shaOk = !ver.remoteSha || (info.localSha && info.localSha === ver.remoteSha)
      if (specSame && versionOk && shaOk) {
        return { ok: true, upgraded: false, alreadyLatest: true, from: info.current, to: info.current, spec: newSpec, exitCode: 0, durationMs: Date.now() - started, needRestart: false, before: { version: info.current, spec: oldSpec === undefined ? null : String(oldSpec) }, backup: null, log: '', error: null }
      }
      let backup = null
      if (!specSame) {
        pkg.dependencies[pkgName] = newSpec
        backup = file + '.bak-dsh-sync-' + new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)
        try {
          copyFileSync(file, backup)
          writeJsonFile(file, pkg)
        } catch (e) {
          return { ok: false, error: '改写 profile package.json 失败：' + (e && e.message ? e.message : String(e)), durationMs: Date.now() - started }
        }
        if (!nonTargetFieldsIntact(before, pkg, pkgName)) {
          try { copyFileSync(backup, file) } catch (e2) { /* ignore */ }
          return { ok: false, error: '改写后校验失败：目标依赖之外的字段发生变化，已还原 package.json（备份见 ' + backup + '）', durationMs: Date.now() - started }
        }
        log('upgrade: ' + (oldSpec === undefined ? '(none)' : String(oldSpec)) + ' -> ' + newSpec + ' (backup ' + backup + ')')
      } else {
        log('upgrade: spec already ' + newSpec + ' but installed content is ' + (installedVer || 'missing') + ' / sha ' + (info.localSha || 'none') + '; forcing install')
      }

      // 5) 复用既有安装路径（绝不新写第二条 pnpm install 分支）。force：摆脱「spec 没变就跳过」。
      const install = o.install || ((r, p, op) => runProfileInstall(r || defaultRunner, p, op))
      const ir = await install(o.runner, o.pnpmPath, { githubHttpsOnly: true, force: true })
      const logTail = (ir && ir.log) ? String(ir.log) : ''
      if (!ir || !ir.ok) {
        let restored = false
        if (backup) {
          try { copyFileSync(backup, file); restored = true; log('upgrade failed; package.json restored from ' + backup) } catch (e) { /* ignore */ }
        }
        return { ok: false, restored, error: (ir && ir.error) ? ir.error : 'pnpm install 失败', log: logTail, durationMs: Date.now() - started, backup, from: info.current, to: ver.latest, spec: newSpec }
      }
      // 6) 重新读 profile package.json 确认 spec 已落地，并核对 node_modules 里的实际版本。
      //    to = 目标版本，needRestart 恒为 true（插件代码在 DSH 启动时加载，生效必须重启）。
      let confirmed = null
      try {
        const after = JSON.parse(readFileSync(file, 'utf8'))
        confirmed = after.dependencies ? after.dependencies[pkgName] : null
      } catch (e) { confirmed = null }
      if (String(confirmed) !== newSpec) {
        return { ok: false, error: '安装后校验失败：profile 里仍是 ' + String(confirmed), log: logTail, durationMs: Date.now() - started, backup, from: info.current, to: ver.latest, spec: newSpec }
      }
      let afterVer = null
      try { afterVer = JSON.parse(readFileSync(join(info.prof.dir, 'node_modules', pkgName, 'package.json'), 'utf8')).version } catch (e) { afterVer = null }
      if (afterVer && tagged && tagged !== String(afterVer)) {
        return { ok: false, error: '安装后校验失败：node_modules 里是 ' + afterVer + '，目标是 ' + ver.latest, log: logTail, durationMs: Date.now() - started, backup, from: info.current, to: ver.latest, spec: newSpec }
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
    'POST /dsh-sync/passphrase': handlePassphrase,
    'POST /dsh-sync/backup': handleBackup,
    'POST /dsh-sync/restore': handleRestore,
    'POST /dsh-sync/restore/preview': handleRestorePreview,
    'POST /dsh-sync/rollback': handleRollback,
    'POST /dsh-sync/delete': handleDelete,
    'POST /dsh-sync/plugins/install': (body) => handlePluginInstall(body),
    'POST /dsh-sync/upgrade': handleUpgrade,
  }

  /** 供 tools-selftest.mjs 直接调用的内部句柄（不启动 DSH、不注册路由） */
  apply._internals = {
    // snapshotRoot 暴露出来仅供自测断言「测试隔离」用（自测绝不能写用户真实快照目录）
    snapshotRoot, dshRoot,
    handlePlugins, handlePluginInstall, buildPluginsReport, resolveProfile, defaultRunner,
    handleVersion, handleUpgrade, inspectSelf, versionCache, runProfileInstall,
    handleStatus, handleDelete, handlePassphrase, handleConfig, handleBackup,
    handleRestore, handleRestorePreview, handleRollback,
    describeScope, localCoverage,
  }

  /**
   * 请求栅栏：与宿主 /api 同一套（Host/Origin 栅栏 + 浏览器 cookie / API 凭据）。
   * 少了它，同网段任意主机、或用户浏览器里打开的任何网页，都能改写 WebDAV 指向并把 ~/.dsh 打包外传
   * （POST + text/plain 是 CORS 简单请求，副作用照样发生）。
   * connection 取不到时 fail-closed：只放过 loopback 直连。
   */
  // 注意：只 inject webServer。connection 在请求时才解析——若把它写进 inject，
  // 一旦宿主的 composition 里没有这个服务，11 个端点会连注册都等不到，整块功能直接消失。
  // 取不到 connection 时按 loopback 判据 fail-closed，安全性不因此下降。
  const requestRejection = (req) => {
    const connection = resolveService(routeCtxRef, 'connection') || resolveService(ctx, 'connection')
    if (connection && typeof connection.requestRejection === 'function') {
      try { return connection.requestRejection(req) } catch (e) { return 403 }
    }
    return isLoopbackRequest(req) ? undefined : 403
  }

  const setupRoutes = (routeCtx) => {
    try {
      routeCtxRef = routeCtx
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
              const rejection = requestRejection(req)
              if (rejection !== undefined) {
                const body = rejection === 401 ? 'unauthorized' : 'forbidden'
                res.writeHead(rejection, {
                  'Content-Type': 'text/plain; charset=utf-8',
                  'Content-Length': String(Buffer.byteLength(body)),
                  'Cache-Control': 'no-store',
                })
                return res.end(body)
              }
              if (req.method !== method) {
                res.setHeader('Allow', method)
                return json(res, { ok: false, error: '方法不允许：需要 ' + method }, 405)
              }
              const parsed = method === 'POST' ? await readBody(req) : { body: {}, parseFailed: false }
              if (parsed.parseFailed) return json(res, { ok: false, error: '请求体不是合法 JSON' }, 400)
              const result = await handler(parsed.body, req)
              json(res, result, 200)
            } catch (e) {
              json(res, { ok: false, error: e && e.message ? e.message : String(e) }, 500)
            }
          },
        })
        if (typeof dispose === 'function') cleanupFns.push(dispose)
      }
      log('HTTP endpoints ready: /dsh-sync/{status,config,passphrase,backup,restore,restore/preview,rollback,delete,plugins,plugins/install,version,upgrade}' +
        '（已套 Host/Origin 栅栏 + browser cookie 认证）')
    } catch (e) {
      log('route registration failed: ' + (e && e.message ? e.message : String(e)))
    }
  }

  // 路由层句柄要在定义之后再挂（requestRejection / setupRoutes 是上面才声明的 const）
  apply._internals.requestRejection = requestRejection
  apply._internals.setupRoutes = setupRoutes

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
  const cfg = { ...(config || {}), __test: true }
  // 自测必须完全隔离。apply() 没给 snapshotRoot 时会退回 join(homedir(), '.dsh-sync-snapshots')，
  // 而自测会反复 makeSnapshot/rollback —— 于是每跑一次自测，就往**用户真实的快照目录**写几份快照，
  // 并按「保留 5 份」把用户自己的回滚点顶掉。
  // 实测事故（2026-10-20）：连跑几次自测后，用户恢复前的快照被挤掉，回滚点丢失。
  // 因此只要没显式给 snapshotRoot，就放进 root 内部：同样隔离，且绝不碰真实 home。
  if (cfg.snapshotRoot === undefined) {
    cfg.snapshotRoot = join(String(cfg.root || join(homedir(), '.dsh')), '.dsh-sync-snapshots')
  }
  // home 挂载点同样必须隔离（理由同上）：不隔离的话自测会读到用户真实 ~/.cc-switch、
  // ~/.claude，而 mirror 用例会按 payload 删掉 home 里「备份没有」的配置 —— 直接删用户数据。
  // 隔离目录默认不存在，于是 collectHomeFiles() 返回空，既有断言（文件数/范围）不受影响。
  if (cfg.homeRoot === undefined) cfg.homeRoot = join(String(cfg.root || join(homedir(), '.dsh')), '__home__')
  __setHomeRootForTest(cfg.homeRoot)
  apply(fakeCtx, cfg)
  selftest = apply._internals
  return selftest
}
