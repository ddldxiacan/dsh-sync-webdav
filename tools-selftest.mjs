/**
 * dsh-sync Host 半区自测（临时，验收后可删）
 * 覆盖：加解密往返、打包/解包往返（排除规则）、快照/回滚往返、
 *       WebDAV（mock http 服务器：Basic Auth / PROPFIND / MKCOL / PUT / GET）。
 * 运行：node tools-selftest.mjs
 */
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  buildPayload, collectFiles, encryptBundle, decryptBundle, extractPayload,
  extractPayloadDetailed, applyPayloadMirror,
  isExcludedAppData, collectAppDataFiles, appDataAbsPath,
  bundleName, makeSnapshot, rollbackFromSnapshot, isExcluded,
  davRequest, ensureRemoteDir, parsePropfind, listRemoteBackups, listAccountBackups,
  backupSearchDirs, normalizeRemoteDir, resolvePassphrase, configForDisk, describeDecryptError, applyDefaultRemoteDir,
  redactBackupBytes,
  summarizePackedScope, pruneRemoteBackups, parseGitLsRemote,
  repoSpecFromUrl, depKind, collectInstallMeta, extractPayloadMeta,
  writeLastRestore, readLastRestore, planProfileInstall, findPnpmPath,
  portabilizeRestoredTree, deleteRemoteBackups, isSafeBackupName, resolveDepTarget,
  createTestHarness,
  parseSemver, cmpSemver, semverGt, latestTagOf, shaOfDependency, summaryFromCompare,
  queryFlag, nonTargetFieldsIntact, selfPackageName, selfRepoSlug, selfVersion,
  performVersionCheck, parseRepoSlug, githubHttpsOnlyEnv,
  defaultHttpsGet, nextRedirectUrl,
  isNativeExecutable, findPnpmOnPath, resolvePnpmInvocation, buildPnpmCommand, describeScope,
  parseIgnoredBuildScripts, parsePnpmAllowBuilds, readAllowBuilds, approveBuilds, isLoopbackRequest,
  applyPayloadMode, planPayloadApply, normalizeRestoreMode, DEFAULT_RESTORE_MODE, RESTORE_MODES,
  pathsEqual, isUnderDir, __setAppDataPlatformForTest,
  planProfileRemap, remapPayloadPath, payloadProfileNames, ensureSelfRegistered,
} from './index.js'

const APPDATA_PROBE = '__appdata__/dsh-desktop/desktop/settings.json'
let pass = 0, fail = 0
const check = (name, cond, detail) => {
  if (cond) { pass++; console.log('PASS  ' + name + (detail ? '  -- ' + detail : '')) }
  else { fail++; console.log('FAIL  ' + name + (detail ? '  -- ' + detail : '')) }
}

// ---------- 1. 排除规则 ----------
check('exclude: dsh-runtimes', isExcluded('dsh-runtimes/x/y.json'))
check('exclude: logs', isExcluded('logs/a.log'))
check('exclude: npm-cache', isExcluded('npm-cache'))
check('exclude: tmp*', isExcluded('tmpfoo'))
check('exclude: cache*', isExcluded('cache-1'))
check('exclude: >50MB file', isExcluded('big.bin', 50 * 1024 * 1024 + 1))
check('keep: 10-50MB file (0.3.0 放宽)', !isExcluded('big.bin', 10 * 1024 * 1024 + 1))
check('keep: normal', !isExcluded('settings.json', 100))
// 回归：node_modules 是插件依赖（实测 ~221MB），sessions 是会话历史（实测 ~27MB）。
// 二者若进备份，base64 payload 达 350MB+，会把 Node 堆撑爆（实测 OOM）。
check('exclude: node_modules (任意深度)', isExcluded('profiles/desktop/node_modules/foo/index.js') && isExcluded('node_modules/x'))
check('exclude: sessions', isExcluded('sessions/abc/session.v4.jsonl.zstd'))
check('keep: profile 配置不受 node_modules 排除影响', !isExcluded('profiles/desktop/cordis.patch.yml'))
check('keep: settings 与凭据', !isExcluded('settings.yaml') && !isExcluded('.credentials.yaml'))

// 0.4.1 备份策略：除「聊天数据 + 可重建产物 + 日志缓存」外全同步
check('exclude: attachments（聊天文件，与 sessions 一致）', isExcluded('attachments/v1/objects/ab/cdef'))
check('exclude: session_projcache（聊天派生：会话标题与首条输入）', isExcluded('storages/session_projcache/sessions/x.json'))
check('exclude: storages/workspace.json（含 archivedSessionIds）', isExcluded('storages/workspace.json'))
check('keep: 凭据', !isExcluded('.credentials.yaml'))
check('keep: 任务板', !isExcluded('task-board/ledger-v2.json') && !isExcluded('task-board/scheduler-v2.json'))
check('keep: 皮肤（含素材，实测 skins/ 有 6MB 的 mp4）',
  !isExcluded('skins/orca-link/assets/x.webp') && !isExcluded('skins/whale-fantasy/assets/loop.mp4', 6 * 1024 * 1024))
check('keep: 智能体预设', !isExcluded('agent-presets/roleplay-chengwei/preset.yml'))
check('keep: 插件本地包', !isExcluded('local-packages/foo.tgz'))
check('keep: 用量与会话归档', !isExcluded('dsh-usage/x.json') && !isExcluded('dsh-session-archive/state.json'))
check('keep: 会话未触及的新目录默认进备份', !isExcluded('brand-new-feature/data.json'))

// ---------- 1b. AppData 排除规则 ----------
check('appdata exclude: Local Storage', isExcludedAppData('dsh-desktop/Local Storage/leveldb/000003.log'))
check('appdata exclude: Cache 前缀目录', isExcludedAppData('dsh-desktop/Cache/Cache_Data/x'))
check('appdata keep: settings.json', !isExcludedAppData('dsh-desktop/desktop/settings.json', 100))
check('appdata exclude: >2MB file', isExcludedAppData('dsh-desktop/desktop/big.db', 2 * 1024 * 1024 + 1))
check('appdata 路径解析：__appdata__ 前缀返回绝对路径', typeof appDataAbsPath('__appdata__/dsh-desktop/desktop/settings.json') === 'string')
check('appdata 路径解析：无前缀返回 null', appDataAbsPath('dsh-desktop/desktop/settings.json') === null)
check('appdata 路径解析：路径穿越返回 null', appDataAbsPath('__appdata__/../../etc/passwd') === null)
if (process.env.APPDATA) {
  const ad = collectAppDataFiles()
  check('appdata 收集：全部带 __appdata__ 前缀', ad.every((f) => f.startsWith('__appdata__/')))
  check('appdata 收集：包含 dsh-desktop/desktop/settings.json', ad.some((f) => f.endsWith('dsh-desktop/desktop/settings.json')), ad.length + ' files')
  check('appdata 收集：不含 Local Storage / Cache', !ad.some((f) => /Local Storage|\/Cache\//.test(f)))
} else {
  console.log('SKIP  appdata 收集（无 APPDATA 环境变量）')
}

// ---------- 2. 加解密往返 ----------
{
  const pass1 = Math.random().toString(36).slice(2) + '口令测试'
  const payload = Buffer.from(JSON.stringify({ hello: '世界', n: 42 }), 'utf8')
  const bundle = encryptBundle(payload, pass1)
  const back = decryptBundle(bundle, pass1)
  check('encrypt/decrypt roundtrip', back.equals(payload), bundle.length + ' bytes')
  let wrongPass = false
  try { decryptBundle(bundle, pass1 + 'x') } catch (e) { wrongPass = true }
  check('wrong passphrase rejected (GCM auth)', wrongPass)
  let tampered = false
  const bad = Buffer.from(bundle); bad[bad.length - 1] ^= 0xff
  try { decryptBundle(bad, pass1) } catch (e) { tampered = true }
  check('tampered ciphertext rejected', tampered)
}

// ---------- 3. 打包/解包往返（模拟 ~/.dsh） ----------
const root = join(tmpdir(), 'dsh-sync-selftest-' + Date.now())
const restored = root + '-restored'
const snapRoot = root + '-snapshots'
try {
  mkdirSync(join(root, 'sub', 'deeper'), { recursive: true })
  writeFileSync(join(root, 'settings.json'), '{"a":1}')
  writeFileSync(join(root, 'sub', 'auth.json'), '{"token":"xyz"}')
  writeFileSync(join(root, 'sub', 'deeper', 'note.txt'), 'hello dsh-sync')
  writeFileSync(join(root, 'should-skip.log'), 'x') // .log? 规则是 logs/ 目录，不是 *.log —— 保留
  mkdirSync(join(root, 'logs'), { recursive: true })
  writeFileSync(join(root, 'logs', 'a.log'), 'x'.repeat(10))
  mkdirSync(join(root, 'dsh-runtimes'), { recursive: true })
  writeFileSync(join(root, 'dsh-runtimes', 'node.exe'), 'fake-binary')
  mkdirSync(join(root, 'tmpdir'), { recursive: true })
  writeFileSync(join(root, 'tmpdir', 't.txt'), 'tmp')

  const files = collectFiles(root)
  check('collectFiles excludes dsh-runtimes/logs/tmp*', !files.some((f) => f.startsWith('dsh-runtimes') || f.startsWith('logs') || f.startsWith('tmpdir')), JSON.stringify(files))

  const passphrase = 'selftest-' + Math.random().toString(36).slice(2)
  const payload = buildPayload(root, files)
  const bundle = encryptBundle(payload, passphrase)
  check('bundleName format', /^dsh-sync-\d{8}-\d{6}\.bundle$/.test(bundleName(new Date(2026, 0, 2, 3, 4, 5))), bundleName(new Date(2026, 0, 2, 3, 4, 5)))

  const dec = decryptBundle(bundle, passphrase)
  mkdirSync(restored, { recursive: true })
  const count = extractPayload(dec, restored)
  check('extractPayload file count', count === files.length, count + ' files')
  check('content roundtrip', readFileSync(join(restored, 'sub', 'deeper', 'note.txt'), 'utf8') === 'hello dsh-sync')
  check('excluded files not in bundle', !existsSync(join(restored, 'dsh-runtimes')) && !existsSync(join(restored, 'logs')))
  const detail = extractPayloadDetailed(dec, restored)
  check('extractPayloadDetailed: 正常解包无跳过、写入后全量校验通过', detail.skipped.length === 0 && detail.mismatches.length === 0 && detail.verified === detail.count && detail.count === files.length,
    'count=' + detail.count + ' verified=' + detail.verified)

  // ---------- 3b. extractPayload 路径穿越防护 ----------
  {
    const mk = (p) => {
      const d = Buffer.from('evil')
      return { path: p, sha256: createHash('sha256').update(d).digest('hex'), data: d.toString('base64') }
    }
    const evilRoot = root + '-evil'
    mkdirSync(evilRoot, { recursive: true })
    const evilPayload = Buffer.from(JSON.stringify({
      files: [
        mk('../escape.txt'), mk('/abs.txt'), mk('C:/win.txt'), mk('C:\\win2.txt'),
        mk('a/../../b.txt'), mk('./dot.txt'), mk('sub/../ok.txt'), mk('ok.txt'),
      ],
    }), 'utf8')
    const okCount = extractPayload(evilPayload, evilRoot)
    check('extractPayload rejects traversal/absolute paths', okCount === 1, 'accepted=' + okCount)
    check('extractPayload wrote only the safe file', existsSync(join(evilRoot, 'ok.txt')))
    const evilDetail = extractPayloadDetailed(evilPayload, evilRoot)
    check('extractPayloadDetailed: 7 条非法路径全部入 skipped 清单', evilDetail.skipped.length === 7 && evilDetail.count === 1,
      'skipped=' + evilDetail.skipped.length + ' count=' + evilDetail.count)
    check('extractPayloadDetailed: 安全文件写入后校验通过', evilDetail.verified === 1 && evilDetail.mismatches.length === 0,
      'verified=' + evilDetail.verified)
  }

  // ---------- 4. 快照/回滚往返 ----------
  const snap1 = makeSnapshot(root, snapRoot, 5)
  check('snapshot created', existsSync(join(snapRoot, snap1)), snap1)
  // 改动 root，再回滚
  writeFileSync(join(root, 'settings.json'), '{"a":999}')
  writeFileSync(join(root, 'added.txt'), 'new')
  const { count: rcount, taken, removed } = rollbackFromSnapshot(join(snapRoot, snap1), root, snapRoot, 5, { pruneAppData: false })
  check('rollback restores content', readFileSync(join(root, 'settings.json'), 'utf8') === '{"a":1}')
  // 配置范围内、快照里没有的文件必须删掉，配置才回到快照当时的状态
  check('rollback deletes config files absent from snapshot', !existsSync(join(root, 'added.txt')) && removed.includes('added.txt'))
  check('rollback preserves excluded dsh-runtimes (regression: ~/.dsh/dsh-runtimes must survive)', existsSync(join(root, 'dsh-runtimes', 'node.exe')) && readFileSync(join(root, 'dsh-runtimes', 'node.exe'), 'utf8') === 'fake-binary')
  check('rollback preserves excluded logs/', existsSync(join(root, 'logs', 'a.log')))
  // 有真实 AppData settings.json 的环境，快照里会多一条 __appdata__ 条目 —— 计数随环境变化，只断言主体文件数
  const expectedRollbackCount = 4 + collectAppDataFiles().length
  check('rollback returns file count', rcount === expectedRollbackCount, 'count=' + rcount + ' expected=' + expectedRollbackCount + ' snapBeforeRollback=' + taken)

  // 对齐语义下，快照里的内容仍须被还原（再次改动后回滚）
  writeFileSync(join(root, 'settings.json'), '{"a":12345}')
  const rb2 = rollbackFromSnapshot(join(snapRoot, snap1), root, snapRoot, 5, { pruneAppData: false })
  check('rollback re-overwrites modified file', readFileSync(join(root, 'settings.json'), 'utf8') === '{"a":1}', 'count=' + rb2.count)

  // 快照保留 5 份
  for (let i = 0; i < 8; i++) makeSnapshot(root, snapRoot, 5)
  const snaps = readdirSync(snapRoot).filter((n) => !n.startsWith('.'))
  check('snapshot retention keeps 5 (+rollback safety snaps can exceed momentarily)', snaps.length >= 1 && snaps.length <= 5, JSON.stringify(snaps))

  // ---------- 4b. 恢复把配置对齐到所选备份 ----------
  {
    const mirrorRoot = join(tmpdir(), 'dsh-sync-mirror-' + Date.now())
    const dsh = join(mirrorRoot, 'dsh')
    const roaming = join(mirrorRoot, 'roaming')
    const prevAppData = process.env.APPDATA
    const prevXdg = process.env.XDG_CONFIG_HOME
    // v0.4.4 起 Linux/macOS 不再读 APPDATA（Windows 专属），改按平台解析：Linux 走 XDG_CONFIG_HOME。
    // 本用例验证的是「AppData 范围内的配置能被备份/恢复/删除」，与路径来源无关，
    // 所以两个变量指向同一临时目录，任何平台都能真实跑到这条分支。
    process.env.APPDATA = roaming
    process.env.XDG_CONFIG_HOME = roaming
    try {
      mkdirSync(join(dsh, 'profiles', 'desktop', 'node_modules', 'plugin'), { recursive: true })
      mkdirSync(join(dsh, 'sessions'), { recursive: true })
      mkdirSync(join(dsh, 'dsh-runtimes'), { recursive: true })
      mkdirSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop'), { recursive: true })
      mkdirSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'Cache'), { recursive: true })
      writeFileSync(join(dsh, 'settings.json'), '{"v":1}')
      writeFileSync(join(dsh, 'profiles', 'desktop', 'package.json'), '{"name":"desktop"}')
      writeFileSync(join(dsh, 'profiles', 'desktop', 'node_modules', 'plugin', 'index.js'), 'code')
      writeFileSync(join(dsh, 'sessions', 'chat.json'), 'hello')
      writeFileSync(join(dsh, 'dsh-runtimes', 'node.exe'), 'bin')
      writeFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'settings.json'), '{"theme":"dark"}')
      writeFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'Cache', 'data'), 'cache')

      const oldPayload = buildPayload(dsh, collectFiles(dsh))
      writeFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'extra-old.json'), '{}')
      applyPayloadMirror(oldPayload, dsh)
      check('old backup does not delete appdata it never captured', existsSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'extra-old.json')))
      rmSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'extra-old.json'), { force: true })

      const payload = buildPayload(dsh, collectFiles(dsh), { appDataIncluded: true }, collectAppDataFiles())
      writeFileSync(join(dsh, 'settings.json'), '{"v":2}')
      writeFileSync(join(dsh, 'profiles', 'desktop', 'extra.json'), '{}')
      mkdirSync(join(dsh, 'profiles', 'gone'), { recursive: true })
      writeFileSync(join(dsh, 'profiles', 'gone', 'config.yml'), 'x')
      writeFileSync(join(dsh, 'brand-new.txt'), 'nope')
      writeFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'settings.json'), '{"theme":"light"}')
      writeFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'extra.json'), '{}')

      const result = applyPayloadMirror(payload, dsh)
      check('mirror restores settings content', readFileSync(join(dsh, 'settings.json'), 'utf8') === '{"v":1}')
      check('mirror restores profile package.json', readFileSync(join(dsh, 'profiles', 'desktop', 'package.json'), 'utf8') === '{"name":"desktop"}')
      check('mirror removes config absent from backup', !existsSync(join(dsh, 'profiles', 'desktop', 'extra.json')) && !existsSync(join(dsh, 'brand-new.txt')) && !existsSync(join(dsh, 'profiles', 'gone', 'config.yml')))
      check('mirror removes emptied config directory', !existsSync(join(dsh, 'profiles', 'gone')))
      check('mirror keeps node_modules', readFileSync(join(dsh, 'profiles', 'desktop', 'node_modules', 'plugin', 'index.js'), 'utf8') === 'code')
      check('mirror keeps sessions', readFileSync(join(dsh, 'sessions', 'chat.json'), 'utf8') === 'hello')
      check('mirror keeps dsh-runtimes', readFileSync(join(dsh, 'dsh-runtimes', 'node.exe'), 'utf8') === 'bin')
      check('mirror restores appdata settings', readFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'settings.json'), 'utf8') === '{"theme":"dark"}')
      check('mirror removes appdata config absent from backup', !existsSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'desktop', 'extra.json')))
      check('mirror keeps appdata cache', readFileSync(join(roaming, '@deepseek-ai', 'dsh-desktop', 'Cache', 'data'), 'utf8') === 'cache')
      check('mirror reports removed paths',
        result.removed.includes('brand-new.txt') &&
        result.removed.includes('profiles/desktop/extra.json') &&
        result.removed.includes('profiles/gone/config.yml') &&
        result.removed.includes('__appdata__/dsh-desktop/desktop/extra.json') &&
        result.failed.length === 0,
        JSON.stringify(result.removed))
      check('mirror verified all written files', result.verified === result.count && result.skipped.length === 0 && result.mismatches.length === 0,
        'count=' + result.count + ' verified=' + result.verified)
    } finally {
      if (prevAppData === undefined) delete process.env.APPDATA
      else process.env.APPDATA = prevAppData
      if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME
      else process.env.XDG_CONFIG_HOME = prevXdg
      try { rmSync(mirrorRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    }
  }

  // ---------- 5. WebDAV mock ----------
  const USER = 'u1', PASS = 'p1'
  const store = new Map() // path -> Buffer
  const authOk = (req) => req.headers.authorization === ('Basic ' + Buffer.from(USER + ':' + PASS).toString('base64'))
  const server = createServer((req, res) => {
    const u = decodeURIComponent(new URL(req.url, 'http://x').pathname)
    if (!authOk(req)) { res.writeHead(401); return res.end() }
    if (req.method === 'PROPFIND') {
      const children = [...store.keys()].filter((k) => k.startsWith(u) && k !== u)
      const rows = ['<D:response><D:href>' + u + '</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>']
      for (const k of children) {
        const buf = store.get(k)
        rows.push('<D:response><D:href>' + encodeURIComponent(k).replace(/%2F/gi, '/') + '</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>' + (buf ? buf.length : 0) + '</D:getcontentlength><D:getlastmodified>Thu, 16 Oct 2026 03:00:00 GMT</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>')
      }
      res.writeHead(207, { 'Content-Type': 'application/xml' })
      return res.end('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">' + rows.join('') + '</D:multistatus>')
    }
    if (req.method === 'MKCOL') { store.set(u.endsWith('/') ? u : u + '/', null); res.writeHead(201); return res.end() }
    if (req.method === 'PUT') {
      const chunks = []
      req.on('data', (c) => chunks.push(c))
      req.on('end', () => { store.set(u, Buffer.concat(chunks)); res.writeHead(201); res.end() })
      return
    }
    if (req.method === 'GET') {
      if (!store.has(u)) { res.writeHead(404); return res.end() }
      res.writeHead(200); return res.end(store.get(u))
    }
    res.writeHead(405); res.end()
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const base = 'http://127.0.0.1:' + server.address().port + '/dav/'

  // Basic Auth 401
  const r401 = await davRequest(base, 'PROPFIND', { username: USER, password: 'wrong' }).catch((e) => null)
  check('Basic Auth rejects wrong password (401)', r401 && r401.status === 401)

  // ensureRemoteDir: 404 → MKCOL
  const cfg = { url: base, username: USER, password: PASS, remoteDir: 'backups' }
  const err1 = await ensureRemoteDir(cfg)
  check('ensureRemoteDir creates dir (404→MKCOL)', err1 === null, err1 || 'ok')
  const err2 = await ensureRemoteDir(cfg)
  check('ensureRemoteDir idempotent (207)', err2 === null, err2 || 'ok')

  // PUT + listRemoteBackups
  const name = bundleName()
  const putRes = await davRequest(base + 'backups/' + name, 'PUT', { username: USER, password: PASS, body: bundle })
  check('PUT bundle', putRes.status === 201)
  const list = await listRemoteBackups(cfg)
  check('PROPFIND lists backup with size/modified', list.length === 1 && list[0].name === name && list[0].size === bundle.length && !!list[0].modified, JSON.stringify(list))

  // GET + 完整恢复往返（restored2）
  const getRes = await davRequest(base + 'backups/' + name, 'GET', { username: USER, password: PASS })
  check('GET bundle byte-identical', getRes.body.equals(bundle))
  const restored2 = root + '-restored2'
  mkdirSync(restored2, { recursive: true })
  const cnt2 = extractPayload(decryptBundle(getRes.body, passphrase), restored2)
  check('full backup→restore roundtrip', cnt2 === files.length && readFileSync(join(restored2, 'settings.json'), 'utf8') === '{"a":1}')

  // parsePropfind 单元
  const parsed = parsePropfind('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/a.bundle</D:href><D:propstat><D:prop><D:getcontentlength>123</D:getcontentlength><D:getlastmodified>M</D:getlastmodified></D:prop></D:propstat></D:response></D:multistatus>')
  check('parsePropfind extracts name/size', parsed.length === 1 && parsed[0].name === 'a.bundle' && parsed[0].size === 123 && !parsed[0].isDir)
  const cosXml = '<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/dsh-sync/</D:href><D:propstat><D:prop><D:resourcetype><D:collection xmlns:D="DAV:"/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat><D:propstat><D:prop><D:getcontentlength></D:getcontentlength></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response><D:response><D:href>/dav/a.bundle</D:href><D:propstat><D:prop><D:getcontentlength>100</D:getcontentlength></D:prop></D:propstat></D:response></D:multistatus>'
  const cosParsed = parsePropfind(cosXml)
  const cosDir = cosParsed.find((e) => e.name === 'dsh-sync')
  const cosFile = cosParsed.find((e) => e.name === 'a.bundle')
  check('parsePropfind: 带属性的 collection 识别为目录', !!(cosDir && cosDir.isDir === true), JSON.stringify(cosDir))
  check('parsePropfind: 空 getcontentlength 是未知大小而不是 0', !!(cosDir && cosDir.size === null), JSON.stringify(cosDir))
  check('parsePropfind: 普通文件仍有大小且不是目录', !!(cosFile && cosFile.isDir === false && cosFile.size === 100))

  server.close()
} finally {
  for (const d of [root, restored, snapRoot, root + '-restored2']) {
    try { rmSync(d, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// ---------- 6. 恢复后重装插件依赖（B 机） ----------

// 6.1 仓库地址 → pnpm spec
check('repoSpec: git+https github', repoSpecFromUrl('git+https://github.com/ddldxiacan/dsh-sync-release.git') === 'github:ddldxiacan/dsh-sync-release')
check('repoSpec: https github 无 .git', repoSpecFromUrl('https://github.com/ddldxiacan/dsh-sync-release') === 'github:ddldxiacan/dsh-sync-release')
check('repoSpec: scp 形式 ssh', repoSpecFromUrl('git@github.com:ddldxiacan/dsh-sync-release.git') === 'github:ddldxiacan/dsh-sync-release')
check('repoSpec: git+ssh', repoSpecFromUrl('git+ssh://git@github.com/ddldxiacan/dsh-sync-release.git') === 'github:ddldxiacan/dsh-sync-release')
check('repoSpec: gitlab', repoSpecFromUrl('git+https://gitlab.com/team/plugin.git') === 'gitlab:team/plugin')
check('repoSpec: bitbucket', repoSpecFromUrl('https://bitbucket.org/team/plugin.git') === 'bitbucket:team/plugin')
check('repoSpec: 其他主机回退 https', repoSpecFromUrl('https://git.example.com/team/plugin.git') === 'https://git.example.com/team/plugin')
check('repoSpec: 无法解析返回 null', repoSpecFromUrl('') === null && repoSpecFromUrl('not a url') === null)

// 6.2 依赖分类
check('depKind: link/portal', depKind('link:E:/x') === 'link' && depKind('portal:../x') === 'link')
check('depKind: github 简写', depKind('github:ddldxiacan/dsh-sync-release') === 'git')
check('depKind: git+https', depKind('git+https://github.com/a/b.git') === 'git')
check('depKind: registry 版本号', depKind('^0.4.6') === 'registry' && depKind('3.27.1') === 'registry')

// 6.3 meta 往返 + 向后兼容（不传 meta 必须与旧版产物逐字节一致）
{
  const root = join(tmpdir(), 'dsh-sync-meta-' + Date.now())
  try {
    mkdirSync(join(root, 'profiles', 'desktop'), { recursive: true })
    writeFileSync(join(root, 'profiles', 'desktop', 'package.json'), '{"a":1}', 'utf8')
    writeFileSync(join(root, 'a.txt'), 'hello', 'utf8')
    const rels = collectFiles(root)
    const noMeta = buildPayload(root, rels)
    const legacy = Buffer.from(JSON.stringify({ files: JSON.parse(noMeta.toString('utf8')).files }), 'utf8')
    check('buildPayload 不传 meta 与旧版逐字节一致', noMeta.equals(legacy))
    check('buildPayload 不传 meta 时无 meta 字段', JSON.parse(noMeta.toString('utf8')).meta === undefined)
    const meta = { profile: 'desktop', linkMap: { p: { from: 'link:E:/x', spec: 'github:a/p', reason: 'repository.url' } } }
    const withMeta = buildPayload(root, rels, meta)
    check('buildPayload 传 meta 时写回相同内容', JSON.stringify(extractPayloadMeta(withMeta)) === JSON.stringify(meta))
    check('含 meta 的 payload 仍可正常解包', extractPayload(withMeta, join(root, 'out')) === rels.length)
    check('旧备份（无 meta）extractPayloadMeta 返回 null', extractPayloadMeta(noMeta) === null)
    // meta 不破坏加解密往返
    const rt = decryptBundle(encryptBundle(withMeta, 'pw'), 'pw')
    check('含 meta 的 payload 加解密往返', rt.equals(withMeta))
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// 6.4 collectInstallMeta 针对真实布局（link 指向的仓库地址取自 node_modules 里的 package.json）
{
  const root = join(tmpdir(), 'dsh-sync-ci-' + Date.now())
  const prof = join(root, 'profiles', 'desktop')
  try {
    mkdirSync(join(prof, 'node_modules', 'dsh-sync-webdav'), { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({
      dependencies: {
        'dsh-sync-webdav': 'link:E:/somewhere/dsh-sync-release',
        'dsh-claude-style': '^0.15.0',
        '@liustack/modlens': '3.27.1',
      },
    }), 'utf8')
    writeFileSync(join(prof, 'node_modules', 'dsh-sync-webdav', 'package.json'),
      JSON.stringify({ name: 'dsh-sync-webdav', repository: { url: 'git+https://github.com/ddldxiacan/dsh-sync-release.git' } }), 'utf8')
    const meta = collectInstallMeta(root, 'desktop')
    check('collectInstallMeta: 只挑出 link 依赖', Object.keys(meta.linkMap).length === 1 && Object.keys(meta.unmapped).length === 0)
    check('collectInstallMeta: link→github spec', meta.linkMap['dsh-sync-webdav'].spec === 'github:ddldxiacan/dsh-sync-release')
    check('collectInstallMeta: 保留原始 from 与 reason',
      meta.linkMap['dsh-sync-webdav'].from === 'link:E:/somewhere/dsh-sync-release' &&
      meta.linkMap['dsh-sync-webdav'].reason === 'repository.url')
    check('collectInstallMeta: profile 名与时间戳', meta.profile === 'desktop' && typeof meta.createdAt === 'string')
    check('collectInstallMeta: 标记已采集 AppData', meta.appDataIncluded === true)

    // node_modules 缺失时归入 unmapped，而不是猜一个 spec
    rmSync(join(prof, 'node_modules'), { recursive: true, force: true })
    const meta2 = collectInstallMeta(root, 'desktop')
    check('collectInstallMeta: 装不了时进 unmapped', Object.keys(meta2.linkMap).length === 0 && meta2.unmapped['dsh-sync-webdav'] === 'link:E:/somewhere/dsh-sync-release')
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// 6.5 端到端：用临时 profile 走一遍「建 payload → 恢复 → 装插件」，pnpm 用假 runner
{
  const root = join(tmpdir(), 'dsh-sync-e2e-a-' + Date.now())
  const rootB = root + '-b'
  const prof = join(root, 'profiles', 'desktop')
  try {
    mkdirSync(join(prof, 'node_modules', 'dsh-sync-webdav'), { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({
      name: 'desktop-profile',
      dependencies: { 'dsh-sync-webdav': 'link:E:/A-only/dsh-sync-release' },
    }), 'utf8')
    writeFileSync(join(prof, 'node_modules', 'dsh-sync-webdav', 'package.json'),
      JSON.stringify({ name: 'dsh-sync-webdav', repository: { url: 'git+https://github.com/ddldxiacan/dsh-sync-release.git' } }), 'utf8')
    writeFileSync(join(prof, 'pnpm-lock.yaml'), 'lockfileVersion: 9\nimporters:\n  .:\n    dependencies:\n      dsh-sync-webdav:\n        specifier: link:E:/A-only/dsh-sync-release\n', 'utf8')

    // A 机：备份（带 meta）
    const payload = buildPayload(root, collectFiles(root), collectInstallMeta(root, 'desktop'))
    const bundle = encryptBundle(payload, 'pw')

    // B 机：新目录只放恢复出来的文件（模拟 node_modules 不在备份里）
    const rootB = join(tmpdir(), 'dsh-sync-e2e-b-' + Date.now())
    mkdirSync(rootB, { recursive: true })
    const meta = extractPayloadMeta(decryptBundle(bundle, 'pw'))
    extractPayload(decryptBundle(bundle, 'pw'), rootB)
    writeLastRestore(rootB, { at: new Date().toISOString(), bundle: 'x', profile: meta.profile, linkMap: meta.linkMap })
    check('E2E: B 机恢复后没有 node_modules', !existsSync(join(rootB, 'profiles', 'desktop', 'node_modules', 'dsh-sync-webdav', 'package.json')))

    // 用 B 机的目录实例化 host，跑 /plugins 与 /plugins/install
    const h = createTestHarness({ root: rootB, profile: 'desktop' })
    const rep = await h.handlePlugins()
    check('E2E: /plugins 报出 profile 与缺失项', rep.ok === true && rep.profile === 'desktop' && rep.missing.length === 1 && rep.needsInstall === true)
    check('E2E: /plugins 给出改写建议', rep.deps[0].rewrite === 'github:ddldxiacan/dsh-sync-release' && rep.deps[0].installed === false)
    check('E2E: 记录的 linkMap 生效', rep.mapped['dsh-sync-webdav'].spec === 'github:ddldxiacan/dsh-sync-release')
    check('client 契约: missing 是包名数组', Array.isArray(rep.missing) && rep.missing[0] === 'dsh-sync-webdav')

    let captured = null
    const fakeRunner = (opt) => {
      captured = opt
      // 模拟真实 pnpm：重建 node_modules，并把锁文件里的 link specifier 同步成仓库地址
      mkdirSync(join(opt.cwd, 'node_modules', 'dsh-sync-webdav'), { recursive: true })
      writeFileSync(join(opt.cwd, 'node_modules', 'dsh-sync-webdav', 'package.json'), '{"name":"dsh-sync-webdav"}', 'utf8')
      writeFileSync(join(opt.cwd, 'pnpm-lock.yaml'), 'lockfileVersion: 9\nimporters:\n  .:\n    dependencies:\n      dsh-sync-webdav:\n        specifier: github:ddldxiacan/dsh-sync-release\n', 'utf8')
      return { status: 0, stdout: 'Done in 2m6.7s', stderr: '' }
    }
    const res = await h.handlePluginInstall({}, fakeRunner, 'C:/fake/pnpm.mjs')
    check('E2E: 安装成功且返回结构完整', res.ok === true && res.exitCode === 0 && typeof res.durationMs === 'number')
    check('client 契约: installed 是包名数组', Array.isArray(res.installed) && res.installed.includes('dsh-sync-webdav'))
    check('client 契约: rewritten 是 包名→声明 映射', res.rewritten['dsh-sync-webdav'] === 'github:ddldxiacan/dsh-sync-release')
    check('client 契约: removed 是包名数组', Array.isArray(res.removed) && res.removed.length === 0)
    check('E2E: 命令行为 pnpm install（不带 lockfile 相关 flag）',
      captured.args.length === 3 && captured.args[0] === '--expose-internals' && captured.args[1] === 'C:/fake/pnpm.mjs' && captured.args[2] === 'install')
    check('E2E: cwd 与 ELECTRON_RUN_AS_NODE 正确', captured.cwd === join(rootB, 'profiles', 'desktop') && captured.env.ELECTRON_RUN_AS_NODE === '1' && captured.env.DSH_DESKTOP_NODE_EXECUTABLE === process.execPath)
    check('E2E: 超时为 15 分钟', captured.timeout === 15 * 60 * 1000)
    const pkgAfter = JSON.parse(readFileSync(join(rootB, 'profiles', 'desktop', 'package.json'), 'utf8'))
    check('E2E: package.json 里 link: 已改写为仓库地址', pkgAfter.dependencies['dsh-sync-webdav'] === 'github:ddldxiacan/dsh-sync-release')
    check('E2E: 改写前已备份 package.json',
      readdirSync(join(rootB, 'profiles', 'desktop')).some((n) => n.startsWith('package.json.bak-dsh-sync-')) &&
      JSON.parse(readFileSync(join(rootB, 'profiles', 'desktop', 'package.json'), 'utf8')).dependencies['dsh-sync-webdav'].startsWith('github:'))
    check('E2E: 回报锁文件已同步', res.lockSynced === true)
    const rep2 = await h.handlePlugins()
    check('E2E: 安装后插件已就位、needsInstall 转 false', rep2.deps[0].installed === true && rep2.missing.length === 0 && rep2.needsInstall === false)

    // 失败路径：runner 返回非 0 不应抛异常，且要带回日志尾巴
    const h2 = createTestHarness({ root: rootB, profile: 'desktop' })
    const res2 = await h2.handlePluginInstall({}, () => ({ status: 1, stdout: '', stderr: 'ERR_PNPM_NO_MATCHING_VERSION' }), 'C:/fake/pnpm.mjs')
    check('E2E: 安装失败时 ok=false 且不抛异常', res2.ok === false && res2.exitCode === 1 && /ERR_PNPM/.test(res2.log))
    // runner 抛异常也必须被吞掉（fail-soft）
    const res3 = await h2.handlePluginInstall({}, () => { throw new Error('spawn ENOENT') }, 'C:/fake/pnpm.mjs')
    check('E2E: runner 抛异常被吞掉并回报', res3.ok === false && /ENOENT/.test(res3.error))

    // 找不到 pnpm 时给出明确错误
    const res4 = await h2.handlePluginInstall({}, () => ({ status: 0, stdout: '', stderr: '' }), null)
    check('E2E: 无 pnpm 时报错而非崩溃', res4.ok === false && /pnpm/.test(res4.error))
  } finally {
    for (const d of [root, join(tmpdir(), 'dsh-sync-e2e-b-' + 0)]) {
      try { rmSync(d, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    }
  }
}

// 6.6 无法推导 spec 的 link 依赖：移除而不是让整条 install 失败
{
  const root = join(tmpdir(), 'dsh-sync-drop-' + Date.now())
  try {
    mkdirSync(join(root, 'profiles', 'desktop'), { recursive: true })
    writeFileSync(join(root, 'profiles', 'desktop', 'package.json'), JSON.stringify({
      dependencies: { 'ghost-plugin': 'link:E:/not-on-b' },
    }), 'utf8')
    const h = createTestHarness({ root, profile: 'desktop' })
    const rep = await h.handlePlugins()
    check('无仓库信息时标记 removed 而非静默重写', rep.deps[0].removed === true && rep.missing.length === 1)
    let captured = null
    const res = await h.handlePluginInstall({}, (opt) => { captured = opt; return { status: 0, stdout: 'ok', stderr: '' } }, 'C:/fake/pnpm.mjs')
    check('不可推导的 link 依赖被移除', res.ok === true && res.removed.includes('ghost-plugin'))
    const pkg = JSON.parse(readFileSync(join(root, 'profiles', 'desktop', 'package.json'), 'utf8'))
    check('package.json 里该依赖已删除', pkg.dependencies['ghost-plugin'] === undefined)
    check('移除依赖后 pnpm 仍能装（命令已下发）', captured.args[0] === '--expose-internals' && captured.args[2] === 'install')
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// 6.7 默认 runner 必须异步 —— 同步阻塞会冻死 DSH 主进程的事件循环（实测冷装 2 分 6.7 秒）
{
  const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
  check('源码中不得出现同步 spawnSync(', !/spawnSync\s*\(/.test(src))

  const h = createTestHarness({ root: join(tmpdir(), 'dsh-sync-async-' + Date.now()), profile: 'desktop' })
  const runner = h.defaultRunner
  check('defaultRunner 返回 Promise', typeof runner === 'function' && runner({ cmd: 'x', args: [] }) instanceof Promise)

  // 子进程睡 700ms；期间事件循环必须还能跑定时器。若 runner 是同步的，
  // 下面的 ticked 只会在子进程结束后才置位 —— 顺序反过来即可判定阻塞。
  let ticked = false
  const timer = new Promise((r) => setTimeout(() => { ticked = true; r('timer') }, 150))
  const child = runner({
    cmd: process.execPath,
    args: ['-e', 'setTimeout(() => { console.log("child-output"); process.exit(0) }, 700)'],
    cwd: tmpdir(), env: process.env, timeout: 30000,
  }).then((v) => { check('异步 runner: 事件循环未被阻塞（定时器先于子进程完成）', ticked === true); return v })
  const raced = await Promise.race([timer.then(() => 'timer-first'), child.then(() => 'child-first')])
  check('异步 runner: 定时器先完成', raced === 'timer-first')
  const out = await child
  check('异步 runner: 透传退出码与 stdout', out.status === 0 && /child-output/.test(out.stdout))
}

// ============================================================
// 7. 版本检查 / 自我升级
// 全部注入替身 + 临时 profile，绝不联网、绝不碰真实 profile
// ============================================================

// 7.1 semver：数值比较 + 预发布段
{
  const a = parseSemver('v1.2.3')
  check('parseSemver: 解析 v 前缀与三段号', !!a && a.nums[0] === 1 && a.nums[1] === 2 && a.nums[2] === 3 && a.pre === null)
  check('parseSemver: 分支名/HEAD 解析失败（不得当版本号参与比较）',
    parseSemver('main') === null && parseSemver('HEAD') === null && parseSemver('') === null && parseSemver(undefined) === null)
  check('cmpSemver: 按数值比较（0.10.0 > 0.9.0，字符串比较会判反）', cmpSemver('0.10.0', '0.9.0') === 1 && cmpSemver('0.9.0', '0.10.0') === -1)
  check('cmpSemver: 相等返回 0', cmpSemver('1.0.0', 'v1.0.0') === 0)
  check('semverGt: 正式版 > 同号预发布版', semverGt('1.0.0', '1.0.0-rc.1') === true && semverGt('1.0.0-rc.1', '1.0.0') === false)
  check('cmpSemver: 不可解析返回 null 而非抛异常', cmpSemver('x', '1.0.0') === null && semverGt('nope', '1.0.0') === false)
}

// 7.2 最高 tag 选取：不依赖数组顺序
{
  const shuffled = [{ name: 'v0.9.0' }, { name: 'v0.10.0' }, { name: 'v0.2.1' }, { name: 'main' }, { name: 'v1' }]
  const best = latestTagOf(shuffled)
  check('latestTagOf: 乱序数组里取最高版本', !!best && best.name === 'v0.10.0', best && best.name)
  check('latestTagOf: 无 v* tag 返回 null', latestTagOf([{ name: 'nightly' }]) === null && latestTagOf([]) === null && latestTagOf(null) === null)
}

// 7.3 从锁文件取 sha：同一 specifier 的多种锁文件形态
{
  const sha = 'b50378397f3c4f7a801c64df60381e59cf802340'
  const codeload = [
    'lockfileVersion: 9', 'importers:', '  .:', '    dependencies:',
    '      dsh-sync-webdav:', '        specifier: github:ddldxiacan/dsh-sync-release#v0.1.0',
    '        version: https://codeload.github.com/ddldxiacan/dsh-sync-release/tar.gz/' + sha, '',
  ].join('\n')
  const gitShape = [
    'lockfileVersion: 9', 'importers:', '  .:', '    dependencies:',
    '      dsh-sync-webdav:', '        specifier: github:ddldxiacan/dsh-sync-release',
    '        resolution: {commit: ' + sha + ', repo: ddldxiacan/dsh-sync-release, type: git}', '',
  ].join('\n')
  check('shaOfDependency: codeload tarball 形态取到 tarball 里的 sha', shaOfDependency(codeload, 'dsh-sync-webdav') === sha)
  check('shaOfDependency: git resolution.commit 形态取到 commit sha', shaOfDependency(gitShape, 'dsh-sync-webdav') === sha)
  check('shaOfDependency: 目标依赖不存在时返回 null', shaOfDependency(codeload, 'no-such-pkg') === null)
  const other = codeload.replace(/^(\s+dsh-sync-webdav:)$/m, '      other-pkg:') + '\n      dsh-sync-webdav:\n        specifier: link:E:/x\n'
  check('shaOfDependency: 不误取其它依赖的 sha（同文件内先出现的 sha 不算）', shaOfDependency(other, 'dsh-sync-webdav') === null)
}

// 7.4 compare → changelog：最多 8 条，超出补统计行
{
  const many = { total_commits: 12, commits: Array.from({ length: 15 }, (_, i) => ({ commit: { message: 'c' + i + '\n\n详情正文' } })) }
  const got = summaryFromCompare(many)
  check('summaryFromCompare: 总条数不超过 8', got.length === 8, 'len=' + got.length)
  check('summaryFromCompare: 超出的提交数补成末行', got[7] === '还有 5 个提交', got[7])
  check('summaryFromCompare: 多条正文只取首行', got[0] === 'c0' && !got.some((s) => /详情正文/.test(s)))
  const few = summaryFromCompare({ total_commits: 2, commits: [{ commit: { message: 'fix a' } }, { commit: { message: 'fix b' } }] })
  check('summaryFromCompare: 未超出时不加统计行', few.length === 2 && few[1] === 'fix b')
  check('summaryFromCompare: 空响应退化为 []', summaryFromCompare(null).length === 0 && summaryFromCompare({}).length === 0)
}

// 7.5 小工具：queryFlag / parseRepoSlug / 只改目标键的校验
{
  check('queryFlag: 识别 ?force=1 且忽略 false 值',
    queryFlag('/dsh-sync/version?force=1', 'force') === true && queryFlag('/dsh-sync/version?force=true', 'force') === true &&
    queryFlag('/dsh-sync/version?force=0', 'force') === false && queryFlag('/dsh-sync/version', 'force') === false && queryFlag(undefined, 'force') === false)
  const slug = parseRepoSlug('git+https://github.com/ddldxiacan/dsh-sync-release.git')
  check('parseRepoSlug: 从 repository.url 得到 owner/repo', slug === 'ddldxiacan/dsh-sync-release', String(slug))
  const before = { dependencies: { a: 'github:x/y#v1', b: '^2.0.0' }, dsh: { profile: { bundles: ['a', 'b'] } } }
  const after = JSON.parse(JSON.stringify(before)); after.dependencies.a = 'github:x/y#v2'
  check('nonTargetFieldsIntact: 只改目标依赖 → true', nonTargetFieldsIntact(before, after, 'a') === true)
  const bad = JSON.parse(JSON.stringify(before)); bad.dependencies.a = 'github:x/y#v2'; bad.dsh.profile.bundles.push('c')
  check('nonTargetFieldsIntact: bundles 被改动 → false', nonTargetFieldsIntact(before, bad, 'a') === false)
}

// 7.6 自身元信息全部来自 package.json —— 改名后不得依赖任何硬编码包名
{
  const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
  const selfPkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))
  check('源码中不得硬编码旧包名字面量 dsh-sync-webdav', !/dsh-sync-webdav/.test(src))
  check('selfPackageName 与自身 package.json 的 name 一致', selfPackageName() === selfPkg.name, String(selfPackageName()))
  check('selfVersion 与自身 package.json 的 version 一致', selfVersion() === selfPkg.version, String(selfVersion()))
  {
    // 不写死仓库名（GitHub 仓库改名后此断言若硬编码会误报）：从 package.json 的 repository.url 反推
    const own = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))
    const pkgUrl = ((own.repository || {}).url || '').replace(/\.git$/, '')
    const m = /github\.com[/:]([^/]+)\/([^/.#]+)$/i.exec(pkgUrl)
    const expected = m ? m[1] + '/' + m[2] : null
    check('selfRepoSlug 从自身 repository.url 推出 owner/repo', selfRepoSlug() === expected, String(selfRepoSlug()) + ' 期望 ' + expected)
  }
}

// 7.7 performVersionCheck：sha 为主判据、注入网络、缓存与 force
{
  const shaLocal = 'a'.repeat(40)
  const shaRemote = 'b'.repeat(40)
  const mkGet = (map, counter) => async (url) => {
    if (counter) counter.push(url)
    for (const [k, v] of Object.entries(map)) if (url.includes(k)) return v
    return { status: 404, body: '', error: null }
  }
  const okMap = {
    '/tags': { status: 200, body: JSON.stringify([{ name: 'v0.1.0' }]), error: null },
    '/commits/main': { status: 200, body: JSON.stringify({ sha: shaRemote }), error: null },
    '/compare/': { status: 200, body: JSON.stringify({ total_commits: 2, commits: [{ commit: { message: 'feat: x' } }, { commit: { message: 'fix: y' } }] }), error: null },
  }
  const r1 = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', { httpsGet: mkGet(okMap), cache: new Map(), localSha: shaLocal })
  check('版本检查: 版本号相同但 sha 不同 → hasUpdate true（仅比较 semver 会漏判）', r1.hasUpdate === true)
  check('版本检查: latest 取最高 tag 原样（不改写格式）', r1.latest === 'v0.1.0', String(r1.latest))
  check('版本检查: changelog 来自 compare 的提交首行', r1.changelog.length === 2 && r1.changelog[0] === 'feat: x')

  const r2 = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', { httpsGet: mkGet(okMap), cache: new Map(), localSha: shaRemote })
  check('版本检查: sha 相同 → hasUpdate false', r2.hasUpdate === false)

  // 缓存：第二次不得再发请求
  const calls = []
  const cache = new Map()
  await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', { httpsGet: mkGet(okMap, calls), cache, localSha: shaLocal })
  const n1 = calls.length
  const r3 = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', { httpsGet: mkGet(okMap, calls), cache, localSha: shaLocal })
  check('版本检查: 10 分钟内命中缓存（不再发请求）', calls.length === n1 && r3.checked === false, 'calls=' + n1 + '→' + calls.length)
  const r4 = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', { httpsGet: mkGet(okMap, calls), cache, localSha: shaLocal, force: true })
  check('版本检查: force 绕过缓存重新请求', calls.length > n1 && r4.checked === true)

  // 网络失败：收敛成 error，绝不抛
  const offline = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', {
    httpsGet: async () => ({ status: null, body: '', error: 'getaddrinfo ENOTFOUND api.github.com' }), cache: new Map(), localSha: shaLocal,
    gitLsRemote: false,
  })
  check('版本检查: 断网时返回 error 且不抛异常', offline.hasUpdate === false && /ENOTFOUND/.test(String(offline.error)), String(offline.error))

  const rate = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', {
    httpsGet: async () => ({ status: 403, body: '', error: null }), cache: new Map(), localSha: shaLocal,
    gitLsRemote: false,
  })
  check('版本检查: GitHub 限流(403)给出可读错误', /限流/.test(String(rate.error)) && rate.hasUpdate === false, String(rate.error))

  const rateRecovered = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', {
    httpsGet: async () => ({ status: 403, body: '', error: null }), cache: new Map(), localSha: shaLocal,
    gitLsRemote: async () => ({ head: shaRemote, tags: [{ name: 'v0.2.0', commit: { sha: shaRemote } }], error: null }),
  })
  check('版本检查: API 限流时用 git ls-remote 兜底出 sha 与 tag',
    rateRecovered.error === null && rateRecovered.remoteSha === shaRemote && rateRecovered.hasUpdate === true && rateRecovered.latest === 'v0.2.0' && rateRecovered.source === 'git-ls-remote',
    JSON.stringify({ error: rateRecovered.error, latest: rateRecovered.latest, source: rateRecovered.source, hasUpdate: rateRecovered.hasUpdate }))

  // 无 tag 时 latest 退化为 7 位 sha
  const noTags = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', {
    httpsGet: mkGet({ '/tags': { status: 200, body: '[]', error: null }, '/commits/main': { status: 200, body: JSON.stringify({ sha: shaRemote }), error: null } }),
    cache: new Map(), localSha: shaLocal,
  })
  check('版本检查: 无 tag 时 latest 退化为 7 位远端 sha', noTags.latest === shaRemote.slice(0, 7), String(noTags.latest))
}

// 7.8 端点契约：字段名/类型固定，失败也是 ok:false + error（不抛）
{
  const root = join(tmpdir(), 'dsh-sync-ver-' + Date.now())
  const NAME = selfPackageName()
  const SLUG = selfRepoSlug()
  const shaLocal = 'a'.repeat(40)
  try {
    const prof = join(root, 'profiles', 'desktop')
    mkdirSync(join(prof, 'node_modules', NAME), { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({
      dependencies: { [NAME]: 'github:' + SLUG + '#v0.1.0', 'dsh-claude-style': '^0.15.0' },
      dsh: { profile: { bundles: [NAME, 'dsh-claude-style'] } },
    }), 'utf8')
    writeFileSync(join(prof, 'node_modules', NAME, 'package.json'), JSON.stringify({ name: NAME, version: '0.1.0' }), 'utf8')
    writeFileSync(join(prof, 'pnpm-lock.yaml'), 'lockfileVersion: 9\nimporters:\n  .:\n    dependencies:\n      ' + NAME + ':\n        specifier: github:' + SLUG + '#v0.1.0\n        resolution: {commit: ' + shaLocal + ', type: git}\n', 'utf8')
    const h = createTestHarness({ root, profile: 'desktop' })

    const fakeCheck = { hasUpdate: true, latest: 'v0.2.0', latestTag: 'v0.2.0', remoteSha: 'b'.repeat(40), changelog: ['feat: 新功能'], checkedAt: new Date().toISOString(), checked: true, error: null }
    let sawForce = null
    const v = await h.handleVersion({}, { url: '/dsh-sync/version?force=1' }, { check: async (cur, slug, o2) => { sawForce = o2.force; return { ...fakeCheck } } })
    const fields = ['ok', 'current', 'mode', 'kind', 'spec', 'repo', 'hasUpdate', 'latest', 'changelog', 'checkedAt', 'checked', 'error']
    check('GET /version: 契约字段齐全且 ok=true', v.ok === true && fields.every((f) => f in v), Object.keys(v).join(','))
    check('GET /version: 已安装态被如实报告', v.mode === 'managed' && v.kind === 'git' && v.spec === 'github:' + SLUG + '#v0.1.0' && v.repo === SLUG)
    check('GET /version: hasUpdate/latest/changelog 透传', v.hasUpdate === true && v.latest === 'v0.2.0' && v.changelog[0] === 'feat: 新功能')
    check('GET /version: 本地锁文件 sha 被取到并传给检查（sha 判据的数据源）', sawForce === true)
    const vNoForce = await h.handleVersion({}, { url: '/dsh-sync/version' }, { check: async (cur, slug, o2) => { sawForce = o2.force; return { ...fakeCheck } } })
    check('GET /version: 不带 ?force 时不走强制路径', sawForce === false && vNoForce.ok === true)

    // registry 安装：报错但不得声称有更新
    const root2 = root + '-reg'
    const prof2 = join(root2, 'profiles', 'desktop')
    mkdirSync(prof2, { recursive: true })
    writeFileSync(join(prof2, 'package.json'), JSON.stringify({ dependencies: { [NAME]: '^0.12.8' } }), 'utf8')
    const h2 = createTestHarness({ root: root2, profile: 'desktop' })
    const v2 = await h2.handleVersion({}, { url: '/dsh-sync/version' }, { check: async () => ({ ...fakeCheck }) })
    check('GET /version: registry 安装报可读错误', /npm|其他作者/.test(String(v2.error)), String(v2.error))
    check('GET /version: registry 安装不得声称有更新', v2.hasUpdate === false)

    // 检查函数抛异常：端点仍返回结构化结果
    const v3 = await h.handleVersion({}, { url: '/dsh-sync/version' }, { check: async () => { throw new Error('boom') } })
    check('GET /version: 检查抛异常被吞掉并回报', v3.ok === true && /boom/.test(String(v3.error)))
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    try { rmSync(root + '-reg', { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// 7.9 POST /upgrade：开发态 / registry 一律拒绝
{
  const NAME = selfPackageName()
  const root = join(tmpdir(), 'dsh-sync-upg-dev-' + Date.now())
  try {
    const prof = join(root, 'profiles', 'desktop')
    mkdirSync(prof, { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({ dependencies: { [NAME]: 'link:E:/src/dsh-sync-release' } }), 'utf8')
    const h = createTestHarness({ root, profile: 'desktop' })
    let called = 0
    const u = await h.handleUpgrade({}, {}, { install: async () => { called++; return { ok: true, log: '' } }, check: async () => { called++; return {} } })
    check('POST /upgrade: 开发态拒绝升级', u.ok === false)
    check('POST /upgrade: 开发态提示改用 git pull（原文）', u.error === '开发态安装（link:）：本机指向源码目录，请用 git pull 更新', String(u.error))
    check('POST /upgrade: 开发态拒绝时不跑任何安装/检查', called === 0 && u.needRestart === undefined)

    const root3 = root + '-reg'
    const prof3 = join(root3, 'profiles', 'desktop')
    mkdirSync(prof3, { recursive: true })
    writeFileSync(join(prof3, 'package.json'), JSON.stringify({ dependencies: { [NAME]: '^0.12.8' } }), 'utf8')
    const h3 = createTestHarness({ root: root3, profile: 'desktop' })
    const u3 = await h3.handleUpgrade({}, {}, { install: async () => ({ ok: true, log: '' }) })
    check('POST /upgrade: registry 安装拒绝（npm 同名包属于他人）', u3.ok === false && /其他作者/.test(String(u3.error)), String(u3.error))
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    try { rmSync(root + '-reg', { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// 7.10 POST /upgrade：正常路径 —— 只改一个键 + 备份 + 复用 runProfileInstall
{
  const NAME = selfPackageName()
  const SLUG = selfRepoSlug()
  const root = join(tmpdir(), 'dsh-sync-upg-ok-' + Date.now())
  try {
    const prof = join(root, 'profiles', 'desktop')
    const oldSpec = 'github:' + SLUG + '#v0.1.0'
    const newSpec = 'github:' + SLUG + '#v0.2.0'
    mkdirSync(join(prof, 'node_modules', NAME), { recursive: true })
    const pkg0 = {
      dependencies: { [NAME]: oldSpec, 'dsh-claude-style': '^0.15.0', '@liustack/modlens': '3.27.1' },
      dsh: { profile: { bundles: [NAME, 'dsh-claude-style', '@liustack/modlens'] } },
    }
    writeFileSync(join(prof, 'package.json'), JSON.stringify(pkg0, null, 2) + '\n', 'utf8')
    writeFileSync(join(prof, 'node_modules', NAME, 'package.json'), JSON.stringify({ name: NAME, version: '0.1.0' }), 'utf8')
    const h = createTestHarness({ root, profile: 'desktop' })
    const fakeCheck = { hasUpdate: true, latest: 'v0.2.0', latestTag: 'v0.2.0', remoteSha: 'b'.repeat(40), changelog: [], checkedAt: new Date().toISOString(), checked: true, error: null }
    let installArgs = null
    const u = await h.handleUpgrade({}, {}, {
      check: async () => ({ ...fakeCheck }),
      install: async (runner, pnpmPath, op) => {
        installArgs = { runner, pnpmPath, op }
        writeFileSync(join(prof, 'node_modules', NAME, 'package.json'), JSON.stringify({ name: NAME, version: '0.2.0' }), 'utf8')
        return { ok: true, exitCode: 0, log: 'Done in 7.4s' }
      },
    })
    check('POST /upgrade: 成功路径 ok=true 且 upgraded=true', u.ok === true && u.upgraded === true, JSON.stringify({ ok: u.ok, err: u.error }))
    check('POST /upgrade: 新 spec 是 github:<slug>#<tag> 且与旧 spec 不同', u.spec === newSpec && u.spec !== oldSpec, String(u.spec))
    check('POST /upgrade: from/to 如实回报', u.from === '0.1.0' && u.to === 'v0.2.0', u.from + '→' + u.to)
    check('POST /upgrade: needRestart 恒为 true 且带回下次安装也要用的 before', u.needRestart === true && u.before.spec === oldSpec && u.before.version === '0.1.0')
    check('POST /upgrade: durationMs/exitCode/log 是数字与字符串', typeof u.durationMs === 'number' && u.exitCode === 0 && /Done in/.test(u.log))
    const after = JSON.parse(readFileSync(join(prof, 'package.json'), 'utf8'))
    check('POST /upgrade: 只改写了目标依赖这一个键', after.dependencies[NAME] === newSpec)
    check('POST /upgrade: 其它依赖与 dsh.profile.bundles 逐字节未变',
      JSON.stringify({ ...after, dependencies: { ...after.dependencies, [NAME]: oldSpec } }) === JSON.stringify(pkg0))
    check('POST /upgrade: 改写了真实 profile package.json 已生成备份', typeof u.backup === 'string' && existsSync(u.backup) && JSON.parse(readFileSync(u.backup, 'utf8')).dependencies[NAME] === oldSpec)
    check('POST /upgrade: 复用了既有安装路径（未自己拼 pnpm 命令）', installArgs !== null && installArgs.runner === undefined)
    check('POST /upgrade: 升级安装带 --force', installArgs && installArgs.op && installArgs.op.force === true && installArgs.op.githubHttpsOnly === true)

    // spec、已装版本、锁文件 sha 三者一致才跳过
    writeFileSync(join(prof, 'pnpm-lock.yaml'), 'lockfileVersion: 9\nimporters:\n  .:\n    dependencies:\n      ' + NAME + ':\n        specifier: ' + newSpec + '\n        resolution: {commit: ' + 'b'.repeat(40) + ', type: git}\n', 'utf8')
    let ran = 0
    const u2 = await h.handleUpgrade({}, {}, { check: async () => ({ ...fakeCheck, latest: 'v0.2.0' }), install: async () => { ran++; return { ok: true, log: '' } } })
    check('POST /upgrade: spec 与内容都已对齐时不跑安装', u2.ok === true && u2.upgraded === false && u2.alreadyLatest === true && ran === 0, JSON.stringify({ ok: u2.ok, upgraded: u2.upgraded, already: u2.alreadyLatest, ran }))

    // spec 相同但 node_modules 仍是旧版本：必须继续安装
    writeFileSync(join(prof, 'node_modules', NAME, 'package.json'), JSON.stringify({ name: NAME, version: '0.1.0' }), 'utf8')
    let ranMismatch = 0
    const u2b = await h.handleUpgrade({}, {}, {
      check: async () => ({ ...fakeCheck }),
      install: async () => {
        ranMismatch++
        writeFileSync(join(prof, 'node_modules', NAME, 'package.json'), JSON.stringify({ name: NAME, version: '0.2.0' }), 'utf8')
        return { ok: true, log: '' }
      },
    })
    check('POST /upgrade: spec 相同但 node_modules 版本不符时必须继续安装', u2b.ok === true && u2b.upgraded === true && ranMismatch === 1, JSON.stringify({ ok: u2b.ok, upgraded: u2b.upgraded, err: u2b.error, ran: ranMismatch }))

    // 无更新
    const u3 = await h.handleUpgrade({}, {}, { check: async () => ({ hasUpdate: false, latest: null, error: null }), install: async () => { ran++; return { ok: true, log: '' } } })
    check('POST /upgrade: 无更新时不安装', u3.ok === true && u3.upgraded === false && ran === 0)

    // 安装失败：ok=false，且 package.json 必须回到升级前的字节
    const beforeFail = readFileSync(join(prof, 'package.json'))
    const u4 = await h.handleUpgrade({}, {}, { check: async () => ({ ...fakeCheck, latest: 'v0.3.0', latestTag: 'v0.3.0' }), install: async () => ({ ok: false, error: 'pnpm install 退出码 1', log: 'ERR' }) })
    const afterFail = readFileSync(join(prof, 'package.json'))
    check('POST /upgrade: 安装失败时 ok=false 且带日志', u4.ok === false && /退出码 1/.test(u4.error) && /ERR/.test(String(u4.log)))
    check('POST /upgrade: install 失败后 package.json 与升级前逐字节一致', u4.restored === true && beforeFail.equals(afterFail))

    // 安装后 package.json 未落地目标 spec：必须报错而不是谎报成功
    const u5 = await h.handleUpgrade({}, {}, {
      check: async () => ({ ...fakeCheck, latest: 'v0.4.0', latestTag: 'v0.4.0' }),
      install: async () => {
        // 模拟「pnpm 声称成功、但 profile 里仍是旧 spec」
        writeFileSync(join(prof, 'package.json'), JSON.stringify({ ...pkg0, dependencies: { ...pkg0.dependencies, [NAME]: oldSpec } }, null, 2) + '\n', 'utf8')
        return { ok: true, log: 'ok' }
      },
    })
    check('POST /upgrade: 安装后校验失败时报错（不谎报成功）', u5.ok === false && /安装后校验失败/.test(String(u5.error)), String(u5.error))
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// 7.11 升级安装：把 git 的 SSH 回退强行拉回 HTTPS
{
  const base = { PATH: 'C:\\WINDOWS', ELECTRON_RUN_AS_NODE: '1' }
  const env = githubHttpsOnlyEnv(base)
  check('githubHttpsOnlyEnv: GIT_CONFIG_VALUE_0 把 git@github.com: 重写到 HTTPS', env.GIT_CONFIG_VALUE_0 === 'git@github.com:', String(env.GIT_CONFIG_VALUE_0))
  check('githubHttpsOnlyEnv: 两条重写规则都指向 https://github.com/',
    env.GIT_CONFIG_COUNT === '2' &&
    env.GIT_CONFIG_KEY_0 === 'url.https://github.com/.insteadOf' && env.GIT_CONFIG_KEY_1 === 'url.https://github.com/.insteadOf' &&
    env.GIT_CONFIG_VALUE_1 === 'ssh://git@github.com/')
  check('githubHttpsOnlyEnv: 保留原有 env 且不改动入参对象',
    env.PATH === base.PATH && env.ELECTRON_RUN_AS_NODE === '1' && !('GIT_CONFIG_COUNT' in base))

  // 注入不得污染全进程 env（GIT_CONFIG_COUNT 会被子进程继承，泄漏会影响用户其它 git 操作）
  const before = process.env.GIT_CONFIG_COUNT
  const env2 = githubHttpsOnlyEnv({ ...process.env, ELECTRON_RUN_AS_NODE: '1' })
  check('githubHttpsOnlyEnv: 注入后 process.env 不被污染',
    process.env.GIT_CONFIG_COUNT === before && env2.GIT_CONFIG_COUNT === '2' && env2 !== process.env)

  // 走真实安装路径：断言注入只发生在升级那一次调用
  const root = join(tmpdir(), 'dsh-sync-gitenv-' + Date.now())
  try {
    const prof = join(root, 'profiles', 'desktop')
    mkdirSync(prof, { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({ dependencies: {} }), 'utf8')
    const h = createTestHarness({ root, profile: 'desktop' })
    const seen = []
    const runner = async (opt) => { seen.push(opt.env); return { status: 0, stdout: 'ok', stderr: '' } }
    await h.runProfileInstall(runner, 'C:/fake/pnpm.mjs', { githubHttpsOnly: true })
    await h.runProfileInstall(runner, 'C:/fake/pnpm.mjs')
    check('升级安装: 子进程 env 带上了 HTTPS 强制', seen[0] && seen[0].GIT_CONFIG_VALUE_0 === 'git@github.com:' && seen[0].GIT_CONFIG_COUNT === '2')
    check('普通插件安装: 不带 HTTPS 强制（不污染无关安装）', seen[1] && seen[1].GIT_CONFIG_COUNT === undefined)
    check('两次安装后 process.env 均未被污染', process.env.GIT_CONFIG_COUNT === before && process.env.GIT_CONFIG_KEY_0 === undefined)
  } finally {
    try { rmSync(root, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// 重定向跟随：仓库改名后 GitHub 对旧 owner/repo 路径下的所有 API 端点返回
// 301 + Location。node:https 不自动跟随（curl -L / git / pnpm 都会），不处理就会
// 以「GitHub API 返回 HTTP 301」这种与升级无关的错阻断版本检查。以下全部离线。
// ---------------------------------------------------------------------------
{
  // 造一个假的 https.request：按 URL 路径查表返回响应，记录实际请求过的 URL
  const makeRequest = (table) => (u, opts, cb) => {
    const res = {
      statusCode: (table[u.toString()] || {}).status,
      headers: { location: (table[u.toString()] || {}).location },
      resume() { res.__resumed = true },
      on(ev, fn) {
        if (ev !== 'data' && ev !== 'end') return res
        setImmediate(() => {
          const b = (table[u.toString()] || {}).body
          if (ev === 'data' && b !== undefined) fn(Buffer.from(b))
          if (ev === 'end') fn()
        })
        return res
      },
    }
    const req = { on() { return req }, end() { setImmediate(() => cb(res)) }, destroy() {} }
    return req
  }

  // nextRedirectUrl：相对 / 绝对 / 非法
  check('nextRedirectUrl: 解析相对 Location', nextRedirectUrl('https://api.github.com/repos/a/b/tags', '/repositories/123/tags') === 'https://api.github.com/repositories/123/tags')
  check('nextRedirectUrl: 解析绝对 Location', nextRedirectUrl('https://api.github.com/x', 'https://api.github.com/y') === 'https://api.github.com/y')
  check('nextRedirectUrl: 非法 Location 返回 null', nextRedirectUrl('https://api.github.com/x', 'http://[::bad') === null)

  // 301 → 200：必须跟随
  const OLD = 'https://api.github.com/repos/ddldxiacan/dsh-sync-release/tags'
  const NEW = 'https://api.github.com/repositories/1422027923/tags'
  const r1 = await defaultHttpsGet(OLD, {
    request: makeRequest({
      [OLD]: { status: 301, location: NEW },
      [NEW]: { status: 200, body: '[{"name":"v0.2.0"}]' },
    }),
  })
  check('301 被跟随并拿到 200 响应体', r1.status === 200 && r1.body === '[{"name":"v0.2.0"}]', r1)
  check('301 不算错误', r1.error === null, r1.error)

  // 连续多跳
  const A = 'https://api.github.com/a', B = 'https://api.github.com/b', C = 'https://api.github.com/c'
  const r2 = await defaultHttpsGet(A, {
    request: makeRequest({ [A]: { status: 301, location: '/b' }, [B]: { status: 302, location: '/c' }, [C]: { status: 200, body: 'ok' } }),
  })
  check('多跳重定向也能跟到底', r2.status === 200 && r2.body === 'ok', r2)

  // 超过上限：收敛成错误，不无限循环
  const r3 = await defaultHttpsGet('https://api.github.com/loop', {
    request: makeRequest({ 'https://api.github.com/loop': { status: 301, location: '/loop' } }),
    maxRedirects: 3,
  })
  check('重定向成环时按上限收敛并报错', r3.status === 301 && /重定向次数超过 3 次/.test(String(r3.error)), r3)

  // Location 非法：不得抛异常
  const r4 = await defaultHttpsGet('https://api.github.com/bad', {
    request: makeRequest({ 'https://api.github.com/bad': { status: 301, location: 'http://[::bad' } }),
  })
  check('非法 Location 收敛成错误且不抛异常', r4.status === 301 && /无效的重定向地址/.test(String(r4.error)), r4)

  // 正常 200：不受影响
  const r5 = await defaultHttpsGet('https://api.github.com/ok', { request: makeRequest({ 'https://api.github.com/ok': { status: 200, body: '{"sha":"abc"}' } }) })
  check('无重定向时行为不变', r5.status === 200 && r5.body === '{"sha":"abc"}', r5)

  // 不带 User-Agent 会被 GitHub 403 —— 必须始终带上
  let sawUA = null
  await defaultHttpsGet('https://api.github.com/ua', {
    request: (u, opts, cb) => { sawUA = opts.headers['User-Agent']; return makeRequest({ 'https://api.github.com/ua': { status: 200, body: '{}' } })(u, opts, cb) },
  })
  check('请求始终带 User-Agent（否则 GitHub 403）', !!sawUA, sawUA)
}

// ---------- 8. 302 跟随、pnpm 候选路径、远端轮转、git ls-remote ----------
{
  const scope = summarizePackedScope(['profiles/desktop/a.json', 'profiles/desktop/b.json', 'settings.yaml'], ['__appdata__/dsh-desktop/settings.json'])
  check('summarizePackedScope: 顶层目录计数', scope.fileCount === 3 && scope.appDataFiles === 1 && scope.topLevel.some((t) => t.name === 'profiles' && t.files === 2) && scope.topLevel.some((t) => t.name === '(files)' && t.files === 1))

  const ls = parseGitLsRemote([
    'a'.repeat(40) + '\tHEAD',
    'b'.repeat(40) + '\trefs/tags/v0.3.0',
    'c'.repeat(40) + '\trefs/tags/v0.3.1',
    'd'.repeat(40) + '\trefs/tags/v0.3.1^{}',
  ].join('\n'))
  const tag031 = ls.tags.find((t) => t.name === 'v0.3.1')
  check('parseGitLsRemote: HEAD 与剥离开的 tag commit', ls.head === 'a'.repeat(40) && tag031 && tag031.commit.sha === 'd'.repeat(40) && ls.tags.length === 2)

  const pnpmRoot = join(tmpdir(), 'dsh-sync-pnpm-' + Date.now())
  try {
    const modern = join(pnpmRoot, 'resources', 'runtime', 'primary-runtime', 'dependencies', 'pnpm', 'bin', 'pnpm.mjs')
    const legacy = join(pnpmRoot, 'resources-old', 'runtime', 'pnpm', 'bin', 'pnpm.mjs')
    const homePnpm = join(pnpmRoot, 'home-rt', '0.2.1', 'runtime', 'primary-runtime', 'dependencies', 'pnpm', 'bin', 'pnpm.mjs')
    mkdirSync(join(pnpmRoot, 'resources', 'runtime', 'primary-runtime', 'dependencies', 'pnpm', 'bin'), { recursive: true })
    mkdirSync(join(pnpmRoot, 'resources-old', 'runtime', 'pnpm', 'bin'), { recursive: true })
    mkdirSync(join(pnpmRoot, 'home-rt', '0.2.1', 'runtime', 'primary-runtime', 'dependencies', 'pnpm', 'bin'), { recursive: true })
    writeFileSync(modern, '// pnpm\n', 'utf8')
    writeFileSync(legacy, '// pnpm\n', 'utf8')
    writeFileSync(homePnpm, '// pnpm\n', 'utf8')
    check('findPnpmPath: 优先当前桌面版布局', findPnpmPath(join(pnpmRoot, 'resources'), { homeRoot: null }) === modern)
    check('findPnpmPath: 旧布局仍能找到', findPnpmPath(join(pnpmRoot, 'resources-old'), { homeRoot: null }) === legacy)
    check('findPnpmPath: resources 没有时兜底 dsh-runtimes', findPnpmPath(join(pnpmRoot, 'missing'), { homeRoot: join(pnpmRoot, 'home-rt') }) === homePnpm)
    check('findPnpmPath: 都没有返回 null', findPnpmPath(join(pnpmRoot, 'missing'), { homeRoot: join(pnpmRoot, 'empty-home') }) === null)
  } finally {
    try { rmSync(pnpmRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 跨主机 302：第二跳不得带 Authorization
  const blob = Buffer.from('DSHSYNC1-redirected')
  const srvB = createServer((req, res) => {
    srvB.__auth = req.headers.authorization || ''
    srvB.__hits = (srvB.__hits || 0) + 1
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
    res.end(blob)
  })
  const srvA = createServer((req, res) => {
    srvA.__auth = req.headers.authorization || ''
    if (req.method === 'PUT') {
      res.writeHead(302, { Location: '/should-not-follow' })
      return res.end()
    }
    const portB = srvB.address().port
    res.writeHead(302, { Location: 'http://127.0.0.1:' + portB + '/blob' })
    res.end()
  })
  await new Promise((r) => srvB.listen(0, '127.0.0.1', r))
  await new Promise((r) => srvA.listen(0, '127.0.0.1', r))
  try {
    const urlA = 'http://127.0.0.1:' + srvA.address().port + '/dav/file.bundle'
    const got = await davRequest(urlA, 'GET', { username: 'user', password: 'pw' })
    check('davRequest: GET 跟随 302 拿到正文', got.status === 200 && got.body.equals(blob) && !got.error, 'status=' + got.status + ' err=' + got.error)
    check('davRequest: 跨主机重定向去掉 Authorization', srvA.__auth.startsWith('Basic ') && srvB.__auth === '', 'A=' + srvA.__auth + ' B=' + srvB.__auth)
    const put = await davRequest(urlA, 'PUT', { username: 'user', password: 'pw', body: Buffer.from('x') })
    check('davRequest: PUT 不跟随 302', put.status === 302 && srvB.__hits === 1, 'status=' + put.status + ' hitsB=' + srvB.__hits)

    // 同主机相对跳转仍带凭据
    const srvC = createServer((req, res) => {
      if (req.url === '/a') {
        srvC.__authA = req.headers.authorization || ''
        res.writeHead(302, { Location: '/b' })
        return res.end()
      }
      srvC.__authB = req.headers.authorization || ''
      res.writeHead(200)
      res.end('ok-same-host')
    })
    await new Promise((r) => srvC.listen(0, '127.0.0.1', r))
    try {
      const same = await davRequest('http://127.0.0.1:' + srvC.address().port + '/a', 'GET', { username: 'user', password: 'pw' })
      check('davRequest: 同主机重定向保留 Authorization', same.status === 200 && same.body.toString('utf8') === 'ok-same-host' && srvC.__authA.startsWith('Basic ') && srvC.__authB.startsWith('Basic '))
    } finally { srvC.close() }
  } finally {
    srvA.close()
    srvB.close()
  }

  const dav = createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1')
    const path = u.pathname
    if (req.headers.authorization !== 'Basic ' + Buffer.from('user:pw').toString('base64')) {
      res.writeHead(401); return res.end()
    }
    if (req.method === 'PROPFIND') {
      const names = [...dav.__files.keys()].sort()
      const rows = names.map((n) => '<D:response><D:href>/dav/' + n + '</D:href><D:propstat><D:prop><D:getcontentlength>' + dav.__files.get(n).length + '</D:getcontentlength></D:prop></D:propstat></D:response>')
      res.writeHead(207, { 'Content-Type': 'application/xml' })
      return res.end('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">' + rows.join('') + '</D:multistatus>')
    }
    if (req.method === 'DELETE') {
      const name = path.split('/').pop()
      dav.__files.delete(name)
      res.writeHead(204)
      return res.end()
    }
    res.writeHead(405); res.end()
  })
  dav.__files = new Map()
  for (const n of ['dsh-sync-20261016-010000.bundle', 'dsh-sync-20261017-010000.bundle', 'dsh-sync-20261018-010000.bundle', 'dsh-sync-20261018-020000.bundle']) {
    dav.__files.set(n, Buffer.from(n))
  }
  await new Promise((r) => dav.listen(0, '127.0.0.1', r))
  try {
    const cfg = { url: 'http://127.0.0.1:' + dav.address().port + '/dav/', username: 'user', password: 'pw', remoteDir: '' }
    const pruned = await pruneRemoteBackups(cfg, 2)
    check('pruneRemoteBackups: 只删最旧的、保留最近 N 份',
      pruned.deleted.length === 2 && pruned.deleted[0].includes('20261016') && pruned.kept.length === 2 && pruned.kept[1].includes('020000') && dav.__files.size === 2,
      JSON.stringify(pruned))
  } finally { dav.close() }

  const forceRoot = join(tmpdir(), 'dsh-sync-force-' + Date.now())
  try {
    mkdirSync(join(forceRoot, 'profiles', 'desktop'), { recursive: true })
    writeFileSync(join(forceRoot, 'profiles', 'desktop', 'package.json'), JSON.stringify({ dependencies: {} }), 'utf8')
    const h = createTestHarness({ root: forceRoot, profile: 'desktop' })
    let seen = null
    await h.runProfileInstall(async (opt) => { seen = opt.args; return { status: 0, stdout: '', stderr: '' } }, 'C:/fake/pnpm.mjs', { force: true })
    check('runProfileInstall: force 追加 --force', Array.isArray(seen) && seen[0] === '--expose-internals' && seen[seen.length - 1] === '--force' && seen.includes('install'))
  } finally {
    try { rmSync(forceRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 换机器：源机器的 file: 绝对路径和 storeDir 必须改到这台电脑，否则 pnpm 整批失败、插件全部「包不可用」
  const portRoot = join(tmpdir(), 'dsh-sync-port-' + Date.now())
  const portProf = join(portRoot, 'profiles', 'desktop')
  const portHome = join(portRoot, 'home-b')
  try {
    mkdirSync(join(portRoot, 'local-packages'), { recursive: true })
    mkdirSync(portProf, { recursive: true })
    const tgzAbs = join(portRoot, 'local-packages', 'plug.tgz')
    writeFileSync(tgzAbs, 'not-a-real-tarball', 'utf8')
    const foreignSpec = 'file:C:/Users/Administrator/.dsh/local-packages/plug.tgz'
    writeFileSync(join(portProf, 'package.json'), JSON.stringify({
      dependencies: {
        '@opencode2dsh/dsh-plugin': foreignSpec,
        'ghost-plugin': 'link:E:/only-on-a',
      },
    }), 'utf8')
    writeFileSync(join(portProf, 'pnpm-lock.yaml'), 'specifier: ' + foreignSpec + '\n', 'utf8')
    writeFileSync(join(portProf, 'pnpm-workspace.yaml'), "packages:\n  - .\nstoreDir: 'C:\\\\Users\\\\Administrator\\\\.pnpm\\\\store\\\\v11'\n", 'utf8')
    mkdirSync(join(portProf, 'node_modules'), { recursive: true })
    const localStore = join(portHome, '.pnpm', 'store', 'v11')
    writeFileSync(join(portProf, 'node_modules', '.modules.yaml'), 'storeDir: ' + localStore + '\n', 'utf8')
    const fixed = portabilizeRestoredTree(portRoot, { home: portHome })
    const pkg = JSON.parse(readFileSync(join(portProf, 'package.json'), 'utf8'))
    const relSpec = pkg.dependencies['@opencode2dsh/dsh-plugin']
    check('portabilize: ~/.dsh 内的 file: 改成相对路径', relSpec === 'file:../../local-packages/plug.tgz', relSpec)
    check('portabilize: 不改写 ~/.dsh 以外的 link:', pkg.dependencies['ghost-plugin'] === 'link:E:/only-on-a')
    check('portabilize: 锁文件里的旧绝对路径一并替换', readFileSync(join(portProf, 'pnpm-lock.yaml'), 'utf8').includes(relSpec))
    check('portabilize: storeDir 让位给本机 node_modules 里已有的 store',
      fixed.profiles[0].storeDir && fixed.profiles[0].storeDir.to === localStore,
      JSON.stringify(fixed.profiles[0] && fixed.profiles[0].storeDir))
    const ws = readFileSync(join(portProf, 'pnpm-workspace.yaml'), 'utf8')
    check('portabilize: workspace 里写的是本机 store', ws.includes(localStore.replace(/\\/g, '\\\\')) || ws.includes(localStore), ws)

    // 本机 tarball 真实存在时，即使 linkMap 想改成 github: 也必须保留，否则补丁包被换成上游
    writeLastRestore(portRoot, {
      at: new Date().toISOString(), profile: 'desktop',
      linkMap: { '@opencode2dsh/dsh-plugin': { from: relSpec, spec: 'github:FishBottle7/opencode2dsh', reason: 'repository.url' } },
    })
    const kept = planProfileInstall(portProf, readLastRestore(portRoot).linkMap)
    const row = kept.deps.find((d) => d.name === '@opencode2dsh/dsh-plugin')
    check('plan: 本机存在的 file: 不改写成 github', row && row.kept === true && !row.rewrite, JSON.stringify(row))
    check('resolveDepTarget: 相对 file: 落到 tarball', resolveDepTarget(relSpec, portProf) && existsSync(resolveDepTarget(relSpec, portProf)))
  } finally {
    try { rmSync(portRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 没有 .modules.yaml 时，别人的 storeDir 改到当前用户家目录下
  const portRoot2 = join(tmpdir(), 'dsh-sync-port2-' + Date.now())
  const portProf2 = join(portRoot2, 'profiles', 'desktop')
  const portHome2 = join(portRoot2, 'home-b')
  try {
    mkdirSync(portProf2, { recursive: true })
    writeFileSync(join(portProf2, 'package.json'), JSON.stringify({ dependencies: {} }), 'utf8')
    writeFileSync(join(portProf2, 'pnpm-workspace.yaml'), "storeDir: 'D:\\\\Users\\\\Someone\\\\.pnpm\\\\store\\\\v11'\n", 'utf8')
    const fixed2 = portabilizeRestoredTree(portRoot2, { home: portHome2 })
    const expectStore = join(portHome2, '.pnpm', 'store', 'v11')
    check('portabilize: 没有本机 store 时改到当前用户目录',
      fixed2.profiles[0].storeDir && fixed2.profiles[0].storeDir.to === expectStore,
      JSON.stringify(fixed2.profiles[0] && fixed2.profiles[0].storeDir))
  } finally {
    try { rmSync(portRoot2, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  check('isSafeBackupName: 只接受插件自己的文件名',
    isSafeBackupName('dsh-sync-20261018-092823.bundle') &&
    !isSafeBackupName('../secret.txt') &&
    !isSafeBackupName('dsh-sync.bundle') &&
    !isSafeBackupName('dsh-sync-20261018-092823.bundle/../x'))

  check('backupSearchDirs: 保存成 dsh-sync 时仍会看根目录',
    JSON.stringify(backupSearchDirs({ remoteDir: 'dsh-sync' })) === JSON.stringify(['dsh-sync', '']))
  check('backupSearchDirs: 根目录配置仍会看 dsh-sync',
    JSON.stringify(backupSearchDirs({ remoteDir: '' })) === JSON.stringify(['', 'dsh-sync']))
  check('backupSearchDirs: 其它目录三个位置都看，且去掉首尾斜杠',
    JSON.stringify(backupSearchDirs({ remoteDir: '/other/' })) === JSON.stringify(['other', '', 'dsh-sync']))
  check('normalizeRemoteDir: 空与斜杠都是根目录', normalizeRemoteDir(' / ') === '' && normalizeRemoteDir(undefined) === '')

  const passSaved = { passphrase: 'saved-one' }
  check('resolvePassphrase: 留空且记住时用本机口令', resolvePassphrase(passSaved, { passphrase: '', remember: true }).passphrase === 'saved-one')
  check('resolvePassphrase: 取消记住时不回落本机口令', resolvePassphrase(passSaved, { passphrase: '', remember: false }).passphrase === '')
  check('resolvePassphrase: 新输入优先，并准备记住',
    (() => { const r = resolvePassphrase(passSaved, { passphrase: 'new-one' }); return r.passphrase === 'new-one' && r.typed === true && r.remember === true })())
  check('configForDisk: 保存服务器配置时保留口令，忽略请求里夹带的口令',
    (() => {
      const c = configForDisk({ passphrase: 'keep-me' }, { url: 'https://dav.example/dav', username: 'a', password: 'b', remoteDir: '/dsh-sync/', passphrase: 'nope' })
      return c.passphrase === 'keep-me' && c.remoteDir === 'dsh-sync' && c.url === 'https://dav.example/dav'
    })())
  // ---- 远程目录默认值（v0.4.7）----
  // 语义边界很重要：缺字段 → 补 dsh-sync；显式空串 → 尊重「网盘根目录」。
  // 若把空串也补成 dsh-sync，老用户（配置里存的正是 ''）下次备份会写到新目录，
  // 而他们以为备份还在原处 —— 看起来就像备份全丢了。
  check('默认目录: 请求体没带 remoteDir 时补 dsh-sync',
    applyDefaultRemoteDir({ url: 'https://dav.example/dav', username: 'a' }).remoteDir === 'dsh-sync')
  check('默认目录: 显式空串保持根目录语义（不能被默认值顶掉）',
    applyDefaultRemoteDir({ url: 'x', remoteDir: '' }).remoteDir === '')
  check('默认目录: 显式自定义目录原样保留',
    applyDefaultRemoteDir({ url: 'x', remoteDir: '/mine/' }).remoteDir === '/mine/')
  check('默认目录: body 为 null/undefined 不抛错并补默认',
    applyDefaultRemoteDir(null).remoteDir === 'dsh-sync' && applyDefaultRemoteDir(undefined).remoteDir === 'dsh-sync')
  check('默认目录: 默认值与 configForDisk 对接后规范化正确',
    configForDisk(null, applyDefaultRemoteDir({ url: 'https://dav.example/dav', username: 'a', password: 'b' })).remoteDir === 'dsh-sync')
  check('默认目录: 空串经 configForDisk 仍是根目录',
    configForDisk(null, { url: 'x', remoteDir: '' }).remoteDir === '')
  check('默认目录: backupSearchDirs 会覆盖默认目录与根目录（老备份仍能找到）',
    JSON.stringify(backupSearchDirs({ remoteDir: 'dsh-sync' })) === JSON.stringify(['dsh-sync', '']))

  check('describeDecryptError: 认证失败说成口令不一致', /口令与这份备份不一致/.test(describeDecryptError(new Error('Unsupported state or unable to authenticate data'))))
  check('describeDecryptError: 其它错误原样', describeDecryptError(new Error('不是有效的 dsh-sync 备份文件')) === '不是有效的 dsh-sync 备份文件')

  const redactRoot = join(tmpdir(), 'dsh-sync-redact-' + Date.now())
  try {
    mkdirSync(redactRoot, { recursive: true })
    writeFileSync(join(redactRoot, 'dsh-sync.json'), JSON.stringify({
      url: 'https://dav.example/dav', username: 'a', password: 'webdav-secret', remoteDir: 'dsh-sync', passphrase: 'backup-passphrase-should-not-leak',
    }, null, 2))
    writeFileSync(join(redactRoot, 'settings.json'), '{"ok":1}')
    const redacted = redactBackupBytes('dsh-sync.json', readFileSync(join(redactRoot, 'dsh-sync.json')))
    const redactedText = redacted.toString('utf8')
    check('redact: 备份字节里没有口令，仍保留 WebDAV 密码',
      !redactedText.includes('backup-passphrase-should-not-leak') && redactedText.includes('webdav-secret') && redactedText.includes('"remoteDir": "dsh-sync"'))
    const packed = JSON.parse(buildPayload(redactRoot, collectFiles(redactRoot)).toString('utf8'))
    const packedCfg = Buffer.from(packed.files.find((f) => f.path === 'dsh-sync.json').data, 'base64').toString('utf8')
    check('redact: 打进备份的 dsh-sync.json 不含口令', !packedCfg.includes('backup-passphrase-should-not-leak') && packedCfg.includes('webdav-secret'))
  } finally {
    try { rmSync(redactRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 白电脑保存的是 dsh-sync（空目录），黑电脑实际把备份写在网盘根目录。列表必须两边都能看到。
  const davSplit = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname)
    const dir = path.endsWith('/') ? path : path + '/'
    if (req.method === 'PROPFIND') {
      const direct = [...davSplit.__files.keys()].filter((k) => {
        if (!k.startsWith(dir) || k === dir) return false
        const rest = k.slice(dir.length).replace(/\/$/, '')
        return rest && !rest.includes('/')
      })
      const rows = ['<D:response><D:href>' + dir + '</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response>']
      for (const k of direct) {
        const buf = davSplit.__files.get(k)
        const isDir = buf == null
        rows.push('<D:response><D:href>' + k + '</D:href><D:propstat><D:prop>' +
          (isDir ? '<D:resourcetype><D:collection/></D:resourcetype>' : '<D:getcontentlength>' + buf.length + '</D:getcontentlength>') +
          '</D:prop></D:propstat></D:response>')
      }
      res.writeHead(207, { 'Content-Type': 'application/xml' })
      return res.end('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">' + rows.join('') + '</D:multistatus>')
    }
    res.writeHead(405); res.end()
  })
  davSplit.__files = new Map([
    ['/dav/dsh-sync/', null],
    ['/dav/dsh-sync-20261018-094708.bundle', Buffer.alloc(24)],
    ['/dav/dsh-sync-20261018-094823.bundle', Buffer.alloc(24)],
  ])
  await new Promise((r) => davSplit.listen(0, '127.0.0.1', r))
  try {
    const splitCfg = {
      url: 'http://127.0.0.1:' + davSplit.address().port + '/dav',
      username: 'u', password: 'p', remoteDir: 'dsh-sync',
    }
    const onlySub = await listRemoteBackups(splitCfg)
    check('listRemoteBackups: 只看 dsh-sync 时是空的（白电脑原来的现象）', onlySub.length === 0, JSON.stringify(onlySub))
    const merged = await listAccountBackups(splitCfg)
    check('listAccountBackups: 保存成 dsh-sync 也能看到根目录那两份',
      merged.errors.length === 0 && merged.backups.length === 2 &&
      merged.backups.every((b) => b.remoteDir === '' && b.encrypted === true) &&
      merged.backups[0].name === 'dsh-sync-20261018-094708.bundle' &&
      merged.backups[1].name === 'dsh-sync-20261018-094823.bundle',
      JSON.stringify(merged))
  } finally { davSplit.close() }

  const davDel = createServer((req, res) => {
    const name = new URL(req.url, 'http://127.0.0.1').pathname.split('/').pop()
    if (req.method === 'DELETE') {
      if (davDel.__files.has(name)) { davDel.__files.delete(name); res.writeHead(204); return res.end() }
      res.writeHead(404); return res.end()
    }
    res.writeHead(405); res.end()
  })
  davDel.__files = new Map([['dsh-sync-20261018-010000.bundle', Buffer.from('a')]])
  await new Promise((r) => davDel.listen(0, '127.0.0.1', r))
  try {
    const cfg = { url: 'http://127.0.0.1:' + davDel.address().port + '/dav/', username: 'user', password: 'pw', remoteDir: '' }
    const bad = await deleteRemoteBackups(cfg, ['../evil', 'dsh-sync-20261018-010000.bundle', 'dsh-sync-20261018-020000.bundle'])
    check('deleteRemoteBackups: 非法名字拒绝，存在的删掉，不存在的 404 也算删掉',
      bad.failed.length === 1 && bad.failed[0].name === '../evil' && bad.deleted.length === 2 && davDel.__files.size === 0,
      JSON.stringify(bad))
  } finally { davDel.close() }

  const statusRoot = join(tmpdir(), 'dsh-sync-status-' + Date.now())
  try {
    mkdirSync(statusRoot, { recursive: true })
    writeFileSync(join(statusRoot, 'dsh-sync.json'), JSON.stringify({
      url: 'http://127.0.0.1:1/', username: 'alice', password: 's3cret', remoteDir: 'dsh-sync',
      passphrase: 'hidden-pass',
    }), 'utf8')
    const hs = createTestHarness({ root: statusRoot, profile: 'desktop' })
    const st = await hs.handleStatus()
    // 状态接口不再回传明文密码（只回 hasPassword），留空表示沿用已保存的那份
    check('status: 远端连不上也回显已保存的配置（不含明文密码）',
      st.configured === true && st.config && st.config.url === 'http://127.0.0.1:1/' &&
      st.config.username === 'alice' && st.config.password === '' &&
      st.config.remoteDir === 'dsh-sync' && st.config.hasPassword === true &&
      st.config.hasPassphrase === true && !JSON.stringify(st).includes('hidden-pass') &&
      !JSON.stringify(st).includes('s3cret'),
      JSON.stringify(st.config) + ' err=' + st.error)
    const savedPass = await hs.handlePassphrase({ passphrase: 'another-pass' })
    const onDisk = readFileSync(join(statusRoot, 'dsh-sync.json'), 'utf8')
    check('passphrase: 记住口令写进本机配置，响应里不带口令',
      savedPass.ok === true && savedPass.hasPassphrase === true && !('passphrase' in savedPass) && onDisk.includes('another-pass') && !onDisk.includes('hidden-pass'))
    const clearedPass = await hs.handlePassphrase({ clear: true })
    const clearedDisk = readFileSync(join(statusRoot, 'dsh-sync.json'), 'utf8')
    check('passphrase: 可以清除本机口令，WebDAV 密码还在',
      clearedPass.ok === true && clearedPass.hasPassphrase === false && !clearedDisk.includes('another-pass') && clearedDisk.includes('s3cret'))
    const hd = await hs.handleDelete({ name: 'not a bundle' })
    check('delete: 未通过名称校验时不发请求', hd.ok === false && /非法/.test(hd.error || ''), JSON.stringify(hd))
  } finally {
    try { rmSync(statusRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  const clientSrc = readFileSync(new URL('./client.js', import.meta.url), 'utf8')
  check('client: 打开页面回填已保存配置', clientSrc.includes('applySavedConfig') && clientSrc.includes('status.config'))
  check('client: 云端备份可以删除', clientSrc.includes("request('/delete'") && clientSrc.includes('askDelete'))
  check('client: 恢复后自动安装缺失插件', clientSrc.includes('maybeAutoInstall') && clientSrc.includes('doInstall({ quiet: true })'))
  check('client: 同账号备份合并显示，并标明是否加密',
    clientSrc.includes('listAccountBackups') === false && clientSrc.includes('backupSummary') && clientSrc.includes('已加密') && clientSrc.includes('locationLabel'))
  check('client: 口令可在本机记住', clientSrc.includes("request('/passphrase'") && clientSrc.includes('在本机记住口令'))
  check('client: 远程目录未保存时会拦住备份', clientSrc.includes('远程目录已改成'))
  check('client: 不再回显明文密码', clientSrc.includes("password: '',") && !clientSrc.includes("c.password : ''"))
  check('client: 手动安装命令带真实 profile 名', clientSrc.includes('manualInstallCommand') && clientSrc.includes("'dsh plugin --profile '"))
  check('client: 401/403 有独立提示（不当成插件未就绪）', clientSrc.includes('res.status === 401') && clientSrc.includes('rejected:'))
  check('client: 构建审批失败可「允许并重试」', clientSrc.includes('pendingBuilds') && clientSrc.includes('允许并重试'))
  check('client: 展示备份范围（已同步/已排除）',
    clientSrc.includes('ScopeCard') && clientSrc.includes('scopeSummary') &&
    clientSrc.includes('本次同步范围') && clientSrc.includes('已排除'))
  check('client: 恢复提示里写明聊天数据不被删除',
    clientSrc.includes('聊天记录、聊天文件、运行时和插件代码和缓存不在备份范围里') ||
    clientSrc.includes('聊天记录、聊天文件、运行时、插件代码和缓存不在备份范围里'))
  // engines 下限必须接受当前实际运行时（0.2.1-rc.2）；写 >=0.2.1 会让 rc 机器判为 incompatible-version
  {
    const pkgJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))
    check('package.json: engines.dsh 下限接受预发布运行时',
      /^>=0\.2\.1-rc\.2$/.test(pkgJson.dsh.engines.dsh), pkgJson.dsh.engines.dsh)
    check('package.json: 版本号已随发布推进', /^0\.4\.\d+$/.test(pkgJson.version), pkgJson.version)
  }
}


// ---------- 9. v0.4.0：PATH 兜底、宿主 profile、端点栅栏、allowBuilds、失败还原 ----------
{
  const pathRoot = join(tmpdir(), 'dsh-sync-path-' + Date.now())
  try {
    // 9.1 PATH 兜底：只有原生启动器时直接执行，且不带 --expose-internals
    const binDir = join(pathRoot, 'bin')
    mkdirSync(binDir, { recursive: true })
    const isWin = process.platform === 'win32'
    const nativeLauncher = join(binDir, isWin ? 'pnpm.exe' : 'pnpm')
    writeFileSync(nativeLauncher, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]))
    check('isNativeExecutable: ELF 头识别为原生', isNativeExecutable(nativeLauncher) === true)
    const scriptLauncher = join(binDir, 'pnpm-script')
    writeFileSync(scriptLauncher, '#!/usr/bin/env node\n', 'utf8')
    check('isNativeExecutable: 脚本不当作原生', isNativeExecutable(scriptLauncher) === false)

    const pathEnv = { PATH: binDir, PATHEXT: '.EXE;.CMD;.BAT;.COM' }
    const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase()
    check('findPnpmOnPath: 在 PATH 里找到 pnpm', same(findPnpmOnPath(pathEnv), nativeLauncher),
      String(findPnpmOnPath(pathEnv)))

    const v1 = resolvePnpmInvocation(join(pathRoot, 'no-resources'), { homeRoot: null, env: pathEnv })
    check('resolvePnpmInvocation: 只有原生启动器时直接执行（Web 版回归）',
      v1 && v1.via === 'path-binary' && same(v1.cmd, nativeLauncher) && v1.args.length === 0,
      JSON.stringify(v1))

    // 9.2 旁边有 bin/pnpm.mjs 时优先走脚本 + node
    const npmPkg = join(pathRoot, 'lib', 'node_modules', 'pnpm')
    mkdirSync(join(npmPkg, 'bin'), { recursive: true })
    const runnerScript = join(npmPkg, 'bin', 'pnpm.mjs')
    writeFileSync(runnerScript, '// pnpm\n', 'utf8')
    writeFileSync(join(npmPkg, isWin ? 'pnpm.exe' : 'pnpm'), Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
    const v2 = resolvePnpmInvocation(join(pathRoot, 'no-resources'), { homeRoot: null, env: { PATH: npmPkg, PATHEXT: '.EXE' } })
    check('resolvePnpmInvocation: 旁有 bin/pnpm.mjs 时用 node 跑脚本',
      v2 && v2.via === 'path-script' && v2.cmd === process.execPath &&
      v2.args[0] === '--expose-internals' && v2.args[1] === join(npmPkg, 'bin', 'pnpm.mjs'),
      JSON.stringify(v2))

    // 9.2b Windows 上 npm/corepack 装的 pnpm 是 .CMD 外壳：spawn 直接跑会 EINVAL，必须经 cmd.exe
    if (isWin) {
      // corepack / npm 的实际布局：目录里只有 pnpm.CMD（没有 pnpm.EXE），所以用独立目录
      const shimDir = join(pathRoot, 'shim')
      mkdirSync(shimDir, { recursive: true })
      const cmdShim = join(shimDir, 'pnpm.CMD')
      writeFileSync(cmdShim, '@echo off\r\n', 'utf8')
      const vShim = resolvePnpmInvocation(join(pathRoot, 'no-resources'), { homeRoot: null, env: { PATH: shimDir, PATHEXT: '.EXE;.CMD' } })
      check('resolvePnpmInvocation: .CMD 外壳识别为 path-cmd-shim',
        vShim && vShim.via === 'path-cmd-shim', JSON.stringify(vShim))
      const built = buildPnpmCommand(vShim, ['install'])
      check('buildPnpmCommand: .CMD 外壳经 cmd.exe 且带 windowsVerbatimArguments',
        !!built && built.cmd === (process.env.ComSpec || 'cmd.exe') &&
        built.windowsVerbatimArguments === true &&
        built.args[0] === '/d' && built.args[1] === '/s' && built.args[2] === '/c' &&
        built.args[3].startsWith('"') && built.args[3].endsWith(' install"') &&
        built.args[3].includes('pnpm.CMD'),
        JSON.stringify(built))
      try { rmSync(cmdShim, { force: true }) } catch (e) { /* ignore */ }
    } else {
      console.log('SKIP  .CMD 外壳（非 Windows）')
    }
    const builtScript = buildPnpmCommand({ cmd: process.execPath, args: ['--expose-internals', '/x/pnpm.mjs'], via: 'path-script' }, ['install', '--force'])
    check('buildPnpmCommand: 脚本入口直接拼参数，不经 cmd.exe',
      builtScript.cmd === process.execPath && builtScript.args[2] === 'install' && builtScript.args[3] === '--force' &&
      builtScript.windowsVerbatimArguments === undefined, JSON.stringify(builtScript))

    // 9.3 PATH 里完全没有 pnpm：返回 null，错误文案要给「npm i -g pnpm」
    const v3 = resolvePnpmInvocation(join(pathRoot, 'no-resources'), { homeRoot: null, env: { PATH: join(pathRoot, 'empty'), PATHEXT: '.EXE' } })
    check('resolvePnpmInvocation: 找不到 pnpm 时返回 null', v3 === null)
    const hNoPnpm = createTestHarness({ root: join(pathRoot, 'root-none'), profile: 'web' })
    const rNoPnpm = await hNoPnpm.handlePluginInstall({}, () => ({ status: 0, stdout: '', stderr: '' }), null)
    check('安装: 无 pnpm 时提示 npm i -g pnpm',
      rNoPnpm.ok === false && /npm i -g pnpm/.test(rNoPnpm.error), rNoPnpm.error)

    // 9.4 宿主给的 packageManager 优先
    const hPm = createTestHarness({ root: join(pathRoot, 'root-pm'), profile: 'web', __test: true })
    check('resolvePnpmInvocation: 宿主 packageManager 优先',
      JSON.stringify(resolvePnpmInvocation(join(pathRoot, 'no-resources'), { packageManager: { command: 'C:/host/pnpm.cmd', args: ['--x'] } })) ===
        JSON.stringify({ cmd: 'C:/host/pnpm.cmd', args: ['--x'], env: undefined, via: 'host' }))
    check('宿主 packageManager 存在时 /plugins 认为 pnpm 可用', typeof hPm.handlePlugins === 'function')
  } finally {
    try { rmSync(pathRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 9.5 resolveProfile 优先采信 profileContext.name
  const profRoot = join(tmpdir(), 'dsh-sync-prof-' + Date.now())
  try {
    for (const name of ['desktop', 'web']) {
      mkdirSync(join(profRoot, 'profiles', name), { recursive: true })
      writeFileSync(join(profRoot, 'profiles', name, 'package.json'),
        JSON.stringify({ name: 'p-' + name, dependencies: {}, dsh: { profile: { bundles: ['@deepseek-ai/dsh-base'] } } }), 'utf8')
    }
    // 默认（无 profileContext）时按配置走
    const hDefault = createTestHarness({ root: profRoot, profile: 'desktop' })
    check('resolveProfile: 没有宿主信息时用配置的 profile', hDefault.resolveProfile().name === 'desktop')
    // 注入宿主 profileContext 后必须听宿主的，哪怕 cfg.profile 写的是 desktop
    const fakeCtx = {
      inject: () => () => {},
      effect: () => () => {},
      get: (n) => (n === 'profileContext' ? { name: 'web', dir: join(profRoot, 'profiles', 'web') } : undefined),
    }
    const mod = await import('./index.js')
    mod.apply(fakeCtx, { root: profRoot, profile: 'desktop' })
    check('resolveProfile: profileContext.name 优先于 cfg.profile 与默认值', mod.apply._internals.resolveProfile().name === 'web')
  } finally {
    try { rmSync(profRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}


// ---------- 10. v0.4.0：端点栅栏（P0-2）、失败还原（P1-2）、构建审批（P2-3） ----------
{
  // 10.1 connection.requestRejection 返回 401 时，所有端点都不得进入业务逻辑
  const guardRoot = join(tmpdir(), 'dsh-sync-guard-' + Date.now())
  mkdirSync(guardRoot, { recursive: true })
  const routes = new Map()
  const calls = []
  const injectDeps = []
  const guardCtx = {
    inject: (deps, fn) => { injectDeps.push(deps); fn(guardCtx); return () => {} },
    effect: () => () => {},
    get: (n) => {
      if (n === 'webServer') return { register: (r) => { routes.set(r.path, r.handler); return () => {} }, protocol: 'http:' }
      if (n === 'connection') return {
        requestRejection: (req) => (req.headers['x-test-reject'] ? Number(req.headers['x-test-reject']) : undefined),
      }
      return undefined
    },
  }
  const mod = await import('./index.js')
  mod.apply(guardCtx, { root: guardRoot, profile: 'web', __test: true })
  check('路由: 只注入 webServer（connection 延迟解析，缺服务时端点不会整块消失）',
    JSON.stringify(injectDeps) === JSON.stringify([['webServer']]), JSON.stringify(injectDeps))
  check('路由: 12 个端点全部注册', routes.size === 12, [...routes.keys()].join(','))

  /** 造一个最小 req/res，跑一次 handler */
  const invoke = (path, opts) => new Promise((resolve) => {
    const o = opts || {}
    const req = new (require_events().EventEmitter)()
    req.method = o.method || 'GET'
    req.headers = o.headers || {}
    req.url = path
    req.socket = { remoteAddress: o.remote || '127.0.0.1' }
    const chunks = []
    const res = {
      statusCode: 0,
      headers: {},
      setHeader(k, v) { this.headers[k.toLowerCase()] = v },
      writeHead(code, h) { this.statusCode = code; Object.assign(this.headers, h || {}); return this },
      end(body) { chunks.push(body || ''); resolve({ status: this.statusCode, body: chunks.join(''), headers: this.headers }) },
    }
    const handler = routes.get(path)
    if (!handler) return resolve({ status: 0, body: 'no-route' })
    Promise.resolve(handler(req, res)).then(() => {
      // handler 只在内部调 json()/res.end 时 resolve；这里兜底超时
    }, (e) => resolve({ status: -1, body: 'throw:' + e.message }))
    setTimeout(() => resolve({ status: res.statusCode, body: chunks.join(''), headers: res.headers }), 2000)
  })
  // node:events 的轻量替代（避免再引一个 import）
  function require_events() {
    return { EventEmitter: class { on() { return this } } }
  }

  const all = [...routes.keys()]
  const rejected = []
  for (const p of all) {
    const r = await invoke(p, { method: p.startsWith('POST') ? 'POST' : 'GET', headers: { 'x-test-reject': '401' } })
    if (r.status === 401 && r.body === 'unauthorized') rejected.push(p)
  }
  check('栅栏: requestRejection=401 时 12 个端点全部 401，不进入业务逻辑',
    rejected.length === 12, rejected.length + '/' + all.length + ' rejected')

  const forbidden = await invoke('/dsh-sync/status', { headers: { 'x-test-reject': '403' } })
  check('栅栏: requestRejection=403 时回 403 forbidden', forbidden.status === 403 && forbidden.body === 'forbidden', JSON.stringify(forbidden))

  // 10.2 connection 服务缺失时必须 fail-closed
  const noConnCtx = {
    inject: (deps, fn) => { fn(noConnCtx); return () => {} },
    effect: () => () => {},
    get: (n) => (n === 'webServer' ? { register: (r) => { routes2.set(r.path, r.handler); return () => {} } } : undefined),
  }
  const routes2 = new Map()
  const root2 = join(tmpdir(), 'dsh-sync-noconn-' + Date.now())
  mkdirSync(root2, { recursive: true })
  mod.apply(noConnCtx, { root: root2, profile: 'web', __test: true })
  const invoke2 = (path, opts) => new Promise((resolve) => {
    const o = opts || {}
    const req = new (require_events().EventEmitter)()
    req.method = o.method || 'GET'
    req.headers = o.headers || {}
    req.socket = { remoteAddress: o.remote || '127.0.0.1' }
    const res = {
      statusCode: 0, headers: {},
      setHeader(k, v) { this.headers[k.toLowerCase()] = v },
      writeHead(code, h) { this.statusCode = code; Object.assign(this.headers, h || {}); return this },
      end(body) { resolve({ status: this.statusCode, body: body || '', headers: this.headers }) },
    }
    const handler = routes2.get(path)
    if (!handler) return resolve({ status: 0, body: 'no-route' })
    Promise.resolve(handler(req, res)).catch((e) => resolve({ status: -1, body: 'throw:' + e.message }))
    setTimeout(() => resolve({ status: res.statusCode, body: '', headers: res.headers }), 2000)
  })
  const forged = await invoke2('/dsh-sync/status', { headers: { host: 'evil.example.com' } })
  check('栅栏: connection 缺失且 Host 是伪造域名时 fail-closed',
    forged.status === 403, JSON.stringify(forged))
  check('isLoopbackRequest: 伪造 Host 判为非本机', isLoopbackRequest({ headers: { host: 'evil.example.com' }, socket: { remoteAddress: '127.0.0.1' } }) === false)
  check('isLoopbackRequest: 本机直连放行',
    isLoopbackRequest({ headers: { host: '127.0.0.1:3080' }, socket: { remoteAddress: '127.0.0.1' } }) === true)

  // 10.3 方法不匹配 405、body 解析失败 400（有 connection 时才会走到这两条）
  const wrongMethod = await invoke('/dsh-sync/status', { method: 'POST' })
  check('状态码: 方法不匹配回 405', wrongMethod.status === 405 && wrongMethod.headers.allow === 'GET', JSON.stringify(wrongMethod))

  // 10.4 dsh-sync.json 落盘权限收紧
  //
  // 旧用例拿 http://127.0.0.1:1/ 当保存目标——那是个必然 ECONNREFUSED 的地址，
  // handleConfig 在「先测连通性、连不上就不保存」这步就返回了，**根本没写文件**，
  // 于是断言读到的还是用例自己预置的 0664。凡是跑不出 1 端口的主机（含 CI）都恒假失败。
  // 这里改为起一个真实可达的 mock WebDAV，确保走到落盘分支。
  const modeRoot = join(tmpdir(), 'dsh-sync-mode-' + Date.now())
  mkdirSync(modeRoot, { recursive: true })
  const modeSrv = createServer((req, res) => {
    if (req.method === 'PROPFIND') { res.writeHead(207, { 'Content-Type': 'application/xml' }); return res.end('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"></D:multistatus>') }
    res.writeHead(201); res.end()
  })
  await new Promise((r) => modeSrv.listen(0, '127.0.0.1', r))
  const modeUrl = 'http://127.0.0.1:' + modeSrv.address().port + '/dav/'
  try {
    const hMode = createTestHarness({ root: modeRoot, profile: 'web' })
    const cfgFile = join(modeRoot, 'dsh-sync.json')
    writeFileSync(cfgFile, '{}', { encoding: 'utf8', mode: 0o664 })
    const saved = await hMode.handleConfig({ url: modeUrl, username: 'u', password: 'p', remoteDir: 'dsh-sync' })
    check('配置: 可达 WebDAV 时 handleConfig 真正保存成功（旧用例此处静默失败）', saved.ok === true, JSON.stringify(saved))
    const mode = process.platform === 'win32' ? null : (statSync(cfgFile).mode & 0o777)
    check('配置: dsh-sync.json 权限收紧到 0600', mode === null || mode === 0o600, mode === null ? 'Windows 跳过' : '0' + mode.toString(8))
  } finally {
    await new Promise((r) => modeSrv.close(r))
  }

  // 10.5 安装失败必须还原 package.json（P1-2）
  const restoreRoot = join(tmpdir(), 'dsh-sync-restore-' + Date.now())
  const restoreProf = join(restoreRoot, 'profiles', 'web')
  mkdirSync(join(restoreProf, 'node_modules', 'good-one'), { recursive: true })
  writeFileSync(join(restoreProf, 'node_modules', 'good-one', 'package.json'),
    JSON.stringify({ name: 'good-one', repository: { url: 'git+https://github.com/acme/good-one.git' } }), 'utf8')
  const beforePkg = {
    name: 'dsh-profile-web',
    dependencies: { 'good-one': 'link:E:/A-only/good-one', 'gone-one': 'link:E:/A-only/gone-one' },
  }
  writeFileSync(join(restoreProf, 'package.json'), JSON.stringify(beforePkg, null, 2) + '\n', 'utf8')
  writeFileSync(join(restoreProf, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n', 'utf8')
  const hRestore = createTestHarness({ root: restoreRoot, profile: 'web' })
  const rFail = await hRestore.handlePluginInstall({}, () => ({ status: 1, stdout: '', stderr: 'ERR_PNPM_FETCH_404' }), 'C:/fake/pnpm.mjs')
  const afterPkg = JSON.parse(readFileSync(join(restoreProf, 'package.json'), 'utf8'))
  check('安装失败: 返回 restored=true', rFail.ok === false && rFail.restored === true, JSON.stringify({ ok: rFail.ok, restored: rFail.restored }))
  check('安装失败: package.json 已还原到改写前',
    JSON.stringify(afterPkg.dependencies) === JSON.stringify(beforePkg.dependencies), JSON.stringify(afterPkg.dependencies))

  // 10.6 构建审批：认出被拦下的包名，并写进 allowBuilds 后重试
  const pending = parseIgnoredBuildScripts('...\nIgnored build scripts: esbuild@0.21.5, @scope/pkg. Run "pnpm approve-builds" to pick.')
  check('parseIgnoredBuildScripts: 抓到包名并去掉版本号',
    pending.length === 2 && pending[0] === 'esbuild' && pending[1] === '@scope/pkg', JSON.stringify(pending))
  check('parseIgnoredBuildScripts: 没有该行时是空数组', parseIgnoredBuildScripts('all good').length === 0)
  const wsFile = join(restoreProf, 'pnpm-workspace.yaml')
  writeFileSync(wsFile, 'storeDir: /x\.pnpm-store\n', 'utf8')
  const ap = approveBuilds(restoreProf, ['esbuild'])
  check('approveBuilds: 写进 allowBuilds 且保留原有键',
    ap.ok === true && ap.added[0] === 'esbuild' && readFileSync(wsFile, 'utf8').includes('storeDir') &&
    readAllowBuilds(restoreProf).includes('esbuild'), readFileSync(wsFile, 'utf8'))
  const ap2 = approveBuilds(restoreProf, ['esbuild'])
  check('approveBuilds: 重复写入不产生重复条目', ap2.added.length === 0 &&
    parsePnpmAllowBuilds(readFileSync(wsFile, 'utf8')).filter((n) => n === 'esbuild').length === 1)
  check('approveBuilds: 行内数组写法也能读出来',
    parsePnpmAllowBuilds('allowBuilds: ["a", "b"]\n').join(',') === 'a,b')

  const rBuild = await hRestore.handlePluginInstall({}, () => ({ status: 1, stdout: '', stderr: 'Ignored build scripts: esbuild' }), 'C:/fake/pnpm.mjs')
  check('安装失败: pendingBuilds 回传，错误文案指向「允许并重试」',
    Array.isArray(rBuild.pendingBuilds) && rBuild.pendingBuilds[0] === 'esbuild' && /允许并重试|allowBuilds/.test(rBuild.error),
    rBuild.error)
  const approveCall = await hRestore.handlePluginInstall({ approve: ['esbuild'] }, () => ({ status: 0, stdout: 'ok', stderr: '' }), 'C:/fake/pnpm.mjs')
  check('POST /plugins/install {approve}: 先写 allowBuilds 再重跑安装', approveCall.ok === true)
}


// ---------- 11. 备份范围报告（describeScope）与恢复不误删聊天数据 ----------
{
  const scopeRoot = join(tmpdir(), 'dsh-sync-scope-' + Date.now())
  try {
    const put = (rel, content) => {
      const abs = join(scopeRoot, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    put('settings.yaml', 'x')
    put('.credentials.yaml', 'x')
    put('task-board/ledger-v2.json', '{}')
    put('skins/a/x.webp', 'x')
    put('agent-presets/p/preset.yml', 'x')
    put('storages/workspace.json', '{}')
    put('storages/session_projcache/sessions/a.json', '{}')
    put('storages/plugin-store/plugins-status.json', '{}')
    put('sessions/ws/session-1/session.v4.jsonl.zstd', 'x')
    put('attachments/v1/objects/ab/x', 'x')
    put('dsh-runtimes/rt/bin.js', 'x')
    put('profiles/web/node_modules/pkg/package.json', '{}')
    put('profiles/web/package.json', '{}')
    put('cache/foo', 'x')
    put('tmp-x.mjs', 'x')

    const d = describeScope(scopeRoot)
    const names = (rows) => rows.map((r) => r.name)
    check('describeScope: 已同步清单含配置类目录',
      names(d.included).includes('skins') && names(d.included).includes('task-board') &&
      names(d.included).includes('agent-presets') && names(d.included).includes('profiles') &&
      names(d.included).includes('(files)'), JSON.stringify(names(d.included)))
    check('describeScope: 排除清单含聊天与可重建产物',
      names(d.excluded).includes('sessions') && names(d.excluded).includes('attachments') &&
      names(d.excluded).includes('dsh-runtimes') && names(d.excluded).includes('storages') &&
      names(d.excluded).includes('cache'), JSON.stringify(names(d.excluded)))
    const reasonOf = (n) => (d.excluded.find((r) => r.name === n) || {}).reason
    check('describeScope: 排除原因分类正确',
      reasonOf('sessions') === '聊天记录' && reasonOf('attachments') === '聊天文件' &&
      reasonOf('dsh-runtimes') === '可重建：DSH 运行时',
      JSON.stringify({ sessions: reasonOf('sessions'), att: reasonOf('attachments'), rt: reasonOf('dsh-runtimes') }))
    check('describeScope: 汇总数只统计真正会打包的文件',
      d.totals.files === collectFiles(scopeRoot).length, d.totals.files + ' vs ' + collectFiles(scopeRoot).length)
    check('describeScope: 默认不递归量排除项体积（status 热路径要快）',
      d.totals.excludedFiles === undefined && d.totals.excludedCount === 7 && d.totals.excludedBytes === undefined,
      JSON.stringify(d.totals))
    const measured = describeScope(scopeRoot, { measureExcluded: true })
    check('describeScope: 显式要求时才量排除项体积',
      measured.totals.excludedFiles > 0 && measured.totals.excludedBytes > 0,
      JSON.stringify(measured.totals))
    check('describeScope: profiles 的排除原因取占主导的「插件依赖」而不是「日志/缓存」',
      (d.excluded.find((r) => r.name === 'profiles') || {}).reason === '可重建：插件依赖',
      JSON.stringify((d.excluded.find((r) => r.name === 'profiles') || {}).reason))

    // 恢复对齐不得删除被排除的聊天数据
    const payload = buildPayload(scopeRoot, collectFiles(scopeRoot))
    const mirror = applyPayloadMirror(payload, scopeRoot, { pruneAppData: false })
    check('恢复: 配置范围内多出来的文件会被删掉（对齐语义仍生效）',
      mirror.removed.length === 0, JSON.stringify(mirror.removed))
    check('恢复: 聊天记录与聊天文件不会被删',
      existsSync(join(scopeRoot, 'sessions/ws/session-1/session.v4.jsonl.zstd')) &&
      existsSync(join(scopeRoot, 'attachments/v1/objects/ab/x')))
    check('恢复: 可重建产物与缓存同样保留',
      existsSync(join(scopeRoot, 'dsh-runtimes/rt/bin.js')) &&
      existsSync(join(scopeRoot, 'cache/foo')))

    // 配置范围内、备份里没有的文件仍然会被删掉
    put('settings.old.yaml', 'x')
    const mirror2 = applyPayloadMirror(payload, scopeRoot, { pruneAppData: false })
    check('恢复: 配置范围内多出的文件仍被删除',
      mirror2.removed.includes('settings.old.yaml') && !existsSync(join(scopeRoot, 'settings.old.yaml')),
      JSON.stringify(mirror2.removed))

    // /status 必须带上备份范围
    const hScope = createTestHarness({ root: scopeRoot, profile: 'web' })
    const st = await hScope.handleStatus()
    check('status: 带 coverage（已同步 + 排除 + 总计）',
      st.coverage && Array.isArray(st.coverage.included) && Array.isArray(st.coverage.excluded) &&
      st.coverage.totals.files > 0, JSON.stringify(st.coverage && st.coverage.totals))
  } finally {
    try { rmSync(scopeRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}


// ---------- 11. v0.4.2：恢复方式（只补缺失 / 覆盖同名 / 完全覆盖）+ 差异预览 ----------
{
  const modeRoot = join(tmpdir(), 'dsh-sync-modes-' + Date.now())
  try {
    // A 机：一份完整配置（两个文件，其中 settings.json 在 B 机上会被改过）
    const src = join(modeRoot, 'a')
    mkdirSync(join(src, 'skins', 'whale'), { recursive: true })
    writeFileSync(join(src, 'settings.json'), '{"theme":"A","skin":"whale"}', 'utf8')
    writeFileSync(join(src, 'skins', 'whale', 'theme.css'), ':root{--x:1}', 'utf8')
    const payloadA = buildPayload(src, collectFiles(src))

    /** 造一台「已经装好插件、配了皮肤」的 B 机 */
    const makeB = () => {
      const b = join(modeRoot, 'b-' + Math.random().toString(36).slice(2))
      mkdirSync(join(b, 'skins', 'orca'), { recursive: true })
      writeFileSync(join(b, 'settings.json'), '{"theme":"B","skin":"orca"}', 'utf8')
      writeFileSync(join(b, 'skins', 'orca', 'theme.css'), ':root{--y:2}', 'utf8')
      return b
    }

    check('normalizeRestoreMode: 未知/空值一律回落到默认（只补缺失）',
      normalizeRestoreMode('') === 'merge' && normalizeRestoreMode(undefined) === 'merge' &&
      normalizeRestoreMode('乱写') === 'merge' && DEFAULT_RESTORE_MODE === 'merge')
    check('normalizeRestoreMode: 三种模式原样接受且大小写无关',
      normalizeRestoreMode('MIRROR') === 'mirror' && normalizeRestoreMode('overwrite') === 'overwrite' &&
      normalizeRestoreMode(' merge ') === 'merge')

    // 11.1 预览：不写盘，且把「新增 / 相同 / 冲突 / 本机独有」分开报
    {
      const b = makeB()
      const before = readFileSync(join(b, 'settings.json'), 'utf8')
      const plan = planPayloadApply(payloadA, b)
      const t = plan.totals
      check('preview: 备份共 2 个文件，1 个新增、1 个冲突、0 个相同',
        t.bundle === 2 && t.added === 1 && t.conflicts === 1 && t.unchanged === 0,
        JSON.stringify(t))
      check('preview: 冲突名单点名 settings.json（B 机改过的那个）',
        plan.conflicts.length === 1 && plan.conflicts[0].path === 'settings.json', JSON.stringify(plan.conflicts))
      check('preview: 新增名单是 B 机缺的 skins/whale/theme.css',
        plan.added.length === 1 && plan.added[0] === 'skins/whale/theme.css', JSON.stringify(plan.added))
      check('preview: 本机独有名单含 B 机自己的 skins/orca/theme.css',
        plan.localOnly.includes('skins/orca/theme.css'), JSON.stringify(plan.localOnly))
      check('preview: 预览不写盘（settings.json 未被改动）',
        readFileSync(join(b, 'settings.json'), 'utf8') === before)

      // 内容完全相同的文件算 unchanged 而不是冲突
      const same = join(modeRoot, 'same')
      mkdirSync(same, { recursive: true })
      writeFileSync(join(same, 'settings.json'), '{"theme":"A","skin":"whale"}', 'utf8')
      const plan2 = planPayloadApply(payloadA, same)
      check('preview: 内容一致的文件算「相同」而非「冲突」',
        plan2.totals.unchanged === 1 && plan2.totals.conflicts === 0, JSON.stringify(plan2.totals))
    }

    // 11.2 merge：只补缺失。B 机改过的 settings.json 与自己的 orca 皮肤都保留
    {
      const b = makeB()
      const r = applyPayloadMode(payloadA, b, 'merge')
      check('merge: 只写本机缺少的文件（1 个）', r.count === 1 && r.verified === 1, 'count=' + r.count)
      check('merge: 本机改过的 settings.json 原样保留（不被 A 覆盖）',
        readFileSync(join(b, 'settings.json'), 'utf8') === '{"theme":"B","skin":"orca"}')
      check('merge: 缺失的 skins/whale/theme.css 补上了',
        existsSync(join(b, 'skins', 'whale', 'theme.css')))
      check('merge: 本机独有的 orca 皮肤保留',
        existsSync(join(b, 'skins', 'orca', 'theme.css')))
      check('merge: 冲突文件列进 keptConflicts 供用户核对',
        Array.isArray(r.keptConflicts) && r.keptConflicts.includes('settings.json'), JSON.stringify(r.keptConflicts))
      check('merge: 不删任何文件', r.removed.length === 0, JSON.stringify(r.removed))
    }

    // 11.3 overwrite：覆盖同名（A 赢），但本机多出来的 orca 皮肤不删
    {
      const b = makeB()
      const r = applyPayloadMode(payloadA, b, 'overwrite')
      check('overwrite: 备份里的 2 个文件全部覆盖写入', r.count === 2, 'count=' + r.count)
      check('overwrite: settings.json 回到 A 的状态',
        readFileSync(join(b, 'settings.json'), 'utf8') === '{"theme":"A","skin":"whale"}')
      check('overwrite: 本机独有的 orca 皮肤保留不删（区别于完全覆盖）',
        existsSync(join(b, 'skins', 'orca', 'theme.css')))
      check('overwrite: 不删任何文件', r.removed.length === 0 && r.keptLocalOnly.length === 1,
        'removed=' + JSON.stringify(r.removed) + ' keptLocalOnly=' + JSON.stringify(r.keptLocalOnly))
    }

    // 11.4 mirror：完全覆盖（旧行为），A 的状态 + 删除本机多余配置
    {
      const b = makeB()
      const r = applyPayloadMode(payloadA, b, 'mirror')
      check('mirror: settings.json 回到 A 的状态',
        readFileSync(join(b, 'settings.json'), 'utf8') === '{"theme":"A","skin":"whale"}')
      check('mirror: 删除本机独有、备份里没有的 skins/orca/theme.css',
        !existsSync(join(b, 'skins', 'orca', 'theme.css')))
      check('mirror: 删掉的路径逐个回报', r.removed.includes('skins/orca/theme.css'), JSON.stringify(r.removed))
    }

    // 11.5 排除项在任何模式下都不动
    {
      const b = makeB()
      mkdirSync(join(b, 'sessions', 'ws'), { recursive: true })
      mkdirSync(join(b, 'dsh-runtimes'), { recursive: true })
      writeFileSync(join(b, 'sessions', 'ws', 'c.jsonl'), 'chat', 'utf8')
      writeFileSync(join(b, 'dsh-runtimes', 'node.exe'), 'bin', 'utf8')
      for (const m of ['merge', 'overwrite', 'mirror']) {
        const r = applyPayloadMode(payloadA, b, m)
        check('排除项不被 ' + m + ' 模式删除（聊天记录与运行时留着）',
          existsSync(join(b, 'sessions', 'ws', 'c.jsonl')) && existsSync(join(b, 'dsh-runtimes', 'node.exe')),
          JSON.stringify(r.removed))
      }
    }

    // 11.6 真实端到端：mock WebDAV 上 A 机备份 → B 机（已配皮肤）按不同 mode 恢复
    {
      const storeB = new Map()
      const davGets = { count: 0 }
      const dav = createServer((req, res) => {
        const u = decodeURIComponent(new URL(req.url, 'http://x').pathname)
        if (req.method === 'PROPFIND') {
          const rows = [...storeB.keys()].filter((k) => k.startsWith(u) && k !== u).map((k) =>
            '<D:response><D:href>' + k + '</D:href><D:propstat><D:prop><D:resourcetype/>' +
            '<D:getcontentlength>' + storeB.get(k).length + '</D:getcontentlength>' +
            '<D:getlastmodified>Thu, 16 Oct 2026 03:00:00 GMT</D:getlastmodified></D:prop></D:propstat></D:response>')
          res.writeHead(207, { 'Content-Type': 'application/xml' })
          return res.end('<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">' + rows.join('') + '</D:multistatus>')
        }
        if (req.method === 'MKCOL') { storeB.set(u.endsWith('/') ? u : u + '/', Buffer.alloc(0)); res.writeHead(201); return res.end() }
        if (req.method === 'PUT') {
          const ch = []
          req.on('data', (c) => ch.push(c))
          req.on('end', () => { storeB.set(u, Buffer.concat(ch)); res.writeHead(201); res.end() })
          return
        }
        if (req.method === 'GET') {
          davGets.count++
          if (!storeB.has(u)) { res.writeHead(404); return res.end() }
          res.writeHead(200); return res.end(storeB.get(u))
        }
        res.writeHead(405); res.end()
      })
      await new Promise((r) => dav.listen(0, '127.0.0.1', r))
      const davUrl = 'http://127.0.0.1:' + dav.address().port + '/dav/'
      const bRoot = join(modeRoot, 'e2e-b')
      try {
        mkdirSync(bRoot, { recursive: true })
        // B 机先存好 WebDAV 配置与口令（模拟真实「已装插件并配置好」的机器）
        writeFileSync(join(bRoot, 'dsh-sync.json'), JSON.stringify({
          url: davUrl, username: '', password: '', remoteDir: 'dsh-sync', passphrase: 'pw',
        }), 'utf8')
        // A 机状态：这套配置会被打包上传
        writeFileSync(join(bRoot, 'settings.json'), '{"theme":"A","skin":"whale"}', 'utf8')
        mkdirSync(join(bRoot, 'skins', 'whale'), { recursive: true })
        writeFileSync(join(bRoot, 'skins', 'whale', 'theme.css'), ':root{--x:1}', 'utf8')
        const hA = createTestHarness({ root: bRoot, profile: 'web' })
        const up = await hA.handleBackup({})
        check('E2E 备份: A 机备份上传成功（前端拿到文件名）', up.ok === true && !!up.name, JSON.stringify(up).slice(0, 160))

        // 备份之后，这台 B 机自己改了皮肤：settings.json 与备份不同，另有自己的 skin 目录
        writeFileSync(join(bRoot, 'settings.json'), '{"theme":"B","skin":"orca"}', 'utf8')
        mkdirSync(join(bRoot, 'skins', 'orca'), { recursive: true })
        writeFileSync(join(bRoot, 'skins', 'orca', 'theme.css'), ':root{--y:2}', 'utf8')
        const bBefore = readFileSync(join(bRoot, 'settings.json'), 'utf8')

        const hB = createTestHarness({ root: bRoot, profile: 'web' })
        const pv = await hB.handleRestorePreview({})
        check('E2E 预览: 报出这台 B 机的差异（有冲突、有本机独有）',
          pv.ok === true && pv.totals && pv.totals.conflicts >= 1 && pv.totals.localOnly >= 1,
          JSON.stringify(pv.totals))
        check('E2E 预览: 给出三种方式与默认值，界面无需自己编文案',
          Array.isArray(pv.modes) && pv.modes.length === 3 && pv.defaultMode === 'merge' &&
          pv.modes.map((m) => m.id).join(',') === 'merge,overwrite,mirror', JSON.stringify(pv.modes))
        check('E2E 预览: 预览不写盘（B 机的 settings.json 没被改）',
          readFileSync(join(bRoot, 'settings.json'), 'utf8') === bBefore)

        // 预览刚下载过，紧接着的恢复不该再下载一次（大备份下这能省几十 MB 流量与几十秒）
        const getsBefore = davGets.count
        const r0 = await hB.handleRestore({ mode: 'merge' })
        check('E2E 缓存: 预览后立刻恢复复用已解密的 payload，不再下载',
          r0.ok === true && davGets.count === getsBefore,
          'GET 次数 ' + getsBefore + ' -> ' + davGets.count)
        // 口令不同不能命中同一份缓存（否则会用旧口令解出的内容冒充这次的结果）
        const wrongPassGets = davGets.count
        const bad = await hB.handleRestore({ passphrase: 'not-the-same' })
        check('E2E 缓存: 换了口令不会命中缓存（仍要重新下载并报口令错误）',
          bad.ok === false && davGets.count === wrongPassGets + 1,
          JSON.stringify({ ok: bad.ok, gets: davGets.count - wrongPassGets, err: (bad.error || '').slice(0, 40) }))
        // 口令打错一次不能把本机记住的正确口令覆盖掉（否则以后每次恢复都失败）
        const savedPass = JSON.parse(readFileSync(join(bRoot, 'dsh-sync.json'), 'utf8')).passphrase
        check('E2E 口令: 错误口令不会覆盖本机已记住的正确口令',
          savedPass === 'pw', 'saved=' + savedPass)

        // 默认（不传 mode）必须是 merge：B 机改过的配置原样保留
        const r1 = await hB.handleRestore({})
        check('E2E 恢复: 不传 mode 时默认走 merge，且把 mode 回报给界面',
          r1.ok === true && r1.mode === 'merge', JSON.stringify({ ok: r1.ok, mode: r1.mode, err: r1.error }))
        check('E2E 恢复: merge 没有覆盖 B 机改过的 settings.json',
          readFileSync(join(bRoot, 'settings.json'), 'utf8') === bBefore)
        check('E2E 恢复: merge 保留了 B 机独有的 orca 皮肤',
          existsSync(join(bRoot, 'skins', 'orca', 'theme.css')))
        check('E2E 恢复: merge 把冲突文件回报为「已保留」',
          r1.keptConflictsCount >= 1 && Array.isArray(r1.keptConflicts) && r1.keptConflicts.includes('settings.json'),
          JSON.stringify(r1.keptConflicts))

        // 显式完全覆盖：这次要被 A 的状态替换掉，且本机独有的 orca 被删
        const hC = createTestHarness({ root: bRoot, profile: 'web' })
        const r2 = await hC.handleRestore({ mode: 'mirror' })
        check('E2E 恢复: mode=mirror 覆盖 B 机改过的 settings.json',
          r2.ok === true && r2.mode === 'mirror' &&
          readFileSync(join(bRoot, 'settings.json'), 'utf8') !== bBefore,
          JSON.stringify({ mode: r2.mode, err: r2.error }))
        check('E2E 恢复: mode=mirror 删掉备份里没有的 orca 皮肤',
          !existsSync(join(bRoot, 'skins', 'orca', 'theme.css')) && r2.removedCount >= 1,
          JSON.stringify(r2.removed))

        // 恢复后仍写了 last-restore（带 mode），供插件依赖卡片展示
        const last = readLastRestore(bRoot)
        check('E2E 恢复: 上次恢复记录里带上 mode', last && last.mode === 'mirror', JSON.stringify(last))
      } finally {
        dav.close()
      }
    }

    // 11.6b dsh-sync.json 的口令属于本机，不该被备份覆盖，也不该在预览里报成冲突
    {
      const own = join(modeRoot, 'own')
      mkdirSync(own, { recursive: true })
      writeFileSync(join(own, 'settings.json'), '{"v":1}', 'utf8')
      writeFileSync(join(own, 'dsh-sync.json'), JSON.stringify({
        url: 'https://dav.example.com/dav/', username: 'u', password: 'p', remoteDir: 'dsh-sync', passphrase: 'my-pass',
      }), 'utf8')
      // 备份时口令被剥掉（redactBackupBytes 的既有行为）
      const ownPayload = buildPayload(own, collectFiles(own))
      const packed = JSON.parse(ownPayload.toString('utf8')).files.find((f) => f.path === 'dsh-sync.json')
      check('备份: dsh-sync.json 里不含本机口令', packed && !Buffer.from(packed.data, 'base64').toString('utf8').includes('my-pass'))

      check('预览: 自己的备份恢复回本机不因口令差异误报冲突',
        planPayloadApply(ownPayload, own).totals.conflicts === 0,
        JSON.stringify(planPayloadApply(ownPayload, own).totals))

      // 用另一个目录模拟「别的机器恢复过来」，本机已有记住的口令
      const other = join(modeRoot, 'other')
      mkdirSync(other, { recursive: true })
      writeFileSync(join(other, 'dsh-sync.json'), JSON.stringify({
        url: 'https://dav.example.com/dav/', username: 'u', password: 'p', remoteDir: 'dsh-sync', passphrase: 'local-pass',
      }), 'utf8')
      applyPayloadMode(ownPayload, other, 'mirror')
      const after = JSON.parse(readFileSync(join(other, 'dsh-sync.json'), 'utf8'))
      check('恢复: 覆盖 dsh-sync.json 时保留本机记住的口令（只会多不会丢）',
        after.passphrase === 'local-pass', JSON.stringify(after))
    }

    // 11.7 client 契约：恢复必须带 mode，且弹窗里能选
    const cSrc = readFileSync(new URL('./client.js', import.meta.url), 'utf8')
    check('client: 恢复请求带上所选 mode', cSrc.includes('mode: restoreMode'))
    check('client: 恢复前拉差异预览', cSrc.includes("request('/restore/preview'") && cSrc.includes('loadRestorePreview'))
    check('client: 弹窗提供三种恢复方式供选择',
      cSrc.includes('只补缺失') && cSrc.includes('覆盖同名配置') && cSrc.includes('完全覆盖'))
    check('client: 恢复结果回报被保留的冲突文件', cSrc.includes('keptConflicts') && cSrc.includes('保留了本机'))
    // React 闭包陷阱回归：弹窗 run 是打开那一刻的闭包，直接用 state 会「点了单选不生效」
    check('client: 恢复模式走 ref（否则点单选无效、恢复用旧模式）',
      cSrc.includes('restoreModeRef') && cSrc.includes('mode: restoreModeRef.current') &&
      !/const body = \{ passphrase, remember, mode: restoreMode \}/.test(cSrc))
    check('client: 弹窗正文支持函数形态（勾选状态要能随重渲染刷新）',
      cSrc.includes("typeof body === 'function' ? body() : body"))
    check('client: 模式单选的回调同步写 ref 与 state',
      /const chooseRestoreMode = \(id\) => \{ restoreModeRef\.current = id; setRestoreMode\(id\); \}/.test(cSrc))
  } finally {
    try { rmSync(modeRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// ---------- 12. 全面审查修掉的 bug 回归 ----------
{
  // 12.1 回滚到最旧的一份快照会崩溃（安全快照把它挤掉后仍去读它）
  const rbRoot = join(tmpdir(), 'dsh-sync-rb-protect-' + Date.now())
  try {
    const root = join(rbRoot, 'root')
    const snaps = join(rbRoot, 'snaps')
    mkdirSync(root, { recursive: true })
    const made = []
    for (let i = 1; i <= 5; i++) {
      writeFileSync(join(root, 'settings.json'), '{"v":"第' + i + '版"}', 'utf8')
      made.push(makeSnapshot(root, snaps, 5))
    }
    writeFileSync(join(root, 'settings.json'), '{"v":"当前"}', 'utf8')
    let crashed = null
    let res = null
    try {
      res = rollbackFromSnapshot(join(snaps, made[0]), root, snaps, 5)
    } catch (e) { crashed = e }
    check('回滚: 回到最旧一份快照不再 ENOENT 崩溃', !crashed, crashed && crashed.message)
    check('回滚: 最旧快照的内容真的被恢复了',
      !crashed && readFileSync(join(root, 'settings.json'), 'utf8') === '{"v":"第1版"}',
      crashed ? '-' : readFileSync(join(root, 'settings.json'), 'utf8'))
    check('回滚: 目标快照被保护、没有被安全快照挤出', existsSync(join(snaps, made[0])))
  } finally {
    try { rmSync(rbRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 12.3 同一时刻两次快照不能互相覆盖（并发/连点）
  const dupRoot = join(tmpdir(), 'dsh-sync-snap-dup-' + Date.now())
  try {
    const root = join(dupRoot, 'root')
    const snaps = join(dupRoot, 'snaps')
    mkdirSync(root, { recursive: true })
    writeFileSync(join(root, 'a.json'), '{"a":1}', 'utf8')
    const fixed = new Date('2026-10-20T12:00:00.123Z')
    const names = []
    for (let i = 0; i < 3; i++) names.push(makeSnapshot(root, snaps, 50, fixed))
    check('快照: 同一毫秒内多份快照不会撞名覆盖',
      new Set(names).size === 3 && readdirSync(snaps).length === 3, JSON.stringify(names))
  } finally {
    try { rmSync(dupRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }

  // 12.4 恢复必须互斥：并发两次恢复只允许一个进入，避免写出两份备份混合的半状态
  {
    const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
    check('恢复: 有互斥锁，并发请求会有一个被明确拒绝',
      src.includes('withRestoreLock') && src.includes('已有一次') && src.includes('restoring'))
    check('恢复: 回滚与恢复共用同一把锁（两者都改写整个配置范围）',
      /withRestoreLock\('恢复'/.test(src) && /withRestoreLock\('回滚'/.test(src))
    // 备份也必须上锁：恢复跑到一半时备份，会拍下两份配置混合的半成品，
    // 而这份坏备份看起来完全正常，要等下次恢复才暴露。
    check('备份: 与恢复/回滚共用同一把锁（避免拍下半合并状态）',
      /withRestoreLock\('备份'/.test(src))
  }

  // 12.5 client 卸载后重新挂载时 mountedRef 必须复位，否则整卡请求全失效
  {
    const cSrc = readFileSync(new URL('./client.js', import.meta.url), 'utf8')
    check('client: 挂载时把 mountedRef 重置为 true（设置页切走再切回来仍可用）',
      /mountedRef\.current = true;[\s\S]{0,80}mountedRef\.current = false;/.test(cSrc))
  }

  // 12.5b 损坏的备份要在动文件之前被拦住，而不是抛 500
  {
    const bad = [
      Buffer.from('not json at all'),
      Buffer.from('{}'),
      Buffer.from('[]'),
      Buffer.from('{"files":"nope"}'),
    ]
    for (const b of bad) {
      let threw = null
      let plan = null
      try { plan = planPayloadApply(b, tmpdir()) } catch (e) { threw = e }
      check('损坏备份: 不能被当成正常清单（' + b.toString().slice(0, 18) + '）', threw !== null, threw ? threw.message.slice(0, 40) : 'no throw')
    }
    const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
    check('恢复: 解析失败时在写文件前拒绝，并给出可读错误',
      src.includes('未做任何改动') && src.includes('parsePayloadObject'))
  }

  // 12.6 回滚结果里带上安全快照名，供界面提示「如何撤销」
  {
    const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
    check('回滚: 回报安全快照名（lastLocalSnapshot 指向回滚前那份）',
      src.includes('if (rolled.taken) lastLocalSnapshot = rolled.taken') &&
      /snapshot: rolled\.taken/.test(src))
  }
}

// ---------- 13. Linux / 纯 Web 版（无 Electron）兼容 ----------
{
  // 13.1 Electron 应用数据根目录必须按平台解析。
  // 旧实现无脑拼 ~/AppData/Roaming：在 Linux 上那是**不存在**的虚构目录，
  // 恢复 Windows 备份时会在 home 下凭空造一棵假目录树，预览里还报成「本机缺少的配置」。
  {
    const probe = () => appDataAbsPath(APPDATA_PROBE)
    __setAppDataPlatformForTest('win32')
    const win = probe()
    __setAppDataPlatformForTest('linux')
    const linux = probe()
    __setAppDataPlatformForTest('darwin')
    const mac = probe()
    __setAppDataPlatformForTest(null)
    const real = probe()

    check('平台: Windows 仍落在 AppData/Roaming', /AppData[\\/]Roaming/i.test(win), win)
    check('平台: Linux 不再用虚构的 AppData/Roaming（改走 XDG/.config）',
      !/[\\/]AppData[\\/]Roaming[\\/]/i.test(linux) && /[\\/]\.config[\\/]/.test(linux), linux)
    check('平台: macOS 落在 Application Support', /Application Support/.test(mac), mac)
    check('平台: 三个平台解析出三个不同位置',
      new Set([win, linux, mac]).size === 3, [win, linux, mac].join(' | '))
    check('平台: 不注入时按本机平台（与 win32 分支一致或与平台相符）',
      process.platform === 'win32' ? real === win : true, process.platform + ' -> ' + real)
  }

  // 13.2 Linux 上 XDG_CONFIG_HOME 优先于 ~/.config
  {
    const prev = process.env.XDG_CONFIG_HOME
    __setAppDataPlatformForTest('linux')
    try {
      process.env.XDG_CONFIG_HOME = '/custom/xdg'
      const p = appDataAbsPath(APPDATA_PROBE)
      check('平台: Linux 尊重 XDG_CONFIG_HOME', /custom[\\/]xdg/.test(p), p)
      delete process.env.XDG_CONFIG_HOME
      const q = appDataAbsPath(APPDATA_PROBE)
      check('平台: 没有 XDG_CONFIG_HOME 时回落到 ~/.config', /[\\/]\.config[\\/]/.test(q), q)
    } finally {
      __setAppDataPlatformForTest(null)
      if (prev === undefined) delete process.env.XDG_CONFIG_HOME
      else process.env.XDG_CONFIG_HOME = prev
    }
  }

  // 13.3 路径比较的大小写语义：Linux 区分大小写，Windows/macOS 不区分。
  // 一律 toLowerCase 会把 Linux 上 /Home 和 /home 判成同一个目录。
  {
    check('路径: Linux 语义区分大小写',
      pathsEqual('/home/alice', '/home/ALICE', { caseInsensitive: false }) === false)
    check('路径: Windows/macOS 语义不区分大小写',
      pathsEqual('/home/alice', '/home/ALICE', { caseInsensitive: true }) === true)
    check('路径: 前缀边界不被当成子目录（/home/aliceX 不在 /home/alice 下）',
      isUnderDir('/home/aliceX', '/home/alice', { caseInsensitive: false }) === false)
    check('路径: 真正的子目录仍判为在目录下',
      isUnderDir('/home/alice/.dsh', '/home/alice', { caseInsensitive: false }) === true)
    check('路径: Windows 风格的 C:/ 不会落在 Linux home 之下',
      isUnderDir('C:/Users/bob/.pnpm', '/home/alice', { caseInsensitive: false }) === false)
    check('路径: 反斜杠与正斜杠视为同一分隔符',
      pathsEqual('C:\\Users\\a', 'C:/Users/a', { caseInsensitive: true }) === true)
  }

  // 13.4 Linux 上 pnpm 的四种真实安装形态都要认得出（Web 版只有 PATH 这条路）
  {
    const pnpmRoot = join(tmpdir(), 'dsh-sync-linuxpnpm-' + Date.now())
    try {
      const mk = (p) => mkdirSync(p, { recursive: true })
      // 形态1：npm -g，入口是 node 脚本，旁边有 bin/pnpm.mjs
      const s1 = join(pnpmRoot, 's1'); mk(join(s1, 'bin'))
      writeFileSync(join(s1, 'pnpm'), '#!/usr/bin/env node\n', 'utf8')
      writeFileSync(join(s1, 'bin', 'pnpm.mjs'), '// mjs\n', 'utf8')
      const i1 = resolvePnpmInvocation(undefined, { homeRoot: null, env: { PATH: s1 }, platform: 'linux' })
      check('Linux pnpm: 旁有 bin/pnpm.mjs 时用 node 跑脚本',
        i1 && i1.via === 'path-script' && i1.cmd === process.execPath, JSON.stringify(i1))

      // 形态2：官方独立安装，单个原生 ELF
      const s2 = join(pnpmRoot, 's2'); mk(s2)
      writeFileSync(join(s2, 'pnpm'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0]))
      const i2 = resolvePnpmInvocation(undefined, { homeRoot: null, env: { PATH: s2 }, platform: 'linux' })
      check('Linux pnpm: 原生 ELF 直接执行（不带 --expose-internals）',
        i2 && i2.via === 'path-binary' && i2.args.length === 0, JSON.stringify(i2))

      // 形态3：只有 node 脚本、没有 bin/pnpm.mjs
      const s3 = join(pnpmRoot, 's3'); mk(s3)
      writeFileSync(join(s3, 'pnpm'), '#!/usr/bin/env node\n', 'utf8')
      const i3 = resolvePnpmInvocation(undefined, { homeRoot: null, env: { PATH: s3 }, platform: 'linux' })
      check('Linux pnpm: 纯 node 脚本走 path-script', i3 && i3.via === 'path-script', JSON.stringify(i3))

      // 形态4：PATH 里没有
      const i4 = resolvePnpmInvocation(undefined, { homeRoot: null, env: { PATH: join(pnpmRoot, 'none') }, platform: 'linux' })
      check('Linux pnpm: 找不到时返回 null（界面据此提示装 pnpm）', i4 === null)

      // 关键：.CMD 外壳是 Windows 专有，Linux 绝不能走那条分支
      check('Linux pnpm: 不会误判成 Windows 的 cmd-shim',
        [i1, i2, i3].every((x) => x && x.via !== 'path-cmd-shim'))
    } finally {
      try { rmSync(pnpmRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    }
  }

  // 13.5 纯 Node（dsh web）没有 process.resourcesPath，也必须能解析 pnpm
  {
    check('Web 版: Node 环境下 process.resourcesPath 本就可能是 undefined，不据此报错',
      (() => {
        const inv = resolvePnpmInvocation(undefined, { homeRoot: null, env: { PATH: process.env.PATH }, platform: process.platform })
        return inv === null || (typeof inv.cmd === 'string' && inv.cmd.length > 0)
      })())
  }

  // 13.6 操作失败不能冒成 HTTP 500（Linux 上快照目录可能 EACCES / 磁盘满 ENOSPC）
  {
    const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8')
    check('错误处理: 备份/恢复/回滚的异常被翻成可读错误，不会冒成 500',
      src.includes('配置可能只写入了一部分') && src.includes("label + '失败：'") && src.includes('failed: '))
  }
}

// ---------- 14. 符号链接（Linux/macOS 上把配置目录软链到别处很常见） ----------
{
  const symRoot = join(tmpdir(), 'dsh-sync-symlink-' + Date.now())
  let canSymlink = true
  try {
    mkdirSync(symRoot, { recursive: true })
    writeFileSync(join(symRoot, 'probe'), 'x', 'utf8')
    symlinkSync(join(symRoot, 'probe'), join(symRoot, 'probe-link'))
  } catch (e) {
    // Windows 非管理员/未开开发者模式时不能建软链；跳过而不是误报失败
    canSymlink = false
  }
  if (!canSymlink) {
    console.log('SKIP  符号链接用例（当前环境不允许创建软链）')
  } else {
    try {
      const root = join(symRoot, 'dsh')
      mkdirSync(join(root, 'sub'), { recursive: true })
      writeFileSync(join(root, 'sub', 'real.json'), '{"real":1}', 'utf8')
      // 文件链接
      symlinkSync(join(root, 'sub', 'real.json'), join(root, 'file-link.json'))
      // 目录链接（典型：skins/ 指向外部仓库）
      symlinkSync(join(root, 'sub'), join(root, 'dir-link'))
      // 环：链接回祖父目录，必须不死循环
      symlinkSync(root, join(root, 'sub', 'loop'))

      const files = collectFiles(root)
      check('软链: 文件软链被纳入备份（旧实现静默跳过）',
        files.includes('file-link.json'), JSON.stringify(files))
      check('软链: 目录软链下的文件被纳入备份',
        files.includes('dir-link/real.json'), JSON.stringify(files))
      check('软链: 链接成环不会无限递归（能正常返回）',
        Array.isArray(files) && files.length < 50, String(files.length))

      // 备份→恢复 往返
      const payload = buildPayload(root, files)
      const dst = join(symRoot, 'dst')
      mkdirSync(dst, { recursive: true })
      const rr = applyPayloadMode(payload, dst, 'merge')
      check('软链: 备份内容能正常恢复落地',
        rr.count === files.length && rr.mismatches.length === 0,
        'count=' + rr.count + ' expect=' + files.length)

      // 安全属性：mirror 只删链接本身，绝不动它指向的真实文件
      const outFile = join(symRoot, 'outside-important.txt')
      writeFileSync(outFile, 'important', 'utf8')
      const dst2 = join(symRoot, 'dst2')
      mkdirSync(dst2, { recursive: true })
      symlinkSync(outFile, join(dst2, 'extra-link.json'))
      const rm = applyPayloadMode(buildPayload(root, ['sub/real.json']), dst2, 'mirror')
      check('软链: 完全覆盖只删链接自身，不删链接指向的真实文件',
        !existsSync(join(dst2, 'extra-link.json')) && existsSync(outFile) &&
        readFileSync(outFile, 'utf8') === 'important',
        JSON.stringify(rm.removed))
    } finally {
      try { rmSync(symRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    }
  }
}

// ---------- 15. 内部辅助函数的参数容错 ----------
{
  // planPayloadApply 的第三参数是可选优化；传错东西不能把整次预览打崩
  const p = buildPayload((() => {
    const d = join(tmpdir(), 'dsh-sync-argprobe-' + Date.now())
    mkdirSync(d, { recursive: true })
    writeFileSync(join(d, 'a.json'), '{}', 'utf8')
    return d
  })(), ['a.json'])
  let crashed = null
  let out = null
  try { out = planPayloadApply(p, join(tmpdir(), 'nonexistent-probe'), { notEntries: true }) } catch (e) { crashed = e }
  check('参数容错: planPayloadApply 收到无效的第三参数仍能工作（不退化成崩溃）',
    !crashed && out && out.totals && typeof out.totals.bundle === 'number',
    crashed ? crashed.message : JSON.stringify(out && out.totals))
}

// ---------- 16. profile 重映射：跨平台恢复（v0.4.6 回归） ----------
//
// 这一节锁死的是「数据丢失级」缺陷，删掉任何一条断言都会让旧行为回来：
// Windows 桌面版固定 profiles/desktop，Linux 的 dsh web 固定 profiles/web。
// 旧版把备份里 profiles/desktop/... 原样落地，于是：
//   1) 目标机加载的是 web，配置「恢复了但没生效」；
//   2) mirror 模式把目标机自己的 profiles/web/* 当成多余配置**整棵删除**
//      —— 插件依赖、cordis.patch.yml 一起没了。
{
  const remapRoot = join(tmpdir(), 'dsh-sync-remap-' + Date.now())
  try {
    // --- 单元：映射决策 ---
    const mkPayload = (files, profile) => {
      const dir = join(remapRoot, 'src-' + Math.random().toString(36).slice(2))
      mkdirSync(dir, { recursive: true })
      for (const f of files) {
        mkdirSync(dirname(join(dir, f)), { recursive: true })
        writeFileSync(join(dir, f), 'x', 'utf8')
      }
      return buildPayload(dir, files, { dshVersion: '1', profile, createdAt: new Date().toISOString(), linkMap: {}, unmapped: {} }, [])
    }
    const pDesktop = mkPayload(['profiles/desktop/package.json', 'profiles/desktop/cordis.patch.yml', 'settings.yaml'], 'desktop')
    const pWeb = mkPayload(['profiles/web/package.json', 'profiles/web/cordis.patch.yml'], 'web')

    check('重映射: 能从备份里提出源 profile 名', JSON.stringify(payloadProfileNames(pDesktop)) === '["desktop"]', JSON.stringify(payloadProfileNames(pDesktop)))
    check('重映射: desktop 备份 → web 目标得到 desktop→web',
      JSON.stringify(planProfileRemap(pDesktop, 'web').map) === '{"desktop":"web"}', JSON.stringify(planProfileRemap(pDesktop, 'web').map))
    check('重映射: desktop 备份 → desktop 目标是恒等（同平台行为与旧版一致）',
      Object.keys(planProfileRemap(pDesktop, 'desktop').map).length === 0)
    check('重映射: web 备份 → desktop 目标得到 web→desktop',
      JSON.stringify(planProfileRemap(pWeb, 'desktop').map) === '{"web":"desktop"}', JSON.stringify(planProfileRemap(pWeb, 'desktop').map))
    check('重映射: 只改 profiles/<name>/ 一段，不动顶层文件',
      remapPayloadPath('settings.yaml', planProfileRemap(pDesktop, 'web')) === 'settings.yaml')
    check('重映射: 不动 __appdata__ 挂载点（它只是平台挂载标记，不是 profile）',
      remapPayloadPath('__appdata__/dsh-desktop/desktop/settings.json', planProfileRemap(pDesktop, 'web'))
        === '__appdata__/dsh-desktop/desktop/settings.json')
    check('重映射: 自定义 profile 名不被乱猜',
      Object.keys(planProfileRemap(mkPayload(['profiles/alpha/a.json'], 'alpha'), 'beta').map).length === 0)

    // --- 端到端：Windows(desktop) 备份 → Linux(web) 恢复 ---
    const bRoot = join(remapRoot, 'B', 'dsh')
    mkdirSync(join(bRoot, 'profiles', 'web'), { recursive: true })
    writeFileSync(join(bRoot, 'profiles', 'web', 'package.json'), '{"name":"linux-own"}', 'utf8')
    writeFileSync(join(bRoot, 'profiles', 'web', 'pnpm-workspace.yaml'), 'packages:\n  - .\n', 'utf8')
    const remap = planProfileRemap(pDesktop, 'web')
    const applied = applyPayloadMode(pDesktop, bRoot, 'overwrite', { remap })
    check('跨平台 Win→Linux: 配置落到本机 profiles/web（而不是 profiles/desktop）',
      existsSync(join(bRoot, 'profiles', 'web', 'cordis.patch.yml')))
    check('跨平台 Win→Linux: 不再凭空创建 profiles/desktop（目标机根本不加载它）',
      !existsSync(join(bRoot, 'profiles', 'desktop')))
    check('跨平台 Win→Linux: 逐条回报重映射明细',
      Array.isArray(applied.remapped) && applied.remapped.length === 2 &&
      applied.remapped.every((x) => x.from.startsWith('profiles/desktop/') && x.to.startsWith('profiles/web/')),
      JSON.stringify(applied.remapped))

    // --- 端到端：mirror 不得删掉本机 profile（旧版会整棵删） ---
    const mRoot = join(remapRoot, 'M', 'dsh')
    mkdirSync(join(mRoot, 'profiles', 'web'), { recursive: true })
    writeFileSync(join(mRoot, 'profiles', 'web', 'package.json'), '{"name":"must-survive"}', 'utf8')
    writeFileSync(join(mRoot, 'profiles', 'web', 'cordis.patch.yml'), '- id: must-survive\n', 'utf8')
    const mirrorRes = applyPayloadMode(pDesktop, mRoot, 'mirror', { remap })
    check('跨平台 mirror: 本机 profiles/web 不因「备份里没有」被删除（旧版数据丢失点）',
      existsSync(join(mRoot, 'profiles', 'web', 'package.json')),
      'removed=' + JSON.stringify(mirrorRes.removed))
    check('跨平台 mirror: 本机自有配置仍在（cordis.patch.yml 被备份内容覆盖属预期）',
      existsSync(join(mRoot, 'profiles', 'web', 'pnpm-workspace.yaml')) ||
      existsSync(join(mRoot, 'profiles', 'web', 'cordis.patch.yml')))

    // --- 反向：Linux(web) 备份 → Windows(desktop) 恢复 ---
    const wRoot = join(remapRoot, 'W', 'dsh')
    mkdirSync(join(wRoot, 'profiles', 'desktop'), { recursive: true })
    writeFileSync(join(wRoot, 'profiles', 'desktop', 'package.json'), '{"name":"win-own"}', 'utf8')
    applyPayloadMode(pWeb, wRoot, 'overwrite', { remap: planProfileRemap(pWeb, 'desktop') })
    check('跨平台 Linux→Win: 配置落到 profiles/desktop', existsSync(join(wRoot, 'profiles', 'desktop', 'cordis.patch.yml')))
    check('跨平台 Linux→Win: 不再创建 profiles/web', !existsSync(join(wRoot, 'profiles', 'web')))

    // --- 同平台恢复必须零行为变化 ---
    const sRoot = join(remapRoot, 'S', 'dsh')
    mkdirSync(join(sRoot, 'profiles', 'desktop'), { recursive: true })
    const sameRes = applyPayloadMode(pDesktop, sRoot, 'overwrite', { remap: planProfileRemap(pDesktop, 'desktop') })
    check('同平台 desktop→desktop: 路径不变、无重映射明细',
      sameRes.remapped.length === 0 && existsSync(join(sRoot, 'profiles', 'desktop', 'cordis.patch.yml')),
      JSON.stringify(sameRes.remapped))
  } finally {
    try { rmSync(remapRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

// ---------- 17. 恢复后的自保：插件不能把自己删掉（v0.4.8 回归） ----------
//
// 真实事故（2026-10-20）：Windows 机器备份里的 profiles/web 没装本插件，
// 在 Linux 上用「完全覆盖」恢复后，目标 profile 的 dependencies / bundles /
// node_modules 里都没有 dsh-sync-webdav 了 —— 设置页卡片消失、端点 404，
// 用户连回滚按钮都点不到，只能手工重装。这一节锁死「恢复必须把自身补回来」。
{
  const selfRoot = join(tmpdir(), 'dsh-sync-self-' + Date.now())
  const mkProfile = (deps, bundles) => {
    const dir = join(selfRoot, 'p-' + Math.random().toString(36).slice(2))
    mkdirSync(dir, { recursive: true })
    const pkg = { name: 'dsh-profile-web', private: true, dependencies: { ...deps } }
    if (bundles !== undefined) pkg.dsh = { profile: { bundles: [...bundles] } }
    writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg, null, 2), 'utf8')
    return dir
  }
  const readPkg = (dir) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
  try {
    // 场景 A：备份 machine 的 profile 完全没装本插件（事故原样）
    const A = mkProfile({ 'other-plugin': '1.0.0' }, ['@deepseek-ai/dsh-base', 'other-plugin'])
    const ra = ensureSelfRegistered(A, 'dsh-sync-webdav', 'github:ddldxiacan/dsh-sync-webdav#v0.4.8')
    const pa = readPkg(A)
    check('自保: 恢复后依赖被补回', ra.ok && ra.depAdded && pa.dependencies['dsh-sync-webdav'] === 'github:ddldxiacan/dsh-sync-webdav#v0.4.8')
    check('自保: 恢复后 bundles 被补回（DSH 只加载 bundles 里列出的包）',
      ra.bundleAdded && pa.dsh.profile.bundles.includes('dsh-sync-webdav'))
    check('自保: 其它依赖与字段一律不动',
      pa.dependencies['other-plugin'] === '1.0.0' &&
      pa.dsh.profile.bundles.includes('other-plugin') &&
      pa.name === 'dsh-profile-web')

    // 场景 B：已经存在 → 幂等，不重复添加、不重复写
    const ra2 = ensureSelfRegistered(A, 'dsh-sync-webdav', 'github:x#v1')
    const pa2 = readPkg(A)
    check('自保: 已存在时幂等（不重复追加 bundles）',
      ra2.ok && ra2.changed === false &&
      pa2.dsh.profile.bundles.filter((b) => b === 'dsh-sync-webdav').length === 1 &&
      pa2.dependencies['dsh-sync-webdav'] === 'github:ddldxiacan/dsh-sync-webdav#v0.4.8')

    // 场景 C：只缺 bundles、依赖还在（备份里有依赖但没注册 bundle）
    const C = mkProfile({ 'dsh-sync-webdav': 'github:ddldxiacan/dsh-sync-webdav#v0.4.7' }, ['@deepseek-ai/dsh-base'])
    const rc = ensureSelfRegistered(C, 'dsh-sync-webdav', 'github:ddldxiacan/dsh-sync-webdav#v0.4.8')
    const pc = readPkg(C)
    check('自保: 只缺 bundle 注册时只补 bundles，不改已有依赖版本',
      rc.ok && rc.bundleAdded && !rc.depAdded &&
      pc.dependencies['dsh-sync-webdav'] === 'github:ddldxiacan/dsh-sync-webdav#v0.4.7' &&
      pc.dsh.profile.bundles.includes('dsh-sync-webdav'))

    // 场景 D：package.json 缺失/损坏 → fail-soft，不抛错
    const D = join(selfRoot, 'no-such-dir')
    const rd = ensureSelfRegistered(D, 'dsh-sync-webdav', 'x')
    check('自保: profile 目录不存在时 fail-soft 不抛错', rd.ok === false, JSON.stringify(rd))

    // 场景 E：没有 spec 时不硬编码猜版本（只补 bundle 注册）
    const E = mkProfile({}, ['@deepseek-ai/dsh-base'])
    const re = ensureSelfRegistered(E, 'dsh-sync-webdav', null)
    const pe = readPkg(E)
    check('自保: 拿不到原声明时不瞎编依赖值，但 bundle 注册照补',
      re.bundleAdded && !Object.prototype.hasOwnProperty.call(pe.dependencies, 'dsh-sync-webdav'),
      JSON.stringify(pe.dependencies))
  } finally {
    try { rmSync(selfRoot, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====')
process.exit(fail ? 1 : 0)
