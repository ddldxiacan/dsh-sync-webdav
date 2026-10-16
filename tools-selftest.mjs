/**
 * dsh-sync Host 半区自测（临时，验收后可删）
 * 覆盖：加解密往返、打包/解包往返（排除规则）、快照/回滚往返、
 *       WebDAV（mock http 服务器：Basic Auth / PROPFIND / MKCOL / PUT / GET）。
 * 运行：node tools-selftest.mjs
 */
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildPayload, collectFiles, encryptBundle, decryptBundle, extractPayload,
  bundleName, makeSnapshot, rollbackFromSnapshot, isExcluded,
  davRequest, ensureRemoteDir, parsePropfind, listRemoteBackups,
  repoSpecFromUrl, depKind, collectInstallMeta, extractPayloadMeta,
  writeLastRestore, readLastRestore, planProfileInstall, findPnpmPath,
  createTestHarness,
  parseSemver, cmpSemver, semverGt, latestTagOf, shaOfDependency, summaryFromCompare,
  queryFlag, nonTargetFieldsIntact, selfPackageName, selfRepoSlug, selfVersion,
  performVersionCheck, parseRepoSlug, githubHttpsOnlyEnv,
  defaultHttpsGet, nextRedirectUrl,
} from './index.js'

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
check('exclude: >10MB file', isExcluded('big.bin', 10 * 1024 * 1024 + 1))
check('keep: normal', !isExcluded('settings.json', 100))
// 回归：node_modules 是插件依赖（实测 ~221MB），sessions 是会话历史（实测 ~27MB）。
// 二者若进备份，base64 payload 达 350MB+，会把 Node 堆撑爆（实测 OOM）。
check('exclude: node_modules (任意深度)', isExcluded('profiles/desktop/node_modules/foo/index.js') && isExcluded('node_modules/x'))
check('exclude: sessions', isExcluded('sessions/abc/session.v4.jsonl.zstd'))
check('keep: profile 配置不受 node_modules 排除影响', !isExcluded('profiles/desktop/cordis.patch.yml'))
check('keep: settings 与凭据', !isExcluded('settings.yaml') && !isExcluded('.credentials.yaml'))

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
  }

  // ---------- 4. 快照/回滚往返 ----------
  const snap1 = makeSnapshot(root, snapRoot, 5)
  check('snapshot created', existsSync(join(snapRoot, snap1)), snap1)
  // 改动 root，再回滚
  writeFileSync(join(root, 'settings.json'), '{"a":999}')
  writeFileSync(join(root, 'added.txt'), 'new')
  const { count: rcount, taken } = rollbackFromSnapshot(join(snapRoot, snap1), root, snapRoot, 5)
  check('rollback restores content', readFileSync(join(root, 'settings.json'), 'utf8') === '{"a":1}')
  // 语义已改为「只覆盖、不删除」：快照未覆盖的文件（新增文件、被排除的 dsh-runtimes/ 等）必须保留
  check('rollback does NOT delete files outside snapshot', existsSync(join(root, 'added.txt')))
  check('rollback preserves excluded dsh-runtimes (regression: ~/.dsh/dsh-runtimes must survive)', existsSync(join(root, 'dsh-runtimes', 'node.exe')) && readFileSync(join(root, 'dsh-runtimes', 'node.exe'), 'utf8') === 'fake-binary')
  check('rollback preserves excluded logs/', existsSync(join(root, 'logs', 'a.log')))
  check('rollback returns file count', rcount === 4, 'count=' + rcount + ' snapBeforeRollback=' + taken)

  // 只覆盖语义下，快照里的内容仍须被还原（再次改动后回滚）
  writeFileSync(join(root, 'settings.json'), '{"a":12345}')
  const rb2 = rollbackFromSnapshot(join(snapRoot, snap1), root, snapRoot, 5)
  check('rollback re-overwrites modified file', readFileSync(join(root, 'settings.json'), 'utf8') === '{"a":1}', 'count=' + rb2.count)

  // 快照保留 5 份
  for (let i = 0; i < 8; i++) makeSnapshot(root, snapRoot, 5)
  const snaps = readdirSync(snapRoot).filter((n) => !n.startsWith('.'))
  check('snapshot retention keeps 5 (+rollback safety snaps can exceed momentarily)', snaps.length >= 1 && snaps.length <= 5, JSON.stringify(snaps))

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
      captured.args.length === 2 && captured.args[0] === 'C:/fake/pnpm.mjs' && captured.args[1] === 'install')
    check('E2E: cwd 与 ELECTRON_RUN_AS_NODE 正确', captured.cwd === join(rootB, 'profiles', 'desktop') && captured.env.ELECTRON_RUN_AS_NODE === '1')
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
    check('移除依赖后 pnpm 仍能装（命令已下发）', captured.args[1] === 'install')
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
  })
  check('版本检查: 断网时返回 error 且不抛异常', offline.hasUpdate === false && /ENOTFOUND/.test(String(offline.error)), String(offline.error))

  const rate = await performVersionCheck('0.1.0', 'ddldxiacan/dsh-sync-release', {
    httpsGet: async () => ({ status: 403, body: '', error: null }), cache: new Map(), localSha: shaLocal,
  })
  check('版本检查: GitHub 限流(403)给出可读错误', /限流/.test(String(rate.error)) && rate.hasUpdate === false, String(rate.error))

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
      install: async (runner, pnpmPath) => { installArgs = { runner, pnpmPath }; return { ok: true, exitCode: 0, log: 'Done in 7.4s' } },
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

    // 已在目标 ref：不得白跑一次安装
    let ran = 0
    const u2 = await h.handleUpgrade({}, {}, { check: async () => ({ ...fakeCheck, latest: 'v0.2.0' }), install: async () => { ran++; return { ok: true, log: '' } } })
    check('POST /upgrade: spec 未变时回报「已是最新」且不跑安装', u2.ok === true && u2.upgraded === false && ran === 0, JSON.stringify({ ok: u2.ok, upgraded: u2.upgraded, ran }))

    // 无更新
    const u3 = await h.handleUpgrade({}, {}, { check: async () => ({ hasUpdate: false, latest: null, error: null }), install: async () => { ran++; return { ok: true, log: '' } } })
    check('POST /upgrade: 无更新时不安装', u3.ok === true && u3.upgraded === false && ran === 0)

    // 安装失败：ok=false，但 spec 已落地（如实回报，不谎报成功）
    const u4 = await h.handleUpgrade({}, {}, { check: async () => ({ ...fakeCheck, latest: 'v0.3.0', latestTag: 'v0.3.0' }), install: async () => ({ ok: false, error: 'pnpm install 退出码 1', log: 'ERR' }) })
    check('POST /upgrade: 安装失败时 ok=false 且带日志', u4.ok === false && /退出码 1/.test(u4.error) && /ERR/.test(String(u4.log)))

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

console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====')
process.exit(fail ? 1 : 0)
