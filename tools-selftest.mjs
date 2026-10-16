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
    mkdirSync(join(prof, 'node_modules', 'dsh-sync-plugin'), { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({
      dependencies: {
        'dsh-sync-plugin': 'link:E:/somewhere/dsh-sync-release',
        'dsh-claude-style': '^0.15.0',
        '@liustack/modlens': '3.27.1',
      },
    }), 'utf8')
    writeFileSync(join(prof, 'node_modules', 'dsh-sync-plugin', 'package.json'),
      JSON.stringify({ name: 'dsh-sync-plugin', repository: { url: 'git+https://github.com/ddldxiacan/dsh-sync-release.git' } }), 'utf8')
    const meta = collectInstallMeta(root, 'desktop')
    check('collectInstallMeta: 只挑出 link 依赖', Object.keys(meta.linkMap).length === 1 && Object.keys(meta.unmapped).length === 0)
    check('collectInstallMeta: link→github spec', meta.linkMap['dsh-sync-plugin'].spec === 'github:ddldxiacan/dsh-sync-release')
    check('collectInstallMeta: 保留原始 from 与 reason',
      meta.linkMap['dsh-sync-plugin'].from === 'link:E:/somewhere/dsh-sync-release' &&
      meta.linkMap['dsh-sync-plugin'].reason === 'repository.url')
    check('collectInstallMeta: profile 名与时间戳', meta.profile === 'desktop' && typeof meta.createdAt === 'string')

    // node_modules 缺失时归入 unmapped，而不是猜一个 spec
    rmSync(join(prof, 'node_modules'), { recursive: true, force: true })
    const meta2 = collectInstallMeta(root, 'desktop')
    check('collectInstallMeta: 装不了时进 unmapped', Object.keys(meta2.linkMap).length === 0 && meta2.unmapped['dsh-sync-plugin'] === 'link:E:/somewhere/dsh-sync-release')
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
    mkdirSync(join(prof, 'node_modules', 'dsh-sync-plugin'), { recursive: true })
    writeFileSync(join(prof, 'package.json'), JSON.stringify({
      name: 'desktop-profile',
      dependencies: { 'dsh-sync-plugin': 'link:E:/A-only/dsh-sync-release' },
    }), 'utf8')
    writeFileSync(join(prof, 'node_modules', 'dsh-sync-plugin', 'package.json'),
      JSON.stringify({ name: 'dsh-sync-plugin', repository: { url: 'git+https://github.com/ddldxiacan/dsh-sync-release.git' } }), 'utf8')
    writeFileSync(join(prof, 'pnpm-lock.yaml'), 'lockfileVersion: 9\nimporters:\n  .:\n    dependencies:\n      dsh-sync-plugin:\n        specifier: link:E:/A-only/dsh-sync-release\n', 'utf8')

    // A 机：备份（带 meta）
    const payload = buildPayload(root, collectFiles(root), collectInstallMeta(root, 'desktop'))
    const bundle = encryptBundle(payload, 'pw')

    // B 机：新目录只放恢复出来的文件（模拟 node_modules 不在备份里）
    const rootB = join(tmpdir(), 'dsh-sync-e2e-b-' + Date.now())
    mkdirSync(rootB, { recursive: true })
    const meta = extractPayloadMeta(decryptBundle(bundle, 'pw'))
    extractPayload(decryptBundle(bundle, 'pw'), rootB)
    writeLastRestore(rootB, { at: new Date().toISOString(), bundle: 'x', profile: meta.profile, linkMap: meta.linkMap })
    check('E2E: B 机恢复后没有 node_modules', !existsSync(join(rootB, 'profiles', 'desktop', 'node_modules', 'dsh-sync-plugin', 'package.json')))

    // 用 B 机的目录实例化 host，跑 /plugins 与 /plugins/install
    const h = createTestHarness({ root: rootB, profile: 'desktop' })
    const rep = await h.handlePlugins()
    check('E2E: /plugins 报出 profile 与缺失项', rep.ok === true && rep.profile === 'desktop' && rep.missing.length === 1 && rep.needsInstall === true)
    check('E2E: /plugins 给出改写建议', rep.deps[0].rewrite === 'github:ddldxiacan/dsh-sync-release' && rep.deps[0].installed === false)
    check('E2E: 记录的 linkMap 生效', rep.mapped['dsh-sync-plugin'].spec === 'github:ddldxiacan/dsh-sync-release')
    check('client 契约: missing 是包名数组', Array.isArray(rep.missing) && rep.missing[0] === 'dsh-sync-plugin')

    let captured = null
    const fakeRunner = (opt) => {
      captured = opt
      // 模拟真实 pnpm：重建 node_modules，并把锁文件里的 link specifier 同步成仓库地址
      mkdirSync(join(opt.cwd, 'node_modules', 'dsh-sync-plugin'), { recursive: true })
      writeFileSync(join(opt.cwd, 'node_modules', 'dsh-sync-plugin', 'package.json'), '{"name":"dsh-sync-plugin"}', 'utf8')
      writeFileSync(join(opt.cwd, 'pnpm-lock.yaml'), 'lockfileVersion: 9\nimporters:\n  .:\n    dependencies:\n      dsh-sync-plugin:\n        specifier: github:ddldxiacan/dsh-sync-release\n', 'utf8')
      return { status: 0, stdout: 'Done in 2m6.7s', stderr: '' }
    }
    const res = await h.handlePluginInstall({}, fakeRunner, 'C:/fake/pnpm.mjs')
    check('E2E: 安装成功且返回结构完整', res.ok === true && res.exitCode === 0 && typeof res.durationMs === 'number')
    check('client 契约: installed 是包名数组', Array.isArray(res.installed) && res.installed.includes('dsh-sync-plugin'))
    check('client 契约: rewritten 是 包名→声明 映射', res.rewritten['dsh-sync-plugin'] === 'github:ddldxiacan/dsh-sync-release')
    check('client 契约: removed 是包名数组', Array.isArray(res.removed) && res.removed.length === 0)
    check('E2E: 命令行为 pnpm install（不带 lockfile 相关 flag）',
      captured.args.length === 2 && captured.args[0] === 'C:/fake/pnpm.mjs' && captured.args[1] === 'install')
    check('E2E: cwd 与 ELECTRON_RUN_AS_NODE 正确', captured.cwd === join(rootB, 'profiles', 'desktop') && captured.env.ELECTRON_RUN_AS_NODE === '1')
    check('E2E: 超时为 15 分钟', captured.timeout === 15 * 60 * 1000)
    const pkgAfter = JSON.parse(readFileSync(join(rootB, 'profiles', 'desktop', 'package.json'), 'utf8'))
    check('E2E: package.json 里 link: 已改写为仓库地址', pkgAfter.dependencies['dsh-sync-plugin'] === 'github:ddldxiacan/dsh-sync-release')
    check('E2E: 改写前已备份 package.json',
      readdirSync(join(rootB, 'profiles', 'desktop')).some((n) => n.startsWith('package.json.bak-dsh-sync-')) &&
      JSON.parse(readFileSync(join(rootB, 'profiles', 'desktop', 'package.json'), 'utf8')).dependencies['dsh-sync-plugin'].startsWith('github:'))
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

console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====')
process.exit(fail ? 1 : 0)
