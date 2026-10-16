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

console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====')
process.exit(fail ? 1 : 0)
