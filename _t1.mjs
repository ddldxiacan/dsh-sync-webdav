import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
const mod = await import('./index.js')
const root = './_troot'
rmSync(root, { recursive: true, force: true })
mkdirSync(root, { recursive: true })
writeFileSync(join(root, 'dsh-sync.json'), JSON.stringify({url:'https://a/dav/',username:'u',password:'p',remoteDir:'dsh-sync',passphrase:'local-pass'}, null, 2))
const redacted = Buffer.from(JSON.stringify({url:'https://b/dav/',username:'u2',password:'p2',remoteDir:'dsh-sync'}, null, 2) + '\n')
const files = [
  { path: 'dsh-sync.json', sha256: createHash('sha256').update(redacted).digest('hex'), data: redacted.toString('base64') },
]
const payload = Buffer.from(JSON.stringify({ files }))
for (const mode of ['merge','overwrite','mirror']) {
  // reset local each time
  writeFileSync(join(root, 'dsh-sync.json'), JSON.stringify({url:'https://a/dav/',username:'u',password:'p',remoteDir:'dsh-sync',passphrase:'local-pass'}, null, 2))
  const r = mod.applyPayloadMode(payload, root, mode)
  console.log(mode, 'count', r.count, 'verified', r.verified, 'mismatch', JSON.stringify(r.mismatches), 'conflicts', r.conflicts.length)
}
