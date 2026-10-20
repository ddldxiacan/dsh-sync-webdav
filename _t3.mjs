import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
const mod = await import('./index.js')

const tmp = './_troot3'
rmSync(tmp, { recursive: true, force: true })
const root = join(tmp, 'dsh')
const snapRoot = join(tmp, 'snaps')
mkdirSync(join(root,'profiles/web'), { recursive: true })
writeFileSync(join(root,'settings.json'), '{"a":1}\n')
writeFileSync(join(root,'profiles/web/package.json'), '{"name":"web"}\n')
mkdirSync(snapRoot, { recursive: true })
mkdirSync(join(snapRoot,'20250101-000000-000'), { recursive: true })
writeFileSync(join(snapRoot,'20250101-000000-000','settings.json'), '{"snap":1}\n')

const h = mod.createTestHarness({ root, snapshotRoot: snapRoot, profile: 'web' })
const r = await h.handleRollback({ snapshot: '.' })
console.log('rollback result:', JSON.stringify(r))
console.log('root tree:')
const walk=(d,p)=>{for(const n of readdirSync(d)){const a=join(d,n); if(statSync(a).isDirectory()){console.log(' dir ', p+n); walk(a,p+n+'/')}else console.log(' file', p+n)}}
walk(root,'')
