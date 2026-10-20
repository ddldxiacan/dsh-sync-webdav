import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
const mod = await import('./index.js')

// ---- Test A: mirror restore with meta.appDataIncluded=true but NO appdata entries ----
const tmp = './_troot2'
const root = join(tmp, 'dsh')
const appdata = join(tmp, 'AppData/Roaming')
const settingsRel = join(appdata, '@deepseek-ai/dsh-desktop/desktop/settings.json')
rmSync(tmp, { recursive: true, force: true })
mkdirSync(root, { recursive: true })
mkdirSync(join(appdata, '@deepseek-ai/dsh-desktop/desktop'), { recursive: true })
writeFileSync(settingsRel, '{"theme":"dark","userSetting":1}\n')
writeFileSync(join(root, 'settings.json'), '{"a":1}\n')
process.env.APPDATA = appdata
console.log('collectAppDataFiles now:', mod.collectAppDataFiles())
const files = [{ path: 'settings.json', sha256: null, data: Buffer.from('{"a":2}\n').toString('base64') }]
const { createHash } = await import('node:crypto')
files[0].sha256 = createHash('sha256').update('{"a":2}\n').digest('hex')
const payload = Buffer.from(JSON.stringify({ files, meta: { profile: 'desktop', appDataIncluded: true } }))
const r = mod.applyPayloadMode(payload, root, 'mirror')
console.log('removed:', JSON.stringify(r.removed))
console.log('desktop settings.json still exists?', existsSync(settingsRel))
console.log('dsh-desktop dir exists?', existsSync(join(appdata,'@deepseek-ai/dsh-desktop')))
