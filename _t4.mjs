import { mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
const mod = await import('./index.js')
const root='./_t/root'; rmSync('./_t',{recursive:true,force:true}); mkdirSync(root,{recursive:true})
writeFileSync(join(root,'a.json'),'{"a":1}')
// case 1: entry without data
const bad = Buffer.from(JSON.stringify({files:[{path:'a.json', sha256:'deadbeef'}]}))
try { console.log('apply w/o data ->', JSON.stringify(mod.applyPayloadMode(bad, root, 'overwrite'))) }
catch(e){ console.log('THROWS:', e.constructor.name, e.message) }
// case 2: plan only
try { console.log('plan w/o data ->', JSON.stringify(mod.planPayloadApply(bad, root).totals)) } catch(e){ console.log('plan THROWS:', e.message) }
