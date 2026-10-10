// Copies the Draco (geometry) and Basis/KTX2 (texture) decoders shipped with
// three.js into public/, where GLTFLoader fetches them at runtime.
import { cpSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const libs = resolve(root, 'node_modules/three/examples/jsm/libs')

const decoders = {
  draco: resolve(libs, 'draco/gltf'),
  basis: resolve(libs, 'basis'),
}

for (const [name, source] of Object.entries(decoders)) {
  if (!existsSync(source)) {
    console.warn(`[decoders] ${source} not found, skipping ${name}`)
    continue
  }

  cpSync(source, resolve(root, 'public/decoders', name), {
    recursive: true,
    filter: (path) => !path.endsWith('README.md'),
  })
}

console.log('[decoders] Draco and Basis decoders copied to public/decoders/')
