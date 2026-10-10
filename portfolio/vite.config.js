import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import glsl from 'vite-plugin-glsl'

const root = dirname(fileURLToPath(import.meta.url))
const partialsDir = resolve(root, 'src/partials')
const ignoredDirs = new Set(['node_modules', 'dist', 'public', 'src', 'scripts', 'models'])

// Every .html file outside the ignored folders becomes a page, so adding
// resume/index.html is enough to publish /resume/.
function findPages(dir = root) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name.startsWith('.')) return []
    const fullPath = join(dir, entry.name)
    if (entry.isDirectory()) return ignoredDirs.has(entry.name) ? [] : findPages(fullPath)
    return entry.name.endsWith('.html') ? [fullPath] : []
  })
}

// Replaces <!-- @include name --> with src/partials/name.html.
function htmlPartials() {
  const includePattern = /<!--\s*@include\s+([\w-]+)\s*-->/g

  return {
    name: 'html-partials',
    transformIndexHtml: {
      order: 'pre',
      handler: (html) =>
        html.replace(includePattern, (_, name) =>
          readFileSync(join(partialsDir, `${name}.html`), 'utf-8'),
        ),
    },
    configureServer(server) {
      server.watcher.add(partialsDir)
      server.watcher.on('change', (file) => {
        if (file.startsWith(partialsDir)) server.ws.send({ type: 'full-reload' })
      })
    },
  }
}

export default defineConfig({
  plugins: [glsl(), htmlPartials()],
  build: {
    // three.js core is ~560 kB minified; it gets its own long-cached chunk
    // while its addons (glTF loaders) stay in the lazily imported chunk.
    chunkSizeWarningLimit: 700,
    rolldownOptions: {
      input: Object.fromEntries(
        findPages().map((file) => [
          relative(root, file).replace(/\.html$/, '').replaceAll('/', '-'),
          file,
        ]),
      ),
      output: {
        codeSplitting: {
          groups: [
            {
              name: (id) => (id.replaceAll('\\', '/').includes('/node_modules/three/build/') ? 'three' : null),
            },
          ],
        },
      },
    },
  },
})
