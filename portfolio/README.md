# Fiona — portfolio (Vite · three.js · GSAP · Lenis)

Fiona's portfolio, built with the same open-source toolchain as
[guillaumezhu.com](https://guillaumezhu.com/): a vanilla-JS Vite multi-page
site with a WebGL hero, scroll-driven sections, page transitions and a physics
playground. Her experience and education come from her LinkedIn profile.

> **About the reference site.** Its legal notice states that its texts,
> interfaces, animations, graphics, art direction and code belong to Guillaume
> Zhu and may not be reproduced without permission, and its public source
> repository has no license. None of its files, copy, images, 3D models or code
> are included here. The design and code in this folder are original.

## Toolchain

| Tool | Version | Used for |
| --- | --- | --- |
| [Vite](https://vite.dev/) (Rolldown) | 8.x | Dev server and multi-page production build |
| [three.js](https://threejs.org/) | r186 | WebGL hero (custom `ShaderMaterial`), optional glTF logo with Draco / Meshopt / KTX2 |
| [vite-plugin-glsl](https://github.com/UstymUkhman/vite-plugin-glsl) | 1.6 | Import `.glsl` / `.vert` / `.frag` files with `#include` |
| [GSAP](https://gsap.com/) + ScrollTrigger, CustomEase, Observer | 3.15 | Scroll animation, transitions, wheel input (all plugins are free) |
| [Lenis](https://lenis.darkroom.engineering/) | 1.3 | Smooth scrolling, synced with ScrollTrigger |
| [Matter.js](https://brm.io/matter-js/) | 0.20 | 2D physics on the playground page |
| [Satoshi](https://www.fontshare.com/fonts/satoshi) + [Cabinet Grotesk](https://www.fontshare.com/fonts/cabinet-grotesk) | — | Body and display typefaces, loaded from the Fontshare CDN (ITF Free Font License) |
| [glTF Transform CLI](https://gltf-transform.dev/cli) | 4.5 | Compress your own 3D model for the hero (`npm run model:optimize`) |
| [Vercel](https://vercel.com/) | — | Hosting (`vercel.json` included) |

Optional tools outside npm: [Blender](https://www.blender.org/) to model a 3D
logo, and [KTX-Software](https://github.com/KhronosGroup/KTX-Software) (`toktx`)
only if you want KTX2 texture compression instead of WebP.

## Getting started

Requires Node.js 20.19+ (or 22.12+).

```bash
cd portfolio
npm install
npm run dev       # http://localhost:5173
npm run build     # outputs dist/
npm run preview   # serves dist/ locally
```

## Structure

```
portfolio/
├── index.html                 Home: hero, about, experience, focus, education, contact
├── playground/index.html      Matter.js playground
├── contact/  legal/  404.html
├── public/                    Static files (favicon, models/)
├── vite.config.js             Page discovery, HTML partials, chunking
└── src/
    ├── config.js              Name, email, time zone, optional hero model URL
    ├── partials/              head, header, footer, transition (<!-- @include name -->)
    ├── core/                  Lenis + GSAP, transitions, header, themes, reveals, clock
    ├── components/            Loader, section indicator
    ├── sections/              Hero, about, journey (experience), toolkit (focus wheel), contact
    ├── webgl/                 Hero scene, glTF loader, GLSL shaders
    ├── pages/                 One entry module per page type
    └── styles/                base, home, pages, playground
```

## What's included

- **Loader:** canvas ring that tracks real progress (fonts, shader compile, model
  download). Shown once per session.
- **WebGL hero:** noise-displaced sphere with iridescent shading that leans
  toward the pointer and drifts away on scroll. Rendering pauses off-screen.
- **Section themes:** each section declares `data-section-theme="dark|light"`
  and the page background cross-fades as you scroll.
- **Pinned sections:** CSS `position: sticky` stages inside tall tracks,
  scrubbed by ScrollTrigger. Experience tells her three roles as chapters over a
  particle field that morphs between formations. Focus spins a CSS 3D card
  wheel; each card names the role or degree it comes from.
- **Education:** University of Waterloo, Bachelor's Degree in Financial
  Mathematics.
- **Contact marquee:** speed and direction follow scroll velocity.
- **Page transitions:** a cover wipes in on internal links. The next page reads a
  `sessionStorage` flag before first paint and wipes it away. This also handles
  the back/forward cache.
- **Accessibility:** skip link, visible focus, `prefers-reduced-motion` support
  (no smooth scroll or loader, slowed WebGL), semantic landmarks.

## Before publishing

These details weren't in the profile, so they are still placeholders:

1. **Email:** replace `hello@example.com` (footer, contact section, contact
   page, legal notice, `src/config.js`).
2. **LinkedIn URL:** replace `https://www.linkedin.com/in/your-handle/` in
   `src/partials/footer.html` and `contact/index.html`.
3. **Hosting:** fill in the hosting provider in `legal/index.html` and remove
   the reminder box at the top of that page.
4. **Full name (optional):** the site uses "Fiona". Search and replace it to add
   a last name.

## Editing

1. **Copy:** all text lives in the HTML files (`index.html`, the pages and
   `src/partials/`). A few labels that scripts display sit in attributes:
   `data-section-label` (side navigation), `data-group-label` (focus wheel
   heading), `data-words` (playground) and `data-copied-label` (copy button).
2. **Experience:** each chapter is a `.journey__chapter` in `index.html`. The
   particle field supports three chapters.
3. **Look:** colors, fonts, spacing and easing are tokens at the top of
   `src/styles/base.css`.
4. **Projects:** the first version of this site had a project list and a
   project-page template. Restore them from this branch's git history when there
   are case studies to show.
5. **3D logo (optional):** export a GLB from Blender to `models/hero.glb`, run
   `npm run model:optimize` (Draco geometry + WebP textures), then set
   `heroModelUrl: '/models/hero.glb'` in `src/config.js`. The glTF loaders are
   only downloaded when a model is configured.

## Deploying to Vercel

Import the repository and set **Root Directory** to `portfolio`. The Vite preset
detects `npm run build` and the `dist` output. `vercel.json` enables trailing
slashes and long-lived caching for hashed assets.

## Notes

- `npm audit` reports an advisory in `braces`, pulled in by
  `@gltf-transform/cli`. That is a local command-line tool and is never shipped
  to the browser, and no patched `braces` release exists yet.
