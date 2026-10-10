import { site } from '../config.js'
import { gsap, ScrollTrigger } from '../core/gsap.js'
import { createHeroScene } from '../webgl/hero-scene.js'

export function initHero({ onProgress } = {}) {
  const section = document.querySelector('.hero')
  if (!section) return { ready: Promise.resolve(), playIntro() {} }

  let scene = null

  try {
    scene = createHeroScene(section.querySelector('.hero__canvas'), {
      modelUrl: site.heroModelUrl,
      onProgress,
    })
  } catch (error) {
    console.warn('[hero] WebGL is unavailable, showing the static fallback.', error)
    section.classList.add('hero--no-webgl')
  }

  if (scene) {
    ScrollTrigger.create({
      trigger: section,
      start: 'top top',
      end: 'bottom top',
      scrub: true,
      onUpdate: (self) => scene.setScroll(self.progress),
    })
  }

  const lines = section.querySelectorAll('.hero__title .line-mask > span')
  const fades = section.querySelectorAll('[data-hero-fade]')

  function playIntro() {
    scene?.reveal()

    return gsap
      .timeline({ defaults: { ease: 'portfolio.out' } })
      .fromTo(lines, { y: 0, yPercent: 105 }, { yPercent: 0, duration: 1.5, stagger: 0.12 }, 0)
      .to(fades, { opacity: 1, y: 0, duration: 1.2, stagger: 0.08 }, 0.35)
  }

  return { ready: scene?.ready.catch(() => {}) ?? Promise.resolve(), playIntro }
}
