import '../styles/base.css'
import '../styles/project.css'
import { initApp } from '../core/app.js'
import { gsap } from '../core/gsap.js'
import { initReveals, playTitleIntro } from '../core/reveal.js'

const { enter } = initApp()
initReveals()

const cover = document.querySelector('.project-cover__art')

if (cover) {
  gsap.fromTo(
    cover,
    { scale: 0.92 },
    { scale: 1, ease: 'none', scrollTrigger: { trigger: cover, start: 'top bottom', end: 'top 25%', scrub: true } },
  )

  gsap.to(cover.querySelector('.cover-art__glyph'), {
    yPercent: -35,
    ease: 'none',
    scrollTrigger: { trigger: cover, start: 'top bottom', end: 'bottom top', scrub: true },
  })
}

enter.then(() => playTitleIntro())
