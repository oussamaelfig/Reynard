import { gsap, ScrollTrigger } from './gsap.js'

// Elements marked data-reveal start hidden (see base.css) and fade up once.
export function initReveals(root = document) {
  const elements = root.querySelectorAll('[data-reveal]')
  if (!elements.length) return

  ScrollTrigger.batch(elements, {
    start: 'top 90%',
    once: true,
    onEnter: (batch) =>
      gsap.to(batch, { opacity: 1, y: 0, duration: 1.1, stagger: 0.08, ease: 'portfolio.out' }),
  })
}

// Slides the masked lines of a .page-title up into view.
export function playTitleIntro(root = document) {
  const lines = root.querySelectorAll('.page-title .line-mask > span')
  if (!lines.length) return null

  return gsap.fromTo(
    lines,
    { y: 0, yPercent: 105 },
    { yPercent: 0, duration: 1.4, stagger: 0.1, ease: 'portfolio.out' },
  )
}
