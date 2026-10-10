import Lenis from 'lenis'
import 'lenis/dist/lenis.css'
import { gsap, ScrollTrigger } from './gsap.js'
import { prefersReducedMotion } from './motion.js'

let lenis = null

export function initSmoothScroll() {
  if (prefersReducedMotion) return null

  lenis = new Lenis({ lerp: 0.11 })
  lenis.on('scroll', ScrollTrigger.update)

  // Drive Lenis from GSAP's ticker so scroll and ScrollTrigger share one frame loop.
  gsap.ticker.add((time) => lenis.raf(time * 1000))
  gsap.ticker.lagSmoothing(0)

  return lenis
}

export function getLenis() {
  return lenis
}

export function scrollToTarget(target, { immediate = false, offset = 0 } = {}) {
  if (lenis) {
    lenis.scrollTo(target, { immediate, offset, force: true, duration: 1.4 })
    return
  }

  const behavior = immediate || prefersReducedMotion ? 'auto' : 'smooth'

  if (typeof target === 'number') {
    window.scrollTo({ top: target + offset, behavior })
    return
  }

  const element = typeof target === 'string' ? document.querySelector(target) : target
  if (!element) return

  const top = element.getBoundingClientRect().top + window.scrollY + offset
  window.scrollTo({ top, behavior })
}
