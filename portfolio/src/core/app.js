import { initClocks } from './clock.js'
import { ScrollTrigger } from './gsap.js'
import { initHeader } from './header.js'
import { initI18n } from './i18n.js'
import { initPageTransitions } from './page-transition.js'
import { initSectionThemes } from './section-themes.js'
import { initSmoothScroll, scrollToTarget } from './smooth-scroll.js'

// Shared bootstrapping for every page. Page modules create their own
// ScrollTriggers afterwards and call ScrollTrigger.refresh() if needed.
export function initApp({ smoothScroll = true } = {}) {
  initI18n()

  const lenis = smoothScroll ? initSmoothScroll() : null
  const { enter } = initPageTransitions()

  initHeader()
  initSectionThemes()
  initClocks()

  document.querySelectorAll('[data-scroll-top]').forEach((button) => {
    button.addEventListener('click', () => scrollToTarget(0))
  })

  document.fonts?.ready.then(() => {
    ScrollTrigger.refresh()
    if (location.hash && document.querySelector(location.hash)) {
      scrollToTarget(location.hash, { immediate: true })
    }
  })

  return { lenis, enter }
}
