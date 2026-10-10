import { gsap } from './gsap.js'
import { prefersReducedMotion } from './motion.js'
import { scrollToTarget } from './smooth-scroll.js'

// The inline boot script in partials/head.html reads this flag before first
// paint, so the incoming page starts covered and can animate the cover away.
const STORAGE_KEY = 'transition:pending'

const COVERED = 'inset(0% 0% 0% 0%)'
const BELOW = 'inset(100% 0% 0% 0%)'
const ABOVE = 'inset(0% 0% 100% 0%)'

function isModifiedClick(event) {
  return event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey
}

export function initPageTransitions() {
  const root = document.documentElement
  const overlay = document.querySelector('.page-transition')
  const duration = prefersReducedMotion ? 0.01 : 0.85
  let leaving = false

  const enter = new Promise((resolve) => {
    const shouldPlay = overlay && root.dataset.transition === 'in' && root.dataset.loader !== 'pending'

    if (!shouldPlay) {
      delete root.dataset.transition
      resolve()
      return
    }

    gsap.fromTo(
      overlay,
      { clipPath: COVERED, visibility: 'visible' },
      {
        clipPath: ABOVE,
        duration,
        delay: 0.1,
        ease: 'portfolio.inOut',
        onComplete: () => {
          delete root.dataset.transition
          gsap.set(overlay, { clearProps: 'all' })
          resolve()
        },
      },
    )
  })

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[href]')
    if (!link || leaving || event.defaultPrevented || isModifiedClick(event)) return
    if ((link.target && link.target !== '_self') || link.hasAttribute('download')) return
    if (link.dataset.transition === 'off') return

    const url = new URL(link.href, location.href)
    if (url.origin !== location.origin) return

    if (url.pathname === location.pathname && url.search === location.search) {
      event.preventDefault()
      scrollToTarget(url.hash && document.querySelector(url.hash) ? url.hash : 0)
      return
    }

    event.preventDefault()
    leaving = true

    try {
      sessionStorage.setItem(STORAGE_KEY, '1')
    } catch {
      // Without storage the next page simply appears without the reveal.
    }

    gsap.fromTo(
      overlay,
      { clipPath: BELOW, visibility: 'visible' },
      {
        clipPath: COVERED,
        duration,
        ease: 'portfolio.inOut',
        onComplete: () => window.location.assign(url.href),
      },
    )
  })

  // Pages restored from the back/forward cache come back mid-transition.
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return

    leaving = false
    delete root.dataset.transition
    gsap.set(overlay, { clearProps: 'all' })

    try {
      sessionStorage.removeItem(STORAGE_KEY)
    } catch {
      // Nothing to clean up.
    }
  })

  return { enter }
}
