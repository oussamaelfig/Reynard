import { gsap, ScrollTrigger } from '../core/gsap.js'
import { prefersReducedMotion } from '../core/motion.js'
import { splitWords } from '../core/split-words.js'

export function initAbout() {
  const statement = document.querySelector('.about__statement')
  if (!statement) return

  let tween = null

  const build = () => {
    tween?.scrollTrigger?.kill()
    tween?.kill()

    const words = splitWords(statement)
    if (prefersReducedMotion) return

    tween = gsap.fromTo(
      words,
      { opacity: 0.14 },
      {
        opacity: 1,
        ease: 'none',
        stagger: 0.1,
        scrollTrigger: { trigger: statement, start: 'top 80%', end: 'bottom 45%', scrub: true },
      },
    )
  }

  build()

  // Translations replace the text node, so the words need to be split again.
  window.addEventListener('i18n:change', () => {
    build()
    ScrollTrigger.refresh()
  })
}
