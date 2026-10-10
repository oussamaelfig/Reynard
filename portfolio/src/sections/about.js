import { gsap } from '../core/gsap.js'
import { prefersReducedMotion } from '../core/motion.js'
import { splitWords } from '../core/split-words.js'

export function initAbout() {
  const statement = document.querySelector('.about__statement')
  if (!statement) return

  const words = splitWords(statement)
  if (prefersReducedMotion) return

  gsap.fromTo(
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
