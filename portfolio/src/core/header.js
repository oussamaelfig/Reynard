import { ScrollTrigger } from './gsap.js'

export function initHeader() {
  const header = document.querySelector('.site-header')
  if (!header) return

  ScrollTrigger.create({
    start: 0,
    end: 'max',
    onUpdate: (self) => {
      const scroll = self.scroll()
      header.classList.toggle('is-scrolled', scroll > 40)
      header.classList.toggle('is-hidden', self.direction === 1 && scroll > window.innerHeight * 0.4)
    },
  })

  header.addEventListener('focusin', () => header.classList.remove('is-hidden'))
}
