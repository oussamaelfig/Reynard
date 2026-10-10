import { ScrollTrigger } from '../core/gsap.js'
import { scrollToTarget } from '../core/smooth-scroll.js'

// Builds the side navigation from every <section data-section id="..."> on the
// page, labelled with its data-section-label.
export function initScrollIndicator() {
  const nav = document.querySelector('.scroll-indicator')
  const sections = [...document.querySelectorAll('[data-section][id]')]
  if (!nav || !sections.length) return

  const items = sections.map((section, index) => {
    const link = document.createElement('a')
    link.className = 'scroll-indicator__item'
    link.href = `#${section.id}`
    link.dataset.transition = 'off'

    const label = document.createElement('span')
    label.className = 'scroll-indicator__label'
    label.textContent = section.dataset.sectionLabel ?? section.id

    const number = document.createElement('span')
    number.className = 'scroll-indicator__number'
    number.textContent = String(index + 1).padStart(2, '0')

    const tick = document.createElement('span')
    tick.className = 'scroll-indicator__tick'
    tick.setAttribute('aria-hidden', 'true')

    link.append(label, number, tick)
    link.addEventListener('click', (event) => {
      event.preventDefault()
      scrollToTarget(section)
    })

    nav.append(link)
    return link
  })

  const setActive = (activeIndex) => {
    items.forEach((item, index) => {
      const isActive = index === activeIndex
      item.classList.toggle('is-active', isActive)
      if (isActive) item.setAttribute('aria-current', 'location')
      else item.removeAttribute('aria-current')
    })
  }

  sections.forEach((section, index) => {
    ScrollTrigger.create({
      trigger: section,
      start: 'top 50%',
      end: 'bottom 50%',
      onToggle: (self) => self.isActive && setActive(index),
    })
  })

  setActive(0)
}
