import { gsap } from '../core/gsap.js'
import { t } from '../core/i18n.js'

// Cards sit on a CSS 3D cylinder; scrolling rotates it so each card passes
// the front once, and the heading follows the group of the front card.
export function initToolkit() {
  const section = document.querySelector('.toolkit')
  if (!section) return

  const ring = section.querySelector('.toolkit__ring')
  const cards = [...ring.querySelectorAll('.tool-card')]
  const label = section.querySelector('.toolkit__group-label')
  const step = 360 / cards.length
  const state = { rotation: 0 }
  let radius = 0
  let currentGroup = cards[0].dataset.group
  let labelTimeline = null

  function showGroup(group) {
    if (group === currentGroup) return
    currentGroup = group

    labelTimeline?.kill()
    labelTimeline = gsap
      .timeline()
      .to(label, { yPercent: -110, duration: 0.22, ease: 'power2.in' })
      .add(() => {
        label.dataset.i18n = `focus.groups.${group}`
        label.textContent = t(label.dataset.i18n)
      })
      .fromTo(label, { yPercent: 110 }, { yPercent: 0, duration: 0.45, ease: 'power3.out' })
  }

  function render() {
    ring.style.transform = `translateZ(${-radius}px) rotateY(${state.rotation}deg)`

    cards.forEach((card, index) => {
      const angle = (((index * step + state.rotation) % 360) + 360) % 360
      const facing = Math.cos((angle * Math.PI) / 180)
      card.style.opacity = String(0.08 + Math.max(0, facing) ** 1.6 * 0.92)
    })

    const front = (((Math.round(-state.rotation / step) % cards.length) + cards.length) % cards.length)
    cards.forEach((card, index) => card.classList.toggle('is-front', index === front))
    showGroup(cards[front].dataset.group)
  }

  function layout() {
    const cardWidth = cards[0].offsetWidth
    radius = Math.round(cardWidth / 2 / Math.tan(Math.PI / cards.length) + cardWidth * 0.15)

    cards.forEach((card, index) => {
      card.style.transform = `rotateY(${index * step}deg) translateZ(${radius}px)`
    })

    render()
  }

  gsap.to(state, {
    rotation: -(cards.length - 1) * step,
    ease: 'none',
    onUpdate: render,
    scrollTrigger: {
      trigger: section.querySelector('.toolkit__track'),
      start: 'top top',
      end: 'bottom bottom',
      scrub: 0.8,
    },
  })

  layout()
  new ResizeObserver(layout).observe(cards[0])
}
