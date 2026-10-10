import { gsap } from '../core/gsap.js'
import { createParticleField } from './particle-field.js'

// Each chapter owns one unit of timeline time: enter, hold, exit.
const EXIT_AT = 0.72
const MORPH_DURATION = 0.6

function formationAt(time, chapterCount) {
  for (let index = 0; index < chapterCount - 1; index++) {
    const start = index + EXIT_AT
    if (time < start) return index
    if (time < start + MORPH_DURATION) return index + (time - start) / MORPH_DURATION
  }

  return chapterCount - 1
}

export function initJourney() {
  const section = document.querySelector('.journey')
  if (!section) return

  const chapters = [...section.querySelectorAll('.journey__chapter')]
  const counter = section.querySelector('.journey__current')
  const bar = section.querySelector('.journey__progress-bar')
  const field = createParticleField(section.querySelector('.journey__canvas'))

  gsap.set(chapters.slice(1), { autoAlpha: 0 })

  const timeline = gsap.timeline({
    defaults: { ease: 'none' },
    scrollTrigger: {
      trigger: section.querySelector('.journey__track'),
      start: 'top top',
      end: 'bottom bottom',
      scrub: 0.6,
      onToggle: (self) => field.setActive(self.isActive),
    },
    onUpdate: () => {
      const formation = formationAt(timeline.time(), chapters.length)
      field.setFormation(formation)
      counter.textContent = String(Math.round(formation) + 1).padStart(2, '0')
      bar.style.transform = `scaleX(${timeline.progress()})`
    },
  })

  chapters.forEach((chapter, index) => {
    const lines = chapter.querySelectorAll('.line-mask > span')
    const details = chapter.querySelectorAll('.journey__label, .journey__detail')
    const at = index

    if (index > 0) {
      timeline
        .set(chapter, { autoAlpha: 1 }, at)
        .fromTo(lines, { yPercent: 105 }, { yPercent: 0, duration: 0.3, stagger: 0.06, ease: 'power3.out' }, at)
        .fromTo(details, { y: 24, opacity: 0 }, { y: 0, opacity: 1, duration: 0.3, ease: 'power3.out' }, at + 0.08)
    }

    if (index < chapters.length - 1) {
      timeline
        .to(lines, { yPercent: -105, duration: 0.24, stagger: 0.04, ease: 'power2.in' }, at + EXIT_AT)
        .to(details, { y: -24, opacity: 0, duration: 0.2, ease: 'power2.in' }, at + EXIT_AT)
        .set(chapter, { autoAlpha: 0 }, at + 1)
    }
  })

  // Hold the final chapter on screen before the section scrolls away.
  timeline.to({}, { duration: 0.6 })
}
