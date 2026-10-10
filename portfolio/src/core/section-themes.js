import { ScrollTrigger } from './gsap.js'

// Sections declare data-section-theme="dark|light"; the body follows whichever
// section crosses the middle of the viewport, and CSS transitions the colors.
export function initSectionThemes() {
  document.querySelectorAll('[data-section-theme]').forEach((section) => {
    ScrollTrigger.create({
      trigger: section,
      start: 'top 50%',
      end: 'bottom 50%',
      onToggle: (self) => {
        if (self.isActive) document.body.dataset.theme = section.dataset.sectionTheme
      },
    })
  })
}
