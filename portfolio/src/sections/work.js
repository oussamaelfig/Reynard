import { Flip } from 'gsap/Flip'
import { gsap, ScrollTrigger } from '../core/gsap.js'
import { clamp, prefersReducedMotion } from '../core/motion.js'

gsap.registerPlugin(Flip)

const COVER_PROPERTIES = ['--cover-a', '--cover-b', '--cover-c']

function initViewToggle(section, list, onChange) {
  const buttons = [...section.querySelectorAll('.work__view')]

  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      const view = button.dataset.view
      if (list.dataset.view === view) return

      onChange()
      const state = Flip.getState(list.querySelectorAll('.work__item, .work__cover'))

      list.dataset.view = view
      buttons.forEach((other) => {
        other.classList.toggle('is-active', other === button)
        other.setAttribute('aria-pressed', String(other === button))
      })

      Flip.from(state, {
        duration: prefersReducedMotion ? 0 : 0.9,
        ease: 'portfolio.inOut',
        absolute: true,
        nested: true,
        stagger: 0.03,
        onEnter: (elements) =>
          gsap.fromTo(elements, { opacity: 0, scale: 0.85 }, { opacity: 1, scale: 1, duration: 0.7, delay: 0.3 }),
        onComplete: () => ScrollTrigger.refresh(),
      })
    })
  })
}

// Floating cover that trails the cursor over the list and tilts with its lag.
// Mouse vs touch is decided per event: (hover: hover) is misreported by some
// setups (remote desktops, VMs) and hybrid touch laptops.
function initPreview(section, list) {
  const preview = section.querySelector('.work__preview')
  const art = preview.querySelector('.cover-art')
  const glyph = preview.querySelector('.cover-art__glyph')
  const links = [...list.querySelectorAll('.work__link')]
  const pointer = { x: 0, y: 0 }
  let visible = false

  gsap.set(preview, { xPercent: -50, yPercent: -50, scale: 0.6, autoAlpha: 0 })
  const xTo = gsap.quickTo(preview, 'x', { duration: 0.65, ease: 'power3' })
  const yTo = gsap.quickTo(preview, 'y', { duration: 0.65, ease: 'power3' })

  const highlight = (activeLink) => {
    list.classList.toggle('is-hovering', Boolean(activeLink))
    links.forEach((link) => link.classList.toggle('is-hovered', link === activeLink))
  }

  const show = (link) => {
    highlight(link)
    COVER_PROPERTIES.forEach((property) => art.style.setProperty(property, link.style.getPropertyValue(property)))
    glyph.textContent = link.querySelector('.work__name').textContent.trim().charAt(0)

    if (visible) return
    visible = true
    gsap.set(preview, { x: pointer.x, y: pointer.y })
    gsap.to(preview, { autoAlpha: 1, scale: 1, duration: 0.5, ease: 'power3.out', overwrite: 'auto' })
  }

  const hide = () => {
    highlight(null)
    if (!visible) return
    visible = false
    gsap.to(preview, { autoAlpha: 0, scale: 0.6, duration: 0.4, ease: 'power3.in', overwrite: 'auto' })
  }

  section.addEventListener('pointermove', (event) => {
    pointer.x = event.clientX
    pointer.y = event.clientY
    xTo(pointer.x)
    yTo(pointer.y)
  })

  links.forEach((link) => {
    link.addEventListener('pointerenter', (event) => {
      if (event.pointerType === 'touch' || list.dataset.view !== 'list') return
      pointer.x = event.clientX
      pointer.y = event.clientY
      show(link)
    })
  })

  list.addEventListener('pointerleave', hide)
  window.addEventListener('scroll', () => visible && !list.matches(':hover') && hide(), { passive: true })

  gsap.ticker.add(() => {
    if (!visible) return
    const lag = pointer.x - gsap.getProperty(preview, 'x')
    gsap.set(preview, { rotation: clamp(lag * 0.05, -12, 12) })
  })

  return { hide }
}

export function initWork() {
  const section = document.querySelector('.work')
  if (!section) return

  const list = section.querySelector('.work__list')
  const preview = initPreview(section, list)
  initViewToggle(section, list, preview.hide)
}
