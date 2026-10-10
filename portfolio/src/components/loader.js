import { gsap } from '../core/gsap.js'

const TICKS = 72
const MIN_DURATION = 1.2

const inactiveLoader = {
  active: false,
  setProgress() {},
  finish: () => Promise.resolve(),
}

// First-visit loader (once per session, decided in index.html before paint).
// Displayed progress never runs ahead of real progress nor of MIN_DURATION.
export function createLoader() {
  const root = document.documentElement
  const element = document.querySelector('.loader')
  if (!element) return inactiveLoader

  if (root.dataset.loader !== 'pending') {
    element.remove()
    return inactiveLoader
  }

  const canvas = element.querySelector('.loader__canvas')
  const value = element.querySelector('.loader__value')
  const context = canvas.getContext('2d')
  const startedAt = performance.now()
  const state = { target: 0, shown: 0, burst: 0 }
  let width = 0
  let height = 0

  function resize() {
    const ratio = Math.min(window.devicePixelRatio, 2)
    width = canvas.clientWidth
    height = canvas.clientHeight
    canvas.width = width * ratio
    canvas.height = height * ratio
    context.setTransform(ratio, 0, 0, ratio, 0, 0)
  }

  function draw() {
    const elapsed = (performance.now() - startedAt) / 1000
    const goal = Math.min(state.target, elapsed / MIN_DURATION)
    state.shown += (goal - state.shown) * 0.12
    value.textContent = String(Math.round(state.shown * 100))

    const centerX = width / 2
    const centerY = height / 2
    const radius = Math.min(width, height) * (0.2 + state.burst * 0.6)
    const lit = state.shown * TICKS

    context.clearRect(0, 0, width, height)
    context.lineCap = 'round'
    context.lineWidth = 2

    for (let index = 0; index < TICKS; index++) {
      const angle = (index / TICKS) * Math.PI * 2 - Math.PI / 2 + elapsed * 0.25
      const amount = Math.min(1, Math.max(0, lit - index))
      const inner = radius + Math.sin(elapsed * 3 + index * 0.4) * 2
      const outer = inner + 8 + amount * 22 * (1 - state.burst)

      context.strokeStyle =
        amount > 0
          ? `rgba(198, 244, 50, ${(0.35 + amount * 0.65) * (1 - state.burst)})`
          : `rgba(239, 236, 230, ${0.16 * (1 - state.burst)})`
      context.beginPath()
      context.moveTo(centerX + Math.cos(angle) * inner, centerY + Math.sin(angle) * inner)
      context.lineTo(centerX + Math.cos(angle) * outer, centerY + Math.sin(angle) * outer)
      context.stroke()
    }
  }

  resize()
  window.addEventListener('resize', resize)
  gsap.ticker.add(draw)

  function setProgress(progress) {
    state.target = Math.max(state.target, Math.min(1, progress))
  }

  function finish() {
    setProgress(1)

    return new Promise((resolve) => {
      const waitForFullCount = () => {
        if (state.shown < 0.995) return
        gsap.ticker.remove(waitForFullCount)

        gsap
          .timeline({
            onComplete: () => {
              gsap.ticker.remove(draw)
              window.removeEventListener('resize', resize)
              element.remove()
            },
          })
          .to(state, { burst: 1, duration: 1, ease: 'expo.in' }, 0)
          .to(value.parentElement, { yPercent: -60, opacity: 0, duration: 0.6, ease: 'power3.in' }, 0.1)
          .to(element, { clipPath: 'inset(0% 0% 100% 0%)', duration: 1, ease: 'portfolio.inOut' }, 0.55)
          .add(() => {
            root.dataset.loader = 'done'
            resolve()
          }, 0.85)
      }

      gsap.ticker.add(waitForFullCount)
    })
  }

  return { active: true, setProgress, finish }
}
