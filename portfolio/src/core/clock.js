import { site } from '../config.js'

export function initClocks() {
  document.querySelectorAll('[data-year]').forEach((element) => {
    element.textContent = String(new Date().getFullYear())
  })

  const clocks = document.querySelectorAll('[data-clock]')
  if (!clocks.length) return

  const formatter = new Intl.DateTimeFormat('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: site.timeZone,
  })

  const update = () => {
    const time = formatter.format(new Date())
    clocks.forEach((clock) => {
      clock.textContent = time
    })
  }

  update()
  setInterval(update, 15_000)
}
