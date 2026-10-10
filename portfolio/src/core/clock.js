import { site } from '../config.js'
import { getLanguage } from './i18n.js'

export function initClocks() {
  document.querySelectorAll('[data-year]').forEach((element) => {
    element.textContent = String(new Date().getFullYear())
  })

  const clocks = document.querySelectorAll('[data-clock]')
  if (!clocks.length) return

  const update = () => {
    const formatter = new Intl.DateTimeFormat(getLanguage(), {
      hour: '2-digit',
      minute: '2-digit',
      timeZone: site.timeZone,
    })
    const time = formatter.format(new Date())
    clocks.forEach((clock) => {
      clock.textContent = time
    })
  }

  update()
  setInterval(update, 15_000)
  window.addEventListener('i18n:change', update)
}
