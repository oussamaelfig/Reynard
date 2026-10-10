import '../styles/base.css'
import '../styles/pages.css'
import { initApp } from '../core/app.js'
import { t } from '../core/i18n.js'
import { initReveals, playTitleIntro } from '../core/reveal.js'

const { enter } = initApp()
initReveals()
enter.then(() => playTitleIntro())

document.querySelectorAll('[data-copy]').forEach((button) => {
  const label = button.querySelector('[data-i18n]')
  let timer = null

  const setLabel = (key) => {
    label.dataset.i18n = key
    label.textContent = t(key)
  }

  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy)
    } catch {
      window.location.href = `mailto:${button.dataset.copy}`
      return
    }

    setLabel('contactPage.copied')
    clearTimeout(timer)
    timer = setTimeout(() => setLabel('contactPage.copy'), 2000)
  })
})
