import '../styles/base.css'
import '../styles/pages.css'
import { initApp } from '../core/app.js'
import { initReveals, playTitleIntro } from '../core/reveal.js'

const { enter } = initApp()
initReveals()
enter.then(() => playTitleIntro())

document.querySelectorAll('[data-copy]').forEach((button) => {
  const label = button.textContent.trim()
  let timer = null

  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy)
    } catch {
      window.location.href = `mailto:${button.dataset.copy}`
      return
    }

    button.textContent = button.dataset.copiedLabel
    clearTimeout(timer)
    timer = setTimeout(() => {
      button.textContent = label
    }, 2000)
  })
})
