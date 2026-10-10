import '../styles/base.css'
import '../styles/home.css'
import { createLoader } from '../components/loader.js'
import { initScrollIndicator } from '../components/scroll-indicator.js'
import { initApp } from '../core/app.js'
import { ScrollTrigger } from '../core/gsap.js'
import { initReveals } from '../core/reveal.js'
import { initAbout } from '../sections/about.js'
import { initContact } from '../sections/contact.js'
import { initHero } from '../sections/hero.js'
import { initJourney } from '../sections/journey.js'
import { initToolkit } from '../sections/toolkit.js'
import { initWork } from '../sections/work.js'

const loader = createLoader()
const { lenis, enter } = initApp()

if (loader.active) lenis?.stop()

const hero = initHero({ onProgress: loader.setProgress })
initAbout()
initJourney()
initToolkit()
initWork()
initContact()
initScrollIndicator()
initReveals()

Promise.all([hero.ready, document.fonts.ready]).then(async () => {
  await loader.finish()
  lenis?.start()
  ScrollTrigger.refresh()
  await enter
  hero.playIntro()
})
