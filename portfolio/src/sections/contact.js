import { gsap, ScrollTrigger } from '../core/gsap.js'
import { prefersReducedMotion } from '../core/motion.js'

// Infinite marquee whose speed and direction follow the scroll velocity.
// The track holds two identical groups, so moving it by -50% loops seamlessly.
export function initContact() {
  const section = document.querySelector('.contact')
  const track = section?.querySelector('.marquee__track')
  if (!track || prefersReducedMotion) return

  const loop = gsap.to(track, { xPercent: -50, duration: 28, ease: 'none', repeat: -1, paused: true })
  // Start deep into the repeats so a negative timeScale has room to play backwards.
  loop.totalTime(loop.duration() * 1000)

  ScrollTrigger.create({
    trigger: section,
    start: 'top bottom',
    end: 'bottom top',
    onToggle: (self) => (self.isActive ? loop.play() : loop.pause()),
    onUpdate: (self) => {
      const direction = self.direction
      const boost = Math.min(Math.abs(self.getVelocity()) / 300, 5)

      gsap
        .to(loop, { timeScale: direction * (1 + boost), duration: 0.25, overwrite: true })
        .then(() => gsap.to(loop, { timeScale: direction, duration: 1.2, ease: 'power2.out', overwrite: true }))
    },
  })
}
