import { gsap } from '../core/gsap.js'

const PALETTE = [
  [255, 95, 162],
  [91, 77, 255],
  [198, 244, 50],
]

const smoothstep = (value) => value * value * (3 - 2 * value)

// Particles morph between three formations (cloud, grid, phyllotaxis) as the
// journey progresses. `formation` is a float: 0.5 is halfway between 0 and 1.
export function createParticleField(canvas) {
  const context = canvas.getContext('2d')
  const count = window.innerWidth < 768 ? 280 : 560
  const particles = Array.from({ length: count }, () => ({
    angle: Math.random() * Math.PI * 2,
    distance: Math.random(),
    seed: Math.random() * 100,
    size: 0.8 + Math.random() * 1.8,
    x: 0,
    y: 0,
    formations: [],
  }))

  let width = 0
  let height = 0
  let formation = 0
  let running = false

  function buildFormations() {
    const radius = Math.min(width, height) * 0.34
    const side = Math.ceil(Math.sqrt(count))
    const golden = Math.PI * (3 - Math.sqrt(5))

    particles.forEach((particle, index) => {
      const spread = Math.pow(particle.distance, 0.55) * radius * 1.3
      const cloud = {
        x: Math.cos(particle.angle) * spread * 1.5,
        y: Math.sin(particle.angle) * spread * 0.85,
      }

      const grid = {
        x: ((index % side) / (side - 1) - 0.5) * radius * 2.1,
        y: (Math.floor(index / side) / (side - 1) - 0.5) * radius * 2.1,
      }

      const petal = Math.sqrt((index + 0.5) / count) * radius * 1.15
      const flower = {
        x: Math.cos(index * golden) * petal,
        y: Math.sin(index * golden) * petal,
      }

      particle.formations = [cloud, grid, flower]
      particle.x = cloud.x
      particle.y = cloud.y
    })
  }

  function resize() {
    const ratio = Math.min(window.devicePixelRatio, 2)
    width = canvas.clientWidth
    height = canvas.clientHeight
    canvas.width = width * ratio
    canvas.height = height * ratio
    context.setTransform(ratio, 0, 0, ratio, 0, 0)
    buildFormations()
  }

  function draw(time) {
    const from = Math.floor(formation)
    const to = Math.min(from + 1, PALETTE.length - 1)
    const amount = smoothstep(formation - from)
    const color = PALETTE[from].map((channel, index) => Math.round(channel + (PALETTE[to][index] - channel) * amount))

    context.clearRect(0, 0, width, height)
    context.fillStyle = `rgba(${color.join(',')}, 0.85)`

    const centerX = width / 2
    const centerY = height / 2

    for (const particle of particles) {
      const start = particle.formations[from]
      const end = particle.formations[to]
      const wobble = Math.sin(time * 0.9 + particle.seed) * 3
      const targetX = start.x + (end.x - start.x) * amount + wobble
      const targetY = start.y + (end.y - start.y) * amount + Math.cos(time * 0.7 + particle.seed) * 3

      particle.x += (targetX - particle.x) * 0.1
      particle.y += (targetY - particle.y) * 0.1

      context.beginPath()
      context.arc(centerX + particle.x, centerY + particle.y, particle.size, 0, Math.PI * 2)
      context.fill()
    }
  }

  resize()
  new ResizeObserver(resize).observe(canvas)

  return {
    setFormation(value) {
      formation = Math.min(Math.max(value, 0), PALETTE.length - 1)
    },
    setActive(active) {
      if (active === running) return
      running = active
      if (active) gsap.ticker.add(draw)
      else gsap.ticker.remove(draw)
    },
  }
}
