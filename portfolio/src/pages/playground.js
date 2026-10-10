import '../styles/base.css'
import '../styles/playground.css'
import { Observer } from 'gsap/Observer'
import Matter from 'matter-js'
import { initApp } from '../core/app.js'
import { gsap } from '../core/gsap.js'
import { t } from '../core/i18n.js'
import { playTitleIntro } from '../core/reveal.js'

gsap.registerPlugin(Observer)

const { Bodies, Body, Composite, Engine, Mouse, MouseConstraint, Query } = Matter

const SWATCHES = [
  { fill: '#c6f432', text: '#0c0c0e' },
  { fill: '#5b4dff', text: '#efece6' },
  { fill: '#ff5fa2', text: '#0c0c0e' },
  { fill: '#efece6', text: '#0c0c0e' },
]
const GLYPHS = ['✦', '●', '▲', '■']
const MAX_BODIES = 70
const WALL = 400
const STEP = 1000 / 60

const { enter } = initApp({ smoothScroll: false })
enter.then(() => playTitleIntro())

const canvas = document.querySelector('.playground__canvas')
const bar = document.querySelector('.playground__bar')
const context = canvas.getContext('2d')
const engine = Engine.create()
const mouse = Mouse.create(canvas)
const bodies = []
let walls = []
let width = 0
let height = 0
let floor = 0
let ratio = 1
let gravityTimeline = null
let spawnCalls = []

Composite.add(
  engine.world,
  MouseConstraint.create(engine, { mouse, constraint: { stiffness: 0.2, render: { visible: false } } }),
)

const fontSize = () => Math.round(Math.min(34, Math.max(18, width * 0.026)))
const pick = (list) => list[Math.floor(Math.random() * list.length)]

// The floor sits just above the hint bar (which wraps on narrow screens and in
// longer languages) so resting shapes never cover it.
function buildWalls() {
  floor = bar ? bar.getBoundingClientRect().top - canvas.getBoundingClientRect().top - 12 : height
  Composite.remove(engine.world, walls)
  walls = [
    Bodies.rectangle(width / 2, floor + WALL / 2, width + WALL * 2, WALL, { isStatic: true }),
    Bodies.rectangle(width / 2, -WALL / 2, width + WALL * 2, WALL, { isStatic: true }),
    Bodies.rectangle(-WALL / 2, height / 2, WALL, height + WALL * 2, { isStatic: true }),
    Bodies.rectangle(width + WALL / 2, height / 2, WALL, height + WALL * 2, { isStatic: true }),
  ]
  Composite.add(engine.world, walls)
}

function resize() {
  ratio = Math.min(window.devicePixelRatio, 2)
  width = canvas.clientWidth
  height = canvas.clientHeight
  canvas.width = width * ratio
  canvas.height = height * ratio
  // Matter reads pointer positions in canvas pixels; this maps them back to CSS pixels.
  mouse.pixelRatio = ratio
  buildWalls()

  bodies.forEach((body) => {
    Body.setPosition(body, {
      x: Math.min(Math.max(body.position.x, 40), width - 40),
      y: Math.min(body.position.y, floor - 40),
    })
  })
}

function addBody(body) {
  body.plugin.bornAt = performance.now()
  bodies.push(body)
  Composite.add(engine.world, body)

  if (bodies.length > MAX_BODIES) Composite.remove(engine.world, bodies.shift())
}

function createPill(label, x, y) {
  const size = fontSize()
  context.font = `700 ${size}px "Cabinet Grotesk", sans-serif`
  const bodyHeight = size * 2
  const bodyWidth = context.measureText(label).width + size * 1.6

  const body = Bodies.rectangle(x, y, bodyWidth, bodyHeight, {
    chamfer: { radius: bodyHeight / 2 - 0.5 },
    restitution: 0.35,
    friction: 0.08,
    angle: (Math.random() - 0.5) * 0.8,
  })
  body.plugin.shape = { kind: 'pill', label, size, width: bodyWidth, height: bodyHeight, swatch: pick(SWATCHES) }

  return body
}

function createBadge(x, y) {
  const radius = fontSize() * (1.1 + Math.random() * 0.6)
  const body = Bodies.circle(x, y, radius, { restitution: 0.5, friction: 0.05 })
  body.plugin.shape = { kind: 'circle', label: pick(GLYPHS), size: radius * 0.9, radius, swatch: pick(SWATCHES) }

  return body
}

// Shapes appear one by one inside the top of the canvas (below the ceiling).
function spawnInitial() {
  spawnCalls.forEach((call) => call.kill())
  bodies.splice(0).forEach((body) => Composite.remove(engine.world, body))

  const labels = t('playground.items')
  const factories = [
    ...(Array.isArray(labels) ? labels : []).map((label) => (x, y) => createPill(label, x, y)),
    ...Array.from({ length: 8 }, () => createBadge),
  ].sort(() => Math.random() - 0.5)

  spawnCalls = factories.map((create, index) =>
    gsap.delayedCall(index * 0.09, () =>
      addBody(create(width * (0.12 + Math.random() * 0.76), height * (0.1 + Math.random() * 0.25))),
    ),
  )
}

function draw() {
  context.setTransform(ratio, 0, 0, ratio, 0, 0)
  context.clearRect(0, 0, width, height)
  context.textAlign = 'center'
  context.textBaseline = 'middle'
  const now = performance.now()

  for (const body of bodies) {
    const shape = body.plugin.shape
    const grow = 1 - (1 - Math.min(1, (now - body.plugin.bornAt) / 350)) ** 3

    context.save()
    context.translate(body.position.x, body.position.y)
    context.rotate(body.angle)
    context.scale(grow, grow)
    context.fillStyle = shape.swatch.fill
    context.beginPath()

    if (shape.kind === 'circle') context.arc(0, 0, shape.radius, 0, Math.PI * 2)
    else context.roundRect(-shape.width / 2, -shape.height / 2, shape.width, shape.height, shape.height / 2)

    context.fill()
    context.fillStyle = shape.swatch.text
    context.font = `700 ${shape.size}px "Cabinet Grotesk", sans-serif`
    context.fillText(shape.label, 0, shape.size * 0.06)
    context.restore()
  }
}

// Click (without dragging) on empty space drops a new shape.
let pressed = null

canvas.addEventListener('pointerdown', (event) => {
  pressed = { x: event.offsetX, y: event.offsetY, hit: Query.point(bodies, { x: event.offsetX, y: event.offsetY }).length > 0 }
})

canvas.addEventListener('pointerup', (event) => {
  if (!pressed || pressed.hit) return
  const moved = Math.hypot(event.offsetX - pressed.x, event.offsetY - pressed.y)
  pressed = null
  if (moved > 6) return

  const labels = t('playground.items')
  const body =
    Math.random() < 0.5 && Array.isArray(labels)
      ? createPill(pick(labels), event.offsetX, event.offsetY)
      : createBadge(event.offsetX, event.offsetY)
  addBody(body)
})

// Gravity flips for a moment, then settles back.
function pulseGravity(strength) {
  gravityTimeline?.kill()
  gravityTimeline = gsap
    .timeline()
    .to(engine.gravity, { y: strength, duration: 0.3 })
    .to(engine.gravity, { y: 1, duration: 1, delay: 1.2 })
}

Observer.create({
  target: canvas,
  type: 'wheel',
  onChangeY: (self) => pulseGravity(self.deltaY < 0 ? -1 : 1.8),
})

document.querySelector('[data-gravity-flip]')?.addEventListener('click', () => pulseGravity(-1))
document.querySelector('[data-reset]')?.addEventListener('click', spawnInitial)
window.addEventListener('i18n:change', () => {
  resize()
  spawnInitial()
})
window.addEventListener('resize', resize)

resize()

document.fonts.load(`700 ${fontSize()}px "Cabinet Grotesk"`).finally(() => {
  spawnInitial()

  // Fixed 60 Hz steps keep the simulation stable at any frame rate.
  let pending = 0
  gsap.ticker.add((time, deltaTime) => {
    pending = Math.min(pending + deltaTime, STEP * 4)
    while (pending >= STEP) {
      Engine.update(engine, STEP)
      pending -= STEP
    }
    draw()
  })
})
