import * as THREE from 'three'
import { gsap } from '../core/gsap.js'
import { lerp, prefersReducedMotion } from '../core/motion.js'
import fragmentShader from './shaders/blob.frag'
import vertexShader from './shaders/blob.vert'

const BASE_AMPLITUDE = 0.42

export function createHeroScene(canvas, { modelUrl = null, onProgress = () => {} } = {}) {
  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
    powerPreference: 'high-performance',
  })
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))

  const scene = new THREE.Scene()
  const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 50)

  // pivot: reveal + scroll transforms, spinner: pointer-driven rotation.
  const pivot = new THREE.Group()
  const spinner = new THREE.Group()
  pivot.add(spinner)
  scene.add(pivot)

  const uniforms = {
    uTime: { value: 0 },
    uAmplitude: { value: BASE_AMPLITUDE },
    uFrequency: { value: 1.25 },
    uReveal: { value: 0 },
    uScroll: { value: 0 },
    uPointer: { value: new THREE.Vector2() },
    uColorA: { value: new THREE.Color('#5b4dff') },
    uColorB: { value: new THREE.Color('#ff5fa2') },
    uColorC: { value: new THREE.Color('#c6f432') },
  }

  const transform = { reveal: 0.001, scroll: 0 }

  function applyTransform() {
    pivot.position.y = transform.scroll * 1.4
    pivot.scale.setScalar(Math.max(0.001, transform.reveal * (1 - transform.scroll * 0.3)))
  }

  function createBlob() {
    const segments = window.innerWidth < 768 ? 128 : 192
    const geometry = new THREE.SphereGeometry(1, segments, segments)
    const material = new THREE.ShaderMaterial({ vertexShader, fragmentShader, uniforms })
    return new THREE.Mesh(geometry, material)
  }

  async function createContent() {
    if (modelUrl) {
      try {
        const { loadHeroModel } = await import('./hero-model.js')
        return await loadHeroModel(modelUrl, renderer, scene, onProgress)
      } catch (error) {
        console.warn(`[hero] Could not load ${modelUrl}; using the procedural shape instead.`, error)
      }
    }

    return createBlob()
  }

  const ready = createContent().then((content) => {
    spinner.add(content)
    renderer.compile(scene, camera)
    onProgress(1)
  })

  function resize() {
    const width = canvas.clientWidth
    const height = canvas.clientHeight
    if (!width || !height) return

    renderer.setSize(width, height, false)
    camera.aspect = width / height
    camera.position.z = width < height ? 11 : 8
    camera.updateProjectionMatrix()
  }

  const resizeObserver = new ResizeObserver(resize)
  resizeObserver.observe(canvas)
  resize()

  let isVisible = true
  const visibilityObserver = new IntersectionObserver(([entry]) => {
    isVisible = entry.isIntersecting
  })
  visibilityObserver.observe(canvas)

  const pointer = { x: 0, y: 0, targetX: 0, targetY: 0, energy: 0 }

  window.addEventListener(
    'pointermove',
    (event) => {
      const x = (event.clientX / window.innerWidth) * 2 - 1
      const y = -(event.clientY / window.innerHeight) * 2 + 1
      pointer.energy = Math.min(1, pointer.energy + Math.hypot(x - pointer.targetX, y - pointer.targetY) * 2)
      pointer.targetX = x
      pointer.targetY = y
    },
    { passive: true },
  )

  const speed = prefersReducedMotion ? 0.25 : 1

  gsap.ticker.add((time) => {
    if (!isVisible) return

    pointer.x = lerp(pointer.x, pointer.targetX, 0.05)
    pointer.y = lerp(pointer.y, pointer.targetY, 0.05)
    pointer.energy *= 0.95

    uniforms.uTime.value = time * speed
    uniforms.uPointer.value.set(pointer.x, pointer.y)
    uniforms.uAmplitude.value = lerp(uniforms.uAmplitude.value, BASE_AMPLITUDE + pointer.energy * 0.25, 0.08)

    spinner.rotation.y = pointer.x * 0.6 + time * 0.12 * speed
    spinner.rotation.x = -pointer.y * 0.4

    renderer.render(scene, camera)
  })

  applyTransform()

  return {
    ready,
    reveal() {
      gsap.to(transform, { reveal: 1, duration: 2.2, ease: 'expo.out', onUpdate: applyTransform })
      gsap.to(uniforms.uReveal, { value: 1, duration: 2.8, ease: 'power2.out' })
    },
    setScroll(progress) {
      transform.scroll = progress
      uniforms.uScroll.value = progress
      applyTransform()
    },
  }
}
