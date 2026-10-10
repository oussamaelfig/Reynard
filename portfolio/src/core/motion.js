export const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

export const clamp = (value, min, max) => Math.min(max, Math.max(min, value))

export const lerp = (from, to, amount) => from + (to - from) * amount
