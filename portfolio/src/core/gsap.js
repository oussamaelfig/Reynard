import { gsap } from 'gsap'
import { CustomEase } from 'gsap/CustomEase'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger, CustomEase)

CustomEase.create('portfolio.out', 'M0,0 C0.16,1 0.3,1 1,1')
CustomEase.create('portfolio.inOut', 'M0,0 C0.76,0 0.24,1 1,1')

export { gsap, ScrollTrigger }
