import en from '../i18n/en.json'
import fr from '../i18n/fr.json'

const dictionaries = { en, fr }
const STORAGE_KEY = 'lang'
const FALLBACK = 'en'

let current = FALLBACK

function lookup(dictionary, key) {
  return key.split('.').reduce((node, part) => node?.[part], dictionary)
}

function detectLanguage() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored in dictionaries) return stored
  } catch {
    // Storage can be unavailable (privacy mode); fall through to the browser language.
  }

  const browser = navigator.language?.slice(0, 2)
  return browser in dictionaries ? browser : FALLBACK
}

export function t(key) {
  return lookup(dictionaries[current], key) ?? lookup(dictionaries[FALLBACK], key) ?? key
}

export function getLanguage() {
  return current
}

// data-i18n="key"                 -> textContent
// data-i18n-attr="attr:key;attr:key" -> attributes (content, aria-label, ...)
export function applyTranslations(root = document) {
  root.querySelectorAll('[data-i18n]').forEach((element) => {
    const value = t(element.dataset.i18n)
    if (typeof value === 'string') element.textContent = value
  })

  root.querySelectorAll('[data-i18n-attr]').forEach((element) => {
    element.dataset.i18nAttr.split(';').forEach((pair) => {
      const [attribute, key] = pair.split(':').map((part) => part.trim())
      const value = attribute && key ? t(key) : null
      if (typeof value === 'string') element.setAttribute(attribute, value)
    })
  })
}

export function setLanguage(language) {
  if (!(language in dictionaries) || language === current) return

  current = language
  document.documentElement.lang = language

  try {
    localStorage.setItem(STORAGE_KEY, language)
  } catch {
    // The choice simply won't persist across pages.
  }

  applyTranslations()
  window.dispatchEvent(new CustomEvent('i18n:change', { detail: { language } }))
}

export function initI18n() {
  current = detectLanguage()
  document.documentElement.lang = current
  if (current !== FALLBACK) applyTranslations()

  document.querySelectorAll('[data-lang-toggle]').forEach((button) => {
    button.addEventListener('click', () => setLanguage(current === 'en' ? 'fr' : 'en'))
  })
}
