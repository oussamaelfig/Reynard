// Wraps every word of an element in <span class="word"> while keeping real
// spaces between them, so wrapping and screen readers behave as plain text.
export function splitWords(element) {
  const words = element.textContent.trim().split(/\s+/)
  const fragment = document.createDocumentFragment()

  words.forEach((word, index) => {
    if (index > 0) fragment.append(' ')

    const span = document.createElement('span')
    span.className = 'word'
    span.textContent = word
    fragment.append(span)
  })

  element.replaceChildren(fragment)

  return [...element.querySelectorAll('.word')]
}
