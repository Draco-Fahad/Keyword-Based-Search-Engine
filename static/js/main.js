// Add any global JavaScript functionality here

// Helper function to format dates
function formatDate(dateString) {
  const date = new Date(dateString)
  return date.toLocaleDateString()
}

// Helper function to highlight search terms in text
function highlightSearchTerms(text, terms) {
  if (!text || !terms || !terms.length) return text

  let result = text

  terms.forEach((term) => {
    if (!term) return

    const regex = new RegExp(`(${term})`, "gi")
    result = result.replace(regex, "<mark>$1</mark>")
  })

  return result
}

// Flash message auto-hide
document.addEventListener("DOMContentLoaded", () => {
  const flashMessages = document.querySelectorAll(".flash-messages .alert")

  flashMessages.forEach((message) => {
    setTimeout(() => {
      message.style.opacity = "0"
      setTimeout(() => {
        message.remove()
      }, 500)
    }, 5000)
  })
})
