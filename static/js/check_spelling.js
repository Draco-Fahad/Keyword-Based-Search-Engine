// document.addEventListener('DOMContentLoaded', function() {
//     const searchInput = document.getElementById('search-input');
//     const suggestionsContainer = document.getElementById('spelling-suggestions');
//     let typingTimer;
//     const doneTypingInterval = 300;

//     // Check spelling as user types
//     searchInput.addEventListener('input', function() {
//         clearTimeout(typingTimer);
        
//         if (searchInput.value) {
//             typingTimer = setTimeout(checkSpelling, doneTypingInterval);
//         } else {
//             suggestionsContainer.innerHTML = '';
//         }
//     });

//     function checkSpelling() {
//         const words = searchInput.value.split(/\s+/).filter(word => word.length > 2);

//         if (!words.length) return;

//         suggestionsContainer.innerHTML = '';

//         words.forEach(word => {
//             fetch(`/check_spelling?word=${encodeURIComponent(word)}`)
//                 .then(response => response.json())
//                 .then(data => {
//                     if (!data.isCorrect) {
//                         const wordSpan = document.createElement('span');
//                         wordSpan.textContent = word;
//                         wordSpan.className = 'misspelled';

//                         // Add tooltip for suggestions
//                         const tooltip = document.createElement('span');
//                         tooltip.className = 'spelling-tooltip';
//                         tooltip.textContent = data.suggestions.length ? 
//                             `Did you mean: ${data.suggestions.join(', ')}` : 
//                             'No suggestions available';
//                         wordSpan.appendChild(tooltip);

//                         // Show tooltip on hover
//                         wordSpan.addEventListener('mouseenter', function() {
//                             tooltip.style.display = 'block';
//                         });

//                         wordSpan.addEventListener('mouseleave', function() {
//                             tooltip.style.display = 'none';
//                         });

//                         suggestionsContainer.appendChild(wordSpan);
//                         suggestionsContainer.appendChild(document.createTextNode(' '));
//                     }
//                 });
//         });
//     }
// });
