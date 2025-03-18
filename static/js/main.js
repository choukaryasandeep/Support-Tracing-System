// Form validation and UI enhancements
document.addEventListener('DOMContentLoaded', function() {
    // Add form input animations
    const formInputs = document.querySelectorAll('input, select');
    formInputs.forEach(input => {
        input.classList.add('form-input');
    });

    // Add card animations
    const cards = document.querySelectorAll('.max-w-md');
    cards.forEach(card => {
        card.classList.add('card');
    });

    // Add button animations
    const buttons = document.querySelectorAll('button[type="submit"]');
    buttons.forEach(button => {
        button.classList.add('btn');
    });

    // Add navigation link effects
    const navLinks = document.querySelectorAll('nav a');
    navLinks.forEach(link => {
        link.classList.add('nav-link');
    });

    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const emailInput = form.querySelector('input[type="email"]');
            const passwordInput = form.querySelector('input[type="password"]');
            let isValid = true;

            // Remove existing error messages
            const existingErrors = form.querySelectorAll('.error-message');
            existingErrors.forEach(error => error.remove());

            // Email validation
            if (emailInput && !isValidEmail(emailInput.value)) {
                e.preventDefault();
                showError(emailInput, 'Please enter a valid email address');
                isValid = false;
            }

            // Password validation
            if (passwordInput && passwordInput.value.length < 6) {
                e.preventDefault();
                showError(passwordInput, 'Password must be at least 6 characters long');
                isValid = false;
            }

            // Show loading spinner if form is valid
            if (isValid) {
                const submitButton = form.querySelector('button[type="submit"]');
                submitButton.innerHTML = '<div class="spinner"></div>';
                submitButton.disabled = true;
            }
        });
    });

    // Error message animation
    const errorMessages = document.querySelectorAll('.bg-red-100');
    errorMessages.forEach(message => {
        message.classList.add('error-message');
    });
});

// Helper functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showError(input, message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'text-red-500 text-sm mt-1 error-message';
    errorDiv.textContent = message;
    input.parentNode.appendChild(errorDiv);
    input.classList.add('border-red-500');

    // Remove error state after 5 seconds
    setTimeout(() => {
        errorDiv.remove();
        input.classList.remove('border-red-500');
    }, 5000);
} 