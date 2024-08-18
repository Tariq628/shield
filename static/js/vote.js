function submitForm() {
    const name = document.getElementById('name').value;
    const category = document.getElementById('category').value;
    const location = document.getElementById('location').value;
    const description = document.getElementById('description').value;

    fetch('/submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, category, location, description }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showConfirmation('Response submitted successfully!');
        } else {
            showConfirmation(data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showConfirmation('Error submitting response');
    });
}

function showConfirmation(message) {
    const confirmationOverlay = document.getElementById('confirmation-overlay');
    const confirmationMessage = document.getElementById('confirmation-message');
    confirmationMessage.textContent = message;
    confirmationOverlay.classList.add('active');
    setTimeout(() => {
        document.querySelector('.confirmation-content').classList.add('active');
    }, 10);
}

function closeConfirmation() {
    const confirmationOverlay = document.getElementById('confirmation-overlay');
    document.querySelector('.confirmation-content').classList.remove('active');
    setTimeout(() => {
        confirmationOverlay.classList.remove('active');
    }, 500);
}

document.addEventListener('DOMContentLoaded', function() {
    checkSessionStatus();
});

function checkSessionStatus() {
    fetch('/session-status')
        .then(response => response.json())
        .then(data => {
            if (data.loggedIn) {
                const welcomeMessage = document.getElementById('welcome-message');
                welcomeMessage.textContent = `Welcome ${data.first_name} ${data.last_name}`;
                welcomeMessage.style.display = 'inline';
                const signInButton = document.getElementById('sign-in');
                if (signInButton) {
                    signInButton.style.display = 'none';
                }
                const logoutButton = document.getElementById('logout-button');
                if (logoutButton) {
                    logoutButton.style.display = 'inline';
                }
            }
        })
        .catch(error => console.error('Error checking session status:', error));
}

function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function logout() {
    fetch('/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const welcomeMessage = document.getElementById('welcome-message');
            welcomeMessage.style.display = 'none';
            const signInButton = document.getElementById('sign-in');
            if (signInButton) {
                signInButton.style.display = 'inline';
            }
            const logoutButton = document.getElementById('logout-button');
            if (logoutButton) {
                logoutButton.style.display = 'none';
            }
        } else {
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Error logging out:', error);
    });
}
