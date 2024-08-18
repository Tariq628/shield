document.addEventListener('DOMContentLoaded', function() {
    checkSessionStatus();
    updateMobileNav();

    const signInButton = document.getElementById('sign-in');
    if (signInButton) {
        signInButton.addEventListener('click', function(event) {
            event.preventDefault();
            openModal();
        });
    }

    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', function(event) {
            event.preventDefault();
            logout();
        });
    }

    const scrollToTopBtn = document.getElementById('scrollToTopBtn');
    
    window.addEventListener('scroll', function() {
        if (window.scrollY > 300) { // Show button after scrolling down 300px
            scrollToTopBtn.classList.add('show');
        } else {
            scrollToTopBtn.classList.remove('show');
        }
    });

    scrollToTopBtn.addEventListener('click', function() {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
});

function openModal() {
    document.body.classList.add('modal-active', 'modal-opening');
    document.getElementById('modal-overlay').classList.add('active');
    document.querySelector('.modal-content').classList.add('active');
    setTimeout(() => {
        document.body.classList.remove('modal-opening');
    }, 500); // Duration of the transition
}

function closeModal() {
    document.body.classList.add('modal-closing');
    document.querySelector('.modal-content').classList.remove('active');
    document.getElementById('modal-overlay').classList.remove('active');
    setTimeout(() => {
        document.body.classList.remove('modal-active', 'modal-closing');
    }, 0); // Duration of the transition
}

document.getElementById('modal-overlay').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});

function login() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const welcomeMessage = document.getElementById('welcome-message');
            welcomeMessage.textContent = `Welcome ${data.firstName} ${data.lastName}`;
            welcomeMessage.style.display = 'inline';
            const signInButton = document.getElementById('sign-in');
            if (signInButton) {
                signInButton.style.display = 'none';
            }
            const logoutButton = document.getElementById('logout-button');
            if (logoutButton) {
                logoutButton.style.display = 'inline';
            }
            closeModal();
            updateMobileNav();
        } else {
            alert(data.message);
        }
    })
    .catch(error => {
        console.error('Error logging in:', error);
    });
}

function updateMobileNav() {
    fetch('/session-status')
        .then(response => response.json())
        .then(data => {
            const signInButton = document.getElementById('sign-in');
            const logoutButton = document.getElementById('logout-button');

            if (data.loggedIn) {
                if (signInButton) {
                    signInButton.style.display = 'none';
                }
                if (logoutButton) {
                    logoutButton.style.display = 'inline';
                }
            } else {
                if (signInButton) {
                    signInButton.style.display = 'inline';
                }
                if (logoutButton) {
                    logoutButton.style.display = 'none';
                }
            }
        })
        .catch(error => console.error('Error checking session status:', error));
}

function scrollToSection() {
    const section = document.getElementById('main');
    section.scrollIntoView({ behavior: 'smooth' });
}

function checkLoginStatusAndVote(event) {
    event.preventDefault();
    fetch('/session-status')
        .then(response => response.json())
        .then(data => {
            if (data.loggedIn) {
                window.location.href = 'contact.html';
            } else {
                openModal();
            }
        })
        .catch(error => console.error('Error checking session status:', error));
}
