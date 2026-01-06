document.addEventListener('DOMContentLoaded', () => {

    // --- MODAL TOGGLE LOGIC ---
    const modal = document.getElementById('login-modal');
    const openBtns = [
        document.getElementById('login-btn-nav'),
        document.getElementById('login-btn-hero')
    ];
    const closeBtn = document.getElementById('close-modal');

    function openModal() {
        modal.classList.remove('hidden');
    }

    function closeModal() {
        modal.classList.add('hidden');
    }

    openBtns.forEach(btn => {
        if (btn) btn.addEventListener('click', openModal);
    });

    if (closeBtn) closeBtn.addEventListener('click', closeModal);

    // Close on click outside
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });


    // --- FORM SUBMIT LOGIC (Reuse existing backend) ---
    const loginForm = document.getElementById('login-form');
    const errorBox = document.getElementById('error-message');
    const submitBtn = document.getElementById('submit-btn');

    async function getCsrfToken() {
        try {
            const res = await fetch('/api/auth/csrf-token');
            const data = await res.json();
            return data.csrf_token || data.csrfToken;
        } catch (e) {
            console.error('CSRF fetch failed', e);
            return null;
        }
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // UI Reset
        errorBox.classList.add('hidden');
        errorBox.textContent = '';
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging in...';

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        // 1. Get Token
        const csrfToken = await getCsrfToken();

        // 2. Post to existing /login
        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ email, password, remember: document.getElementById('remember-me').checked })
            });

            const data = await response.json();

            if (data.success) {
                // 3. Handle Success (Redirect)
                window.location.href = data.redirect || '/';
            } else {
                // 4. Handle Error
                errorBox.textContent = data.message || 'Invalid credentials';
                errorBox.classList.remove('hidden');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Login';
            }

        } catch (err) {
            errorBox.textContent = 'Network error. Please try again.';
            errorBox.classList.remove('hidden');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Login';
        }
    });

    // --- PASSWORD TOGGLE LOGIC ---
    const togglePassword = document.getElementById('toggle-password');
    const passwordInput = document.getElementById('password');

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener('click', function () {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';

            // Toggle Eye Icon
            const icon = this.querySelector('i');
            if (icon) {
                icon.classList.toggle('fa-eye', !isPassword);
                icon.classList.toggle('fa-eye-slash', isPassword);
            }
        });
    }

});
