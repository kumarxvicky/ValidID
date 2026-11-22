const authView = document.querySelector('#auth-view');
const dashboardView = document.querySelector('#dashboard-view');
const form = document.querySelector('#auth-form');
const nameField = document.querySelector('#name-field');
const nameInput = document.querySelector('#name');
const emailInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const passwordHint = document.querySelector('#password-hint');
const message = document.querySelector('#form-message');
const submitButton = document.querySelector('#submit-button');
const loginTab = document.querySelector('#login-tab');
const registerTab = document.querySelector('#register-tab');
let mode = 'login';
let csrfToken = '';

document.querySelector('#year').textContent = new Date().getFullYear();

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (options.method && options.method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Something went wrong. Please try again.');
  return data;
}

async function refreshCsrf() {
  const data = await api('/api/csrf');
  csrfToken = data.csrfToken;
}

function setMode(nextMode) {
  mode = nextMode;
  const registering = mode === 'register';
  nameField.hidden = !registering;
  nameInput.required = registering;
  passwordHint.hidden = !registering;
  passwordInput.autocomplete = registering ? 'new-password' : 'current-password';
  loginTab.classList.toggle('active', !registering);
  registerTab.classList.toggle('active', registering);
  loginTab.setAttribute('aria-selected', String(!registering));
  registerTab.setAttribute('aria-selected', String(registering));
  document.querySelector('#form-eyebrow').textContent = registering ? 'GET STARTED' : 'WELCOME BACK';
  document.querySelector('#form-title').innerHTML = registering ? 'Create your<br>identity' : 'Sign in to your<br>identity portal';
  document.querySelector('#form-subtitle').textContent = registering ? 'Set up your account in just a moment.' : 'Enter your details to continue.';
  document.querySelector('#submit-button span:first-child').textContent = registering ? 'Create my account' : 'Sign in';
  document.querySelector('#terms-note').textContent = registering
    ? 'By creating an account, you’ll receive a unique user ID for your identity.'
    : 'Your account is protected with securely hashed passwords and a private session.';
  message.hidden = true;
  message.textContent = '';
}

function showMessage(text, success = false) {
  message.textContent = text;
  message.classList.toggle('success', success);
  message.hidden = false;
}

function renderDashboard(user) {
  authView.hidden = true;
  dashboardView.hidden = false;
  document.querySelector('#welcome-title').textContent = `Welcome, ${user.name.split(' ')[0]}`;
  document.querySelector('#profile-name').textContent = user.name;
  document.querySelector('#profile-email').textContent = user.email;
  document.querySelector('#profile-avatar').textContent = user.name.trim().charAt(0).toUpperCase();
  document.querySelector('#public-id').textContent = user.id;
  document.querySelector('#copy-feedback').textContent = 'Keep your ID handy when you need to identify your account.';
}

function renderAuth() {
  dashboardView.hidden = true;
  authView.hidden = false;
}

loginTab.addEventListener('click', () => setMode('login'));
registerTab.addEventListener('click', () => setMode('register'));

document.querySelector('#toggle-password').addEventListener('click', (event) => {
  const visible = passwordInput.type === 'text';
  passwordInput.type = visible ? 'password' : 'text';
  event.currentTarget.textContent = visible ? 'Show' : 'Hide';
  event.currentTarget.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.hidden = true;
  const payload = { email: emailInput.value.trim(), password: passwordInput.value };
  if (mode === 'register') payload.name = nameInput.value.trim();
  submitButton.disabled = true;
  submitButton.querySelector('span:first-child').textContent = mode === 'register' ? 'Creating account…' : 'Signing in…';

  try {
    const data = await api(mode === 'register' ? '/api/register' : '/api/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    csrfToken = data.csrfToken;
    renderDashboard(data.user);
    form.reset();
  } catch (error) {
    showMessage(error.message);
  } finally {
    submitButton.disabled = false;
    submitButton.querySelector('span:first-child').textContent = mode === 'register' ? 'Create my account' : 'Sign in';
  }
});

document.querySelector('#copy-id').addEventListener('click', async () => {
  const id = document.querySelector('#public-id').textContent;
  try {
    await navigator.clipboard.writeText(id);
    document.querySelector('#copy-feedback').textContent = 'Your user ID has been copied.';
  } catch {
    document.querySelector('#copy-feedback').textContent = 'Select and copy your user ID above.';
  }
});

document.querySelector('#logout-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
    await refreshCsrf();
    renderAuth();
    setMode('login');
    emailInput.value = '';
    passwordInput.value = '';
  } catch (error) {
    document.querySelector('#copy-feedback').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

async function initialize() {
  try {
    await refreshCsrf();
    const data = await api('/api/me');
    renderDashboard(data.user);
  } catch (error) {
    renderAuth();
    if (!error.message.includes('sign in')) showMessage(error.message);
  }
}

initialize();
