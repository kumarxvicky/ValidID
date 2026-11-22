const loginView = document.querySelector('#login-view');
const controlView = document.querySelector('#control-view');
const loginForm = document.querySelector('#admin-login-form');
const loginMessage = document.querySelector('#login-message');
const adminMessage = document.querySelector('#admin-message');
const accountList = document.querySelector('#account-list');
const accountCount = document.querySelector('#account-count');
const loginButton = document.querySelector('#login-button');
let csrfToken = '';
let currentUser = null;

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

function showLoginMessage(text, success = false) {
  loginMessage.textContent = text;
  loginMessage.classList.toggle('success', success);
  loginMessage.hidden = false;
}

function showAdminMessage(text, success = false) {
  adminMessage.textContent = text;
  adminMessage.classList.toggle('success', success);
  adminMessage.hidden = false;
}

function renderLogin() {
  currentUser = null;
  controlView.hidden = true;
  loginView.hidden = false;
}

function renderControl(user) {
  currentUser = user;
  loginView.hidden = true;
  controlView.hidden = false;
  document.querySelector('#signed-in-name').textContent = user.name;
  loadAccounts();
}

function createAction(label, action, accountId, danger = false) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `account-action${danger ? ' danger' : ''}`;
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.accountId = String(accountId);
  return button;
}

function renderAccounts(users) {
  accountList.replaceChildren();
  accountCount.textContent = `${users.length} account${users.length === 1 ? '' : 's'}`;
  if (!users.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-list';
    empty.textContent = 'No registered accounts yet.';
    accountList.append(empty);
    return;
  }

  for (const user of users) {
    const row = document.createElement('article');
    row.className = 'account-row';
    const info = document.createElement('div');
    info.className = 'account-info';
    const name = document.createElement('strong');
    name.className = 'account-name';
    name.textContent = user.name;
    const isSelf = currentUser && user.publicId === currentUser.id;
    if (isSelf) {
      const you = document.createElement('span');
      you.className = 'you-tag';
      you.textContent = 'You';
      name.append(' ', you);
    }
    const email = document.createElement('span');
    email.className = 'account-email';
    email.textContent = user.email;
    info.append(name, email);

    const labels = document.createElement('div');
    labels.className = 'account-labels';
    const role = document.createElement('span');
    role.className = `tag${user.role === 'admin' ? ' admin' : ''}`;
    role.textContent = user.role === 'admin' ? 'Admin' : 'User';
    const status = document.createElement('span');
    status.className = `tag ${user.isActive ? 'active' : 'disabled'}`;
    status.textContent = user.isActive ? 'Active' : 'Disabled';
    labels.append(role, status);

    const actions = document.createElement('div');
    actions.className = 'account-actions';
    if (!isSelf) {
      actions.append(createAction(user.role === 'admin' ? 'Remove admin' : 'Make admin', 'role', user.id));
      actions.append(createAction(user.isActive ? 'Disable' : 'Enable', 'status', user.id, user.isActive));
    }
    row.append(info, labels, actions);
    accountList.append(row);
  }
}

async function loadAccounts() {
  accountList.setAttribute('aria-busy', 'true');
  accountList.textContent = 'Loading accounts…';
  try {
    const data = await api('/api/admin/users');
    renderAccounts(data.users);
  } catch (error) {
    accountList.replaceChildren();
    accountCount.textContent = 'Accounts unavailable';
    showAdminMessage(error.message);
  } finally {
    accountList.setAttribute('aria-busy', 'false');
  }
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  loginMessage.hidden = true;
  loginButton.disabled = true;
  loginButton.textContent = 'Signing in…';
  try {
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        email: document.querySelector('#admin-email').value.trim(),
        password: document.querySelector('#admin-password').value,
      }),
    });
    csrfToken = data.csrfToken;
    if (data.user.role !== 'admin') {
      await api('/api/logout', { method: 'POST', body: '{}' });
      await refreshCsrf();
      return showLoginMessage('This account does not have administrator access.');
    }
    loginForm.reset();
    renderControl(data.user);
  } catch (error) {
    showLoginMessage(error.message);
  } finally {
    loginButton.disabled = false;
    loginButton.textContent = 'Sign in to admin';
  }
});

document.querySelector('#show-password').addEventListener('click', (event) => {
  const input = document.querySelector('#admin-password');
  const visible = input.type === 'text';
  input.type = visible ? 'password' : 'text';
  event.currentTarget.textContent = visible ? 'Show' : 'Hide';
  event.currentTarget.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
});

document.querySelector('#reload-accounts').addEventListener('click', loadAccounts);
accountList.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  button.disabled = true;
  adminMessage.hidden = true;
  try {
    if (button.dataset.action === 'role') {
      const row = button.closest('.account-row');
      const currentlyAdmin = row.querySelector('.tag.admin') !== null;
      await api(`/api/admin/users/${button.dataset.accountId}/role`, {
        method: 'PATCH',
        body: JSON.stringify({ role: currentlyAdmin ? 'user' : 'admin' }),
      });
      showAdminMessage(currentlyAdmin ? 'Admin access removed.' : 'Admin access granted.', true);
    } else {
      const isActive = button.textContent.trim() === 'Enable';
      await api(`/api/admin/users/${button.dataset.accountId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ isActive }),
      });
      showAdminMessage(isActive ? 'Account enabled.' : 'Account disabled.', true);
    }
    await loadAccounts();
  } catch (error) {
    showAdminMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

document.querySelector('#admin-signout').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
    await refreshCsrf();
    renderLogin();
    loginMessage.hidden = true;
    loginForm.reset();
  } catch (error) {
    showAdminMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

async function initialize() {
  try {
    await refreshCsrf();
    const data = await api('/api/me');
    if (data.user.role === 'admin') renderControl(data.user);
    else showLoginMessage('This account does not have administrator access.');
  } catch (error) {
    renderLogin();
    if (!error.message.includes('sign in')) showLoginMessage(error.message);
  }
}

initialize();
