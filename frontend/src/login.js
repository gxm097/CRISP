const usernameInput = document.querySelector('#username');
const passwordInput = document.querySelector('#password');
const loginButton = document.querySelector('#login-button');
const errorMessage = document.querySelector('#message');

function handleLogin() {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  const users = JSON.parse(localStorage.getItem('crispUsers')) || [];

  const match = users.find(user => user.username === username && user.password === password);

  if (match) {
    window.location.href = 'SWE Project.html';
  } else {
    errorMessage.textContent = 'Wrong username or password, or no account exists.'
  }
}

loginButton.addEventListener('click', handleLogin);