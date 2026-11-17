const usernameInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const signupButton = document.querySelector('#signup');
const message = document.querySelector('#message');

function handleSignup() {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (username === '' || password === '') {
    message.textContent = 'Please fill in both fields.';
    return;
  }

  const users = JSON.parse(localStorage.getItem('crispUsers')) || [];

  const exists = users.some(user => user.username === username);
  if (exists) {
    message.textContent = 'That username is already taken.';
    return;
  }

  users.push({ username, password });
  localStorage.setItem('crispUsers', JSON.stringify(users));
  message.textContent = 'Account created! You can now log in.';
}

signupButton.addEventListener('click', handleSignup);