const tabs = document.querySelectorAll('.sidebar-tabs');
const views = document.querySelectorAll('.view');

function doSomething(event) {
  const name = event.currentTarget.dataset.view;

  views.forEach(view => {
    view.classList.toggle('hidden', view.id !== name);
  });
}

tabs.forEach(tab => {
  tab.addEventListener('click', doSomething);
});


const themeToggle = document.querySelector('#dark-toggle');
const themeIcon = themeToggle.querySelector('.theme-icon');
const themeLabel = themeToggle.querySelector('.theme-label');

const moonIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';

const sunIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/><line x1="4.9" y1="4.9" x2="6.3" y2="6.3"/><line x1="17.7" y1="17.7" x2="19.1" y2="19.1"/><line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/><line x1="4.9" y1="19.1" x2="6.3" y2="17.7"/><line x1="17.7" y1="6.3" x2="19.1" y2="4.9"/></svg>';

function applyTheme(isDark) {
  document.body.classList.toggle('dark', isDark);
  themeIcon.innerHTML = isDark ? sunIcon : moonIcon;
  themeLabel.textContent = isDark ? 'Light mode' : 'Dark mode';
  localStorage.setItem('crispTheme', isDark ? 'dark' : 'light');
}

applyTheme(localStorage.getItem('crispTheme') === 'dark');

themeToggle.addEventListener('click', () => {
  applyTheme(!document.body.classList.contains('dark'));
});


const signOutTab = document.querySelector('.sign-out-tab');

signOutTab.addEventListener('click', () => {
  window.location.href = '/logout';
});