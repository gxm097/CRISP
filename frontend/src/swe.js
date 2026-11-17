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

function applyTheme(isDark) {
  document.body.classList.toggle('dark', isDark);
  themeToggle.textContent = isDark ? 'Default' : 'Dark Mode';
  localStorage.setItem('crispTheme', isDark ? 'dark' : 'light');
}

applyTheme(localStorage.getItem('crispTheme') === 'dark');

themeToggle.addEventListener('click', () => {
  applyTheme(!document.body.classList.contains('dark'));
});