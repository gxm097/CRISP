// Shared sidebar for every CRISP page.
// Add <script src="/src/layout.js"></script> at the end of a page's <body>.
(function () {
    const mainPages = [
        { href: '/overview', label: 'Overview', icon: 'overview' },
        { href: '/inventory', label: 'Inventory', icon: 'inventory' },
        { href: '/assessments', label: 'Assessments', icon: 'assessments' },
        { href: '/findings', label: 'Findings', icon: 'findings' },
        { href: '/reports', label: 'Reports', icon: 'reports' },
        { href: '/settings', label: 'Settings', icon: 'settings' }
    ];

    function link(page) {
        const active = window.location.pathname === page.href ? ' active' : '';
        return `
            <a class="sidebar-tabs${active}" href="${page.href}">
                <img src="/icons/${page.icon}.png" alt="">
                <div>${page.label}</div>
            </a>`;
    }

    const sidebar = document.createElement('aside');
    sidebar.className = 'sidebar';
    sidebar.innerHTML = `
        <div class="crisp">Crisp</div>
        ${mainPages.map(link).join('')}
        <a class="sign-out-tab" href="/logout">
            <img src="/icons/sign-out.png" alt="">
            <div>Sign out</div>
        </a>`;

    document.body.prepend(sidebar);
    document.body.classList.add('has-sidebar');

    // keep the theme chosen on the Settings page
    try {
        document.body.classList.toggle('dark', localStorage.getItem('crispTheme') === 'dark');
    } catch (e) {}
})();
