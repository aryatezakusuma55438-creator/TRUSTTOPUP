/* ============================================================
   theme-switcher.js
   Instantly toggles between three look-and-feels:
     - "default"  -> the site's original style.css (no class added)
     - "simple"   -> adds body class "theme-simple"   (loads simple.css rules)
     - "modern"   -> adds body class "theme-modern"   (loads modern.css rules)
   Persisted in localStorage so it survives navigation/reload.
   simple.css and modern.css are always loaded on every page but every
   rule inside them is scoped under body.theme-simple / body.theme-modern,
   so they have zero effect until this switcher turns them on.
   ============================================================ */
(function () {
  var KEY = 'tt_theme_v1';
  var THEMES = ['default', 'simple', 'modern'];

  function apply(theme) {
    document.body.classList.remove('theme-simple', 'theme-modern');
    if (theme === 'simple') document.body.classList.add('theme-simple');
    if (theme === 'modern') document.body.classList.add('theme-modern');
    document.querySelectorAll('.tt-theme-pill').forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-theme') === theme);
    });
    window.dispatchEvent(new CustomEvent('tt-theme-change', { detail: { theme: theme } }));
  }

  function setTheme(theme) {
    if (THEMES.indexOf(theme) === -1) theme = 'default';
    try { localStorage.setItem(KEY, theme); } catch (e) {}
    apply(theme);
  }

  function getTheme() {
    try { return localStorage.getItem(KEY) || 'default'; } catch (e) { return 'default'; }
  }

  // Apply saved theme as early as possible (before paint where possible)
  apply(getTheme());

  document.addEventListener('DOMContentLoaded', function () {
    apply(getTheme());
    document.querySelectorAll('.tt-theme-pill').forEach(function (btn) {
      btn.addEventListener('click', function () {
        setTheme(btn.getAttribute('data-theme'));
      });
    });
  });

  window.TTThemeSwitcher = { setTheme: setTheme, getTheme: getTheme };
})();
