// Theme — runs after <head> inline script sets initial attribute
(function () {
  const THEMES = ['light', 'dark', 'system'];

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('byn-theme', t);
    document.querySelectorAll('.theme-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.theme === t);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    // Bind toggle buttons
    document.querySelectorAll('.theme-btn').forEach(b => {
      b.addEventListener('click', () => setTheme(b.dataset.theme));
    });
    // Sync active state (theme was already applied by inline head script)
    setTheme(localStorage.getItem('byn-theme') || 'system');

    // Copy-to-clipboard for cmd blocks
    document.querySelectorAll('.cmd-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        const text = btn.previousElementSibling
          ? btn.previousElementSibling.textContent.trim()
          : btn.closest('.cmd-block')?.querySelector('span')?.textContent.trim() || '';
        navigator.clipboard?.writeText(text).then(() => {
          const orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(() => (btn.textContent = orig), 1600);
        });
      });
    });

    // Scroll-spy — updates TOC active item as user scrolls
    initScrollSpy();
  });

  function initScrollSpy() {
    const main = document.querySelector('.docs-main');
    if (!main) return;
    const headings = [...main.querySelectorAll('h2[id], h3[id]')];
    const tocLinks = [...document.querySelectorAll('.docs-toc a[href^="#"]')];
    if (!headings.length || !tocLinks.length) return;

    // Cache absolute positions once (static docs page, heights don't change)
    const positions = headings.map(h => ({
      id: h.id,
      top: h.getBoundingClientRect().top + window.scrollY,
    }));

    function update() {
      // 80px = nav height + a little breathing room
      const threshold = window.scrollY + 80;
      let activeId = positions[0].id;
      for (const p of positions) {
        if (p.top <= threshold) activeId = p.id;
      }
      tocLinks.forEach(a => {
        a.classList.toggle('active', a.getAttribute('href') === '#' + activeId);
      });
    }

    let raf = null;
    window.addEventListener('scroll', () => {
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => { update(); raf = null; });
    }, { passive: true });

    update();
  }
})();
