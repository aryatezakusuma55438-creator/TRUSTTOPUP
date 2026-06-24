// ============ STARS ============
const starsContainer = document.getElementById('stars-container');
if (starsContainer) {
  for (let i = 0; i < 80; i++) {
    const star = document.createElement('div');
    star.classList.add('star');
    const size = Math.random() * 3 + 1;
    star.style.cssText = `width:${size}px;height:${size}px;top:${Math.random()*100}%;left:${Math.random()*100}%;animation-delay:${Math.random()*3}s;animation-duration:${1.5+Math.random()*2}s;`;
    starsContainer.appendChild(star);
  }
}

// ============ LOADING SCREEN ============
// Tied to the actual page 'load' event (not a fixed timer), so a slow
// connection naturally shows a longer loading animation, and a fast one
// dismisses it almost immediately.
const introEl = document.getElementById('intro');
if (introEl) {
  let introEnded = false;
  const MIN_VISIBLE_MS = 500; // avoid a jarring instant-flash on very fast loads
  const shownAt = Date.now();

  function endIntro() {
    if (introEnded) return;
    introEnded = true;
    const elapsed = Date.now() - shownAt;
    const wait = Math.max(0, MIN_VISIBLE_MS - elapsed);
    setTimeout(() => {
      introEl.style.transition = 'opacity 0.5s ease';
      introEl.style.opacity = '0';
      setTimeout(() => {
        introEl.style.display = 'none';
        const m = document.getElementById('main-site');
        if (m) m.classList.add('visible');
      }, 500);
    }, wait);
  }

  window.skipIntro = function() { endIntro(); }

  if (new URLSearchParams(window.location.search).get('skip') === '1') {
    endIntro();
  } else if (document.readyState === 'complete') {
    endIntro();
  } else {
    window.addEventListener('load', endIntro);
    setTimeout(endIntro, 15000); // safety net
  }
}

// ============ NAV ============
document.addEventListener('click',(e)=>{
  const menu=document.getElementById('dotsMenu');
  const overlay=document.getElementById('navOverlay');
  const btn=document.getElementById('hamburgerBtn');
  const dotsBtn=document.getElementById('dotsBtn');
  if(!menu) return;
  const clickedBtn = (btn && btn.contains(e.target)) || (dotsBtn && dotsBtn.contains(e.target));
  if(!clickedBtn && !menu.contains(e.target) && menu.classList.contains('open')){
    menu.classList.remove('open');
    if(overlay) overlay.classList.remove('open');
  }
});
function toggleMenu() {
  const m = document.getElementById('dotsMenu');
  const o = document.getElementById('navOverlay');
  if (!m) return;
  const isOpen = m.classList.contains('open');
  if (isOpen) {
    m.classList.remove('open');
    if (o) o.classList.remove('open');
  } else {
    m.classList.add('open');
    if (o) o.classList.add('open');
  }
}
function closeMenu() {
  const m = document.getElementById('dotsMenu');
  const o = document.getElementById('navOverlay');
  if (m) m.classList.remove('open');
  if (o) o.classList.remove('open');
}
function scrollToGames() { const el=document.getElementById('games-section'); if(el) el.scrollIntoView({behavior:'smooth'}); }

// ============ MODALS (Donate only -- top-up now lives on /topup/<slug>) ============
function openDonate(e) {
  if(e) e.preventDefault();
  const menu=document.getElementById('dotsMenu');
  const overlay=document.getElementById('navOverlay');
  if(menu) menu.classList.remove('open');
  if(overlay) overlay.classList.remove('open');
  const d=document.getElementById('donate-modal'); if(d) d.classList.add('open');
}
function closeDonate() { const d=document.getElementById('donate-modal'); if(d) d.classList.remove('open'); }

const donateModal = document.getElementById('donate-modal');
if (donateModal) donateModal.addEventListener('click', e=>{ if(e.target===donateModal) closeDonate(); });

function showToast(msg) {
  const t=document.getElementById('toast'); if(!t) return;
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),3500);
}

// ===== BANNER SLIDESHOW =====
let currentSlide = 0;
const totalSlides = 4;
let bannerInterval;

function goSlide(index) {
  const slides = document.querySelectorAll('.banner-slide');
  const dots   = document.querySelectorAll('.banner-dot');
  if (!slides.length) return;
  slides[currentSlide].classList.remove('active');
  dots[currentSlide].classList.remove('active');
  currentSlide = index;
  slides[currentSlide].classList.add('active');
  dots[currentSlide].classList.add('active');
}

function nextSlide() {
  goSlide((currentSlide + 1) % totalSlides);
}

function startBanner() {
  if (document.querySelector('.banner-slider')) {
    bannerInterval = setInterval(nextSlide, 5000);
  }
}

document.addEventListener('DOMContentLoaded', startBanner);

// ============ GAME SEARCH (navbar) ============
function toggleMobileSearch(barId) {
  const bar = document.getElementById(barId);
  if (!bar) return;
  bar.classList.toggle('open');
  if (bar.classList.contains('open')) {
    const input = bar.querySelector('input');
    if (input) setTimeout(() => input.focus(), 50);
  }
}

function filterGames(query, resultsId) {
  resultsId = resultsId || 'game-search-results';
  const resultsEl = document.getElementById(resultsId);
  if (!resultsEl) return;

  const q = query.trim().toLowerCase();
  if (!q) { resultsEl.classList.remove('open'); resultsEl.innerHTML = ''; return; }

  const games = window.ALL_GAMES || [];
  const matches = games.filter(g => g.name.toLowerCase().includes(q));

  if (matches.length === 0) {
    resultsEl.innerHTML = '<div class="nav-search-empty">No games found.</div>';
  } else {
    resultsEl.innerHTML = matches.map(g => `
      <a href="/topup/${g.slug}" class="nav-search-result-item">
        <img src="/static/game/${g.image}" alt="${g.name}" onerror="this.style.display='none'">
        <div>
          <div class="nav-search-result-name">${g.name}</div>
          <div class="nav-search-result-price">Starting ${g.price}</div>
        </div>
      </a>
    `).join('');
  }
  resultsEl.classList.add('open');
}

// Close search dropdown when clicking outside of it
document.addEventListener('click', (e) => {
  document.querySelectorAll('.nav-search-results.open').forEach(el => {
    const wrapper = el.closest('.nav-center');
    if (wrapper && !wrapper.contains(e.target)) el.classList.remove('open');
  });
});
