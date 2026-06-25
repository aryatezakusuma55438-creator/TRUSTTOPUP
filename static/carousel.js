/* ============================================================
   carousel.js — Netflix/Steam-style horizontal carousel
   - Mouse drag, touch swipe, arrow nav, autoplay, infinite loop
   - Usage: <div class="tt-carousel" data-autoplay="4000">
              <div class="tt-carousel-track">...cards...</div>
              <button class="tt-car-arrow tt-car-prev">‹</button>
              <button class="tt-car-arrow tt-car-next">›</button>
            </div>

   Coexistence with coverflow.js (Modern theme only):
   When root.dataset.coverflow === '1', coverflow.js owns this carousel's
   visuals/interaction entirely. Every interactive entry point below is
   guarded to no-op in that state, rather than tearing this engine down —
   that keeps things simple and lets switching themes back to Simple/Default
   instantly resume this engine with zero re-init.
   root._ttPause / root._ttPlay are exposed so coverflow.js can stop this
   engine's autoplay/timers while it's in control, and hand control back.
   ============================================================ */
(function () {
  function initCarousel(root) {
    var track = root.querySelector('.tt-carousel-track');
    if (!track) return;
    var originals = Array.prototype.slice.call(track.children);
    if (originals.length === 0) return;

    function isCoverflowActive() { return root.dataset.coverflow === '1'; }

    // Clone a batch at start + end for seamless infinite loop.
    // Clones are stripped of data-original so coverflow.js (which only
    // ever looks at [data-original] cards) never sees or touches them.
    var cloneCount = Math.min(originals.length, 5);
    var endClones = originals.slice(0, cloneCount).map(function (n) {
      var c = n.cloneNode(true); c.removeAttribute('data-original'); return c;
    });
    var startClones = originals.slice(-cloneCount).map(function (n) {
      var c = n.cloneNode(true); c.removeAttribute('data-original'); return c;
    });
    startClones.forEach(function (c) { track.insertBefore(c, track.firstChild); });
    endClones.forEach(function (c) { track.appendChild(c); });

    var allCards = function () { return Array.prototype.slice.call(track.children); };
    var cardWidth = function () {
      var c = track.children[0];
      if (!c) return 0;
      var style = getComputedStyle(track);
      var gap = parseFloat(style.gap || style.columnGap || 0) || 0;
      return c.getBoundingClientRect().width + gap;
    };

    // Position so the "real" first item is in view (skip the prepended start clones)
    function settle() {
      if (isCoverflowActive()) return;
      track.style.scrollBehavior = 'auto';
      track.scrollLeft = cardWidth() * cloneCount;
    }
    requestAnimationFrame(function () { requestAnimationFrame(settle); });
    window.addEventListener('resize', function () { settle(); });

    function loopCheck() {
      if (isCoverflowActive()) return;
      var cw = cardWidth();
      if (!cw) return;
      var max = cw * (allCards().length - cloneCount);
      if (track.scrollLeft <= cw * 0.5) {
        track.style.scrollBehavior = 'auto';
        track.scrollLeft += cw * originals.length;
      } else if (track.scrollLeft >= max - cw * 0.5) {
        track.style.scrollBehavior = 'auto';
        track.scrollLeft -= cw * originals.length;
      }
    }

    function scrollByCards(n) {
      if (isCoverflowActive()) return;
      track.style.scrollBehavior = 'smooth';
      track.scrollLeft += cardWidth() * n;
    }

    // Arrow buttons
    var prevBtn = root.querySelector('.tt-car-prev');
    var nextBtn = root.querySelector('.tt-car-next');
    if (prevBtn) prevBtn.addEventListener('click', function () { scrollByCards(-1); pauseThenResume(); });
    if (nextBtn) nextBtn.addEventListener('click', function () { scrollByCards(1); pauseThenResume(); });

    // Drag (mouse) + swipe (touch) via pointer events
    var isDown = false, startX = 0, startScroll = 0, moved = 0;
    track.addEventListener('pointerdown', function (e) {
      if (isCoverflowActive()) return;
      isDown = true;
      moved = 0;
      startX = e.clientX;
      startScroll = track.scrollLeft;
      track.style.scrollBehavior = 'auto';
      track.setPointerCapture && track.setPointerCapture(e.pointerId);
      pause();
    });
    track.addEventListener('pointermove', function (e) {
      if (!isDown || isCoverflowActive()) return;
      var dx = e.clientX - startX;
      moved = Math.abs(dx);
      track.scrollLeft = startScroll - dx;
    });
    function endDrag() {
      if (!isDown) return;
      isDown = false;
      loopCheck();
      pauseThenResume();
    }
    track.addEventListener('pointerup', endDrag);
    track.addEventListener('pointercancel', endDrag);
    track.addEventListener('pointerleave', function () { if (isDown) endDrag(); });

    // Prevent click-through on cards after a real drag
    track.addEventListener('click', function (e) {
      if (moved > 6) { e.preventDefault(); e.stopPropagation(); }
    }, true);

    track.addEventListener('scroll', function () {
      if (isCoverflowActive()) return;
      window.clearTimeout(track._loopT);
      track._loopT = window.setTimeout(loopCheck, 80);
    });

    // Autoplay
    var autoplayMs = parseInt(root.getAttribute('data-autoplay') || '0', 10);
    var timer = null;
    function play() {
      if (!autoplayMs || isCoverflowActive()) return;
      timer = window.setInterval(function () { scrollByCards(1); }, autoplayMs);
    }
    function pause() { if (timer) { clearInterval(timer); timer = null; } }
    function pauseThenResume() {
      pause();
      window.clearTimeout(root._resumeT);
      root._resumeT = window.setTimeout(play, 2500);
    }
    root.addEventListener('mouseenter', pause);
    root.addEventListener('mouseleave', play);
    play();

    // Exposed so coverflow.js can take over cleanly and hand control back
    root._ttPause = pause;
    root._ttPlay = play;
  }

  function initAll() {
    document.querySelectorAll('.tt-carousel').forEach(initCarousel);
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(initAll, 0);
  } else {
    document.addEventListener('DOMContentLoaded', initAll);
  }
})();
