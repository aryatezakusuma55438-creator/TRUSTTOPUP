/* ============================================================
   coverflow.js — Premium 3D Coverflow for "Popular This Week" / "Top Sellers"
   Active ONLY while body.theme-modern is on. Simple/Default themes keep
   using the original carousel.js engine untouched — see the handoff
   protocol described in carousel.js's header comment.

   - Operates only on cards marked [data-original] (the real, non-cloned
     cards carousel.js leaves behind), so both engines can read/own the
     same DOM without stepping on each other.
   - True coverflow: every card's transform is computed from its circular
     distance to a floating "center" index — infinite in both directions,
     no cloning needed since distance wraps around the full set.
   - Drag/swipe directly manipulates the center index; release applies
     momentum with friction, then eases to the nearest card (snap).
   ============================================================ */
(function () {
  var ROOT_SELECTOR = '.tt-section-carousel .tt-carousel';
  var instances = new Map(); // root -> state

  function breakpointConfig() {
    var w = window.innerWidth;
    if (w <= 640)  return { spreadX: 145, spreadZ: 160, maxRot: 38, scaleStep: 0.62, minScale: 0.3, opacityStep: 0.55 };
    if (w <= 1024) return { spreadX: 160, spreadZ: 150, maxRot: 28, scaleStep: 0.42, minScale: 0.45, opacityStep: 0.32 };
    return            { spreadX: 190, spreadZ: 170, maxRot: 25, scaleStep: 0.38, minScale: 0.5,  opacityStep: 0.26 };
  }

  function wrapDelta(d, n) {
    d = d % n;
    if (d > n / 2) d -= n;
    if (d < -n / 2) d += n;
    return d;
  }

  function buildState(root) {
    var track = root.querySelector('.tt-carousel-track');
    var cards = Array.prototype.slice.call(track.querySelectorAll('.tt-car-card[data-original]'));
    if (cards.length < 2) return null;

    // Box sizing (width/height/position/left) is owned entirely by CSS
    // (see modern.css [data-coverflow] rules, with breakpoint variants).
    // JS only ever touches transform/opacity/filter/z-index per frame —
    // mixing JS-measured pixel sizes in here was what let cards collapse
    // or balloon once they left the normal flex flow.
    cards.forEach(function (card) {
      card.style.position = 'absolute';
      card.style.top = '0';
      card.style.left = '50%';
      card.style.willChange = 'transform, opacity, filter';
    });

    track.style.transformStyle = 'preserve-3d';
    track.style.cursor = 'grab';

    return {
      root: root, track: track, cards: cards, n: cards.length,
      center: 0,            // floating center index
      velocity: 0,          // index units / ms
      dragging: false,
      startX: 0, startCenter: 0, lastX: 0, lastT: 0, moved: 0,
      rafId: null, hoverIndex: -1,
      autoplayMs: parseInt(root.getAttribute('data-autoplay') || '0', 10),
      autoplayTimer: null, resumeTimer: null,
      bound: false,
    };
  }

  function render(state, animated) {
    var cfg = breakpointConfig();
    var t = Date.now() / 1000;
    state.cards.forEach(function (card, i) {
      var d = wrapDelta(i - state.center, state.n);
      var absD = Math.abs(d);
      var isHover = i === state.hoverIndex && absD < 0.5;

      var scale = Math.max(cfg.minScale, 1.3 - absD * cfg.scaleStep);
      var tx = d * cfg.spreadX;
      var tz = absD < 0.05 ? 150 : (150 - absD * cfg.spreadZ);
      tz = Math.max(tz, -650);
      var rot = Math.max(-65, Math.min(65, -d * cfg.maxRot));
      var opacity = Math.max(0.12, 1 - absD * cfg.opacityStep);
      var blur = absD < 0.35 ? 0 : Math.min(absD * 1.4, 6);
      var z = Math.round(200 - absD * 10);
      var floatY = Math.sin(t * 0.8 + i * 1.3) * (absD < 0.4 ? 3 : 5);

      var hoverExtra = '';
      if (isHover) {
        tz += 40; scale *= 1.05; floatY -= 15;
        hoverExtra = ' rotateX(8deg)';
      }

      card.style.transition = animated && !state.dragging
        ? 'transform .45s cubic-bezier(.22,.9,.32,1), opacity .45s ease, filter .45s ease'
        : (state.dragging ? 'none' : 'transform .12s ease-out, opacity .2s ease, filter .2s ease');
      card.style.zIndex = z;
      card.style.opacity = opacity;
      card.style.filter = blur ? ('blur(' + blur.toFixed(1) + 'px)') : 'none';
      card.style.pointerEvents = absD > state.n / 2 - 0.5 ? 'none' : 'auto';
      card.style.setProperty('--cf-d', Math.max(0, 1 - absD).toFixed(3));
      card.style.transform =
        'translate(-50%,0) translate3d(' + tx.toFixed(1) + 'px,' + floatY.toFixed(1) + 'px,' + tz.toFixed(1) + 'px) ' +
        'rotateY(' + rot.toFixed(1) + 'deg)' + hoverExtra + ' scale(' + scale.toFixed(3) + ')';
    });
  }

  function loop(state) {
    // Idle gentle float animation when not dragging/animating momentum
    render(state, true);
    state._floatRaf = requestAnimationFrame(function () { loop(state); });
  }

  function stopMomentum(state) {
    if (state.rafId) { cancelAnimationFrame(state.rafId); state.rafId = null; }
  }

  function snapTo(state, targetIndex) {
    stopMomentum(state);
    var start = state.center, startTime = null, dur = 380;
    // shortest path to target across the wrap
    var diff = wrapDelta(targetIndex - start, state.n);
    var goal = start + diff;
    function step(ts) {
      if (!startTime) startTime = ts;
      var p = Math.min(1, (ts - startTime) / dur);
      var ease = 1 - Math.pow(1 - p, 3);
      state.center = start + (goal - start) * ease;
      render(state, false);
      if (p < 1) {
        state.rafId = requestAnimationFrame(step);
      } else {
        state.center = ((goal % state.n) + state.n) % state.n;
        render(state, false);
        scheduleAutoplay(state);
      }
    }
    state.rafId = requestAnimationFrame(step);
  }

  function runMomentum(state) {
    stopMomentum(state);
    function step() {
      state.velocity *= 0.93;
      state.center += state.velocity * 16;
      render(state, false);
      if (Math.abs(state.velocity) > 0.0006) {
        state.rafId = requestAnimationFrame(step);
      } else {
        snapTo(state, Math.round(state.center));
      }
    }
    if (Math.abs(state.velocity) > 0.0006) {
      state.rafId = requestAnimationFrame(step);
    } else {
      snapTo(state, Math.round(state.center));
    }
  }

  function scheduleAutoplay(state) {
    clearTimeout(state.resumeTimer);
    clearInterval(state.autoplayTimer);
    if (!state.autoplayMs || state.root.dataset.coverflow !== '1') return;
    state.resumeTimer = setTimeout(function () {
      state.autoplayTimer = setInterval(function () {
        if (state.dragging) return;
        snapTo(state, Math.round(state.center) + 1);
      }, state.autoplayMs);
    }, 1200);
  }

  function pauseAutoplay(state) {
    clearTimeout(state.resumeTimer);
    clearInterval(state.autoplayTimer);
  }

  function bindEvents(state) {
    if (state.bound) return;
    state.bound = true;
    var track = state.track;
    var cfg = breakpointConfig();

    track.addEventListener('pointerdown', function (e) {
      state.dragging = true;
      state.moved = 0;
      state.startX = e.clientX;
      state.startCenter = state.center;
      state.lastX = e.clientX;
      state.lastT = Date.now();
      state.velocity = 0;
      track.style.cursor = 'grabbing';
      track.setPointerCapture && track.setPointerCapture(e.pointerId);
      stopMomentum(state);
      pauseAutoplay(state);
    });

    track.addEventListener('pointermove', function (e) {
      if (!state.dragging) return;
      cfg = breakpointConfig();
      var dx = e.clientX - state.startX;
      state.moved = Math.abs(dx);
      state.center = state.startCenter - dx / cfg.spreadX;
      render(state, false);
      var now = Date.now();
      var dt = now - state.lastT;
      if (dt > 0) {
        state.velocity = (-(e.clientX - state.lastX) / cfg.spreadX) / dt;
      }
      state.lastX = e.clientX; state.lastT = now;
    });

    function endDrag() {
      if (!state.dragging) return;
      state.dragging = false;
      track.style.cursor = 'grab';
      runMomentum(state);
    }
    track.addEventListener('pointerup', endDrag);
    track.addEventListener('pointercancel', endDrag);
    track.addEventListener('pointerleave', function () { if (state.dragging) endDrag(); });

    // Click: drag of >6px cancels navigation; a real click on a non-center
    // card re-centers it instead of navigating straight away.
    state.cards.forEach(function (card, i) {
      card.addEventListener('click', function (e) {
        if (state.moved > 6) { e.preventDefault(); e.stopPropagation(); return; }
        var d = Math.abs(wrapDelta(i - state.center, state.n));
        if (d > 0.5) {
          e.preventDefault();
          snapTo(state, i);
        }
      });
      card.addEventListener('pointerenter', function () { state.hoverIndex = i; });
      card.addEventListener('pointerleave', function () { if (state.hoverIndex === i) state.hoverIndex = -1; });
    });

    window.addEventListener('resize', function () { render(state, false); });
  }

  function mount(root) {
    var state = instances.get(root);
    if (!state) {
      state = buildState(root);
      if (!state) return;
      instances.set(root, state);
      bindEvents(state);
    }
    root.dataset.coverflow = '1';
    root._ttPause && root._ttPause();
    if (!state._floatRaf) loop(state);
    render(state, false);
    scheduleAutoplay(state);
  }

  function unmount(root) {
    var state = instances.get(root);
    root.dataset.coverflow = '';
    if (state) {
      pauseAutoplay(state);
      stopMomentum(state);
      if (state._floatRaf) { cancelAnimationFrame(state._floatRaf); state._floatRaf = null; }
      state.cards.forEach(function (card) {
        ['position', 'top', 'left', 'transform', 'opacity', 'filter',
         'zIndex', 'transition', 'pointerEvents', 'willChange'].forEach(function (p) { card.style[p] = ''; });
      });
      state.track.style.transformStyle = state.track.style.cursor = '';
    }
    root._ttPlay && root._ttPlay();
  }

  function syncAll() {
    var isModern = document.body.classList.contains('theme-modern');
    document.querySelectorAll(ROOT_SELECTOR).forEach(function (root) {
      if (isModern) mount(root); else unmount(root);
    });
  }

  function init() {
    syncAll();
    window.addEventListener('tt-theme-change', syncAll);
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(init, 0);
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }
})();
