/* Archnemix motion layer — scroll-driven depth, reveals, tilt, and a
 * magnetic cursor, layered over the existing editorial design without
 * changing content, fonts, colors, or layout. Vanilla JS; one
 * requestAnimationFrame loop drives everything (lerped scroll with
 * inertia); only transform/opacity are animated; all listeners are
 * passive; prefers-reduced-motion falls back to plain opacity fades.
 * The pages' existing Three.js scenes are untouched. */
(() => {
  'use strict';
  const docEl = document.documentElement;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  // "Fine pointer" = primary pointer is not coarse. (Headless browsers
  // report no pointer at all; touchscreen laptops report fine. Cursor
  // chrome stays invisible until the first real pointermove either way.)
  const finePointer = !window.matchMedia('(pointer: coarse)').matches;
  const parallaxScale = finePointer ? 1 : 0.5; // phones: half depth
  const lerp = (a, b, t) => a + (b - a) * t;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

  docEl.classList.add(reduced ? 'motion-reduced' : 'motion-on');

  /* ---------------- injected chrome: orbs, progress, chapter dots ------ */
  const orbs = document.createElement('div');
  orbs.className = 'motion-orbs';
  orbs.setAttribute('aria-hidden', 'true');
  orbs.innerHTML = '<span class="orb orb-a"></span><span class="orb orb-b"></span><span class="orb orb-c"></span>';
  document.body.prepend(orbs);
  const orbEls = [...orbs.children];

  const progress = document.createElement('div');
  progress.className = 'scroll-progress';
  progress.setAttribute('aria-hidden', 'true');
  progress.innerHTML = '<span class="scroll-progress-fill"></span>';
  document.body.prepend(progress);
  const progressFill = progress.firstElementChild;

  const sections = [...document.querySelectorAll('main > section')];
  sections.forEach((s, i) => { if (!s.id) s.id = `chapter-${i}`; });
  const dotsNav = document.createElement('nav');
  dotsNav.className = 'chapter-dots';
  dotsNav.setAttribute('aria-label', 'Page chapters');
  const dots = sections.map((s) => {
    const heading = s.querySelector('h1, h2')?.textContent?.trim().replace(/\s+/g, ' ') || s.id;
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'chapter-dot';
    b.title = heading;
    b.setAttribute('aria-label', `Go to: ${heading}`);
    b.addEventListener('click', () => {
      s.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    });
    dotsNav.appendChild(b);
    return b;
  });
  if (sections.length > 2) document.body.appendChild(dotsNav);

  /* ---------------- hero floating shapes (foreground layer) ------------ */
  const hero = document.querySelector('.hero, .page-intro');
  const floatShapes = [];
  if (hero && !reduced) {
    hero.classList.add('has-floats');
    const kinds = ['sq', 'ring', 'sq rust', 'dot', 'ring rust'];
    kinds.forEach((kind, i) => {
      const outer = document.createElement('span');
      outer.className = 'float-shape';
      outer.setAttribute('aria-hidden', 'true');
      outer.innerHTML = `<span class="float-shape-inner ${kind}"></span>`;
      outer.style.left = `${6 + i * 21}%`;
      outer.style.top = `${10 + (i % 3) * 26}%`;
      outer.firstElementChild.style.animationDuration = `${4 + i * 0.6}s`;
      outer.firstElementChild.style.animationDelay = `${-i * 1.1}s`;
      hero.appendChild(outer);
      floatShapes.push(outer);
    });
  }

  /* ---------------- section reveals (IntersectionObserver) ------------- */
  const revealTargets = sections.filter((s) => !s.classList.contains('hero') && !s.hasAttribute('data-no-reveal'));
  revealTargets.forEach((s) => {
    s.classList.add('rv');
    [...s.children].slice(0, 8).forEach((child, i) => {
      child.classList.add('rv-child');
      child.style.setProperty('--d', `${i * 80}ms`);
    });
  });
  if (reduced || !('IntersectionObserver' in window)) {
    // Reduced motion: everything simply present (CSS keeps a gentle fade).
    revealTargets.forEach((s) => s.classList.add('in'));
  } else {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        // Reveal when entering, and also when a jump-scroll has already
        // carried the section above the viewport (never strand content).
        if ((e.isIntersecting && e.intersectionRatio > 0.08) || e.boundingClientRect.bottom < 0) {
          e.target.classList.add('in');
          io.unobserve(e.target);
        }
      }
    }, { threshold: [0, 0.25, 0.5, 0.75, 1] });
    revealTargets.forEach((s) => io.observe(s));
  }

  /* ---------------- parallax targets ----------------------------------- */
  const parallaxEls = [];
  const addParallax = (el, depth, z, maxShift = 70) => {
    if (el && !parallaxEls.some((p) => p.el === el)) parallaxEls.push({ el, depth, z, maxShift, top: 0, h: 0 });
  };
  if (!reduced) {
    addParallax(document.querySelector('.hero h1, .page-intro h1'), 0.6, -30); // headline: mid-layer
    addParallax(document.querySelector('.hero .lede, .page-intro .lede2'), 0.75, -15);
    // Numerals sit inline in the flex band-head: only a whisper of drift
    // (±12px), or they detach from their headings and overlap content.
    document.querySelectorAll('.band-no').forEach((el) => addParallax(el, 0.35, -50, 12));
    document.querySelectorAll('[data-parallax]').forEach((el) => {
      addParallax(el, parseFloat(el.dataset.parallax) || 0.5, 0);
    });
  }
  let sectionTops = [];
  function remeasure() {
    for (const p of parallaxEls) {
      const r = p.el.getBoundingClientRect();
      p.top = r.top + window.scrollY;
      p.h = r.height;
    }
    sectionTops = sections.map((s) => s.getBoundingClientRect().top + window.scrollY);
  }
  remeasure();
  window.addEventListener('resize', remeasure, { passive: true });
  window.addEventListener('load', remeasure, { passive: true });
  if (document.fonts?.ready) document.fonts.ready.then(remeasure).catch(() => {});

  /* ---------------- 3D tilt + specular ---------------------------------- */
  const TILT_SELECTOR = '.pipe-stage, .stat, .decision, .widget, .stage-frame, .pipe-frame, .pipe-readout';
  if (!reduced) {
    document.querySelectorAll(TILT_SELECTOR).forEach((el) => {
      el.classList.add('tilt');
      const max = el.matches('.stage-frame, .pipe-frame') ? 4 : 10;
      el.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect();
        const px = (e.clientX - r.left) / r.width;
        const py = (e.clientY - r.top) / r.height;
        const ry = (px - 0.5) * 2 * max;
        const rx = (0.5 - py) * 2 * max;
        el.style.transition = 'transform 0.12s ease-out';
        el.style.transform = `perspective(800px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) translateZ(10px)`;
        el.style.setProperty('--mx', `${(px * 100).toFixed(1)}%`);
        el.style.setProperty('--my', `${(py * 100).toFixed(1)}%`);
        el.classList.add('tilting');
      }, { passive: true });
      el.addEventListener('pointerleave', () => {
        el.style.transition = '';
        el.style.transform = '';
        el.classList.remove('tilting');
      }, { passive: true });
    });
  }

  /* ---------------- magnetic cursor (fine pointers only) ---------------- */
  let cursor = null;
  if (finePointer && !reduced) {
    document.body.classList.add('has-cursor');
    const dot = document.createElement('span');
    dot.className = 'cursor-dot';
    const ring = document.createElement('span');
    ring.className = 'cursor-ring';
    dot.setAttribute('aria-hidden', 'true');
    ring.setAttribute('aria-hidden', 'true');
    document.body.append(dot, ring);
    cursor = { dot, ring, x: innerWidth / 2, y: innerHeight / 2, rx: innerWidth / 2, ry: innerHeight / 2, hovering: false, burstUntil: 0 };
    window.addEventListener('pointermove', (e) => {
      cursor.x = e.clientX; cursor.y = e.clientY;
      document.body.classList.add('cursor-seen');
    }, { passive: true });
    window.addEventListener('pointerdown', () => { cursor.burstUntil = performance.now() + 300; ring.classList.add('burst'); }, { passive: true });
    const hoverSel = 'a, button, .tilt, canvas, input, select, textarea, [role="button"]';
    document.addEventListener('pointerover', (e) => {
      cursor.hovering = !!e.target.closest?.(hoverSel);
      ring.classList.toggle('hovering', cursor.hovering);
    }, { passive: true });

    // Magnetic pull: buttons/nav drift up to 8px toward the cursor.
    document.querySelectorAll('.btn, .masthead-nav a, .wordmark, .chapter-dot').forEach((el) => {
      el.classList.add('magnetic');
      el.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect();
        const dx = clamp((e.clientX - (r.left + r.width / 2)) * 0.18, -8, 8);
        const dy = clamp((e.clientY - (r.top + r.height / 2)) * 0.18, -8, 8);
        el.style.transform = `translate(${dx.toFixed(1)}px, ${dy.toFixed(1)}px)`;
      }, { passive: true });
      el.addEventListener('pointerleave', () => { el.style.transform = ''; }, { passive: true });
    });
  }

  /* ---------------- the single animation loop --------------------------- */
  let smoothY = window.scrollY;
  let lastActive = -1;
  function frame(now) {
    const maxScroll = Math.max(1, document.body.scrollHeight - window.innerHeight);
    smoothY = reduced ? window.scrollY : lerp(smoothY, window.scrollY, 0.1);
    if (Math.abs(smoothY - window.scrollY) < 0.05) smoothY = window.scrollY;
    const scrollProgress = clamp(smoothY / maxScroll, 0, 1);

    progressFill.style.transform = `scaleX(${scrollProgress.toFixed(4)})`;

    if (!reduced) {
      // Ambient orbs drift + hue-rotate across the whole scroll.
      orbs.style.filter = `hue-rotate(${(scrollProgress * 30).toFixed(1)}deg)`;
      orbEls[0].style.transform = `translate3d(${(scrollProgress * 140).toFixed(1)}px, ${(-scrollProgress * 90).toFixed(1)}px, 0)`;
      orbEls[1].style.transform = `translate3d(${(-scrollProgress * 110).toFixed(1)}px, ${(scrollProgress * 130).toFixed(1)}px, 0)`;
      orbEls[2].style.transform = `translate3d(${(scrollProgress * 70).toFixed(1)}px, ${(scrollProgress * 60).toFixed(1)}px, 0)`;

      // Parallax: offset from viewport centre, depth-scaled.
      const centre = smoothY + window.innerHeight / 2;
      for (const p of parallaxEls) {
        const dy = clamp((centre - (p.top + p.h / 2)) * (p.depth - 1) * 0.12 * parallaxScale, -p.maxShift, p.maxShift);
        p.el.style.transform = `translate3d(0, ${dy.toFixed(1)}px, ${p.z}px)`;
      }
      // Hero foreground shapes move faster than scroll (in front of camera).
      floatShapes.forEach((s, i) => {
        s.style.transform = `translate3d(0, ${(-smoothY * (0.14 + i * 0.03) * parallaxScale).toFixed(1)}px, 40px)`;
      });
    }

    // Chapter dots: last section whose top passed 40% of the viewport.
    let active = 0;
    for (let i = 0; i < sectionTops.length; i++) {
      if (smoothY + window.innerHeight * 0.4 >= sectionTops[i]) active = i;
    }
    if (active !== lastActive) {
      lastActive = active;
      dots.forEach((d, i) => d.classList.toggle('active', i === active));
    }

    if (cursor) {
      cursor.rx = lerp(cursor.rx, cursor.x, 0.15);
      cursor.ry = lerp(cursor.ry, cursor.y, 0.15);
      cursor.dot.style.transform = `translate3d(${cursor.x}px, ${cursor.y}px, 0) translate(-50%, -50%)`;
      const bursting = now < cursor.burstUntil;
      if (!bursting) cursor.ring.classList.remove('burst');
      const scale = bursting ? 2 : cursor.hovering ? 1.5 : 1;
      cursor.ring.style.transform = `translate3d(${cursor.rx.toFixed(1)}px, ${cursor.ry.toFixed(1)}px, 0) translate(-50%, -50%) scale(${scale})`;
      cursor.ring.style.opacity = bursting ? String(Math.max(0, (cursor.burstUntil - now) / 300)) : '';
    }

    requestAnimationFrame(frame); // browsers pause rAF on hidden tabs
  }
  requestAnimationFrame(frame);

  /* ---------------- install-command copy button (site chrome) ---------- */
  const copyBtn = document.getElementById('copyInstall');
  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      const text = document.getElementById('installCmd')?.textContent?.trim() ?? '';
      const done = () => {
        const prev = copyBtn.textContent;
        copyBtn.textContent = 'Copied ✓';
        setTimeout(() => { copyBtn.textContent = prev; }, 1600);
      };
      try { await navigator.clipboard.writeText(text); done(); }
      catch {
        const range = document.createRange();
        const node = document.getElementById('installCmd');
        if (node) { range.selectNode(node); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range); }
        try { document.execCommand('copy'); done(); } catch { /* selection left in place for manual copy */ }
      }
    });
  }
})();
