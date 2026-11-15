/* Shared site UI enhancements: scroll progress hairline, reveal observer,
   responsive navigation drawer, and code-block copy actions.
   Every page remains 100% readable and navigable if JavaScript is off. */

export function initScrollProgress() {
  const bar = document.querySelector('.scroll-progress');
  if (!bar) return;
  let ticking = false;
  const update = () => {
    ticking = false;
    const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const ratio = Math.max(0, Math.min(1, window.scrollY / max));
    bar.style.transform = `scaleX(${ratio.toFixed(4)})`;
  };
  const onScroll = () => {
    if (!ticking) {
      ticking = true;
      requestAnimationFrame(update);
    }
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  update();
}

export function initRevealObserver() {
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const nodes = [...document.querySelectorAll('[data-reveal]')];
  if (!nodes.length || reduced || !('IntersectionObserver' in window)) return;

  document.documentElement.classList.add('reveal-ready');
  const obs = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add('is-revealed');
      obs.unobserve(entry.target);
    }
  }, { rootMargin: '0px 0px -8% 0px', threshold: 0.05 });

  for (const node of nodes) {
    const rect = node.getBoundingClientRect();
    if (rect.top < window.innerHeight * 0.92) {
      node.classList.add('is-revealed');
    } else {
      obs.observe(node);
    }
  }
}

export function initMobileNav() {
  const btn = document.querySelector('.nav-toggle');
  const nav = document.querySelector('.masthead-nav');
  if (!btn || !nav) return;

  btn.addEventListener('click', () => {
    const open = !nav.classList.contains('is-open');
    nav.classList.toggle('is-open', open);
    btn.setAttribute('aria-expanded', String(open));
  });
  nav.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      nav.classList.remove('is-open');
      btn.setAttribute('aria-expanded', 'false');
    });
  });
}

export function initCopyControls() {
  const copyBtn = document.getElementById('copyInstall');
  const installCmd = document.getElementById('installCmd');
  if (copyBtn && installCmd) {
    copyBtn.addEventListener('click', async () => {
      const text = installCmd.textContent?.trim() ?? '';
      try {
        await navigator.clipboard.writeText(text);
        copyBtn.textContent = 'Copied';
      } catch {
        copyBtn.textContent = 'Select & copy';
        const range = document.createRange();
        range.selectNode(installCmd);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2200);
    });
  }

  document.querySelectorAll('pre.code').forEach((pre) => {
    if (pre.parentElement?.classList.contains('code-wrap')) return;
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'code-copy';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy code snippet');
    btn.addEventListener('click', async () => {
      const code = pre.textContent ?? '';
      try {
        await navigator.clipboard.writeText(code);
        btn.textContent = 'Copied';
        btn.classList.add('is-copied');
      } catch {
        btn.textContent = 'Failed';
      }
      setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('is-copied');
      }, 2000);
    });
    wrap.appendChild(btn);
  });
}

export function initSharedUi() {
  initScrollProgress();
  initRevealObserver();
  initMobileNav();
  initCopyControls();
}
