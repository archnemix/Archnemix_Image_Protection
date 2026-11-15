/* Decision Atlas: accordion, auto-generated sidebar index, scrollspy, search & tag filters */

export function initAtlas() {
  const decisions = [...document.querySelectorAll('.decision')];
  document.querySelectorAll('.seg button, .tech-toolbar .chip[data-tag]').forEach((btn) => {
    btn.setAttribute('aria-pressed', String(btn.classList.contains('is-active')));
  });

  const indexNav = document.getElementById('techIndex');
  if (indexNav) {
    let currentGroup = null;
    for (const card of decisions) {
      let g = null;
      let el = card;
      while (el && !g) {
        el = el.previousElementSibling;
        if (el?.classList?.contains('group-head')) g = el;
      }
      const gName = g?.querySelector('h2')?.textContent ?? '';
      if (gName && gName !== currentGroup) {
        currentGroup = gName;
        const div = document.createElement('div');
        div.className = 'idx-group';
        div.textContent = gName;
        indexNav.appendChild(div);
      }
      const a = document.createElement('a');
      a.href = `#${card.id}`;
      a.textContent = `${card.querySelector('.decision-no')?.textContent ?? ''} · ${card.querySelector('.decision-title')?.textContent ?? ''}`;
      a.dataset.for = card.id;
      indexNav.appendChild(a);
    }

    const links = [...indexNav.querySelectorAll('a')];
    const setCurrent = (id) => {
      for (const link of links) {
        const active = link.dataset.for === id;
        link.classList.toggle('is-current', active);
        if (active) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
      }
    };
    links.forEach((link) => link.addEventListener('click', () => setCurrent(link.dataset.for)));
    if ('IntersectionObserver' in window) {
      const spy = new IntersectionObserver((entries) => {
        for (const en of entries) {
          if (en.isIntersecting) setCurrent(en.target.id);
        }
      }, { rootMargin: '-25% 0px -55% 0px' });
      decisions.forEach((d) => spy.observe(d));
    }
  }

  function setOpen(card, open) {
    const body = card.querySelector('.decision-body');
    const btn = card.querySelector('.decision-toggle');
    if (!body || !btn) return;
    body.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? 'Close' : 'Open';
    if (open) card.dispatchEvent(new CustomEvent('decision:open'));
  }

  decisions.forEach((card, i) => {
    card.querySelector('.decision-toggle')?.addEventListener('click', () => {
      setOpen(card, card.querySelector('.decision-body')?.hidden);
    });
    if (i === 0) setOpen(card, true);
  });

  if (location.hash) {
    const target = document.querySelector(location.hash);
    if (target?.classList?.contains('decision')) setOpen(target, true);
  }

  const search = document.getElementById('techSearch');
  const count = document.getElementById('techCount');
  let activeTag = null;

  function applyFilter() {
    const q = (search?.value ?? '').trim().toLowerCase();
    let shown = 0;
    for (const card of decisions) {
      const tagOk = !activeTag || (card.dataset.tags ?? '').includes(activeTag);
      const textOk = !q || card.textContent.toLowerCase().includes(q);
      const show = tagOk && textOk;
      card.hidden = !show;
      if (show) shown++;
    }
    if (count) count.textContent = `${shown} of ${decisions.length} decisions`;
  }

  search?.addEventListener('input', applyFilter);
  document.querySelectorAll('.tech-toolbar .chip[data-tag]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const tag = chip.dataset.tag;
      activeTag = activeTag === tag ? null : tag;
      document.querySelectorAll('.tech-toolbar .chip[data-tag]').forEach((c) => {
        const active = c.dataset.tag === activeTag;
        c.classList.toggle('is-active', active);
        c.setAttribute('aria-pressed', String(active));
      });
      applyFilter();
    });
  });
  applyFilter();
}
