/* Docs page module: scroll-spy on the sticky index + shared UI */
import { initSharedUi } from '../shared/ui.js';

initSharedUi();

const links = new Map();
document.querySelectorAll('.tech-index a[href^="#"]').forEach((a) => {
  const id = a.getAttribute('href').slice(1);
  if (id) links.set(id, a);
});

const sections = [...links.keys()]
  .map((id) => document.getElementById(id))
  .filter(Boolean);

let current = null;
function setCurrent(id) {
  const next = links.get(id);
  if (!next) return;
  if (current && current !== next) {
    current.classList.remove('is-current');
    current.removeAttribute('aria-current');
  }
  current = next;
  current.classList.add('is-current');
  current.setAttribute('aria-current', 'location');
}

links.forEach((a, id) => a.addEventListener('click', () => setCurrent(id)));

if (sections.length && 'IntersectionObserver' in window) {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) setCurrent(entry.target.id);
    }
  }, { rootMargin: '-20% 0px -55% 0px' });
  sections.forEach((s) => observer.observe(s));
}
