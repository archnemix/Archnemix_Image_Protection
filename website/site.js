/* Archnemix website — deliberately small shared behaviour.
 *
 * The previous motion layer owned an always-on requestAnimationFrame
 * loop for a progress bar, custom cursor, parallax panels, magnetic
 * buttons and blurred ambient orbs. That fought the browser chrome and
 * burned CPU/GPU even while the reader was looking at ordinary copy.
 * This replacement leaves scrolling, the scrollbar and the cursor to
 * the browser. It only:
 *   1. wires the copy-install button;
 *   2. performs cheap one-time IntersectionObserver reveals;
 *   3. lazy-loads the homepage's detailed pipeline widgets shortly
 *      before they enter the viewport.
 *
 * It performs no network requests. The detailed pipeline module is a
 * same-origin static script loaded by the browser only when needed;
 * all imagery it creates is generated locally on canvases. */
(() => {
  const scriptUrl = document.currentScript?.src || new URL('site.js', window.location.href).href;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Copy-install button (homepage). Clipboard failure is not fatal:
  // select the command so the visitor can copy it manually.
  const copyButton = document.getElementById('copyInstall');
  const installCommand = document.getElementById('installCmd');
  if (copyButton && installCommand) {
    copyButton.addEventListener('click', async () => {
      const previous = copyButton.textContent;
      try {
        await navigator.clipboard.writeText(installCommand.textContent.trim());
        copyButton.textContent = 'Copied ✓';
      } catch {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(installCommand);
        selection?.removeAllRanges();
        selection?.addRange(range);
        copyButton.textContent = 'Selected';
      }
      window.setTimeout(() => { copyButton.textContent = previous; }, 1800);
    });
  }

  // One-time, passive section reveals. No frame loop and no layout reads
  // during scrolling: the observer fires once per section, then forgets it.
  const revealTargets = document.querySelectorAll(
    'main > .band, main > .simple-band, main > .tech-layout, .site-footer',
  );
  if (!reduceMotion && 'IntersectionObserver' in window && revealTargets.length) {
    const revealObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add('is-inview');
        revealObserver.unobserve(entry.target);
      }
    }, { rootMargin: '0px 0px -7% 0px', threshold: 0.01 });

    revealTargets.forEach((target) => {
      target.classList.add('reveal');
      revealObserver.observe(target);
    });
  }

  // Homepage detailed pipeline (journey, profiles, steal, identify).
  // Keep its canvas work out of the opening film and first paint: import
  // it when the section is roughly one viewport away.
  const pipelineDetail = document.getElementById('pipeline-detail');
  if (pipelineDetail) {
    let started = false;
    const loadDetails = () => {
      if (started) return;
      started = true;
      import(new URL('pipeline-details.js', scriptUrl).href).catch(() => {
        // The static facts already in the HTML remain readable if a
        // local module cannot load (for example an unusual file URL).
      });
    };

    if ('IntersectionObserver' in window) {
      const detailObserver = new IntersectionObserver((entries) => {
        if (!entries.some((entry) => entry.isIntersecting)) return;
        detailObserver.disconnect();
        loadDetails();
      }, { rootMargin: '900px 0px', threshold: 0 });
      detailObserver.observe(pipelineDetail);
    } else if ('requestIdleCallback' in window) {
      window.requestIdleCallback(loadDetails, { timeout: 2500 });
    } else {
      window.setTimeout(loadDetails, 1200);
    }
  }
})();
