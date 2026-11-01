/* Shared procedural "photograph" for the website's live demos: a dusk
 * valley with aurora, moon, ridges, lake and pines, painted on a 2D
 * canvas so every page artifact derives from one image with zero
 * external assets. Used by pipeline.js (stage artifacts) and film.js
 * (the scroll-scrubbed tile film). */

export function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* The sample "photograph" (same painter as the overview page). */
export function paintValley(w, h) {
  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  const x = c.getContext('2d');
  const rand = mulberry32(0xa2c4e6);

  const sky = x.createLinearGradient(0, 0, 0, h * 0.72);
  sky.addColorStop(0, '#0b2620');
  sky.addColorStop(0.38, '#175144');
  sky.addColorStop(0.72, '#6d9a7e');
  sky.addColorStop(1, '#d9c9a3');
  x.fillStyle = sky;
  x.fillRect(0, 0, w, h);

  for (let i = 0; i < 220; i++) {
    const sx = rand() * w, sy = rand() * h * 0.42;
    x.fillStyle = `rgba(240,238,220,${0.12 + rand() * 0.5})`;
    x.fillRect(sx, sy, rand() < 0.12 ? 2 : 1, 1);
  }

  x.globalCompositeOperation = 'lighter';
  for (let band = 0; band < 3; band++) {
    const baseY = h * (0.13 + band * 0.085);
    const amp = h * (0.035 + band * 0.012);
    const phase = rand() * 6.28;
    for (let pass = 0; pass < 5; pass++) {
      x.beginPath();
      for (let px = -20; px <= w + 20; px += 8) {
        const py = baseY + Math.sin(px / w * 5.2 + phase) * amp + Math.sin(px / w * 13.7 + phase * 2) * amp * 0.35 + pass * 7;
        px === -20 ? x.moveTo(px, py) : x.lineTo(px, py);
      }
      x.strokeStyle = `rgba(${90 + band * 30},${220 - band * 18},${150},${0.05 + (4 - pass) * 0.012})`;
      x.lineWidth = 15 - pass * 2.4;
      x.stroke();
    }
  }
  x.globalCompositeOperation = 'source-over';

  const mx = w * 0.79, my = h * 0.2, mr = h * 0.055;
  const halo = x.createRadialGradient(mx, my, mr * 0.4, mx, my, mr * 4.2);
  halo.addColorStop(0, 'rgba(238,234,210,0.4)');
  halo.addColorStop(1, 'rgba(238,234,210,0)');
  x.fillStyle = halo;
  x.fillRect(mx - mr * 4.2, my - mr * 4.2, mr * 8.4, mr * 8.4);
  x.fillStyle = '#ece5cc';
  x.beginPath(); x.arc(mx, my, mr, 0, 6.29); x.fill();
  x.fillStyle = 'rgba(160,155,130,0.5)';
  x.beginPath(); x.arc(mx - mr * 0.3, my - mr * 0.15, mr * 0.16, 0, 6.29); x.fill();
  x.beginPath(); x.arc(mx + mr * 0.25, my + mr * 0.3, mr * 0.11, 0, 6.29); x.fill();

  const ridge = (baseY, jag, color, snow) => {
    x.beginPath();
    x.moveTo(-10, h + 10);
    let y = baseY;
    const peaks = [];
    for (let px = -10; px <= w + 10; px += 14) {
      y += (rand() - 0.5) * jag;
      y = Math.max(baseY - jag * 1.7, Math.min(baseY + jag * 0.7, y));
      x.lineTo(px, y);
      peaks.push([px, y]);
    }
    x.lineTo(w + 10, h + 10);
    x.closePath();
    x.fillStyle = color;
    x.fill();
    if (snow) {
      x.fillStyle = 'rgba(232,234,222,0.75)';
      for (const [px, py] of peaks) {
        if (py < baseY - jag * 0.75 && rand() < 0.7) {
          x.beginPath();
          x.moveTo(px - 9, py + 13); x.lineTo(px, py); x.lineTo(px + 9, py + 13);
          x.lineTo(px + 3, py + 9); x.lineTo(px, py + 13); x.lineTo(px - 4, py + 8);
          x.closePath(); x.fill();
        }
      }
    }
  };
  ridge(h * 0.56, h * 0.05, '#2a5647', true);
  ridge(h * 0.64, h * 0.045, '#1a4032', false);
  ridge(h * 0.72, h * 0.038, '#0f2c20', false);

  const lakeY = h * 0.8;
  const floor = x.createLinearGradient(0, lakeY - h * 0.06, 0, h);
  floor.addColorStop(0, '#14382a');
  floor.addColorStop(0.25, '#275c46');
  floor.addColorStop(0.55, '#173e2f');
  floor.addColorStop(1, '#08190f');
  x.fillStyle = floor;
  x.fillRect(0, lakeY - h * 0.045, w, h - lakeY + h * 0.045);
  for (let i = 0; i < 260; i++) {
    const lx = w * 0.79 + (rand() - 0.5) * w * 0.22 * (0.4 + rand());
    const ly = lakeY + rand() * (h - lakeY) * 0.92;
    x.fillStyle = `rgba(226,230,205,${0.05 + rand() * 0.22})`;
    x.fillRect(lx, ly, 3 + rand() * 16, 1.3);
  }
  for (let i = 0; i < 160; i++) {
    const lx = rand() * w, ly = lakeY + rand() * (h - lakeY) * 0.7;
    x.fillStyle = `rgba(110,210,160,${0.03 + rand() * 0.1})`;
    x.fillRect(lx, ly, 4 + rand() * 22, 1.2);
  }

  const pine = (px, ph) => {
    x.fillStyle = '#050d09';
    x.fillRect(px - 1.5, h - ph * 0.32, 3, ph * 0.32);
    for (let t = 0; t < 4; t++) {
      const tw = ph * (0.34 - t * 0.07), ty = h - ph * 0.25 - t * ph * 0.2;
      x.beginPath();
      x.moveTo(px - tw / 2, ty); x.lineTo(px, ty - ph * 0.34); x.lineTo(px + tw / 2, ty);
      x.closePath(); x.fill();
    }
  };
  for (let i = 0; i < 9; i++) pine(w * 0.02 + rand() * w * 0.1, h * (0.16 + rand() * 0.15));
  for (let i = 0; i < 8; i++) pine(w * 0.9 + rand() * w * 0.09, h * (0.14 + rand() * 0.16));
  for (let i = 0; i < 26; i++) pine(rand() * w, h * (0.045 + rand() * 0.05));

  for (let i = 0; i < 4200; i++) {
    x.fillStyle = rand() < 0.5 ? 'rgba(0,0,0,0.05)' : 'rgba(255,250,235,0.045)';
    x.fillRect(rand() * w, rand() * h, 1.3, 1.3);
  }
  const vig = x.createRadialGradient(w / 2, h / 2, h * 0.36, w / 2, h / 2, h * 0.95);
  vig.addColorStop(0, 'rgba(0,0,0,0)');
  vig.addColorStop(1, 'rgba(2,8,5,0.42)');
  x.fillStyle = vig;
  x.fillRect(0, 0, w, h);

  return c;
}
