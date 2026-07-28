// api/monitor.js
// Vercel Cron kutsuu tätä GET-pyynnöllä vercel.json:in aikataulun mukaan.
// Tarkistaa sivustot, vertaa edelliseen tilaan (Vercel Blob) ja lähettää
// sähköpostin Resendillä VAIN kun tila muuttuu (kaatui / palasi).

import { put, list } from '@vercel/blob';
import { Resend } from 'resend';
import sites from '../sites.json' with { type: 'json' };

const STATE_BLOB = 'wp-guard-state.json';
const TIMEOUT_MS = 10000;

export default async function handler(req, res) {
  // Suojaus: vain Vercelin cron (tai sinä itse CRON_SECRETillä) saa ajaa tämän.
  // Puuttuva muuttuja on aina 401 – muuten vertailuarvoksi tulisi merkkijono
  // "Bearer undefined", jonka kuka tahansa voisi arvata.
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'];
  if (!secret || auth !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const prevState = await loadState();
  const results = await Promise.all(sites.map(checkSite));

  const changes = [];
  const newState = {};

  for (const r of results) {
    newState[r.url] = { up: r.up, status: r.status, checkedAt: new Date().toISOString() };
    const prev = prevState[r.url];
    // Ilmoita vain tilan muutoksesta. Ensimmäisellä ajolla (prev puuttuu)
    // ilmoitetaan vain jos sivu on nurin.
    if (!prev && !r.up) changes.push({ ...r, type: 'down' });
    else if (prev && prev.up && !r.up) changes.push({ ...r, type: 'down' });
    else if (prev && !prev.up && r.up) changes.push({ ...r, type: 'up' });
  }

  if (changes.length > 0) {
    await sendAlert(changes);
  }

  await saveState(newState);

  return res.status(200).json({
    checked: results.length,
    down: results.filter(r => !r.up).map(r => r.name),
    alertsSent: changes.length,
  });
}

async function checkSite(site) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(site.url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'wp-guard/1.0 (uptime monitor)' },
    });
    clearTimeout(timer);
    // 2xx ja 3xx = OK. 401/403 voi olla tarkoituksellinen (esim. vanha.
    // -arkistosivu admin-suojattuna) - lisää tähän poikkeuksia tarpeen mukaan.
    const up = resp.status >= 200 && resp.status < 400;
    return { ...site, up, status: resp.status };
  } catch (err) {
    clearTimeout(timer);
    const reason = err.name === 'AbortError' ? `timeout ${TIMEOUT_MS / 1000}s` : err.message;
    return { ...site, up: false, status: reason };
  }
}

async function sendAlert(changes) {
  const resend = new Resend(process.env.RESEND_API_KEY);
  const downs = changes.filter(c => c.type === 'down');
  const ups = changes.filter(c => c.type === 'up');

  const subject = downs.length > 0
    ? `🔴 NURIN: ${downs.map(d => d.name).join(', ')}`
    : `🟢 Palasi: ${ups.map(u => u.name).join(', ')}`;

  const lines = changes.map(c =>
    c.type === 'down'
      ? `🔴 ${c.name} EI VASTAA (${c.status})\n   ${c.url}`
      : `🟢 ${c.name} palasi linjoille (HTTP ${c.status})\n   ${c.url}`
  );

  await resend.emails.send({
    from: process.env.ALERT_FROM,      // esim. 'WP-guard <valvonta@esimerkki.fi>'
    to: process.env.ALERT_TO,          // oma sähköpostisi
    subject,
    text: `${lines.join('\n\n')}\n\n— WP-guard, ${new Date().toLocaleString('fi-FI', { timeZone: 'Europe/Helsinki' })}`,
  });
}

async function loadState() {
  try {
    const { blobs } = await list({ prefix: STATE_BLOB });
    if (blobs.length === 0) return {};
    const resp = await fetch(blobs[0].url, { cache: 'no-store' });
    return await resp.json();
  } catch {
    return {};
  }
}

async function saveState(state) {
  await put(STATE_BLOB, JSON.stringify(state), {
    access: 'public',
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: 'application/json',
  });
}
