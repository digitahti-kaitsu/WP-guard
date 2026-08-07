// api/monitor.js
// Vercel Cron kutsuu tätä GET-pyynnöllä vercel.json:in aikataulun mukaan.
// Tarkistaa sivustot, vertaa edelliseen tilaan (Vercel Blob) ja lähettää
// sähköpostin Resendillä VAIN kun tila muuttuu (kaatui / palasi).

import { put, list } from '@vercel/blob';
import { Resend } from 'resend';
import sites from '../sites.json' with { type: 'json' };

const STATE_BLOB = 'wp-guard-state.json';
const TIMEOUT_MS = 10000;

// Montako peräkkäistä epäonnistunutta tarkistusta vaaditaan ennen hälytystä.
// Webhotellit tuottavat satunnaisia hetkellisiä hidasteluja, joissa sivu ei
// vastaa aikarajassa mutta on seuraavassa hetkessä taas pystyssä. Yhden ajon
// perusteella hälyttäminen tuottaa niistä turhia viestejä, ja turha viesti on
// kalliimpi kuin myöhässä tullut: se opettaa sivuuttamaan koko hälytyksen.
// Hintana on, että aito katko havaitaan yhtä ajoväliä myöhemmin.
const VAHVISTUKSIA = 2;

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
    const { fails, alerted, halytys } = paatteleTila(prevState[r.url], r.up);
    if (halytys === 'down') changes.push({ ...r, type: 'down', fails });
    else if (halytys === 'up') changes.push({ ...r, type: 'up' });

    newState[r.url] = {
      up: r.up,
      status: r.status,
      checkedAt: new Date().toISOString(),
      fails,
      alerted,
    };
  }

  if (changes.length > 0) {
    await sendAlert(changes);
  }

  await saveState(newState);

  return res.status(200).json({
    checked: results.length,
    down: results.filter(r => !r.up).map(r => r.name),
    // Epäonnistuneet mutta vielä vahvistusta vailla – näkyy käsin ajettaessa,
    // jottei tarvitse arvailla miksi hälytystä ei tullut.
    pending: Object.entries(newState)
      .filter(([, s]) => !s.up && !s.alerted)
      .map(([url, s]) => `${url} (${s.fails}/${VAHVISTUKSIA})`),
    alertsSent: changes.length,
  });
}

// Päättelee sivuston uuden tilan ja sen, lähteekö hälytys.
//
// Kolme sääntöä:
//  1. Hälytys "down" vasta kun epäonnistumisia on VAHVISTUKSIA peräkkäin.
//  2. Hälytys lähtee kerran katkoa kohti, ei joka ajolla – siitä huolehtii
//     alerted-lippu, joka on eri asia kuin sivuston tila.
//  3. "up" lähtee vain jos katkosta oli ilmoitettu. Muuten hetkellisestä
//     hidastelusta tulisi "palasi"-viesti ilman edeltävää "kaatui"-viestiä.
//
// Vanhoissa tilatiedostoissa ei ole kenttiä fails/alerted; ne oletetaan
// nolliksi, jolloin nurin oleva sivusto vain aloittaa laskurin alusta.
//
// Vietynä, jotta tämän voi testata ilman verkkoa tai sähköpostia.
export function paatteleTila(prev, up) {
  const edellinen = prev ?? {};
  const fails = up ? 0 : (edellinen.fails ?? 0) + 1;
  const oliHalytetty = edellinen.alerted ?? false;

  if (!up && fails >= VAHVISTUKSIA && !oliHalytetty) {
    return { fails, alerted: true, halytys: 'down' };
  }
  if (up && oliHalytetty) {
    return { fails, alerted: false, halytys: 'up' };
  }
  return { fails, alerted: oliHalytetty, halytys: null };
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

  // Vahvistusten määrä kerrotaan viestissä, jotta näkee ettei kyse ole
  // yksittäisestä hetkellisestä hidastelusta vaan toistuvasta katkosta.
  const lines = changes.map(c =>
    c.type === 'down'
      ? `🔴 ${c.name} EI VASTAA (${c.status})\n   Epäonnistui ${c.fails} peräkkäisessä tarkistuksessa.\n   ${c.url}`
      : `🟢 ${c.name} palasi linjoille (HTTP ${c.status})\n   ${c.url}`
  );

  await resend.emails.send({
    from: process.env.ALERT_FROM,      // esim. 'WP-guard <vahti@digitahti.fi>'
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
