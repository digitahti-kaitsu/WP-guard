// api/security.js
// Viikoittainen tietoturvatarkistus OMILLE sivustoille.
//
// OMISTAJUUSVARMISTUS: tarkistus ajetaan vain, jos sivun <head>-osasta
// löytyy meta-tagi <meta name="wp-guard-verify" content="TOKEN"> ja token
// täsmää sites.json:iin. Ilman sitä sivusto ohitetaan kokonaan.
// Tagi lisätään sivustolle mukana tulevalla MU-pluginilla (wp-guard-meta.php).
//
// Tarkistukset ovat passiivisia: tavallisia GET-pyyntöjä ja otsakkeiden
// lukua, ei mitään tunkeutuvaa.

import tls from 'node:tls';
import { Resend } from 'resend';
import sites from '../sites.json' with { type: 'json' };

const TIMEOUT_MS = 8000;

export default async function handler(req, res) {
  // Puuttuva CRON_SECRET on aina 401, ks. api/monitor.js.
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'];
  if (!secret || auth !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Uusin WordPress-versio haetaan kerran per ajo, ei kerran per sivusto.
  const uusinWp = await haeUusinWordPress();

  const reports = [];
  for (const site of sites) {
    reports.push(await auditSite(site, uusinWp));
  }

  await sendReport(reports);
  return res.status(200).json({
    audited: reports.filter(r => r.verified).length,
    skipped: reports.filter(r => !r.verified).map(r => r.name),
  });
}

async function auditSite(site, uusinWp) {
  const findings = [];
  const u = new URL(site.url);

  // 1) Omistajuusvarmistus: hae etusivu ja etsi verify-meta-tagi
  const home = await fetchPage(site.url);
  if (!home.ok) {
    return { ...site, verified: false, findings: [], error: `Etusivua ei saatu haettua (${home.error})` };
  }
  const metaRe = /<meta[^>]+name=["']wp-guard-verify["'][^>]+content=["']([^"']+)["']/i;
  const altRe = /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']wp-guard-verify["']/i;
  const m = home.body.match(metaRe) || home.body.match(altRe);
  if (!m || m[1] !== site.token) {
    return { ...site, verified: false, findings: [], error: 'Verify-tagi puuttuu tai token ei täsmää – ohitettu' };
  }

  // 2) Tietoturvaotsakkeet
  const h = home.headers;
  const hsts = h.get('strict-transport-security');
  if (!hsts) {
    findings.push('⚠️ HSTS-otsake (Strict-Transport-Security) puuttuu');
  } else {
    // Pelkkä otsakkeen olemassaolo ei riitä. Lyhyt max-age näyttää
    // suojaukselta mutta ei ehdi suojata miltään, ja tyypillinen syy on
    // käyttöönoton testiarvo joka on jäänyt nostamatta.
    const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)"?/i)?.[1]);
    if (!Number.isFinite(maxAge)) {
      findings.push(`⚠️ HSTS-otsakkeesta puuttuu kelvollinen max-age: "${hsts}"`);
    } else if (maxAge < 86400) {
      findings.push(`⚠️ HSTS voimassa vain ${kesto(maxAge)} – liian lyhyt suojatakseen. Nosta arvoon 31536000`);
    } else if (maxAge < 31536000) {
      findings.push(`ℹ️ HSTS voimassa ${kesto(maxAge)} – suositus on vuosi (31536000)`);
    }
  }
  if (!h.get('x-content-type-options')) findings.push('⚠️ X-Content-Type-Options: nosniff puuttuu');
  if (!h.get('x-frame-options') && !(h.get('content-security-policy') || '').includes('frame-ancestors')) {
    findings.push('⚠️ Clickjacking-suoja puuttuu (X-Frame-Options tai CSP frame-ancestors)');
  }
  if (!h.get('referrer-policy')) findings.push('ℹ️ Referrer-Policy puuttuu (pieni asia)');
  const powered = h.get('x-powered-by');
  if (powered) findings.push(`ℹ️ X-Powered-By paljastaa: "${powered}"`);

  // 3) HTTP → HTTPS -ohjaus
  const httpUrl = `http://${u.hostname}/`;
  const httpResp = await fetchPage(httpUrl, { redirect: 'manual' });
  if (httpResp.ok || httpResp.status) {
    const loc = httpResp.headers?.get('location') || '';
    const redirectsToHttps = httpResp.status >= 300 && httpResp.status < 400 && loc.startsWith('https://');
    if (!redirectsToHttps) findings.push('🔴 HTTP-versio ei ohjaa HTTPS:ään');
  }

  // 4) SSL-sertifikaatin vanheneminen
  const cert = await getCertExpiry(u.hostname);
  if (cert.error) {
    findings.push(`⚠️ Sertifikaattia ei voitu tarkistaa: ${cert.error}`);
  } else if (cert.daysLeft < 0) {
    findings.push(`🔴 SSL-sertifikaatti VANHENTUNUT (${cert.validTo})`);
  } else if (cert.daysLeft <= 14) {
    findings.push(`🔴 SSL-sertifikaatti vanhenee ${cert.daysLeft} pv kuluttua (${cert.validTo})`);
  }

  // 5) WordPress-versio ja tietovuodot.
  // Versio saadaan vain generator-metasta. Se on samalla syy olla
  // piilottamatta tagia: vanhentunut ydin on isompi riski kuin se, että
  // versionumero näkyy – hyökkääjän botti kokeilee joka tapauksessa.
  const gen = home.body.match(/<meta[^>]+name=["']generator["'][^>]*content=["']WordPress\s+([\d.]+)/i);
  if (gen) {
    const versio = gen[1];
    if (uusinWp && vertaaVersioita(versio, uusinWp) < 0) {
      // Eri pää- tai alaversio tarkoittaa kuukausien päivitysvelkaa.
      // Pelkkä korjausversio jäljessä on tyypillisesti päivien.
      const isoLoikka = versio.split('.').slice(0, 2).join('.') !== uusinWp.split('.').slice(0, 2).join('.');
      findings.push(`${isoLoikka ? '🔴' : '⚠️'} WordPress ${versio} on vanhentunut – uusin on ${uusinWp}`);
    } else {
      findings.push(`ℹ️ Generator-meta paljastaa WordPress-version (${versio})${uusinWp ? ' – ajan tasalla' : ''}`);
    }
  }
  const readme = await fetchPage(new URL('/readme.html', site.url).href);
  if (readme.ok && /WordPress/i.test(readme.body)) {
    findings.push('⚠️ /readme.html on avoin (paljastaa WP-version)');
  }
  const debugLog = await fetchPage(new URL('/wp-content/debug.log', site.url).href);
  if (debugLog.ok && debugLog.body.length > 0 && !/<html/i.test(debugLog.body)) {
    findings.push('🔴 /wp-content/debug.log on julkisesti luettavissa!');
  }
  const uploads = await fetchPage(new URL('/wp-content/uploads/', site.url).href);
  if (uploads.ok && /Index of \//i.test(uploads.body)) {
    findings.push('⚠️ Hakemistolistaus päällä: /wp-content/uploads/');
  }
  const xmlrpc = await fetchPage(new URL('/xmlrpc.php', site.url).href);
  if (xmlrpc.status === 405 || (xmlrpc.ok && /XML-RPC/i.test(xmlrpc.body))) {
    findings.push('ℹ️ xmlrpc.php vastaa – jos ei käytössä (Jetpack tms.), kannattaa estää');
  }

  return { ...site, verified: true, findings };
}

// WordPressin oma rajapinta kertoo uusimman vakaan version. Jos kutsu
// epäonnistuu, versiotarkistus ohitetaan hiljaisesti: väärä hälytys
// vanhentuneesta ytimestä olisi pahempi kuin puuttuva tieto.
async function haeUusinWordPress() {
  try {
    const resp = await fetch('https://api.wordpress.org/core/version-check/1.7/', {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { 'User-Agent': 'wp-guard/1.0 (version check)' },
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.offers?.[0]?.current ?? null;
  } catch {
    return null;
  }
}

// Vertaa versionumeroita osa kerrallaan, jotta 6.10 on uudempi kuin 6.9.
// Palauttaa negatiivisen luvun kun a on vanhempi kuin b.
function vertaaVersioita(a, b) {
  const osatA = a.split('.').map(Number);
  const osatB = b.split('.').map(Number);
  for (let i = 0; i < Math.max(osatA.length, osatB.length); i++) {
    const ero = (osatA[i] ?? 0) - (osatB[i] ?? 0);
    if (ero !== 0) return ero;
  }
  return 0;
}

// Sekunnit luettavaan muotoon raporttia varten.
function kesto(sekunnit) {
  if (sekunnit < 3600) return `${sekunnit} s`;
  if (sekunnit < 86400) return `${Math.round(sekunnit / 3600)} h`;
  return `${Math.round(sekunnit / 86400)} vrk`;
}

async function fetchPage(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      redirect: 'follow',
      ...opts,
      signal: controller.signal,
      headers: { 'User-Agent': 'wp-guard/1.0 (security check, oma sivusto)' },
    });
    clearTimeout(timer);
    let body = '';
    try { body = (await resp.text()).slice(0, 200000); } catch { /* binääri tms. */ }
    return { ok: resp.status >= 200 && resp.status < 300, status: resp.status, headers: resp.headers, body };
  } catch (err) {
    clearTimeout(timer);
    return { ok: false, error: err.name === 'AbortError' ? 'timeout' : err.message };
  }
}

function getCertExpiry(hostname) {
  return new Promise(resolve => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: TIMEOUT_MS },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || !cert.valid_to) return resolve({ error: 'ei sertifikaattitietoja' });
        const validTo = new Date(cert.valid_to);
        const daysLeft = Math.floor((validTo - Date.now()) / 86400000);
        resolve({ validTo: validTo.toLocaleDateString('fi-FI'), daysLeft });
      }
    );
    socket.on('error', err => resolve({ error: err.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ error: 'timeout' }); });
  });
}

async function sendReport(reports) {
  const resend = new Resend(process.env.RESEND_API_KEY);
  const totalFindings = reports.reduce((n, r) => n + (r.findings?.length || 0), 0);
  const hasCritical = reports.some(r => r.findings?.some(f => f.startsWith('🔴')));

  const sections = reports.map(r => {
    if (!r.verified) return `⏭️ ${r.name}\n   ${r.error}`;
    if (r.findings.length === 0) return `✅ ${r.name} – ei huomautettavaa`;
    return `${r.name}:\n${r.findings.map(f => '   ' + f).join('\n')}`;
  });

  const subject = hasCritical
    ? `🔴 Tietoturvaraportti: kriittisiä löydöksiä (${totalFindings} huomiota)`
    : totalFindings > 0
      ? `🟡 Tietoturvaraportti: ${totalFindings} huomiota`
      : '🟢 Tietoturvaraportti: kaikki kunnossa';

  await resend.emails.send({
    from: process.env.ALERT_FROM,
    to: process.env.ALERT_TO,
    subject,
    text: `Viikoittainen tietoturvatarkistus\n\n${sections.join('\n\n')}\n\n— WP-guard, ${new Date().toLocaleString('fi-FI', { timeZone: 'Europe/Helsinki' })}`,
  });
}
