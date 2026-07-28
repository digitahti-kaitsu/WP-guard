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

  const reports = [];
  for (const site of sites) {
    reports.push(await auditSite(site));
  }

  await sendReport(reports);
  return res.status(200).json({
    audited: reports.filter(r => r.verified).length,
    skipped: reports.filter(r => !r.verified).map(r => r.name),
  });
}

async function auditSite(site) {
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
  if (!h.get('strict-transport-security')) findings.push('⚠️ HSTS-otsake (Strict-Transport-Security) puuttuu');
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

  // 5) WordPress-tietovuodot
  if (/<meta[^>]+name=["']generator["'][^>]+WordPress/i.test(home.body)) {
    findings.push('ℹ️ Generator-meta paljastaa WordPress-version');
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
