# WP-guard

WordPress-sivustojen valvonta Vercel-projektina. Kaksi cron-ajettavaa serverless-funktiota:

- `api/monitor.js` – uptime-tarkistus 10 min välein (`*/10 * * * *`). Vertaa tilaa edelliseen ajoon (Vercel Blob, tiedosto `wp-guard-state.json`) ja lähettää sähköpostin Resendillä VAIN tilan muuttuessa (kaatui/palasi).
- `api/security.js` – passiivinen tietoturvatarkistus maanantaisin klo 05 UTC (`0 5 * * 1`). Lähettää aina viikkoraportin.

## Arkkitehtuuriperiaatteet

- **Omistajuusvarmistus on pakollinen tietoturvatarkistuksessa.** `api/security.js` ajaa tarkistukset vain, jos sivuston etusivulta löytyy `<meta name="wp-guard-verify" content="TOKEN">` ja token täsmää `sites.json`-tiedostoon. Tätä ei saa poistaa tai ohittaa – se takaa, ettei tarkistus koskaan kohdistu sivustoon, joka ei ole omassa ylläpidossa. Tagi tuotetaan sivustolla MU-pluginilla `wp-guard-meta.php`.
- **Kaikki tarkistukset ovat passiivisia** (GET-pyyntöjä ja otsakkeiden lukua). Ei brute forcea, ei haavoittuvuusskannausta, ei POST-pyyntöjä kohdesivuille.
- **Ei postitulvaa**: uptime-hälytys vain tilan muutoksesta; ensimmäinen ajo hälyttää vain jos sivu on valmiiksi nurin.
- Molemmat endpointit vaativat `Authorization: Bearer CRON_SECRET` -otsakkeen. Vercel lisää sen cron-kutsuihin automaattisesti, kun `CRON_SECRET`-ympäristömuuttuja on asetettu. Puuttuva muuttuja johtaa aina 401:een – ilman erillistä tarkistusta vertailuarvoksi tulisi merkkijono `"Bearer undefined"`.

## Ympäristömuuttujat (Vercel)

| Muuttuja | Kuvaus |
|---|---|
| `CRON_SECRET` | satunnainen merkkijono, suojaa endpointit |
| `RESEND_API_KEY` | Resend-avain sähköposteille |
| `ALERT_FROM` | esim. `WP-guard <valvonta@esimerkki.fi>` (domain verifioitu Resendissä) |
| `ALERT_TO` | vastaanottajan sähköposti |
| `BLOB_READ_WRITE_TOKEN` | tulee Blob-storesta, kun "Add a read-write token env var" on rastitettu |

## Sivulista

`sites.json`: taulukko `{ name, url, token }`. Token generoidaan per sivusto (`openssl rand -hex 16`) ja sama token laitetaan sivuston MU-pluginiin. Tiedosto tuodaan staattisesti (`import ... with { type: 'json' }`), joten se kuuluu versionhallintaan ja muutos vaatii deployn. Käytä kanonista osoitetta, jottei jokainen tarkistus tee turhaa uudelleenohjaushyppyä.

## Kehitys ja testaus

```bash
npm install
npx vercel dev          # paikallinen ajo
# testikutsu:
curl -H "Authorization: Bearer $CRON_SECRET" http://localhost:3000/api/monitor
```

Syntaksitarkistus ilman deployta: `node --check api/monitor.js api/security.js`

Ei testikehikkoa eikä bundleria – vaniljaa Node ESM:ää, Vercelin oletus-runtime. Pidä se niin. `package.json`issa on `"type": "module"`, koska tiedostopääte on `.js` ja koodi käyttää import-syntaksia.

## Kieli

Käyttöliittymäkieli (sähköpostit, kommentit, dokumentaatio) on suomi. Aikaleimat muotoillaan `Europe/Helsinki`-vyöhykkeellä.

## Dokumentaatio

Asennus- ja käyttöohje on `README.md`. Jos muutat toiminnallisuutta, päivitä myös se.
