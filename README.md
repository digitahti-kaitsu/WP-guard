# WP-guard

Kevyt uptime- ja tietoturvavalvonta WordPress-sivustoille. Pyörii Vercelin cron-ajoina, lähettää sähköpostia Resendillä, maksaa käytännössä nolla.

> *A lightweight uptime and passive security monitor for WordPress sites, running as Vercel cron jobs. Finnish-language project: all emails, comments and documentation are in Finnish.*

Tehty ylläpitäjälle, jolla on kourallinen asiakassivustoja eikä halua jokaisesta maksaa sivukohtaisesta valvontapalvelusta. Ei dashboardia, ei tiliä, ei agenttia sivustolla – kaksi serverless-funktiota ja sähköposti kun jokin on vialla.

## Mitä se tekee

**`api/monitor.js` – uptime, 10 min välein.** Hakee jokaisen sivuston etusivun ja vertaa tulosta edelliseen ajoon (tila talletetaan Vercel Blobiin). Sähköposti lähtee **vain tilan muuttuessa** – kun sivu kaatuu ja kun se palaa. Nurin oleva sivusto ei siis lähetä viestiä kymmenen minuutin välein.

**`api/security.js` – tietoturvatarkistus, maanantaisin.** Käy sivustot läpi ja lähettää viikkoraportin. Tarkistaa tietoturvaotsakkeet, HTTPS-ohjauksen, SSL-sertifikaatin vanhenemisen ja tavallisimmat WordPress-tietovuodot.

## Periaatteet

Kolme asiaa, jotka on tarkoituksella tehty näin:

**Omistajuusvarmistus on pakollinen.** Tietoturvatarkistus ajetaan vain, jos sivuston etusivulta löytyy `<meta name="wp-guard-verify" content="TOKEN">` ja token täsmää `sites.json`-tiedostoon. Ilman sitä sivusto ohitetaan ja se mainitaan raportissa. Näin työkalu ei voi vahingossa kohdistua sivustoon, joka ei ole omassa ylläpidossa – ei silloinkaan, jos kirjoitat listaan väärän osoitteen.

**Kaikki tarkistukset ovat passiivisia.** Tavallisia GET-pyyntöjä ja otsakkeiden lukua. Ei brute forcea, ei haavoittuvuusskannausta, ei POST-pyyntöjä kohdesivuille. Tämä ei ole tunkeutumistestaustyökalu eikä sellaiseksi kannata muokata.

**Ei postitulvaa.** Uptime-hälytys vain tilan muutoksesta. Ensimmäinen ajo hälyttää vain, jos sivu on jo valmiiksi nurin. Valvonta jota ei jaksa lukea ei valvo mitään.

## Vaatimukset

- **Vercel Pro.** Hobby-tilillä cron saa ajaa korkeintaan kerran päivässä, ja tiheämpi lauseke **kaataa deployn** virheeseen *"Hobby accounts are limited to daily cron jobs."* Monitorin oletusaikataulu on `*/10 * * * *`. Hobbylla vaihtoehdot ovat päivittäinen aikataulu (jolloin uptime-valvonnasta ei ole juuri hyötyä) tai ulkoinen kutsuja, esim. cron-job.org, joka pyytää `/api/monitor`ia halutulla tahdilla `CRON_SECRET`illä.
- **Resend-tili** sähköposteihin. Ilmainen taso (100 viestiä/pv) riittää hyvin.
- **Pääsy valvottavien sivustojen tiedostoihin**, jotta verify-tagin saa asennettua.

## Asennus

### 1. Resend

Luo tili osoitteessa [resend.com](https://resend.com) ja **verifioi lähettäjädomain**. Verifiointi on pakollista – ilman sitä lähetys ei onnistu lainkaan. Resend antaa DNS-tietueet (SPF/DKIM), jotka lisätään domainin hallintaan. Ota API-avain talteen.

Postilaatikon ei tarvitse olla oikeasti olemassa: lähettämiseen riittää verifioitu domain. Jos vastaat joskus hälytysviestiin, vastaus kimpoaa takaisin.

### 2. Projekti Verceliin

Forkkaa tai kloonaa repo omaan Git-palveluusi ja tuo se Vercelin dashboardista: **Add New → Project → Import Git Repository**.

- Framework Preset: **Other**
- Root Directory: `./`
- Build Command ja Output Directory: tyhjiksi

Lisää ympäristömuuttujat jo Configure-ruudussa, ennen ensimmäistä deployta – muuttujat vaikuttavat vain niihin deployeihin, jotka luodaan niiden asettamisen jälkeen.

| Muuttuja | Arvo |
|---|---|
| `CRON_SECRET` | satunnainen merkkijono, esim. `openssl rand -hex 32` |
| `RESEND_API_KEY` | Resendin API-avain |
| `ALERT_FROM` | `WP-guard <valvonta@omadomain.fi>` – ei lainausmerkkejä Vercelin kenttään |
| `ALERT_TO` | vastaanottajan sähköposti |

`CRON_SECRET` on omatekoinen merkkijono, ei mistään palvelusta haettu. Vercel lähettää sen arvon automaattisesti cron-kutsujen `Authorization: Bearer` -otsakkeessa, ja koodi vertaa otsaketta muuttujaan.

**Valitse `ALERT_TO`-osoite valvottavan infran ulkopuolelta.** Jos sähköpostisi on samalla palvelimella kuin valvottava sivusto, hälytys sivuston kaatumisesta ei tavoita sinua.

### 3. Vercel Blob

**Storage → Create Database → Blob.**

- **Access: Public.** Koodi kirjoittaa tilan `access: 'public'`-optiolla ja lukee sen takaisin tavallisella `fetch`illä. Private-storesta luku ei onnistu, eikä se näkyisi virheenä: koodi palauttaisi tyhjän tilan, jolloin jokainen ajo luulisi olevansa ensimmäinen – ja kaatunut sivusto lähettäisi hälytyksen kymmenen minuutin välein.
- Rastita **"Add a read-write token env var to this connection"**. Ilman sitä syntyy vain `BLOB_STORE_ID`, jota `@vercel/blob` ei osaa käyttää, ja ensimmäinen ajo kaatuu virheeseen "No token found".

Tilatiedosto on pieni, kulut ovat käytännössä nolla. Se sisältää valvottavien sivustojen osoitteet ja niiden ylhäällä/alhaalla-tilan – ei mitään salaista, mutta hyvä tiedostaa Public-valinnan yhteydessä.

Storen luonnin jälkeen tee **uusi deploy**, jotta funktiot näkevät uudet muuttujat.

### 4. Sivulista

Muokkaa `sites.json`:

```json
[
  { "name": "Asiakas Oy", "url": "https://asiakas.fi/", "token": "..." }
]
```

Käytä **kanonista osoitetta**. Jos sivusto ohjaa www-muotoon, kirjoita se www:n kanssa – muuten jokainen tarkistus tekee turhan uudelleenohjaushypyn.

Tiedosto tuodaan koodiin staattisesti (`import sites from '../sites.json'`), joten se **kuuluu versionhallintaan eikä ympäristömuuttujaan**, ja muutos vaatii uuden deployn. Staattinen tuonti on tässä oikea ratkaisu myös siksi, että Vercel osaa silloin sisällyttää tiedoston funktion bundleen.

### 5. Omistajuusvarmistus

1. Generoi jokaiselle sivustolle oma token: `openssl rand -hex 16`
2. Kirjoita token sivuston kohdalle `sites.json`-tiedostoon
3. Kopioi `wp-guard-meta.php` sivuston kansioon `wp-content/mu-plugins/` (luo kansio jos puuttuu) ja vaihda tiedostoon sama token. MU-pluginia ei tarvitse aktivoida – se on käytössä heti kun tiedosto on kansiossa. Multisitessa tiedostossa on valmis esimerkki blog_id-kohtaisista tokeneista.
4. Tarkista että etusivun lähdekoodissa näkyy `<meta name="wp-guard-verify" content="...">`

Muulle kuin WordPressille tagin voi lisätä käsin `<head>`-osaan. Tagin täytyy olla **etusivulla**, koska tarkistus hakee vain juuriosoitteen.

Token ei ole salaisuus – se näkyy sivuston julkisessa lähdekoodissa, samaan tapaan kuin Google Search Consolen verifiointitunnus. Sen tehtävä on todistaa, että sama taho hallitsee sekä sivulistaa että sivustoa.

### 6. Testaus

```bash
curl -H "Authorization: Bearer SINUN_CRON_SECRET" \
  https://PROJEKTISI.vercel.app/api/monitor
```

Aja kahdesti: ensimmäinen kirjoittaa tilan Blobiin, toinen lukee sen takaisin. Vasta toinen ajo todistaa Blob-yhteyden toimivaksi molempiin suuntiin. Vastauksesta näkee montako sivua tarkistettiin ja mitkä ovat nurin.

Ilman `Authorization`-otsaketta endpointin pitää vastata `401` – se on nopea tapa varmistaa, että deploy on elossa ja suojaus toimii.

## Mitä tietoturvatarkistus tarkistaa

Kaikki passiivisia GET-pyyntöjä:

- **Tietoturvaotsakkeet:** HSTS, X-Content-Type-Options, clickjacking-suoja (X-Frame-Options tai CSP `frame-ancestors`), Referrer-Policy
- **HTTP → HTTPS -uudelleenohjaus**
- **SSL-sertifikaatin vanheneminen**, varoitus 14 pv etukäteen
- **WP-tietovuodot:** generator-meta, avoin `/readme.html`, julkinen `debug.log`, hakemistolistaus uploads-kansiossa, `xmlrpc.php`

Löydökset on merkitty: 🔴 korjaa heti, ⚠️ kannattaa korjata, ℹ️ tiedoksi.

Testiajo käsin:

```bash
curl -H "Authorization: Bearer SINUN_CRON_SECRET" \
  https://PROJEKTISI.vercel.app/api/security
```

## Löydösten korjaaminen

Suurin osa raportin löydöksistä korjaantuu yhdellä `.htaccess`-lohkolla. Se käy sellaisenaan sekä WordPress-sivustoille että staattisille sivuille Apache- ja LiteSpeed-palvelimilla.

```apache
# Estä hakemistolistaus, jottei kansioiden sisältöä voi selata.
Options -Indexes

# Estä pääsy WordPressin readme-tiedostoon, joka paljastaa WP-version.
# Tiedostoa ei kannata poistaa: WordPress palauttaa sen jokaisessa
# päivityksessä. Esto sen sijaan kestää päivitysten yli.
<Files "readme.html">
    Require all denied
</Files>

<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=300"
</IfModule>
```

**HSTS kahdessa vaiheessa.** Yllä oleva `max-age=300` on tarkoituksella viisi minuuttia. HSTS on lupaus selaimelle, ettei sivustoa käytetä koskaan HTTP:n yli, eikä lupausta voi perua – selain muistaa sen `max-age`-ajan riippumatta siitä mitä palvelin myöhemmin vastaa. Seuraa vuorokausi ettei mikään hajoa ja nosta vasta sitten arvoon `31536000`. Älä lisää `includeSubDomains`-määrettä ellei jokainen aliverkkotunnus toimi varmasti HTTPS:llä.

Tarkistus huomauttaa lyhyestä `max-age`-arvosta niin kauan kuin se on voimassa, ja näyttää arvon raportissa. Se on tarkoituksellista: testiarvo jää muuten helposti pysyväksi, jolloin otsake näyttää suojaukselta suojaamatta miltään. Löydös katoaa itsestään kun arvo on vähintään vuosi.

**WordPressissä** lohko sijoitetaan `# BEGIN WordPress` -lohkon **ulkopuolelle**. WordPress kirjoittaa oman lohkonsa uudelleen aina kun pysyvien osoitteiden asetukset tallennetaan.

**Lue olemassa oleva `.htaccess` ennen kuin korvaat sen.** Siellä on tyypillisesti cPanelin generoima PHP-versiolohko (`# php -- BEGIN cPanel-generated handler`), uudelleenohjauksia tai vanhan sivuston 301-perintöä. Ne on säilytettävä sanatarkasti.

`xmlrpc.php`-esto on jätetty lohkon ulkopuolelle tarkoituksella: se rikkoo Jetpackin ja WordPressin mobiilisovelluksen. Jos kumpaakaan ei käytetä, lisää:

```apache
<Files "xmlrpc.php">
    Require all denied
</Files>
```

Generator-metaa ja `X-Powered-By`-otsaketta ei kannata jahdata. Ne ovat versiotiedon piilottelua, eikä hyökkääjä tarvitse niitä. Jälkimmäinen on usein webhotellin asettama eikä poistu `.htaccess`illa.

## Vianetsintä

**Verify-tagi ei näy, vaikka plugin on asennettu.** Lähes aina koko sivun välimuisti. Tarkista ensin kyselymerkkijonolla, joka ohittaa välimuistin:

```bash
curl -s "https://sivusto.fi/?x=$(date +%s)" | grep wp-guard-verify
```

Jos tagi löytyy näin mutta ei ilman kyselymerkkijonoa, kyse on välimuistista eikä asennuksesta. Tyhjennä se, tai odota TTL:n umpeutumista.

**Välimuistitasoja voi olla useita.** WordPressin lisäosan purge ei kosketa palveluntarjoajan proxy-välimuistia. Katso otsakkeista kumpi on kyseessä: `x-litespeed-cache: hit` on lisäosan tai palvelimen välimuisti, `x-proxy-cache: STALE` on erillinen käänteisproxy sen edessä.

**`Vary: User-Agent` -ansa.** Jotkin proxyt pitävät erillistä välimuistimerkintää jokaiselle selaintunnisteelle. Jos testaat omalla skriptilläsi eri tunnisteella kuin mitä WP-guard käyttää, voit katsella eri välimuistimerkintää kuin varsinainen tarkistus – ja päätyä väärään johtopäätökseen. Käytä testatessa samaa tunnistetta kuin `api/security.js`.

**Cron ei aja.** Cronit ajetaan vain tuotantodeploysta, eivät preview-haaroista. Tarkista **Settings → Cron Jobs** ja ajojen lokit sieltä.

## Kehitys

```bash
npm install
npx vercel dev
```

Syntaksitarkistus ilman deployta:

```bash
node --check api/monitor.js api/security.js
```

Ei testikehikkoa eikä bundleria – vaniljaa Node ESM:ää ja Vercelin oletus-runtimea. Se on tarkoituksellista: projektin koko arvo on siinä, että sen voi lukea kokonaan kertaistumalta.

Aikaleimat muotoillaan `Europe/Helsinki`-vyöhykkeellä. Jos olet muualla, vaihda `toLocaleString`-kutsujen aikavyöhyke.

## Rajoitukset

- Tarkistaa vain etusivun, ei alasivuja
- Uptime perustuu HTTP-statuskoodiin. WordPressin kriittinen virhe palauttaa joskus 200, jolloin "valkoinen ruutu" ei näy katkona
- Ei historiaa eikä tilastoja – vain nykytila ja sähköposti muutoksesta
- Ei korvaa varmuuskopioita, päivityksiä eikä palomuuria

## Lisenssi

MIT. Katso [LICENSE](LICENSE).
