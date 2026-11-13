# Revisione di sicurezza — WatchDog Web

Revisione della web app prima della consegna. Due metodi, uno complementare all'altro:

1. **lettura manuale** del codice che regge la sicurezza (sessioni, CSRF, controllo degli
   accessi, cifratura, allowlist di rete, intestazioni);
2. **scansione automatica** con [watchdog-pentest](https://github.com/ErgiHysa24/watchdog-pentest),
   lo strumento di pentest del progetto, puntato sull'app in esecuzione.

## Esito in breve

La web app **supera la propria scansione di pentest senza alcun finding** sulla superficie
pubblica e di accesso (16 moduli, 0 problemi). Sono stati applicati due piccoli irrobustimenti
delle intestazioni; il resto sono raccomandazioni di difesa in profondità, non problemi.

## Controlli verificati (presenti e corretti)

- **Sessioni**: cookie firmato, `HttpOnly`, `SameSite=Lax`, `Secure` + prefisso `__Host-` in
  HTTPS; scadenza, inattività (il polling di stato non tiene viva la sessione), versione di
  sessione che chiude le altre sessioni al cambio password / 2FA.
- **CSRF**: token legato alla sessione su ogni azione che cambia stato, più controllo
  dell'intestazione `Origin`. La scansione conferma che un'azione senza token viene rifiutata.
- **Accesso**: blocco dell'utente dopo 5 tentativi e dell'IP dopo 20; stesso trattamento e
  stesso tempo di risposta per utenti esistenti e inesistenti (niente enumerazione al login);
  la scansione conferma «blocco osservato dopo 5 tentativi».
- **Verifica in due passaggi** (TOTP): obbligatoria secondo la politica, segreto cifrato,
  codice non riutilizzabile, codici errati che bloccano l'utente.
- **Autorizzazione**: ogni risorsa non visibile risulta «inesistente» (niente IDOR); pagine e
  azioni da amministratore protette sul server; API con token dai permessi dell'utente e di
  sola lettura per default.
- **Credenziali degli obiettivi**: cifrate con Fernet (chiave derivata da `WATCHDOG_SECRET_KEY`),
  mai restituite dall'API; password con scrypt e confronto a tempo costante.
- **SSRF / scansioni**: `netpolicy` consente solo le reti private configurate, mai loopback,
  link-local (metadata), multicast o i servizi di WatchDog; controllo ripetuto al momento della
  scansione risolvendo il nome allora (difesa dal cambio DNS, TOCTOU).
- **Intestazioni**: CSP senza inline né risorse esterne, `nosniff`, `X-Frame-Options: DENY` +
  `frame-ancestors 'none'`, COOP/CORP, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control:
  no-store`, limite di dimensione del corpo (413). Report completo servito in sandbox a origine
  separata.
- **Configurazione**: nessun segreto con valore predefinito; l'app non parte senza
  `WATCHDOG_SECRET_KEY` (≥32) e `WATCHDOG_DATABASE_URL`.
- **Container**: sola lettura, `cap_drop: ALL`, `no-new-privileges`, reti interne senza uscita
  per web e database, solo il worker esce; `pip-audit` e Dependabot in CI.

## Modifiche applicate in questa revisione

| File | Modifica | Perché |
|---|---|---|
| `watchdog_web/app.py` | HSTS `max-age=31536000; includeSubDomains` | estende l'obbligo di HTTPS ai sottodomini |
| `watchdog_web/app.py` | `Permissions-Policy` + `browsing-topics=()` | disattiva l'API Topics di tracciamento |
| `tests/test_hardening.py` | asserzioni sulle due intestazioni | evita regressioni |

Tutte e due valgono solo in HTTPS (la prima) o sono inerti altrove; nessun cambiamento di
comportamento. Suite verde (85 test su SQLite e PostgreSQL), `ruff` e `bandit` puliti.

## Raccomandazioni (difesa in profondità, non applicate)

1. **`FORWARDED_ALLOW_IPS: "*"` nel compose** → restringere al proxy. Oggi è sicuro perché il
   servizio `web` non espone porte e la rete `edge` è `internal`: solo Caddy può raggiungerlo,
   quindi solo Caddy può impostare `X-Forwarded-For`. Resta però una difesa in profondità: se
   un domani si pubblicasse una porta del `web` per debug, o cambiasse la topologia, un client
   potrebbe falsificare il proprio IP e aggirare il blocco per-IP o sporcare il registro. Fix
   consigliato: dare alla rete `edge` una sottorete fissa e impostare `FORWARDED_ALLOW_IPS` a
   quella sottorete invece di `*`. Non applicato qui perché una modifica di rete alla vigilia
   della consegna, senza un test end-to-end di compose in CI che ne verifichi la
   non-regressione, è più rischiosa del beneficio; va fatta con calma e provata con
   `docker compose up`.
2. **Enumerazione utenti in registrazione**: la pagina dice se un nome utente è già preso. È un
   compromesso d'uso comune (serve a far scegliere un altro nome) e il percorso di *login* è
   già a prova di enumerazione; si può lasciare così. Alternativa, se si vuole chiudere anche
   questo: messaggio generico e nome occupato segnalato solo dopo l'approvazione.
3. **Opzionali**: `Strict-Transport-Security` con `preload` (è un impegno verso l'elenco dei
   browser: solo a dominio stabile); `SameSite=Strict` sul cookie (leggermente più sicuro, ma
   un link esterno all'app non mostrerebbe l'utente già connesso al primo clic).

## Appendice — esito della scansione watchdog-pentest

Bersaglio: l'app in esecuzione (HTTP di laboratorio). 0 finding; moduli non eseguiti dichiarati
(mai un falso «tutto a posto»):

| Modulo | Esito |
|---|---|
| recon, cookies, csp, cors, info-disclosure | eseguiti, nessun problema |
| auth, rate-limit, api-security | eseguiti, nessun problema (rate-limit: «blocco dopo 5 tentativi») |
| injection, xss, open-redirect, path-traversal | eseguiti, nessun problema |
| tls | non eseguito (bersaglio in HTTP; in produzione è dietro HTTPS) |
| access-control, csrf | non eseguiti senza account di prova |
| ssrf | non applicabile (l'app non espone parametri che scaricano URL) |

Con account di prova in `config.yaml` si eseguono anche `access-control`, `csrf` e le parti
autenticate di `injection`/`xss`.
