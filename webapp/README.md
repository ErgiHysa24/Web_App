# WatchDog Web

Interfaccia web per WatchDog: più persone avviano scansioni dal browser, i risultati restano
in un database e si confrontano nel tempo. Gira in Docker, anche su un Raspberry Pi 4 o 5
con sistema operativo a 64 bit.

Non riscrive nulla del motore: usa lo stesso codice della riga di comando (`risk_assessor`),
quindi controlli, punteggi e report sono identici.

![Quadro generale: sistemi per aree di sicurezza](../docs/assets/webapp-quadro-generale.png)

*Il quadro generale filtrato per tag, con dati di esempio.*

![Mappa della rete: macchine per tag con le porte aperte](../docs/assets/webapp-mappa.png)

## Cosa fa

- **Quadro generale**: una heatmap macchine × aree di sicurezza. Il numero dice quanti problemi
  ci sono, il colore quanto è grave il peggiore; accanto, l'andamento del rischio nelle ultime
  scansioni. Passando sopra una casella si vede il dettaglio, un clic porta a quei risultati.
- **Analisi**: problemi per gravità e per area, confronto tra macchine e tra tag, andamento
  nel tempo di ogni macchina.
- **Mappa della rete**: le macchine raggruppate per tag, con le porte aperte trovate da Nmap
  (colore = gravità del servizio, bordo scuro = raggiungibile dall'esterno).
- **Macchine per utente**: ognuno vede e analizza solo le sue; si possono condividere in sola
  lettura o anche per avviare scansioni. L'amministratore vede tutto.
- **Tag** per raggruppare le macchine: filtri su ogni pagina e scansione di un intero gruppo.
- **Scansioni in contemporanea**: ogni richiesta va in coda; ne girano più insieme, una per
  macchina. L'avanzamento si vede dal vivo e una scansione si può annullare: i tool
  installati sul sistema analizzato vengono comunque rimossi.
- **Storico e confronto**: per ogni macchina, cosa è nuovo, cosa è risolto e cosa non è stato
  ricontrollato tra due scansioni.
- **Report completo** di WatchDog (HTML, JSON, Markdown) per ogni scansione.
- **Registrazione** con verifica in due passaggi e approvazione di un amministratore.
- **API REST** con token, per collegare altri strumenti del laboratorio.

Una scansione che non riesce a collegarsi, o che non completa dei controlli, lo dice
chiaramente: non viene mai mostrata come «nessun problema».

## Installazione

Funziona sul Raspberry Pi (Raspberry Pi OS o Ubuntu **a 64 bit**: `uname -m` deve rispondere
`aarch64`) e su qualsiasi PC con Docker (su Windows e macOS: Docker Desktop, che deve restare aperto).

```sh
# 1. Docker (una volta sola; su Windows e macOS installa invece Docker Desktop)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER      # poi esci e rientra

# 2. Il codice
git clone https://github.com/ErgiHysa24/WatchDog_riskAssessment.git
cd WatchDog_riskAssessment/webapp

# 3. Il file .env: chiavi casuali e indirizzi di questo computer per il certificato HTTPS
python3 setup_env.py                   # su Windows: python setup_env.py

# 4. Costruzione e avvio (la prima volta 5-10 minuti sul Raspberry)
docker compose up -d --build

# 5. Il primo amministratore (chiede la password, almeno 12 caratteri)
docker compose exec web watchdog-web create-admin
```

Apri **`https://localhost:8443`** dal computer su cui gira, oppure
`https://<indirizzo>:8443` dagli altri computer della rete (`setup_env.py` stampa l'indirizzo
giusto). Usa `localhost`, non `127.0.0.1`: il certificato con un indirizzo IP vale solo per
quello in `WATCHDOG_DEFAULT_SNI`. Chi apre `http://…:8080` viene mandato su HTTPS.

Al primo accesso:

1. il browser avvisa che il certificato non è riconosciuto: è normale, il certificato è
   firmato da un'autorità creata dal tuo WatchDog e non da un ente pubblico. Per togliere
   l'avviso, vedi [Certificato](#certificato) qui sotto;
2. l'amministratore deve attivare la **verifica in due passaggi**: inquadra il QR con
   un'app come Google Authenticator, Microsoft Authenticator, Aegis o FreeOTP.

Se aggiorni da una versione precedente: `git pull`, poi di nuovo `python3 setup_env.py` (aggiunge
le impostazioni nuove senza toccare chiavi e password) e `docker compose up -d --build`.

Comandi utili, dalla cartella `webapp`:

| Cosa | Comando |
| --- | --- |
| Stato dei servizi | `docker compose ps` |
| Log del worker (le scansioni) | `docker compose logs -f worker` |
| Fermare / riavviare | `docker compose down` / `docker compose up -d` |
| Aggiornare | `git pull && python3 setup_env.py && docker compose up -d --build` |
| Password dimenticata | `docker compose exec web watchdog-web reset-password <utente>` |
| Telefono perso (2FA) | `docker compose exec web watchdog-web reset-2fa <utente>` |
| Copia del database | `docker compose exec db pg_dump -U watchdog watchdog > backup.sql` |

I dati stanno in volumi Docker (`watchdog_dbdata`, `watchdog_reports`, `watchdog_caddy_data`
con l'autorità di certificazione): restano anche se ricostruisci o aggiorni.
`docker compose down -v` li cancella.

### Certificato

Per far riconoscere il certificato ai browser (niente più avviso), esporta l'autorità di
certificazione del tuo WatchDog e installala come attendibile sui computer che lo usano:

```sh
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt watchdog-ca.crt
```

- **Windows**: doppio clic su `watchdog-ca.crt` → Installa certificato → Computer locale →
  «Autorità di certificazione radice attendibili».
- **macOS**: doppio clic, poi in Accesso Portachiavi imposta «Fidati sempre».
- **Linux**: copia in `/usr/local/share/ca-certificates/` e `sudo update-ca-certificates`;
  Firefox: Impostazioni → Certificati → Importa.

Il certificato vale solo per i nomi e gli indirizzi in `WATCHDOG_SERVER_NAMES` (file `.env`).
Se l'indirizzo del Raspberry cambia, aggiornalo lì e in `WATCHDOG_DEFAULT_SNI`, poi
`docker compose up -d`.

## Primo uso

1. **Macchine → Aggiungi macchina.** Indirizzo, utente SSH e password (o chiave privata).
   Se l'utente usa `sudo` con una password diversa da quella SSH, o accedi con la chiave,
   compila anche «Password di sudo»: senza sudo molti controlli restano incompleti.
2. **Nuova scansione.** Scegli uno o più obiettivi e il tipo:
   - *Controlli nativi*: solo lettura, circa un minuto, non installa nulla.
   - *Completa*: aggiunge Nmap, Lynis, ClamAV e gli altri tool; li installa e poi li rimuove.
   - *Personalizzata*: scegli i singoli controlli.
3. Segui l'avanzamento nella pagina della scansione, poi leggi i risultati e apri il report.

Il sistema da analizzare deve essere raggiungibile via SSH dal Raspberry e stare in una
delle reti consentite (`WATCHDOG_ALLOWED_NETWORKS`, di default le reti private come
192.168.x.x e 10.x.x.x): indirizzi pubblici, il Raspberry stesso e i servizi di WatchDog
vengono rifiutati. Usalo solo su macchine che sei autorizzato ad analizzare.

## Utenti, registrazione e ruoli

**Chi è amministratore.** Il primo amministratore lo crea chi installa l'applicazione, con
`docker compose exec web watchdog-web create-admin`: serve l'accesso alla macchina su cui gira,
quindi nessuno può diventarlo dal browser. Dalla pagina Utenti un amministratore può poi
promuovere altri utenti.

**Registrazione.** Dalla pagina di accesso, «Registrati»:
1. nome utente e password (almeno 12 caratteri);
2. verifica in due passaggi: QR da inquadrare con l'app e primo codice. Senza il codice la
   richiesta non viene creata (le registrazioni lasciate a metà si cancellano dopo 30 minuti);
3. la richiesta compare in **Utenti → Richieste di registrazione**: l'amministratore la approva
   scegliendo il ruolo (analista o solo lettura) oppure la rifiuta. Prima dell'approvazione
   l'account non entra.

Limiti contro gli abusi: 5 registrazioni all'ora dallo stesso indirizzo, al massimo 30
richieste in attesa. Per chiudere la registrazione: `WATCHDOG_REGISTRATION=off` nel file `.env`.

| Ruolo | Può |
| --- | --- |
| Solo lettura | vedere le macchine che altri condividono con lui, con risultati e report |
| Analista | aggiungere le sue macchine, analizzarle, condividerle; vedere quelle condivise con lui |
| Amministratore | vedere e gestire tutte le macchine, gestire utenti e registrazioni, leggere il registro attività |

La verifica in due passaggi è obbligatoria per tutti (`WATCHDOG_REQUIRE_2FA`: `all`, `admin` o
`none`; chi si registra da solo la tiene sempre). Gli utenti creati da un amministratore
cambiano la password al primo accesso.

## Macchine, condivisione e tag

Una macchina appartiene a chi l'ha aggiunta. Dalla sua pagina, nella sezione
**Condivisione**, il proprietario la condivide con altri utenti, in sola lettura o anche per
avviare scansioni; modificarla, condividerla ed eliminarla resta del proprietario (e degli
amministratori). Password e chiavi salvate non si vedono mai, nemmeno condividendo. Per chi non
la può vedere, una macchina «non esiste»: le pagine e l'API non ne rivelano l'esistenza.

I **tag** (per esempio `aula-3`, `linux`, `server`) si scrivono nel modulo della macchina,
separati da virgole. Servono a filtrare quadro generale, analisi, mappa ed elenchi, e a
lanciare una scansione su tutte le macchine di un tag («Analizza le macchine …»).

## Grafici

- **Quadro generale**: heatmap con andamento (piccola linea del rischio delle ultime scansioni).
- **Analisi**: barra dei problemi per gravità, barre per area divise per gravità, confronto
  tra macchine (con la variazione dall'ultima scansione) e tra tag, andamento di ogni macchina
  sulla stessa scala.
- **Mappa della rete**: schema con WatchDog in alto e le macchine raggruppate per tag. Per le
  porte serve una scansione con Nmap (tipo «Completa»); con l'opzione «Scansione Nmap anche
  dall'esterno» si vede anche quali porte sono raggiungibili dalla rete.
- **Pagina di una macchina**: andamento del rischio nel tempo e tabella delle porte aperte.
- **Pagina di una scansione**: problemi per area e gravità; ogni pezzo porta ai risultati.

I grafici sono disegnati dal server (SVG), senza librerie esterne. Ogni valore ha un
tooltip, accessibile anche da tastiera, e una tabella equivalente («Mostra come tabella»).

## API

Crea un token da **profilo → Token per l'API** (lo vedi una volta sola). Ogni token scade
(30, 90 o 365 giorni), è di **sola lettura** a meno che tu non scelga «lettura e scansioni»,
e non può mai fare più di quanto può fare l'utente che lo ha creato.

```sh
TOKEN=wd_...
BASE=https://raspberry:8443/api/v1
# con il certificato del laboratorio: aggiungi --cacert watchdog-ca.crt a ogni curl

curl -H "Authorization: Bearer $TOKEN" $BASE/targets
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"target": "Server web aula 3", "preset": "native"}' $BASE/scans
curl -H "Authorization: Bearer $TOKEN" $BASE/scans/12            # stato e riepilogo
curl -H "Authorization: Bearer $TOKEN" $BASE/scans/12/findings   # risultati
curl -H "Authorization: Bearer $TOKEN" "$BASE/scans/12/report?format=json"
```

| Metodo | Percorso | Cosa fa |
| --- | --- | --- |
| GET | `/me` | verifica il token |
| GET | `/checks` | controlli e tool disponibili |
| GET, POST | `/targets` | elenco (le macchine visibili al token; `?tag=`) e creazione (campo `tags`) |
| GET | `/targets/{id}` | una macchina (mai le credenziali) |
| GET, POST | `/scans` | elenco; avvio di una scansione (risponde 202, va in coda) |
| GET | `/scans/{id}` | stato, avanzamento, riepilogo (`?log=true` per il registro) |
| POST | `/scans/{id}/cancel` | annulla |
| GET | `/scans/{id}/findings` | risultati (`?severity=HIGH&area=network`) |
| GET | `/scans/{id}/report` | report completo (`?format=json`, `md`, `html`) |

Nel riepilogo, `incomplete_checks` dice quanti controlli non sono arrivati in fondo: se non
è zero, un risultato pulito non è garantito. Lo schema completo è su `/api/v1/openapi.json`
(serve il token).

## Come è fatta

```
browser ──HTTPS──► proxy (Caddy) ──► web (FastAPI) ──► PostgreSQL ◄── worker ──SSH──► sistemi
                                                          │             │
                                                   coda, risultati      └─ motore WatchDog
```

Quattro container: `proxy` (HTTPS), `web` (pagine e API), `worker` (prende le scansioni
dalla coda e le esegue), `db` (PostgreSQL 16). La coda è la tabella `scans`: il worker prende la riga successiva con
`FOR UPDATE SKIP LOCKED`, e un indice unico garantisce una sola scansione in corso per
obiettivo. Se il worker si ferma a metà, la scansione viene chiusa come «non riuscita»
invece di restare appesa.

Impostazioni nel file `.env` (vedi `.env.example`, ogni voce è spiegata): porte, nomi per il
certificato, reti consentite, verifica in due passaggi, inattività, scansioni contemporanee
(`WATCHDOG_WORKER_CONCURRENCY`, 2 va bene per un Pi 4), fuso orario.

## Sicurezza

**Accesso**
- Solo HTTPS (TLS 1.2+ con certificato dell'autorità locale), HSTS, cookie di sessione
  `__Host-` con `Secure`, `HttpOnly` e `SameSite=Lax`.
- Password con scrypt, almeno 12 caratteri, niente parole ovvie; cambio obbligatorio al primo
  accesso per gli utenti creati da un amministratore.
- Verifica in due passaggi (TOTP, RFC 6238): obbligatoria per gli amministratori, codici
  non riutilizzabili, segreto cifrato nel database.
- Blocco di 15 minuti dopo 5 tentativi sbagliati (password o codice) per utente, e per
  indirizzo dopo 20; i messaggi sono uguali per utenti esistenti e inesistenti.
- Sessione chiusa dopo 30 minuti di inattività (`WATCHDOG_IDLE_MINUTES`) e comunque dopo 8
  ore; cambio password, attivazione della 2FA o disattivazione dell'utente chiudono le altre
  sessioni.

**Dati**
- Password e chiavi SSH degli obiettivi cifrate nel database (Fernet, chiave derivata da
  `WATCHDOG_SECRET_KEY`); non vengono mai rimostrate né restituite dall'API.
  **Conserva una copia del file `.env`**: senza quella chiave le credenziali salvate non si leggono più.
- Token dell'API salvati solo come hash, con scadenza e, di default, di sola lettura.
- Registro di accessi, scansioni, modifiche e azioni sulla 2FA.

**Obiettivi**
- Solo le reti in `WATCHDOG_ALLOWED_NETWORKS` (di default le private). Mai il Raspberry
  stesso, indirizzi link-local come 169.254.169.254, multicast, né i servizi di WatchDog.
- Il nome dell'obiettivo si risolve al momento della scansione e ci si collega proprio
  all'indirizzo controllato.
- La chiave del server SSH viene registrata alla prima connessione; se in seguito cambia, la
  scansione si ferma invece di collegarsi a una macchina diversa.

**Pagine**
- Token CSRF su ogni modulo e controllo dell'origine della richiesta.
- Content-Security-Policy senza script né stili inline e senza risorse esterne; la pagina non
  può essere inclusa in altri siti (`frame-ancestors 'none'`).
- Il testo che arriva dai sistemi analizzati è trattato come non fidato: sempre mostrato come
  testo, e il report completo è aperto in una sandbox che non può leggere la sessione.
- Richieste più grandi di 256 kB rifiutate; nessuna intestazione che riveli il software usato.

**Container**
- Dall'esterno si raggiunge solo il proxy; web e database non hanno porte pubblicate e stanno
  su reti interne senza accesso a Internet. Solo il worker esce, verso i sistemi da analizzare.
- File system in sola lettura, nessun privilegio Linux (`cap_drop: ALL`, a PostgreSQL solo
  quelli che servono all'avvio), `no-new-privileges`, utente senza privilegi, limiti di
  memoria e processi.
- Dipendenze bloccate con hash; in CI `pip-audit` cerca vulnerabilità note e Dependabot
  propone gli aggiornamenti.

Limiti da conoscere: chi ha accesso al Raspberry e al file `.env` può decifrare le credenziali
salvate, quindi per gli obiettivi usa utenti dedicati, non le tue password personali. Il
certificato non è pubblico: per non avere l'avviso del browser va installata l'autorità
locale sui computer che usano l'applicazione.

## Sviluppo

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e .. -e ".[test]"
python -m pytest                      # SQLite; con PostgreSQL: WATCHDOG_TEST_DATABASE_URL=postgresql+psycopg://...

export WATCHDOG_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export WATCHDOG_DATABASE_URL=postgresql+psycopg://watchdog:PASSWORD@127.0.0.1/watchdog WATCHDOG_REPORTS_DIR=./reports
export WATCHDOG_REQUIRE_2FA=none     # in sviluppo, senza HTTPS
watchdog-web create-admin
uvicorn --factory watchdog_web.app:app_factory --reload &
python -m watchdog_web.worker
```

Il carattere dell'interfaccia è Atkinson Hyperlegible (Braille Institute, licenza SIL OFL),
incluso nel repository.
