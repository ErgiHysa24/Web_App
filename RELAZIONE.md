# WatchDog Web — Relazione tecnica

**Progetto:** applicazione web multi-utente per la valutazione del rischio di sicurezza di
sistemi Linux e macOS
**Autore:** Ergi Hysa
**Anno accademico:** 2025–2026
**Repository:** <https://github.com/ErgiHysa24/watchdog-web>

---

## 1. Introduzione

### 1.1 Contesto

WatchDog, nella sua forma originale, è uno strumento da riga di comando che analizza un sistema
Linux o macOS (configurazione, utenti, servizi, aggiornamenti, vulnerabilità, malware, hardening)
e produce un report con un punteggio di rischio. Funziona bene per una persona su una macchina,
ma in un laboratorio o in un'aula servono cose in più: **più persone** che lavorano insieme, uno
**storico** delle scansioni da confrontare nel tempo, una **coda** per non lanciare tutto a mano,
e un accesso **da browser** invece che da terminale.

### 1.2 Obiettivo

WatchDog Web è l'interfaccia web che aggiunge tutto questo **senza riscrivere il motore**: usa lo
stesso codice di scansione della riga di comando (`risk_assessor`), quindi controlli, punteggi e
report restano identici e verificati. L'applicazione aggiunge il livello che manca: account e
ruoli, database, coda delle scansioni, grafici, API, e il tutto impacchettato in Docker in modo
che parta con un comando, anche su un Raspberry Pi.

### 1.3 Requisiti e vincoli

- **Multi-utente con isolamento**: ognuno vede e analizza solo le proprie macchine; la
  condivisione è esplicita; l'amministratore vede tutto.
- **Sicura per essere esposta in rete**: è uno strumento che custodisce credenziali SSH di altri
  sistemi, quindi la sicurezza dell'applicazione stessa è parte del progetto, non un contorno.
- **Onesta**: una scansione che non si collega o non completa dei controlli lo dichiara; non
  viene mai mostrata come «nessun problema». È lo stesso principio del motore.
- **Riproducibile**: parte da `git clone` con Docker; dipendenze bloccate con hash.

---

## 2. Architettura

```text
browser ──HTTPS──► proxy (Caddy) ──► web (FastAPI) ──► PostgreSQL ◄── worker ──SSH──► sistemi
                                                           │             │
                                                    coda, risultati      └─ motore WatchDog
```

Quattro container, isolati tra loro (vedi §5):

- **proxy** (Caddy 2.10): termina l'HTTPS con un certificato firmato da un'autorità locale creata
  da WatchDog, e inoltra al servizio web. È l'unico raggiungibile dall'esterno.
- **web** (FastAPI/Starlette + uvicorn): serve le pagine (template Jinja2) e l'API REST. Non
  esegue le scansioni: le mette in coda.
- **worker**: prende le scansioni dalla coda una alla volta e le esegue richiamando il motore via
  SSH verso i sistemi da analizzare. È l'unico container che esce verso la rete.
- **db** (PostgreSQL 16): dati e coda.

La separazione **web / worker** è la scelta architetturale centrale: le pagine restano reattive
mentre le scansioni (che durano minuti) girano altrove, e il worker, che è l'unico a toccare la
rete e le credenziali in chiaro durante la connessione, è isolato dal resto.

### 2.1 La coda, dentro il database

Non c'è un sistema di code esterno (Redis, RabbitMQ): **la tabella `scans` è la coda**. Una nuova
scansione nasce `queued`; il worker prende la successiva con
`SELECT ... FOR UPDATE SKIP LOCKED`, così con più worker (o più processi) ognuno prende una riga
diversa senza conflitti. Un **indice unico parziale** (`status = 'running'` per `target_id`)
garantisce a livello di database una sola scansione in corso per obiettivo, anche in caso di gara.
Se il worker si ferma a metà (riavvio, errore), un *heartbeat* permette di riconoscere la
scansione orfana e chiuderla come «non riuscita» invece di lasciarla appesa. È una coda semplice,
senza pezzi in più, che sfrutta le garanzie transazionali che PostgreSQL offre già.

---

## 3. Modello dei dati

Sette tabelle (schema completo e diagramma in [`docs/SCHEMA-DB.md`](docs/SCHEMA-DB.md)):
`users`, `api_tokens`, `targets`, `target_shares`, `scans`, `findings`, `audit_log`. I modelli
sono SQLAlchemy 2 (`watchdog_web/models.py`); lo schema si crea all'avvio.

Le chiavi esterne scelgono con cura il comportamento alla cancellazione: `CASCADE` dove il figlio
non esiste senza il padre (i token di un utente, i finding di una scansione), `SET NULL` dove la
storia va conservata (chi ha creato una macchina, il registro attività resta anche se l'utente
viene eliminato). I campi variabili (tag, conteggi, heatmap delle aree, riferimenti normativi)
sono colonne **JSON** (`JSONB` su PostgreSQL).

---

## 4. Funzionalità

- **Accesso**: login/logout, registrazione con approvazione, verifica in due passaggi (TOTP).
- **Data entry e modifica**: macchine (obiettivo SSH con credenziali cifrate), tag, condivisioni,
  utenti, token API. Tutto persistito in PostgreSQL.
- **Scansioni**: avvio singolo o per tag, coda, esecuzione in parallelo (una per macchina),
  avanzamento dal vivo, annullamento (con rimozione dei tool installati sul target), storico e
  confronto tra due scansioni (nuovo / risolto / non ricontrollato).
- **Grafici** disegnati dal server in SVG, senza librerie JavaScript esterne (coerente con la CSP
  che vieta gli script esterni): heatmap macchine × aree, analisi per gravità e area, mappa della
  rete con le porte aperte, andamento del rischio nel tempo. Ogni grafico ha tooltip accessibili
  da tastiera e una tabella equivalente.
- **Report** completo per ogni scansione (HTML, JSON, Markdown), identico a quello del motore.
- **API REST** con token a scadenza, di sola lettura per default, che non può mai fare più
  dell'utente che l'ha creato.

---

## 5. Sicurezza

È la parte più curata, perché l'applicazione custodisce le credenziali SSH di altri sistemi.
L'approccio segue le linee guida OWASP (Top 10, ASVS, Cheat Sheet).

### 5.1 Autenticazione e sessione

- Password con **scrypt**, almeno 12 caratteri, confronto a tempo costante; un hash fittizio per
  gli utenti inesistenti rende indistinguibile il tempo di risposta (niente enumerazione).
- **Verifica in due passaggi** TOTP (RFC 6238): obbligatoria secondo la politica, segreto
  **cifrato** nel database, codice non riutilizzabile (si memorizza l'ultimo passo usato).
- **Blocco** dopo 5 tentativi falliti per utente e 20 per indirizzo IP; stessi messaggi e stessi
  tempi per utenti esistenti e inesistenti.
- Cookie di sessione **`__Host-`** con `Secure`, `HttpOnly`, `SameSite=Lax`; scadenza per
  inattività e assoluta; un `session_version` sull'utente **invalida tutte le sessioni** al
  cambio password, all'attivazione della 2FA o alla disattivazione.

### 5.2 Autorizzazione

Tre ruoli (solo lettura < analista < amministratore). Una risorsa non visibile all'utente
**«non esiste»**: pagine e API rispondono come per un id inesistente, senza rivelare la presenza
dell'oggetto (niente IDOR). I permessi sono verificati **sul server** per ogni azione, non
nascondendo i pulsanti.

### 5.3 Protezione delle pagine e dei dati

- **CSRF**: token legato alla sessione su ogni modulo, più controllo dell'intestazione `Origin`.
- **Content-Security-Policy** senza script né stili inline e senza risorse esterne; la pagina non
  è includibile altrove (`frame-ancestors 'none'`); oltre a `nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, HSTS. Il report completo, che contiene testo dei sistemi analizzati, è
  servito in **sandbox** su un percorso che non può leggere la sessione.
- Il testo che arriva dai sistemi analizzati è trattato come **non fidato** e sempre mostrato come
  testo (escape automatico dei template).
- **Credenziali cifrate**: password e chiavi SSH degli obiettivi con **Fernet** (chiave derivata
  da `WATCHDOG_SECRET_KEY`); non vengono mai rimostrate né restituite dall'API. I token API sono
  salvati solo come **hash SHA-256**.

### 5.4 Difesa dagli SSRF (gli obiettivi delle scansioni)

Poiché l'utente indica l'indirizzo da analizzare, un controllo di rete (`netpolicy`) consente
**solo** le reti private configurate e rifiuta loopback, link-local (`169.254.169.254`,
i metadata delle istanze cloud), multicast, riservati e i servizi stessi di WatchDog. Il nome
viene risolto **al momento della scansione** e ci si collega esattamente a quell'indirizzo
(difesa dal cambio DNS, TOCTOU). La chiave host SSH è fissata alla prima connessione (TOFU): se
poi cambia, la scansione si ferma.

### 5.5 Hardening dei container

Dall'esterno si raggiunge **solo il proxy**; web e database non pubblicano porte e stanno su reti
**interne senza uscita**; solo il worker esce. Ogni container ha file system in **sola lettura**,
`cap_drop: ALL` (a PostgreSQL solo i privilegi minimi d'avvio), `no-new-privileges`, utente non
privilegiato, limiti di memoria e processi. Le dipendenze sono bloccate con hash; in sviluppo
`bandit` e `pip-audit` controllano codice e vulnerabilità note.

### 5.6 Verifica

Oltre ai test, la sicurezza dell'applicazione è stata provata con uno strumento di **pentest
attivo** (`watchdog-pentest`, progetto parallelo): 16 moduli (OWASP/CWE) su configurazione,
autenticazione, autorizzazione, injection, XSS, CSRF, SSRF. L'applicazione li supera **senza alcun
finding**. Dettaglio in [`webapp/REVISIONE-SICUREZZA.md`](webapp/REVISIONE-SICUREZZA.md).

---

## 6. Scelte tecniche notevoli

- **Niente JavaScript di terze parti**: i grafici sono SVG generati dal server. Questo permette
  una CSP severa (nessuno script esterno) e mantiene l'app leggera, adatta a un Raspberry Pi.
- **La coda nel database** invece di un broker esterno: meno pezzi, garanzie transazionali già
  pronte (`SKIP LOCKED`, indice unico parziale).
- **Riuso del motore**: il codice di scansione non è duplicato; l'app lo importa. Un problema
  corretto nel motore migliora anche la web app.
- **Onestà sui controlli non eseguiti**: il conteggio `incomplete` viaggia dalla scansione fino
  alla heatmap, così l'assenza di segnalazioni non viene mai scambiata per assenza di problemi.

---

## 7. Test e qualità

- **85 test** con `pytest` (`webapp/tests/`), eseguiti sia su **SQLite** sia su **PostgreSQL**:
  autenticazione, 2FA, autorizzazione/isolamento, CSRF, intestazioni di sicurezza, registrazione,
  coda, API.
- Integrazione continua su GitHub Actions: test, `ruff`, `bandit`, `pip-audit` sulle dipendenze
  bloccate, e costruzione dell'immagine Docker (amd64 e arm64 per il Raspberry Pi).
- Verifica manuale end-to-end con `docker compose up` su PC Windows (Docker Desktop).

---

## 8. Limiti

- Chi ha accesso al server e al file `.env` può decifrare le credenziali salvate: per gli
  obiettivi vanno usati utenti SSH dedicati, non password personali.
- Il certificato è firmato da un'autorità locale: per togliere l'avviso del browser va installata
  quell'autorità sui computer che usano l'applicazione.
- Il worker esegue scansioni su sistemi raggiungibili via SSH in reti private: non è pensato per
  obiettivi su Internet (ed è bloccato di proposito).

---

## 9. Sviluppi futuri

- Notifiche (email/webhook) sui risultati critici; scansioni **programmate** con confronto
  automatico.
- Esportazione del quadro generale in PDF e invio periodico.
- Single Sign-On (OIDC) per le organizzazioni.
- Arricchimento del rischio con dati di sfruttabilità reale delle CVE (per esempio EPSS).

---

## 10. Conclusioni

WatchDog Web trasforma uno strumento da riga di comando in un servizio multi-utente senza
rinunciare a ciò che lo rende affidabile: lo stesso motore, lo stesso modello di rischio, la
stessa onestà sui controlli non eseguiti. Il valore aggiunto — account e ruoli, database, coda,
grafici, API — è costruito attorno a una sicurezza presa sul serio: isolamento tra utenti,
credenziali cifrate, difesa dagli SSRF, hardening dei container. Il risultato è un'applicazione
che parte con un comando, gira anche su un Raspberry Pi, e regge una verifica di sicurezza attiva
senza segnalazioni.
