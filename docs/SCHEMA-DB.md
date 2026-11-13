# Schema del database

WatchDog Web usa **PostgreSQL 16** (in sviluppo anche SQLite). Sette tabelle; le chiavi esterne
hanno `ON DELETE CASCADE` dove la riga figlia non ha senso senza il padre (i token di un utente,
i finding di una scansione) e `ON DELETE SET NULL` dove la storia va conservata anche se l'autore
sparisce (chi ha creato una macchina, chi ha richiesto una scansione, il registro attività).

![Schema del database](assets/schema-db.png)

```mermaid
erDiagram
    users ||--o{ api_tokens : "possiede"
    users ||--o{ targets : "crea (created_by)"
    users ||--o{ target_shares : "riceve"
    users ||--o{ scans : "richiede"
    users ||--o{ audit_log : "agisce"
    targets ||--o{ target_shares : "condivisa in"
    targets ||--o{ scans : "analizzata da"
    scans ||--o{ findings : "produce"

    users {
        int id PK
        string username UK
        string password_hash "scrypt"
        string role "admin|analyst|viewer"
        string approval "approved|pending|unconfirmed"
        bool totp_enabled "2FA"
        string totp_secret_enc "cifrato"
        int session_version
        int failed_logins
        datetime locked_until
    }
    api_tokens {
        int id PK
        int user_id FK
        string token_hash UK "SHA-256"
        bool read_only
        datetime expires_at
        bool revoked
    }
    targets {
        int id PK
        int created_by FK "proprietario"
        string name
        string host
        string ssh_user
        string secret_enc "Fernet"
        string sudo_password_enc "Fernet"
        string host_key "TOFU"
        json tags
    }
    target_shares {
        int id PK
        int target_id FK
        int user_id FK
        bool can_scan "lettura o scansione"
    }
    scans {
        int id PK
        int target_id FK
        int requested_by FK
        string status "queued|running|done|failed|cancelled"
        int risk_score
        json areas "heatmap"
        int incomplete
    }
    findings {
        int id PK
        int scan_id FK
        string title
        string severity
        string area
        string source
        json refs "CIS/ISO/NIST/ATTACK"
    }
    audit_log {
        int id PK
        int user_id FK
        string username
        string action
        string ip
        datetime at
    }
```

## Le tabelle

| Tabella | A cosa serve | Note di sicurezza |
|---|---|---|
| **users** | account, ruolo, stato di approvazione, 2FA | password con **scrypt**; segreto TOTP **cifrato**; `session_version` invalida le sessioni al cambio password; `failed_logins`/`locked_until` per il blocco anti brute-force |
| **api_tokens** | token personali per l'API | salvato solo l'**hash SHA-256**; `read_only` e `expires_at`; revocabile |
| **targets** | le macchine da analizzare | password e chiavi SSH **cifrate** (Fernet); `host_key` fissata alla prima connessione (TOFU); `created_by` = proprietario |
| **target_shares** | condivisione di una macchina con un altro utente | vincolo di unicità `(target_id, user_id)`; `can_scan` distingue sola lettura da scansione |
| **scans** | ogni scansione **ed è anche la coda** dei lavori | indice unico parziale: una sola scansione `running` per obiettivo; il worker prende la riga con `FOR UPDATE SKIP LOCKED` |
| **findings** | i risultati, una riga per problema | collegati a CIS/ISO 27001/NIST/ATT&CK in `refs` |
| **audit_log** | chi ha fatto cosa e quando | `username` resta anche se l'utente viene eliminato (`SET NULL` sulla FK) |

Le colonne `tags`, `options`, `areas`, `counts`, `summary`, `refs` sono **JSON** (`JSONB` su
PostgreSQL). Lo schema viene creato all'avvio dai modelli SQLAlchemy in
[`webapp/watchdog_web/models.py`](../webapp/watchdog_web/models.py).
