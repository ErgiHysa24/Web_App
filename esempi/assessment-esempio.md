# Security Assessment Report

**Obiettivo:** `localhost`  
**Modalità:** `local`  
**Sistema:** Ubuntu 24.04.5 LTS · apt · container docker  
**Inizio:** 2026-11-13T17:56:29.701191+00:00  
**Fine:** 2026-11-13T17:56:37.373385+00:00  

## Riepilogo

**Rischio complessivo:** **MEDIUM** (punteggio **52/100**; il livello è la severità più alta trovata)  
**Rischio massimo (impatto × probabilità):** **MEDIUM** (6/12)

| Severità | Finding |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 7 |
| 🔵 LOW | 5 |
| ⚪ INFO | 13 |
| **Totale** | **25** |

## Rischio = impatto × probabilità

L'impatto è la gravità del finding (1 basso … 4 critico); la probabilità dice quanto è probabile che il problema sia reale e sfruttabile, stimata dalla confidenza del rilevamento (1 bassa, 2 media, 3 alta). Rischio = impatto × probabilità (0-12).

| Impatto \ Probabilità | Bassa (1) | Media (2) | Alta (3) |
|---|---|---|---|
| Critico (4) | 0 | 0 | 0 |
| Alto (3) | 0 | 0 | 0 |
| Medio (2) | 0 | 4 | 3 |
| Basso (1) | 1 | 4 | 0 |

| Livello di rischio | Finding |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 7 |
| LOW | 5 |
| INFO | 13 |

## Aree (heatmap)

| Area | 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ⚪ INFO | Totale |
|---|---|---|---|---|---|---|
| Accessi e privilegi | · | · | 3 | 1 | 4 | 8 |
| Rete ed esposizione | · | · | 1 | 2 | 3 | 6 |
| Vulnerabilità e aggiornamenti | · | · | 2 | · | 1 | 3 |
| Hardening e conformità | · | · | 1 | 2 | 3 | 6 |
| Log e monitoraggio | · | · | · | · | 1 | 1 |
| Sistema e svolgimento | · | · | · | · | 1 | 1 |

### Accessi e privilegi

| Controllo | CRITICAL | HIGH | MEDIUM | LOW | INFO | Totale |
|---|---|---|---|---|---|---|
| Password policy e sudo | · | · | 3 | 1 | · | 4 |
| Utenti e gruppi | · | · | · | · | 4 | 4 |

### Rete ed esposizione

| Controllo | CRITICAL | HIGH | MEDIUM | LOW | INFO | Totale |
|---|---|---|---|---|---|---|
| Firewall | · | · | · | · | 1 | 1 |
| Kernel | · | · | 1 | 2 | · | 3 |
| Servizi e porte | · | · | · | · | 2 | 2 |

### Vulnerabilità e aggiornamenti

| Controllo | CRITICAL | HIGH | MEDIUM | LOW | INFO | Totale |
|---|---|---|---|---|---|---|
| Aggiornamenti | · | · | 1 | · | · | 1 |
| Pacchetti | · | · | 1 | · | 1 | 2 |

### Hardening e conformità

| Controllo | CRITICAL | HIGH | MEDIUM | LOW | INFO | Totale |
|---|---|---|---|---|---|---|
| File system | · | · | 1 | 2 | 1 | 4 |
| Kernel | · | · | · | · | 1 | 1 |
| Protezioni del sistema | · | · | · | · | 1 | 1 |

### Log e monitoraggio

| Controllo | CRITICAL | HIGH | MEDIUM | LOW | INFO | Totale |
|---|---|---|---|---|---|---|
| Log e audit | · | · | · | · | 1 | 1 |

### Sistema e svolgimento

| Controllo | CRITICAL | HIGH | MEDIUM | LOW | INFO | Totale |
|---|---|---|---|---|---|---|
| Informazioni di sistema | · | · | · | · | 1 | 1 |

## Riferimenti normativi

_Controlli a cui si riferiscono i problemi trovati: un aiuto per l'audit, non una dimostrazione di conformità._

### CIS Controls v8

| Controllo | Titolo | Problemi | Più grave |
|---|---|---|---|
| 4.1 | Establish and maintain a secure configuration process | 3 | MEDIUM |
| 5.2 | Use unique passwords | 2 | MEDIUM |
| 7.3 | Perform automated operating system patch management | 2 | MEDIUM |
| 5.4 | Restrict administrator privileges to dedicated administrator accounts | 1 | MEDIUM |
| 8.3 | Ensure adequate audit log storage | 1 | MEDIUM |
| 3.3 | Configure data access control lists | 2 | LOW |

### ISO/IEC 27001:2022

| Controllo | Titolo | Problemi | Più grave |
|---|---|---|---|
| A.8.5 | Secure authentication | 3 | MEDIUM |
| A.8.9 | Configuration management | 3 | MEDIUM |
| A.5.17 | Authentication information | 2 | MEDIUM |
| A.8.8 | Management of technical vulnerabilities | 2 | MEDIUM |
| A.8.2 | Privileged access rights | 1 | MEDIUM |
| A.8.6 | Capacity management | 1 | MEDIUM |
| A.8.3 | Information access restriction | 2 | LOW |

### NIST SP 800-53 Rev. 5

| Controllo | Titolo | Problemi | Più grave |
|---|---|---|---|
| CM-6 | Configuration Settings | 5 | MEDIUM |
| IA-5 | Authenticator Management | 2 | MEDIUM |
| SI-2 | Flaw Remediation | 2 | MEDIUM |
| AC-6 | Least Privilege | 1 | MEDIUM |
| AC-7 | Unsuccessful Logon Attempts | 1 | MEDIUM |
| AU-4 | Audit Log Storage Capacity | 1 | MEDIUM |
| AC-3 | Access Enforcement | 2 | LOW |

## Tecniche d'attacco (MITRE ATT&CK v20.0)

_Tecniche che i problemi rendono possibili: giudizio di WatchDog, non una mappa ufficiale._

| ID | Tecnica | Problemi | Più grave |
|---|---|---|---|
| T1110 | Brute Force | 3 | MEDIUM |
| T1068 | Exploitation for Privilege Escalation | 1 | MEDIUM |
| T1190 | Exploit Public-Facing Application | 1 | MEDIUM |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | 1 | MEDIUM |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | 1 | LOW |

## Findings

| Rischio | Impatto | Probabilità | Severità | Titolo | Categoria | Origine | Confidenza |
|---|---|---|---|---|---|---|---|
| MEDIUM (6) | 2 | 3 | 🟡 MEDIUM | Aggiornamenti disponibili: 53 | packages | `packages:apt-upgradable` | HIGH |
| MEDIUM (6) | 2 | 3 | 🟡 MEDIUM | Disco quasi pieno: /opt/claude-code (93%) | filesystem | `filesystem:disk-usage` | HIGH |
| MEDIUM (6) | 2 | 3 | 🟡 MEDIUM | sudo senza password per qualsiasi comando: claude | authentication | `auth-policy:sudo-nopasswd-all` | HIGH |
| MEDIUM (4) | 2 | 2 | 🟡 MEDIUM | Accetta i reindirizzamenti ICMP (net.ipv4.conf.all.accept_redirects=1) | network | `kernel:net.ipv4.conf.all.accept_redirects` | MEDIUM |
| MEDIUM (4) | 2 | 2 | 🟡 MEDIUM | Aggiornamenti di sicurezza automatici non attivi | packages | `updates:no-auto-updates` | MEDIUM |
| MEDIUM (4) | 2 | 2 | 🟡 MEDIUM | Nessun blocco dopo tentativi di accesso falliti | authentication | `auth-policy:no-lockout` | MEDIUM |
| MEDIUM (4) | 2 | 2 | 🟡 MEDIUM | Nessun controllo sulla qualità delle password | authentication | `auth-policy:no-pwquality` | MEDIUM |
| LOW (2) | 1 | 2 | 🔵 LOW | Controllo dell'indirizzo sorgente disattivato (net.ipv4.conf.all.rp_filter=0) | network | `kernel:net.ipv4.conf.all.rp_filter` | MEDIUM |
| LOW (2) | 1 | 2 | 🔵 LOW | File scrivibili da tutti nelle cartelle temporanee: 7 | filesystem | `filesystem:world-writable-tmp` | MEDIUM |
| LOW (2) | 1 | 2 | 🔵 LOW | Invia reindirizzamenti ICMP (net.ipv4.conf.all.send_redirects=1) | network | `kernel:net.ipv4.conf.all.send_redirects` | MEDIUM |
| LOW (2) | 1 | 2 | 🔵 LOW | Le password non hanno una scadenza ragionevole | authentication | `auth-policy:pass-max-days` | MEDIUM |
| LOW (1) | 1 | 1 | 🔵 LOW | File SGID trovati: 8 | filesystem | `filesystem:sgid` | LOW |
| INFO (0) | 0 | 1 | ⚪ INFO | Firewall non verificabile dentro un container | firewall | `firewall:container` | LOW |
| INFO (0) | 0 | 2 | ⚪ INFO | Gruppo privilegiato sudo: ubuntu | privileges | `users-collector:privileged-group` | MEDIUM |
| INFO (0) | 0 | 3 | ⚪ INFO | Informazioni di sistema | system_info | `linux-check:linux` | HIGH |
| INFO (0) | 0 | 3 | ⚪ INFO | Pacchetti installati: 1037 | packages | `packages:apt-installed` | HIGH |
| INFO (0) | 0 | 1 | ⚪ INFO | Parametri del kernel dell'host non valutabili dal container | kernel | `kernel:container` | LOW |
| INFO (0) | 0 | 1 | ⚪ INFO | Porte in ascolto non verificabili | network | `services:ports-unverifiable` | LOW |
| INFO (0) | 0 | 3 | ⚪ INFO | Programmi SUID di sistema: 10 | filesystem | `filesystem:suid-standard` | HIGH |
| INFO (0) | 0 | 1 | ⚪ INFO | Protezioni del sistema non valutabili in un container | protections | `protections:container` | LOW |
| INFO (0) | 0 | 1 | ⚪ INFO | Servizi di log e audit non verificabili | logging | `logging:unverifiable` | LOW |
| INFO (0) | 0 | 1 | ⚪ INFO | Stato dei servizi non verificabile | services | `services:unverifiable` | LOW |
| INFO (0) | 0 | 2 | ⚪ INFO | Utente con shell di login: claude | users | `users-collector:login-user` | MEDIUM |
| INFO (0) | 0 | 2 | ⚪ INFO | Utente con shell di login: postgres | users | `users-collector:login-user` | MEDIUM |
| INFO (0) | 0 | 2 | ⚪ INFO | Utente con shell di login: ubuntu | users | `users-collector:login-user` | MEDIUM |

## Dettaglio dei finding

### 1. 🟡 Aggiornamenti disponibili: 53

- **Rischio:** MEDIUM (6) = impatto 2 × probabilità 3
- **Severità:** MEDIUM
- **Categoria:** packages
- **Origine:** `packages:apt-upgradable`
- **Confidenza:** HIGH
- **Riferimenti:** CIS 7.3 · ISO A.8.8 · NIST SI-2

**Descrizione:** 53 pacchetti hanno aggiornamenti disponibili.

**Evidenza:**

```
apt/noble-security 2.8.4ubuntu0.1 amd64 [upgradable from: 2.8.3]
ca-certificates/noble-updates,noble-security 20260816ubuntu0.24.04.1 all [upgradable from: 20260601~24.04.1]
distro-info-data/noble-updates,noble-security 2026.10.12-0ubuntu0.24.04.1 all [upgradable from: 0.72-0ubuntu0.24.04.1]
gir1.2-glib-2.0/noble-updates 2.80.0-6ubuntu3.10 amd64 [upgradable from: 2.80.0-6ubuntu3.9]
git-man/noble-updates,noble-security 1:2.43.0-1ubuntu7.4 all [upgradable from: 1:2.43.0-1ubuntu7.3]
git/noble-updat
```

**Raccomandazione:** Applicare gli aggiornamenti: 'apt update &amp;&amp; apt upgrade'.

### 2. 🟡 Disco quasi pieno: /opt/claude-code (93%)

- **Rischio:** MEDIUM (6) = impatto 2 × probabilità 3
- **Severità:** MEDIUM
- **Categoria:** filesystem
- **Origine:** `filesystem:disk-usage`
- **Confidenza:** HIGH
- **Riferimenti:** CIS 8.3 · ISO A.8.6 · NIST AU-4

**Descrizione:** Il mount /opt/claude-code è utilizzato al 93%.

**Evidenza:**

```
/dev/vdc                                                                 386952   351860         27332      93% /opt/claude-code
```

**Raccomandazione:** Liberare spazio o estendere il filesystem.

### 3. 🟡 sudo senza password per qualsiasi comando: claude

- **Rischio:** MEDIUM (6) = impatto 2 × probabilità 3
- **Severità:** MEDIUM
- **Categoria:** authentication
- **Origine:** `auth-policy:sudo-nopasswd-all`
- **Confidenza:** HIGH
- **Riferimenti:** CIS 5.4 · ISO A.8.2 · NIST AC-6

**Descrizione:** Questi utenti o gruppi diventano root senza password: chi ne ottiene l'accesso ottiene root.

**Evidenza:**

```
claude ALL=(ALL) NOPASSWD: ALL
```

**Raccomandazione:** Limitare NOPASSWD ai soli comandi necessari, oppure richiedere la password.

### 4. 🟡 Accetta i reindirizzamenti ICMP (net.ipv4.conf.all.accept_redirects=1)

- **Rischio:** MEDIUM (4) = impatto 2 × probabilità 2
- **Severità:** MEDIUM
- **Categoria:** network
- **Origine:** `kernel:net.ipv4.conf.all.accept_redirects`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 4.1 · ISO A.8.9 · NIST CM-6

**Descrizione:** Un attaccante sulla rete può alterare le rotte del sistema.

**Evidenza:**

```
net.ipv4.conf.all.accept_redirects = 1 (consigliato: 0)
```

**Raccomandazione:** Impostare net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.d/.

### 5. 🟡 Aggiornamenti di sicurezza automatici non attivi

- **Rischio:** MEDIUM (4) = impatto 2 × probabilità 2
- **Severità:** MEDIUM
- **Categoria:** packages
- **Origine:** `updates:no-auto-updates`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 7.3 · ISO A.8.8 · NIST SI-2

**Descrizione:** Le correzioni di sicurezza non vengono applicate da sole: la macchina resta vulnerabile finché qualcuno non aggiorna a mano.

**Evidenza:**

```
pacchetto unattended-upgrades non installato
```

**Raccomandazione:** Installare unattended-upgrades e abilitare gli aggiornamenti di sicurezza automatici.

### 6. 🟡 Nessun blocco dopo tentativi di accesso falliti

- **Rischio:** MEDIUM (4) = impatto 2 × probabilità 2
- **Severità:** MEDIUM
- **Categoria:** authentication
- **Origine:** `auth-policy:no-lockout`
- **Confidenza:** MEDIUM
- **Riferimenti:** ISO A.8.5 · NIST AC-7

**Descrizione:** PAM non usa pam_faillock né pam_tally2: i tentativi di indovinare le password non vengono limitati a livello di account (un fail2ban può compensare per SSH).

**Evidenza:**

```
nessun riferimento in /etc/pam.d
```

**Raccomandazione:** Configurare pam_faillock (deny=5, unlock_time=900) o usare fail2ban.

### 7. 🟡 Nessun controllo sulla qualità delle password

- **Rischio:** MEDIUM (4) = impatto 2 × probabilità 2
- **Severità:** MEDIUM
- **Categoria:** authentication
- **Origine:** `auth-policy:no-pwquality`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 5.2 · ISO A.5.17, A.8.5 · NIST IA-5

**Descrizione:** PAM non usa pam_pwquality, pam_cracklib o pam_passwdqc: sono ammesse password banali.

**Evidenza:**

```
nessun riferimento in /etc/pam.d
```

**Raccomandazione:** Installare e configurare libpam-pwquality (minlen almeno 12).

### 8. 🔵 Controllo dell'indirizzo sorgente disattivato (net.ipv4.conf.all.rp_filter=0)

- **Rischio:** LOW (2) = impatto 1 × probabilità 2
- **Severità:** LOW
- **Categoria:** network
- **Origine:** `kernel:net.ipv4.conf.all.rp_filter`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 4.1 · ISO A.8.9 · NIST CM-6

**Descrizione:** Il filtro rp_filter riduce lo spoofing degli indirizzi IP.

**Evidenza:**

```
net.ipv4.conf.all.rp_filter = 0 (consigliato: 1)
```

**Raccomandazione:** Impostare net.ipv4.conf.all.rp_filter = 1 in /etc/sysctl.d/.

### 9. 🔵 File scrivibili da tutti nelle cartelle temporanee: 7

- **Rischio:** LOW (2) = impatto 1 × probabilità 2
- **Severità:** LOW
- **Categoria:** filesystem
- **Origine:** `filesystem:world-writable-tmp`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 3.3 · ISO A.8.3 · NIST AC-3, CM-6

**Descrizione:** Nelle cartelle temporanee è comune, ma se uno di questi file viene letto o eseguito da un servizio o da uno script di root, chiunque può cambiarne il contenuto.

**Evidenza:**

```
/tmp/uv-setuptools-07c4d9ca76b772c3.lock
/tmp/uv-setuptools-8be88abc6ab73f5f.lock
/tmp/uv-setuptools-e07a12246690ac1f.lock
/tmp/claude-0/-home-claude/a7d998da-f91a-5715-82ef-62101cc4208c/scratchpad/hunt/fs/etc/shadow
/tmp/claude-0/-home-claude/a7d998da-f91a-5715-82ef-62101cc4208c/scratchpad/ln/private/etc/x
/tmp/uv-bcb837755ba79986.lock
/tmp/uv-ce9cd633bb00c47d.lock
```

**Raccomandazione:** Verificare che nessuno script privilegiato usi questi file.

### 10. 🔵 Invia reindirizzamenti ICMP (net.ipv4.conf.all.send_redirects=1)

- **Rischio:** LOW (2) = impatto 1 × probabilità 2
- **Severità:** LOW
- **Categoria:** network
- **Origine:** `kernel:net.ipv4.conf.all.send_redirects`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 4.1 · ISO A.8.9 · NIST CM-6

**Descrizione:** Una macchina che non fa da router non dovrebbe inviarli.

**Evidenza:**

```
net.ipv4.conf.all.send_redirects = 1 (consigliato: 0)
```

**Raccomandazione:** Impostare net.ipv4.conf.all.send_redirects = 0 in /etc/sysctl.d/.

### 11. 🔵 Le password non hanno una scadenza ragionevole

- **Rischio:** LOW (2) = impatto 1 × probabilità 2
- **Severità:** LOW
- **Categoria:** authentication
- **Origine:** `auth-policy:pass-max-days`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 5.2 · ISO A.5.17, A.8.5 · NIST IA-5

**Descrizione:** PASS_MAX_DAYS vale 99999: le password nuove non scadono praticamente mai. Le linee guida CIS indicano al massimo 365 giorni.

**Evidenza:**

```
PASS_MAX_DAYS 99999
```

**Raccomandazione:** Impostare PASS_MAX_DAYS 365 (o secondo la politica aziendale). Vale per gli account creati dopo la modifica.

### 12. 🔵 File SGID trovati: 8

- **Rischio:** LOW (1) = impatto 1 × probabilità 1
- **Severità:** LOW
- **Categoria:** filesystem
- **Origine:** `filesystem:sgid`
- **Confidenza:** LOW
- **Riferimenti:** CIS 3.3 · ISO A.8.3 · NIST AC-3, CM-6

**Descrizione:** File con bit SGID impostato.

**Evidenza:**

```
/usr/bin/chage
/usr/bin/expiry
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/sbin/pam_extrausers_chkpwd
/usr/sbin/unix_chkpwd
/usr/sbin/postdrop
/usr/sbin/postqueue
```

**Raccomandazione:** Verificare che ogni file SGID sia necessario.

### 13. ⚪ Firewall non verificabile dentro un container

- **Rischio:** INFO (0) = impatto 0 × probabilità 1
- **Severità:** INFO
- **Categoria:** firewall
- **Origine:** `firewall:container`
- **Confidenza:** LOW

**Descrizione:** Il sistema è un container (docker): il firewall è quello dell'host e da qui non si vede. Va controllato sull'host.

**Evidenza:**

```
ufw/firewalld non attivi nel container; nessuna regola di input nel suo namespace
```

**Raccomandazione:** Verificare a mano su questo sistema: l'assenza di segnalazioni qui non significa che vada tutto bene.

### 14. ⚪ Gruppo privilegiato sudo: ubuntu

- **Rischio:** INFO (0) = impatto 0 × probabilità 2
- **Severità:** INFO
- **Categoria:** privileges
- **Origine:** `users-collector:privileged-group`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 5.4 · ISO A.8.2 · NIST AC-6

**Descrizione:** Questi utenti sono nel gruppo 'sudo': possono ottenere i privilegi di root.

**Evidenza:**

```
sudo:x:27:ubuntu
```

**Raccomandazione:** Verificare che la membership sia autorizzata.

### 15. ⚪ Informazioni di sistema

- **Rischio:** INFO (0) = impatto 0 × probabilità 3
- **Severità:** INFO
- **Categoria:** system_info
- **Origine:** `linux-check:linux`
- **Confidenza:** HIGH

**Descrizione:** Sistema rilevato: Ubuntu, 24.04, kernel 6.18.44-fc-v445, x86_64

**Evidenza:**

```
architecture: x86_64
hostname: vm
kernel: 6.18.44-fc-v445
os_id: ubuntu
os_name: Ubuntu
os_version: 24.04
```

**Raccomandazione:** Nessuna azione richiesta.

### 16. ⚪ Pacchetti installati: 1037

- **Rischio:** INFO (0) = impatto 0 × probabilità 3
- **Severità:** INFO
- **Categoria:** packages
- **Origine:** `packages:apt-installed`
- **Confidenza:** HIGH

**Descrizione:** Rilevati 1037 pacchetti installati via apt.

**Evidenza:**

```
apt list --installed -> 1037 pacchetti
```

**Raccomandazione:** Nessuna azione richiesta.

### 17. ⚪ Parametri del kernel dell'host non valutabili dal container

- **Rischio:** INFO (0) = impatto 0 × probabilità 1
- **Severità:** INFO
- **Categoria:** kernel
- **Origine:** `kernel:container`
- **Confidenza:** LOW

**Descrizione:** Il sistema è un container (docker): i parametri sysctl non di rete appartengono al kernel dell'host e vanno controllati lì.

**Evidenza:**

```
kernel.randomize_va_space, kernel.kptr_restrict, kernel.dmesg_restrict, kernel.yama.ptrace_scope, kernel.unprivileged_bpf_disabled, fs.protected_hardlinks, fs.protected_symlinks, fs.suid_dumpable
```

**Raccomandazione:** Verificare a mano su questo sistema: l'assenza di segnalazioni qui non significa che vada tutto bene.

### 18. ⚪ Porte in ascolto non verificabili

- **Rischio:** INFO (0) = impatto 0 × probabilità 1
- **Severità:** INFO
- **Categoria:** network
- **Origine:** `services:ports-unverifiable`
- **Confidenza:** LOW

**Descrizione:** Sul sistema non ci sono né `ss` né `netstat`: le porte aperte non sono state controllate.

**Evidenza:**

```
ss e netstat non trovati
```

**Raccomandazione:** Verificare a mano su questo sistema: l'assenza di segnalazioni qui non significa che vada tutto bene.

### 19. ⚪ Programmi SUID di sistema: 10

- **Rischio:** INFO (0) = impatto 0 × probabilità 3
- **Severità:** INFO
- **Categoria:** filesystem
- **Origine:** `filesystem:suid-standard`
- **Confidenza:** HIGH
- **Riferimenti:** CIS 3.3 · ISO A.8.3 · NIST AC-3, CM-6

**Descrizione:** Programmi con il bit SUID previsti dalla distribuzione (passwd, sudo, mount…).

**Evidenza:**

```
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/umount
```

**Raccomandazione:** Nessuna azione richiesta; tenerli aggiornati.

### 20. ⚪ Protezioni del sistema non valutabili in un container

- **Rischio:** INFO (0) = impatto 0 × probabilità 1
- **Severità:** INFO
- **Categoria:** protections
- **Origine:** `protections:container`
- **Confidenza:** LOW

**Descrizione:** SELinux, AppArmor e cifratura del disco appartengono all'host che esegue il container: vanno controllati lì.

**Evidenza:**

```
container docker
```

**Raccomandazione:** Verificare a mano su questo sistema: l'assenza di segnalazioni qui non significa che vada tutto bene.

### 21. ⚪ Servizi di log e audit non verificabili

- **Rischio:** INFO (0) = impatto 0 × probabilità 1
- **Severità:** INFO
- **Categoria:** logging
- **Origine:** `logging:unverifiable`
- **Confidenza:** LOW

**Descrizione:** Non c'è un init system riconoscibile (tipico di un container): non si può sapere se auditd, syslog o fail2ban sono attivi.

**Evidenza:**

```
init: unknown, container docker
```

**Raccomandazione:** Verificare a mano su questo sistema: l'assenza di segnalazioni qui non significa che vada tutto bene.

### 22. ⚪ Stato dei servizi non verificabile

- **Rischio:** INFO (0) = impatto 0 × probabilità 1
- **Severità:** INFO
- **Categoria:** services
- **Origine:** `services:unverifiable`
- **Confidenza:** LOW

**Descrizione:** Non c'è un init system riconoscibile (tipico di un container): non si può sapere quali servizi sono attivi o in errore.

**Evidenza:**

```
init: unknown, container docker
```

**Raccomandazione:** Verificare a mano su questo sistema: l'assenza di segnalazioni qui non significa che vada tutto bene.

### 23. ⚪ Utente con shell di login: claude

- **Rischio:** INFO (0) = impatto 0 × probabilità 2
- **Severità:** INFO
- **Categoria:** users
- **Origine:** `users-collector:login-user`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 5.1, 5.4 · ISO A.5.16, A.8.2 · NIST AC-2, AC-6

**Descrizione:** L'utente 'claude' può effettuare un accesso interattivo (shell: /bin/bash).

**Evidenza:**

```
claude:x:999:30001::/home/claude:/bin/bash
```

**Raccomandazione:** Nessuna azione richiesta.

### 24. ⚪ Utente con shell di login: postgres

- **Rischio:** INFO (0) = impatto 0 × probabilità 2
- **Severità:** INFO
- **Categoria:** users
- **Origine:** `users-collector:login-user`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 5.1, 5.4 · ISO A.5.16, A.8.2 · NIST AC-2, AC-6

**Descrizione:** L'utente 'postgres' può effettuare un accesso interattivo (shell: /bin/bash).

**Evidenza:**

```
postgres:x:102:104:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

**Raccomandazione:** Nessuna azione richiesta.

### 25. ⚪ Utente con shell di login: ubuntu

- **Rischio:** INFO (0) = impatto 0 × probabilità 2
- **Severità:** INFO
- **Categoria:** users
- **Origine:** `users-collector:login-user`
- **Confidenza:** MEDIUM
- **Riferimenti:** CIS 5.1, 5.4 · ISO A.5.16, A.8.2 · NIST AC-2, AC-6

**Descrizione:** L'utente 'ubuntu' può effettuare un accesso interattivo (shell: /bin/bash).

**Evidenza:**

```
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
```

**Raccomandazione:** Nessuna azione richiesta.

---

_Report generato da WatchDog — controlli eseguiti: linux, users, ssh_config, firewall, services, filesystem, packages, auth_policy, kernel, logging, updates, persistence, protections_
