"""
WatchDog - risk assessment di sicurezza per Linux (qualsiasi distribuzione) e macOS.

- analisi locale o via SSH, con riconoscimento automatico del sistema;
- controlli nativi per Linux e macOS e tool esterni (Nmap, Lynis, chkrootkit, OpenSCAP,
  ClamAV, debsecan, debsums; su richiesta Trivy, AIDE, rkhunter);
- report JSON, Markdown, HTML e a video.

Rischio e punteggio sono calcolati in modo deterministico, senza intelligenza artificiale.
"""
__version__ = "1.4.0"
__author__ = "Ergi Hysa"
