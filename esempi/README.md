# Report di esempio

Esempio reale del report che WatchDog Web produce per ogni scansione (lo stesso che si scarica
dalla pagina di una scansione, nei tre formati). È l'esito di una scansione in modalità
*Controlli nativi* su un sistema Linux.

| File | Formato | A cosa serve |
|---|---|---|
| [`assessment-esempio.html`](assessment-esempio.html) | HTML | report completo, si apre offline: riepilogo, heatmap delle aree, matrice del rischio, riferimenti normativi, controlli non completati, ricerca e filtri |
| [`assessment-esempio.md`](assessment-esempio.md) | Markdown | riepilogo e tabella dei finding, da leggere o allegare |
| [`assessment-esempio.json`](assessment-esempio.json) | JSON | tutti i dati, per l'elaborazione da parte di altri programmi o dell'API |

**Esito dell'esempio:** livello **MEDIO**, punteggio **52/100**, 25 finding
(7 medi, 5 bassi, 13 informativi). Ogni finding ha gravità, confidenza, descrizione, evidenza,
raccomandazione e i riferimenti a CIS / ISO 27001 / NIST / MITRE ATT&CK.

Anteprima dell'HTML e di altri grafici in [`../docs/assets/`](../docs/assets/).
