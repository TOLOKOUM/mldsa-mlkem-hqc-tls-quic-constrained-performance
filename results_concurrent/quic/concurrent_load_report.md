# Charge concurrente — QUIC — latence et succès par niveau

| Concurrence | N connexions | Succès (%) | Latence moy. (ms) | Latence p95 (ms) | Latence max (ms) | Débit réel (hs/s) |
|---|---|---|---|---|---|---|
| 1 | 500 | 100.0 | 2.9 | 3.35 | 3.96 | 21.59 |
| 5 | 2500 | 100.0 | 3.01 | 5.44 | 10.17 | 58.17 |
| 10 | 5000 | 100.0 | 4.0 | 7.92 | 57.15 | 72.32 |
| 20 | 10000 | 100.0 | 5.95 | 14.01 | 84.55 | 78.64 |

Le débit réel n'est calculable que si `--wall-clock-ms-tls/--wall-clock-ms-quic` a été fourni (temps mur du batch complet, tel qu'imprimé par le launcher). Sans lui, il apparaît en "NA" plutôt qu'estimé, pour éviter de présumer un passage à l'échelle linéaire — ce que ce test sert justement à vérifier.

Les CSV bruts de chaque niveau sont conservés en permanence dans `captures/<protocole>/single/none/concurrent_load/history_c<N>/`.