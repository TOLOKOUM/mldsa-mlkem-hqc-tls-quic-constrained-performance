# Charge concurrente — TLS — latence et succès par niveau

| Concurrence | N connexions | Succès (%) | Latence moy. (ms) | Latence p95 (ms) | Latence max (ms) | Débit réel (hs/s) |
|---|---|---|---|---|---|---|
| 1 | 500 | 100.0 | 3.8 | 5.0 | 7.0 | 48.95 |
| 5 | 2500 | 100.0 | 1.57 | 4.0 | 8.0 | 107.39 |
| 10 | 5000 | 100.0 | 1.34 | 2.0 | 6.0 | 122.07 |
| 20 | 10000 | 100.0 | 1.39 | 3.0 | 7.0 | 126.72 |

Le débit réel n'est calculable que si `--wall-clock-ms-tls/--wall-clock-ms-quic` a été fourni (temps mur du batch complet, tel qu'imprimé par le launcher). Sans lui, il apparaît en "NA" plutôt qu'estimé, pour éviter de présumer un passage à l'échelle linéaire — ce que ce test sert justement à vérifier.

Les CSV bruts de chaque niveau sont conservés en permanence dans `captures/<protocole>/single/none/concurrent_load/history_c<N>/`.