# Charge concurrente — comparaison TLS vs QUIC

| Concurrence | TLS lat. moy. (ms) | TLS débit (hs/s) | QUIC lat. moy. (ms) | QUIC débit (hs/s) |
|---|---|---|---|---|
| 1 | 3.8 | 48.95 | 2.9 | 21.59 |
| 5 | 1.57 | 107.39 | 3.01 | 58.17 |
| 10 | 1.34 | 122.07 | 4.0 | 72.32 |
| 20 | 1.39 | 126.72 | 5.95 | 78.64 |

## Note méthodologique (asymétrie TLS/QUIC attendue)

`openssl s_server` traite les connexions séquentiellement (accept → handshake → close → accept suivant), sans multi-threading explicite. Sous charge concurrente croissante côté TLS, une hausse marquée de la latence moyenne et p95, et un plafonnement du débit réel, sont donc attendus — ils reflètent la mise en file d'attente TCP, pas un surcoût cryptographique par connexion. Côté QUIC (msquic, événementiel), débit et latence devraient rester plus stables à mesure que la concurrence augmente. Si les deux protocoles montrent un comportement similaire, cela invaliderait cette hypothèse et mériterait d'être creusé avant publication.