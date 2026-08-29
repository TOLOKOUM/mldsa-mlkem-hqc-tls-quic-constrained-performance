# Annexe méthodologique — Consommation CPU/mémoire des handshakes

**Lignes brutes agrégées : 5040**  

**Combinaisons distinctes (protocol/auth_mode/network_profile/sig_alg/kem/role) : 1260**  

**Dont combinaisons avec un seul bloc exploitable (pas d'IC bootstrap) : 0**

| Protocole | Scénario réseau | Rôle | Classe KEM | N combinaisons | CPU moyen/handshake (ms) | Surcoût CPU vs classique (%) | Pic mémoire moyen (MiB) |
|---|---|---|---|---|---|---|---|
| quic | none | client | classique | 10 | 24.208 | 0.0 | 5.41 |
| quic | none | client | hybride | 20 | 41.65 | 72.1 | 5.86 |
| quic | none | client | pq_pur | 12 | 38.059 | 57.2 | 5.51 |
| quic | none | server | classique | 10 | 63.323 | 0.0 | 8.63 |
| quic | none | server | hybride | 20 | 99.987 | 57.9 | 10.09 |
| quic | none | server | pq_pur | 12 | 96.769 | 52.8 | 9.73 |
| quic | simple_loss1.3_delay62.51ms | client | classique | 10 | 31.048 | 0.0 | 5.39 |
| quic | simple_loss1.3_delay62.51ms | client | hybride | 20 | 51.566 | 66.1 | 5.67 |
| quic | simple_loss1.3_delay62.51ms | client | pq_pur | 12 | 48.916 | 57.5 | 5.35 |
| quic | simple_loss1.3_delay62.51ms | server | classique | 10 | 438.744 | 0.0 | 9.25 |
| quic | simple_loss1.3_delay62.51ms | server | hybride | 20 | 525.451 | 19.8 | 10.36 |
| quic | simple_loss1.3_delay62.51ms | server | pq_pur | 12 | 551.249 | 25.6 | 9.91 |
| quic | simple_loss1.5833_delay83.52ms | client | classique | 10 | 33.187 | 0.0 | 5.36 |
| quic | simple_loss1.5833_delay83.52ms | client | hybride | 20 | 54.059 | 62.9 | 5.59 |
| quic | simple_loss1.5833_delay83.52ms | client | pq_pur | 12 | 50.341 | 51.7 | 5.36 |
| quic | simple_loss1.5833_delay83.52ms | server | classique | 10 | 561.13 | 0.0 | 9.22 |
| quic | simple_loss1.5833_delay83.52ms | server | hybride | 20 | 663.751 | 18.3 | 10.37 |
| quic | simple_loss1.5833_delay83.52ms | server | pq_pur | 12 | 700.827 | 24.9 | 9.95 |
| quic | stable | client | classique | 10 | 24.227 | 0.0 | 5.43 |
| quic | stable | client | hybride | 20 | 41.155 | 69.9 | 5.83 |
| quic | stable | client | pq_pur | 12 | 38.086 | 57.2 | 5.48 |
| quic | stable | server | classique | 10 | 609.905 | 0.0 | 9.04 |
| quic | stable | server | hybride | 20 | 422.587 | -30.7 | 10.12 |
| quic | stable | server | pq_pur | 12 | 428.203 | -29.8 | 9.78 |
| quic | unstable | client | classique | 10 | 25.395 | 0.0 | 5.38 |
| quic | unstable | client | hybride | 20 | 44.005 | 73.3 | 5.85 |
| quic | unstable | client | pq_pur | 12 | 40.868 | 60.9 | 5.48 |
| quic | unstable | server | classique | 10 | 1896.633 | 0.0 | 9.08 |
| quic | unstable | server | hybride | 20 | 1469.232 | -22.5 | 10.24 |
| quic | unstable | server | pq_pur | 12 | 1506.716 | -20.6 | 9.88 |
| tls | none | client | classique | 20 | 22.333 | 0.0 | 5.38 |
| tls | none | client | hybride | 40 | 36.97 | 65.5 | 5.37 |
| tls | none | client | pq_pur | 24 | 36.401 | 63.0 | 5.35 |
| tls | none | server | classique | 20 | 1.97 | 0.0 | 6.16 |
| tls | none | server | hybride | 40 | 11.351 | 476.2 | 6.41 |
| tls | none | server | pq_pur | 24 | 11.745 | 496.2 | 6.24 |
| tls | simple_loss1.3_delay62.51ms | client | classique | 20 | 53.976 | 0.0 | 5.38 |
| tls | simple_loss1.3_delay62.51ms | client | hybride | 40 | 73.91 | 36.9 | 5.4 |
| tls | simple_loss1.3_delay62.51ms | client | pq_pur | 24 | 73.63 | 36.4 | 5.38 |
| tls | simple_loss1.3_delay62.51ms | server | classique | 20 | 5.703 | 0.0 | 6.17 |
| tls | simple_loss1.3_delay62.51ms | server | hybride | 40 | 27.384 | 380.2 | 6.43 |
| tls | simple_loss1.3_delay62.51ms | server | pq_pur | 24 | 26.848 | 370.8 | 6.28 |
| tls | simple_loss1.5833_delay83.52ms | client | classique | 20 | 48.444 | 0.0 | 5.4 |
| tls | simple_loss1.5833_delay83.52ms | client | hybride | 40 | 74.525 | 53.8 | 5.42 |
| tls | simple_loss1.5833_delay83.52ms | client | pq_pur | 24 | 72.698 | 50.1 | 5.41 |
| tls | simple_loss1.5833_delay83.52ms | server | classique | 20 | 6.172 | 0.0 | 6.24 |
| tls | simple_loss1.5833_delay83.52ms | server | hybride | 40 | 27.799 | 350.4 | 6.46 |
| tls | simple_loss1.5833_delay83.52ms | server | pq_pur | 24 | 28.183 | 356.6 | 6.29 |
| tls | stable | client | classique | 20 | 29.553 | 0.0 | 5.34 |
| tls | stable | client | hybride | 40 | 44.237 | 49.7 | 5.4 |
| tls | stable | client | pq_pur | 24 | 43.35 | 46.7 | 5.36 |
| tls | stable | server | classique | 20 | 3.376 | 0.0 | 6.18 |
| tls | stable | server | hybride | 40 | 14.258 | 322.3 | 6.44 |
| tls | stable | server | pq_pur | 24 | 14.021 | 315.3 | 6.27 |
| tls | unstable | client | classique | 20 | 39.648 | 0.0 | 5.36 |
| tls | unstable | client | hybride | 40 | 61.213 | 54.4 | 5.4 |
| tls | unstable | client | pq_pur | 24 | 56.139 | 41.6 | 5.38 |
| tls | unstable | server | classique | 20 | 4.588 | 0.0 | 6.21 |
| tls | unstable | server | hybride | 40 | 19.07 | 315.6 | 6.45 |
| tls | unstable | server | pq_pur | 24 | 17.859 | 289.3 | 6.29 |

## Note méthodologique (à inclure telle quelle dans l'article)

Les mesures CPU proviennent des compteurs cgroup (`cpu.stat`/`cpuacct.usage`) du conteneur, capturés en delta entre le début et la fin de chaque batch de handshakes, puis divisés par le nombre de handshakes. Le pic mémoire provient de `memory.peak` (cgroup v2) ou `memory.max_usage_in_bytes` (cgroup v1). Ces mesures portent sur le conteneur entier, harnais de test inclus, et non sur les seules opérations cryptographiques ; ce biais constant à travers toutes les combinaisons ne remet pas en cause la comparaison relative classique/hybride/PQ pur.

Chaque combinaison a été mesurée sur 4 blocs randomisés indépendants (méthodologie identique à celle des mesures de latence) ; les valeurs moyennes ci-dessus sont la moyenne des moyennes de bloc, avec IC95% par bootstrap de blocs entiers (5000 resamples, seed 12345) rapporté au niveau de chaque combinaison individuelle dans resource_by_combo.csv. Pour les combinaisons ne disposant que d'un seul bloc exploitable, l'IC bootstrap n'est pas calculable et n'est pas rapporté (cf. colonne cpu_ms_ci95_method / mem_MiB_ci95_method).