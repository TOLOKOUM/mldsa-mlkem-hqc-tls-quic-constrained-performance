# Performance de handshake — captures/quic/single/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 2.222 | [2.104, 2.364] | bootstrap_blocs | 2.17 | 2.761 | 3.07 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 1.89 | [1.836, 1.923] | bootstrap_blocs | 1.82 | 2.32 | 2.64 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 2.179 | [2.126, 2.234] | bootstrap_blocs | 2.11 | 2.61 | 2.91 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 2.101 | [1.993, 2.295] | bootstrap_blocs | 2.02 | 2.731 | 3.081 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 26.968 | [24.813, 30.057] | bootstrap_blocs | 25.75 | 34.854 | 39.771 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 10.045 | [9.71, 10.666] | bootstrap_blocs | 9.15 | 13.84 | 15.149 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 20.209 | [18.637, 22.601] | bootstrap_blocs | 18.03 | 26.485 | 29.313 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 3.795 | [3.564, 4.199] | bootstrap_blocs | 3.55 | 4.981 | 6.234 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 25.54 | [24.968, 26.072] | bootstrap_blocs | 23.525 | 33.791 | 34.651 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 9.967 | [9.632, 10.267] | bootstrap_blocs | 9.51 | 13.76 | 14.151 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 19.186 | [19.017, 19.355] | bootstrap_blocs | 17.88 | 24.68 | 25.381 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 3.632 | [3.555, 3.692] | bootstrap_blocs | 3.46 | 4.5 | 4.85 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 17.578 | [17.083, 17.911] | bootstrap_blocs | 16.35 | 22.521 | 23.07 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 1.974 | [1.884, 2.105] | bootstrap_blocs | 1.87 | 2.59 | 3.22 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 17.989 | [17.252, 18.803] | bootstrap_blocs | 16.54 | 22.831 | 24.451 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 2.086 | [1.958, 2.299] | bootstrap_blocs | 2.0 | 2.79 | 3.26 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 4.603 | [4.541, 4.708] | bootstrap_blocs | 4.37 | 5.691 | 6.181 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 3.144 | [3.013, 3.334] | bootstrap_blocs | 3.1 | 3.97 | 4.641 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 5.839 | [5.638, 6.089] | bootstrap_blocs | 5.405 | 7.71 | 8.49 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 4.277 | [4.132, 4.449] | bootstrap_blocs | 3.93 | 5.49 | 6.0 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 59.065 | [56.762, 61.566] | bootstrap_blocs | 54.765 | 76.212 | 83.215 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 12.7 | [12.202, 13.58] | bootstrap_blocs | 11.605 | 16.962 | 19.77 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 52.213 | [49.69, 56.608] | bootstrap_blocs | 47.935 | 68.073 | 74.583 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 5.368 | [5.129, 5.748] | bootstrap_blocs | 5.21 | 6.693 | 7.4 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 59.13 | [57.471, 61.878] | bootstrap_blocs | 54.98 | 74.284 | 81.073 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 14.644 | [13.446, 16.761] | bootstrap_blocs | 12.985 | 19.752 | 24.271 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 50.772 | [49.824, 51.892] | bootstrap_blocs | 48.255 | 63.865 | 68.492 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 6.536 | [6.293, 6.899] | bootstrap_blocs | 6.155 | 8.58 | 9.19 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 47.901 | [46.657, 49.671] | bootstrap_blocs | 45.22 | 60.934 | 64.544 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 2.251 | [2.111, 2.481] | bootstrap_blocs | 2.17 | 2.84 | 3.135 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 48.581 | [47.348, 49.846] | bootstrap_blocs | 45.655 | 61.026 | 66.583 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 3.389 | [3.302, 3.547] | bootstrap_blocs | 3.13 | 4.39 | 5.131 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 4.413 | [4.341, 4.525] | bootstrap_blocs | 4.185 | 5.46 | 5.89 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 5.821 | [5.504, 6.256] | bootstrap_blocs | 5.36 | 7.571 | 8.805 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 94.494 | [90.757, 100.689] | bootstrap_blocs | 89.07 | 115.991 | 131.443 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 12.766 | [12.172, 13.385] | bootstrap_blocs | 11.68 | 16.98 | 19.586 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 94.709 | [92.092, 99.217] | bootstrap_blocs | 90.075 | 112.969 | 133.248 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 13.756 | [13.453, 14.109] | bootstrap_blocs | 12.685 | 18.81 | 19.3 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 84.628 | [83.045, 86.866] | bootstrap_blocs | 80.25 | 102.188 | 109.426 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 2.341 | [2.257, 2.426] | bootstrap_blocs | 2.29 | 2.87 | 3.201 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 87.07 | [83.881, 91.589] | bootstrap_blocs | 81.505 | 103.943 | 115.263 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 3.595 | [3.539, 3.658] | bootstrap_blocs | 3.4 | 4.62 | 5.03 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 2.222 | 2.098 | 5.9 |
| L1 | mldsa44 | P-256 | classique | 2.179 | 2.098 | 3.9 |
| L1 | ed25519 | x25519 | classique | 1.89 | 2.098 | -9.9 |
| L1 | mldsa44 | x25519 | classique | 2.101 | 2.098 | 0.1 |
| L1 | ed25519 | p256_hqc128 | hybride | 26.968 | 2.098 | 1185.4 |
| L1 | mldsa44 | p256_hqc128 | hybride | 25.54 | 2.098 | 1117.3 |
| L1 | ed25519 | p256_mlkem512 | hybride | 10.045 | 2.098 | 378.8 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 9.967 | 2.098 | 375.1 |
| L1 | ed25519 | x25519_hqc128 | hybride | 20.209 | 2.098 | 863.3 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 19.186 | 2.098 | 814.5 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 3.795 | 2.098 | 80.9 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 3.632 | 2.098 | 73.1 |
| L1 | ed25519 | hqc128 | pq_pur | 17.578 | 2.098 | 737.8 |
| L1 | mldsa44 | hqc128 | pq_pur | 17.989 | 2.098 | 757.4 |
| L1 | ed25519 | mlkem512 | pq_pur | 1.974 | 2.098 | -5.9 |
| L1 | mldsa44 | mlkem512 | pq_pur | 2.086 | 2.098 | -0.6 |
| L3 | mldsa65 | P-384 | classique | 4.603 | 4.466 | 3.1 |
| L3 | secp384r1 | P-384 | classique | 5.839 | 4.466 | 30.7 |
| L3 | mldsa65 | x448 | classique | 3.144 | 4.466 | -29.6 |
| L3 | secp384r1 | x448 | classique | 4.277 | 4.466 | -4.2 |
| L3 | mldsa65 | p384_hqc192 | hybride | 59.065 | 4.466 | 1222.5 |
| L3 | secp384r1 | p384_hqc192 | hybride | 59.13 | 4.466 | 1224.0 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 12.7 | 4.466 | 184.4 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 14.644 | 4.466 | 227.9 |
| L3 | mldsa65 | x448_hqc192 | hybride | 52.213 | 4.466 | 1069.1 |
| L3 | secp384r1 | x448_hqc192 | hybride | 50.772 | 4.466 | 1036.9 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 5.368 | 4.466 | 20.2 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 6.536 | 4.466 | 46.4 |
| L3 | mldsa65 | hqc192 | pq_pur | 47.901 | 4.466 | 972.6 |
| L3 | secp384r1 | hqc192 | pq_pur | 48.581 | 4.466 | 987.8 |
| L3 | mldsa65 | mlkem768 | pq_pur | 2.251 | 4.466 | -49.6 |
| L3 | secp384r1 | mlkem768 | pq_pur | 3.389 | 4.466 | -24.1 |
| L5 | mldsa87 | P-521 | classique | 4.413 | 5.117 | -13.8 |
| L5 | secp521r1 | P-521 | classique | 5.821 | 5.117 | 13.8 |
| L5 | mldsa87 | p521_hqc256 | hybride | 94.494 | 5.117 | 1746.7 |
| L5 | secp521r1 | p521_hqc256 | hybride | 94.709 | 5.117 | 1750.9 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 12.766 | 5.117 | 149.5 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 13.756 | 5.117 | 168.8 |
| L5 | mldsa87 | hqc256 | pq_pur | 84.628 | 5.117 | 1553.9 |
| L5 | secp521r1 | hqc256 | pq_pur | 87.07 | 5.117 | 1601.6 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 2.341 | 5.117 | -54.3 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 3.595 | 5.117 | -29.7 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.