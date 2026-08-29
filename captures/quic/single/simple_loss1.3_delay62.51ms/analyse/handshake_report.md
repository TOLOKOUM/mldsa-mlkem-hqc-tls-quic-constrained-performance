# Performance de handshake — captures/quic/single/simple_loss1.3_delay62.51ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 138.822 | [128.801, 153.354] | bootstrap_blocs | 127.875 | 129.171 | 262.738 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 150.427 | [140.497, 160.358] | bootstrap_blocs | 127.475 | 128.55 | 1126.613 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 272.808 | [263.196, 282.461] | bootstrap_blocs | 253.05 | 254.44 | 719.732 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 275.271 | [262.39, 290.655] | bootstrap_blocs | 252.7 | 253.49 | 1251.355 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 172.553 | [161.559, 183.548] | bootstrap_blocs | 157.895 | 175.343 | 1253.075 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 152.801 | [142.851, 162.751] | bootstrap_blocs | 137.62 | 145.502 | 1284.34 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 162.301 | [153.329, 174.075] | bootstrap_blocs | 149.83 | 168.08 | 300.412 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 148.89 | [141.563, 156.183] | bootstrap_blocs | 129.685 | 131.62 | 1279.49 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 294.77 | [290.042, 300.217] | bootstrap_blocs | 282.94 | 305.399 | 662.242 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 294.482 | [283.352, 305.612] | bootstrap_blocs | 263.09 | 273.445 | 2034.55 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 300.618 | [291.632, 307.347] | bootstrap_blocs | 274.935 | 287.394 | 1413.084 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 290.792 | [281.1, 300.483] | bootstrap_blocs | 254.82 | 256.928 | 2031.008 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 161.405 | [152.572, 172.977] | bootstrap_blocs | 147.515 | 163.096 | 1248.868 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 133.285 | [128.694, 137.877] | bootstrap_blocs | 127.57 | 129.111 | 252.74 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 313.57 | [303.256, 322.27] | bootstrap_blocs | 275.415 | 312.814 | 1415.06 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 264.358 | [256.423, 272.294] | bootstrap_blocs | 252.68 | 253.451 | 593.105 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 286.529 | [268.966, 302.227] | bootstrap_blocs | 256.07 | 259.201 | 723.36 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 290.149 | [261.287, 319.012] | bootstrap_blocs | 254.425 | 258.061 | 748.57 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 145.228 | [135.963, 154.67] | bootstrap_blocs | 132.4 | 137.232 | 1130.352 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 151.091 | [147.116, 155.066] | bootstrap_blocs | 130.43 | 132.781 | 1130.08 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 360.249 | [335.341, 379.631] | bootstrap_blocs | 331.345 | 473.192 | 1600.551 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 292.539 | [273.099, 311.485] | bootstrap_blocs | 266.07 | 275.231 | 756.029 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 350.891 | [333.227, 366.37] | bootstrap_blocs | 322.335 | 462.201 | 1595.452 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 277.695 | [264.505, 291.581] | bootstrap_blocs | 256.785 | 260.102 | 723.762 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 207.773 | [193.057, 222.488] | bootstrap_blocs | 202.11 | 217.78 | 347.517 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 154.835 | [142.274, 173.871] | bootstrap_blocs | 142.925 | 155.786 | 274.703 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 205.843 | [195.852, 223.276] | bootstrap_blocs | 193.86 | 218.644 | 1381.862 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 170.819 | [154.322, 186.306] | bootstrap_blocs | 133.69 | 139.582 | 1534.79 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 342.762 | [327.352, 357.885] | bootstrap_blocs | 321.21 | 458.18 | 602.694 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 301.747 | [277.686, 327.12] | bootstrap_blocs | 253.16 | 255.557 | 2255.191 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 208.99 | [195.15, 224.847] | bootstrap_blocs | 189.87 | 238.97 | 1380.419 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 142.214 | [130.306, 154.786] | bootstrap_blocs | 129.395 | 131.39 | 1127.787 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 291.904 | [272.926, 310.881] | bootstrap_blocs | 255.805 | 259.583 | 750.947 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 141.037 | [139.718, 142.357] | bootstrap_blocs | 132.21 | 137.001 | 257.961 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 745.61 | [722.938, 768.281] | bootstrap_blocs | 727.745 | 879.262 | 1168.345 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 304.758 | [277.475, 326.154] | bootstrap_blocs | 266.185 | 279.917 | 2509.965 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 714.956 | [696.487, 733.425] | bootstrap_blocs | 718.375 | 744.774 | 927.269 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 171.629 | [162.359, 182.817] | bootstrap_blocs | 142.39 | 153.485 | 1540.551 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 738.67 | [716.368, 760.972] | bootstrap_blocs | 711.53 | 876.441 | 1590.505 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 281.437 | [268.755, 294.118] | bootstrap_blocs | 253.31 | 254.721 | 737.83 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 715.057 | [700.905, 729.21] | bootstrap_blocs | 706.71 | 797.57 | 1314.761 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 156.159 | [140.425, 169.463] | bootstrap_blocs | 129.77 | 133.84 | 1529.773 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 138.822 | 209.332 | -33.7 |
| L1 | mldsa44 | P-256 | classique | 272.808 | 209.332 | 30.3 |
| L1 | ed25519 | x25519 | classique | 150.427 | 209.332 | -28.1 |
| L1 | mldsa44 | x25519 | classique | 275.271 | 209.332 | 31.5 |
| L1 | ed25519 | p256_hqc128 | hybride | 172.553 | 209.332 | -17.6 |
| L1 | mldsa44 | p256_hqc128 | hybride | 294.77 | 209.332 | 40.8 |
| L1 | ed25519 | p256_mlkem512 | hybride | 152.801 | 209.332 | -27.0 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 294.482 | 209.332 | 40.7 |
| L1 | ed25519 | x25519_hqc128 | hybride | 162.301 | 209.332 | -22.5 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 300.618 | 209.332 | 43.6 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 148.89 | 209.332 | -28.9 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 290.792 | 209.332 | 38.9 |
| L1 | ed25519 | hqc128 | pq_pur | 161.405 | 209.332 | -22.9 |
| L1 | mldsa44 | hqc128 | pq_pur | 313.57 | 209.332 | 49.8 |
| L1 | ed25519 | mlkem512 | pq_pur | 133.285 | 209.332 | -36.3 |
| L1 | mldsa44 | mlkem512 | pq_pur | 264.358 | 209.332 | 26.3 |
| L3 | mldsa65 | P-384 | classique | 286.529 | 218.249 | 31.3 |
| L3 | secp384r1 | P-384 | classique | 145.228 | 218.249 | -33.5 |
| L3 | mldsa65 | x448 | classique | 290.149 | 218.249 | 32.9 |
| L3 | secp384r1 | x448 | classique | 151.091 | 218.249 | -30.8 |
| L3 | mldsa65 | p384_hqc192 | hybride | 360.249 | 218.249 | 65.1 |
| L3 | secp384r1 | p384_hqc192 | hybride | 207.773 | 218.249 | -4.8 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 292.539 | 218.249 | 34.0 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 154.835 | 218.249 | -29.1 |
| L3 | mldsa65 | x448_hqc192 | hybride | 350.891 | 218.249 | 60.8 |
| L3 | secp384r1 | x448_hqc192 | hybride | 205.843 | 218.249 | -5.7 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 277.695 | 218.249 | 27.2 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 170.819 | 218.249 | -21.7 |
| L3 | mldsa65 | hqc192 | pq_pur | 342.762 | 218.249 | 57.1 |
| L3 | secp384r1 | hqc192 | pq_pur | 208.99 | 218.249 | -4.2 |
| L3 | mldsa65 | mlkem768 | pq_pur | 301.747 | 218.249 | 38.3 |
| L3 | secp384r1 | mlkem768 | pq_pur | 142.214 | 218.249 | -34.8 |
| L5 | mldsa87 | P-521 | classique | 291.904 | 216.471 | 34.8 |
| L5 | secp521r1 | P-521 | classique | 141.037 | 216.471 | -34.8 |
| L5 | mldsa87 | p521_hqc256 | hybride | 745.61 | 216.471 | 244.4 |
| L5 | secp521r1 | p521_hqc256 | hybride | 714.956 | 216.471 | 230.3 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 304.758 | 216.471 | 40.8 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 171.629 | 216.471 | -20.7 |
| L5 | mldsa87 | hqc256 | pq_pur | 738.67 | 216.471 | 241.2 |
| L5 | secp521r1 | hqc256 | pq_pur | 715.057 | 216.471 | 230.3 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 281.437 | 216.471 | 30.0 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 156.159 | 216.471 | -27.9 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.