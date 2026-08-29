# Performance de handshake — captures/tls/single/stable

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 292.722 | [242.054, 345.343] | bootstrap_blocs | 2.415 | 1258.904 | 2039.877 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 285.082 | [256.278, 303.287] | bootstrap_blocs | 2.56 | 1224.833 | 1885.016 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 322.245 | [304.678, 339.813] | bootstrap_blocs | 2.505 | 1453.32 | 3327.292 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 328.917 | [260.816, 397.018] | bootstrap_blocs | 2.035 | 1431.376 | 4206.787 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 353.049 | [303.467, 405.529] | bootstrap_blocs | 26.395 | 1324.557 | 3087.358 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 298.464 | [245.346, 344.224] | bootstrap_blocs | 11.695 | 1284.244 | 3108.591 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 423.694 | [388.857, 456.825] | bootstrap_blocs | 20.06 | 1667.107 | 3323.638 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 305.793 | [243.477, 365.531] | bootstrap_blocs | 2.885 | 1076.465 | 3110.668 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 472.921 | [419.185, 520.049] | bootstrap_blocs | 27.42 | 2106.459 | 3525.463 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 330.715 | [287.14, 378.042] | bootstrap_blocs | 8.805 | 1497.47 | 2938.583 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 356.025 | [303.936, 399.654] | bootstrap_blocs | 32.91 | 1519.34 | 2133.198 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 306.423 | [280.514, 336.038] | bootstrap_blocs | 2.665 | 1447.651 | 2735.307 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 367.81 | [347.787, 390.552] | bootstrap_blocs | 21.565 | 1306.074 | 3125.105 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 277.25 | [259.497, 295.792] | bootstrap_blocs | 4.455 | 1235.728 | 2035.284 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 351.484 | [319.295, 396.065] | bootstrap_blocs | 20.33 | 1476.031 | 3321.801 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 384.287 | [319.463, 449.111] | bootstrap_blocs | 2.105 | 1473.396 | 3111.468 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 382.374 | [332.336, 432.412] | bootstrap_blocs | 4.67 | 1448.468 | 3492.809 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 362.892 | [328.715, 393.807] | bootstrap_blocs | 9.065 | 1631.818 | 3118.155 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 310.077 | [283.516, 336.638] | bootstrap_blocs | 5.45 | 1229.22 | 3057.541 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 268.95 | [210.423, 318.079] | bootstrap_blocs | 5.02 | 1085.304 | 2093.376 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 517.091 | [456.239, 568.657] | bootstrap_blocs | 62.84 | 1732.641 | 5427.334 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 288.308 | [276.675, 300.308] | bootstrap_blocs | 10.76 | 1296.148 | 2092.307 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 429.107 | [382.541, 473.356] | bootstrap_blocs | 53.455 | 1710.921 | 3325.516 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 373.48 | [323.444, 423.515] | bootstrap_blocs | 5.325 | 1484.477 | 4156.303 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 550.895 | [495.375, 642.667] | bootstrap_blocs | 61.46 | 1761.612 | 6429.428 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 313.852 | [245.667, 381.446] | bootstrap_blocs | 11.945 | 1253.218 | 3107.132 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 556.047 | [388.77, 778.283] | bootstrap_blocs | 55.15 | 1546.505 | 3353.361 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 270.784 | [221.768, 319.8] | bootstrap_blocs | 5.39 | 1255.883 | 2735.618 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 448.893 | [382.68, 486.355] | bootstrap_blocs | 55.495 | 1902.783 | 3207.973 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 395.202 | [344.203, 446.916] | bootstrap_blocs | 2.775 | 1676.106 | 4083.455 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 362.034 | [349.898, 372.548] | bootstrap_blocs | 51.23 | 1503.615 | 3210.868 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 269.539 | [243.286, 303.483] | bootstrap_blocs | 4.02 | 1254.891 | 2089.265 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 406.859 | [366.265, 447.454] | bootstrap_blocs | 4.995 | 1650.926 | 3087.587 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 294.935 | [259.981, 329.889] | bootstrap_blocs | 6.04 | 1214.455 | 2108.312 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 577.818 | [491.381, 658.547] | bootstrap_blocs | 140.015 | 2371.354 | 5968.462 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 443.998 | [341.627, 554.015] | bootstrap_blocs | 13.55 | 1495.247 | 4342.043 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 446.586 | [440.758, 457.485] | bootstrap_blocs | 94.1 | 1608.179 | 3182.111 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 255.255 | [214.551, 295.958] | bootstrap_blocs | 11.46 | 1276.65 | 2262.759 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 594.928 | [472.349, 751.381] | bootstrap_blocs | 87.67 | 2164.278 | 4722.263 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 378.614 | [354.345, 411.048] | bootstrap_blocs | 2.985 | 1661.885 | 3318.238 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 709.147 | [556.761, 910.981] | bootstrap_blocs | 91.105 | 1975.287 | 4733.436 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 283.961 | [247.725, 321.186] | bootstrap_blocs | 4.02 | 1435.075 | 2711.163 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 292.722 | 307.241 | -4.7 |
| L1 | mldsa44 | P-256 | classique | 322.245 | 307.241 | 4.9 |
| L1 | ed25519 | x25519 | classique | 285.082 | 307.241 | -7.2 |
| L1 | mldsa44 | x25519 | classique | 328.917 | 307.241 | 7.1 |
| L1 | ed25519 | p256_hqc128 | hybride | 353.049 | 307.241 | 14.9 |
| L1 | mldsa44 | p256_hqc128 | hybride | 472.921 | 307.241 | 53.9 |
| L1 | ed25519 | p256_mlkem512 | hybride | 298.464 | 307.241 | -2.9 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 330.715 | 307.241 | 7.6 |
| L1 | ed25519 | x25519_hqc128 | hybride | 423.694 | 307.241 | 37.9 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 356.025 | 307.241 | 15.9 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 305.793 | 307.241 | -0.5 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 306.423 | 307.241 | -0.3 |
| L1 | ed25519 | hqc128 | pq_pur | 367.81 | 307.241 | 19.7 |
| L1 | mldsa44 | hqc128 | pq_pur | 351.484 | 307.241 | 14.4 |
| L1 | ed25519 | mlkem512 | pq_pur | 277.25 | 307.241 | -9.8 |
| L1 | mldsa44 | mlkem512 | pq_pur | 384.287 | 307.241 | 25.1 |
| L3 | mldsa65 | P-384 | classique | 382.374 | 331.073 | 15.5 |
| L3 | secp384r1 | P-384 | classique | 310.077 | 331.073 | -6.3 |
| L3 | mldsa65 | x448 | classique | 362.892 | 331.073 | 9.6 |
| L3 | secp384r1 | x448 | classique | 268.95 | 331.073 | -18.8 |
| L3 | mldsa65 | p384_hqc192 | hybride | 517.091 | 331.073 | 56.2 |
| L3 | secp384r1 | p384_hqc192 | hybride | 550.895 | 331.073 | 66.4 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 288.308 | 331.073 | -12.9 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 313.852 | 331.073 | -5.2 |
| L3 | mldsa65 | x448_hqc192 | hybride | 429.107 | 331.073 | 29.6 |
| L3 | secp384r1 | x448_hqc192 | hybride | 556.047 | 331.073 | 68.0 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 373.48 | 331.073 | 12.8 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 270.784 | 331.073 | -18.2 |
| L3 | mldsa65 | hqc192 | pq_pur | 448.893 | 331.073 | 35.6 |
| L3 | secp384r1 | hqc192 | pq_pur | 362.034 | 331.073 | 9.4 |
| L3 | mldsa65 | mlkem768 | pq_pur | 395.202 | 331.073 | 19.4 |
| L3 | secp384r1 | mlkem768 | pq_pur | 269.539 | 331.073 | -18.6 |
| L5 | mldsa87 | P-521 | classique | 406.859 | 350.897 | 15.9 |
| L5 | secp521r1 | P-521 | classique | 294.935 | 350.897 | -15.9 |
| L5 | mldsa87 | p521_hqc256 | hybride | 577.818 | 350.897 | 64.7 |
| L5 | secp521r1 | p521_hqc256 | hybride | 446.586 | 350.897 | 27.3 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 443.998 | 350.897 | 26.5 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 255.255 | 350.897 | -27.3 |
| L5 | mldsa87 | hqc256 | pq_pur | 594.928 | 350.897 | 69.5 |
| L5 | secp521r1 | hqc256 | pq_pur | 709.147 | 350.897 | 102.1 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 378.614 | 350.897 | 7.9 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 283.961 | 350.897 | -19.1 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.