# Performance de handshake — captures/quic/single/stable

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 99.8 | 354.512 | [301.977, 415.337] | bootstrap_blocs | 2.12 | 1126.767 | 3081.383 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 98.8 | 265.243 | [236.924, 301.754] | bootstrap_blocs | 1.9 | 1001.917 | 3000.671 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 342.303 | [318.333, 368.305] | bootstrap_blocs | 2.345 | 2074.462 | 4999.253 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 99.8 | 402.654 | [349.447, 438.293] | bootstrap_blocs | 2.1 | 2074.667 | 5078.408 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 112.658 | [105.034, 123.111] | bootstrap_blocs | 26.01 | 1019.495 | 2122.942 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 241.458 | [188.092, 310.571] | bootstrap_blocs | 9.675 | 1037.613 | 3007.225 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 139.959 | [98.208, 181.71] | bootstrap_blocs | 17.84 | 1023.903 | 1126.639 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 256.116 | [236.277, 280.027] | bootstrap_blocs | 3.46 | 1031.624 | 3001.961 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 184.481 | [155.925, 219.771] | bootstrap_blocs | 27.435 | 1085.889 | 2466.79 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 283.079 | [258.834, 307.323] | bootstrap_blocs | 9.73 | 2014.857 | 4006.038 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 150.273 | [127.742, 172.805] | bootstrap_blocs | 20.815 | 1063.711 | 2135.751 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 300.203 | [288.768, 309.362] | bootstrap_blocs | 3.85 | 2026.214 | 4027.328 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 83.324 | [63.522, 103.126] | bootstrap_blocs | 16.98 | 128.134 | 1090.042 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 99.8 | 253.195 | [226.265, 280.017] | bootstrap_blocs | 1.86 | 1055.889 | 3000.83 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 182.193 | [141.308, 230.336] | bootstrap_blocs | 18.395 | 1073.794 | 2123.166 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 411.194 | [348.787, 490.549] | bootstrap_blocs | 2.085 | 2089.053 | 5034.248 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 98.4 | 648.815 | [523.337, 823.102] | bootstrap_blocs | 5.165 | 3028.559 | 7100.825 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 99.8 | 635.12 | [589.884, 690.841] | bootstrap_blocs | 3.31 | 3028.774 | 5115.161 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 99.6 | 441.322 | [431.557, 455.191] | bootstrap_blocs | 5.545 | 3003.759 | 7001.047 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 99.6 | 299.377 | [258.117, 333.633] | bootstrap_blocs | 3.96 | 3000.91 | 6999.592 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 99.8 | 164.09 | [141.524, 186.746] | bootstrap_blocs | 58.76 | 1035.97 | 1208.841 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 428.297 | [364.406, 503.15] | bootstrap_blocs | 13.28 | 3006.727 | 4032.459 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 178.989 | [151.702, 209.797] | bootstrap_blocs | 53.545 | 1047.794 | 1490.022 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 550.207 | [502.196, 598.218] | bootstrap_blocs | 5.57 | 3001.651 | 4805.234 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 168.518 | [151.044, 179.863] | bootstrap_blocs | 55.255 | 1046.138 | 2125.596 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 219.176 | [176.411, 254.114] | bootstrap_blocs | 12.66 | 1040.106 | 3012.161 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 99.8 | 138.264 | [112.186, 163.228] | bootstrap_blocs | 50.48 | 1033.68 | 1110.667 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 99.8 | 232.777 | [161.146, 304.696] | bootstrap_blocs | 6.34 | 1032.247 | 3004.363 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 162.628 | [136.345, 188.911] | bootstrap_blocs | 48.045 | 1045.531 | 1150.355 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 99.8 | 473.624 | [428.848, 499.068] | bootstrap_blocs | 2.22 | 2999.146 | 4001.393 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 132.932 | [108.366, 176.644] | bootstrap_blocs | 46.395 | 528.025 | 1129.086 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 213.423 | [183.47, 249.39] | bootstrap_blocs | 3.425 | 1003.332 | 3000.586 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 99.6 | 719.385 | [638.32, 800.45] | bootstrap_blocs | 4.96 | 3029.778 | 7000.06 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 99.6 | 326.716 | [255.404, 397.457] | bootstrap_blocs | 5.32 | 1307.258 | 3005.003 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 260.599 | [217.224, 303.975] | bootstrap_blocs | 91.785 | 1113.296 | 3088.947 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 99.8 | 477.824 | [390.513, 582.37] | bootstrap_blocs | 12.88 | 3035.277 | 4256.011 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 221.818 | [188.905, 269.769] | bootstrap_blocs | 95.78 | 1059.053 | 1891.113 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 232.672 | [192.073, 273.272] | bootstrap_blocs | 12.72 | 1038.973 | 3011.184 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 204.796 | [184.504, 231.854] | bootstrap_blocs | 83.04 | 1074.562 | 1493.728 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 99.6 | 540.098 | [409.043, 671.153] | bootstrap_blocs | 2.47 | 3028.599 | 7025.72 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 163.333 | [148.176, 178.491] | bootstrap_blocs | 85.405 | 577.25 | 1081.022 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 268.994 | [198.498, 339.49] | bootstrap_blocs | 3.48 | 1030.857 | 3002.25 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 354.512 | 341.178 | 3.9 |
| L1 | mldsa44 | P-256 | classique | 342.303 | 341.178 | 0.3 |
| L1 | ed25519 | x25519 | classique | 265.243 | 341.178 | -22.3 |
| L1 | mldsa44 | x25519 | classique | 402.654 | 341.178 | 18.0 |
| L1 | ed25519 | p256_hqc128 | hybride | 112.658 | 341.178 | -67.0 |
| L1 | mldsa44 | p256_hqc128 | hybride | 184.481 | 341.178 | -45.9 |
| L1 | ed25519 | p256_mlkem512 | hybride | 241.458 | 341.178 | -29.2 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 283.079 | 341.178 | -17.0 |
| L1 | ed25519 | x25519_hqc128 | hybride | 139.959 | 341.178 | -59.0 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 150.273 | 341.178 | -56.0 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 256.116 | 341.178 | -24.9 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 300.203 | 341.178 | -12.0 |
| L1 | ed25519 | hqc128 | pq_pur | 83.324 | 341.178 | -75.6 |
| L1 | mldsa44 | hqc128 | pq_pur | 182.193 | 341.178 | -46.6 |
| L1 | ed25519 | mlkem512 | pq_pur | 253.195 | 341.178 | -25.8 |
| L1 | mldsa44 | mlkem512 | pq_pur | 411.194 | 341.178 | 20.5 |
| L3 | mldsa65 | P-384 | classique | 648.815 | 506.159 | 28.2 |
| L3 | secp384r1 | P-384 | classique | 441.322 | 506.159 | -12.8 |
| L3 | mldsa65 | x448 | classique | 635.12 | 506.159 | 25.5 |
| L3 | secp384r1 | x448 | classique | 299.377 | 506.159 | -40.9 |
| L3 | mldsa65 | p384_hqc192 | hybride | 164.09 | 506.159 | -67.6 |
| L3 | secp384r1 | p384_hqc192 | hybride | 168.518 | 506.159 | -66.7 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 428.297 | 506.159 | -15.4 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 219.176 | 506.159 | -56.7 |
| L3 | mldsa65 | x448_hqc192 | hybride | 178.989 | 506.159 | -64.6 |
| L3 | secp384r1 | x448_hqc192 | hybride | 138.264 | 506.159 | -72.7 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 550.207 | 506.159 | 8.7 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 232.777 | 506.159 | -54.0 |
| L3 | mldsa65 | hqc192 | pq_pur | 162.628 | 506.159 | -67.9 |
| L3 | secp384r1 | hqc192 | pq_pur | 132.932 | 506.159 | -73.7 |
| L3 | mldsa65 | mlkem768 | pq_pur | 473.624 | 506.159 | -6.4 |
| L3 | secp384r1 | mlkem768 | pq_pur | 213.423 | 506.159 | -57.8 |
| L5 | mldsa87 | P-521 | classique | 719.385 | 523.051 | 37.5 |
| L5 | secp521r1 | P-521 | classique | 326.716 | 523.051 | -37.5 |
| L5 | mldsa87 | p521_hqc256 | hybride | 260.599 | 523.051 | -50.2 |
| L5 | secp521r1 | p521_hqc256 | hybride | 221.818 | 523.051 | -57.6 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 477.824 | 523.051 | -8.6 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 232.672 | 523.051 | -55.5 |
| L5 | mldsa87 | hqc256 | pq_pur | 204.796 | 523.051 | -60.8 |
| L5 | secp521r1 | hqc256 | pq_pur | 163.333 | 523.051 | -68.8 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 540.098 | 523.051 | 3.3 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 268.994 | 523.051 | -48.6 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 354.421 | 342.3031 | 12.1179 | [-21.9279, 51.8208] | non | 0.625 | 0.125 |
| L1 | hqc128 | 83.324 | 182.1926 | -98.8686 | [-169.8647, -47.5186] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 253.1182 | 411.1941 | -158.0759 | [-210.7399, -107.2749] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 112.6579 | 184.4809 | -71.823 | [-113.6077, -37.2918] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 241.4579 | 283.0785 | -41.6207 | [-74.8723, 13.7204] | non | 0.25 | 0.125 |
| L1 | x25519 | 265.3971 | 402.6965 | -137.2994 | [-179.9105, -94.6884] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 139.9587 | 150.2734 | -10.3147 | [-52.3475, 45.0417] | non | 0.75 | 0.125 |
| L1 | x25519_mlkem512 | 256.1161 | 300.2028 | -44.0867 | [-59.8663, -19.5131] | oui | 0.125 | 0.125 |
| L3 | P-384 | 441.3019 | 649.4594 | -208.1575 | [-368.9578, -91.7801] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 132.9318 | 162.628 | -29.6962 | [-53.7117, -9.5747] | oui | 0.125 | 0.125 |
| L3 | mlkem768 | 213.4233 | 473.6572 | -260.2339 | [-315.3242, -180.9914] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 168.5185 | 164.1581 | 4.3603 | [-29.0521, 37.7728] | non | 0.875 | 0.125 |
| L3 | p384_mlkem768 | 219.1756 | 428.2966 | -209.121 | [-326.7389, -136.3043] | oui | 0.125 | 0.125 |
| L3 | x448 | 299.4544 | 635.0081 | -335.5537 | [-374.2084, -301.0811] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 138.2871 | 178.9892 | -40.7021 | [-98.8512, -6.8898] | oui | 0.125 | 0.125 |
| L3 | x448_mlkem768 | 233.0109 | 550.2069 | -317.196 | [-416.6441, -190.7996] | oui | 0.125 | 0.125 |
| L5 | P-521 | 326.4306 | 719.5002 | -393.0696 | [-561.5722, -269.4821] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 163.3332 | 204.7962 | -41.463 | [-84.4576, -8.7009] | oui | 0.25 | 0.125 |
| L5 | mlkem1024 | 268.994 | 540.1623 | -271.1683 | [-341.129, -165.8107] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 221.8184 | 260.5992 | -38.7808 | [-98.3753, 25.1036] | non | 0.375 | 0.125 |
| L5 | p521_mlkem1024 | 232.6723 | 477.6674 | -244.9951 | [-331.1245, -161.8301] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.