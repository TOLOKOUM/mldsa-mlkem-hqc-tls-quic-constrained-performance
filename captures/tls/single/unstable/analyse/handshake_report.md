# Performance de handshake — captures/tls/single/unstable

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 1434.175 | [950.638, 2253.327] | bootstrap_blocs | 213.15 | 4112.15 | 14239.683 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 1251.877 | [1073.837, 1506.623] | bootstrap_blocs | 419.85 | 4362.119 | 13247.206 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 99.6 | 2469.791 | [2028.952, 2871.123] | bootstrap_blocs | 1012.775 | 8027.104 | 27940.663 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 2802.074 | [2077.477, 3526.671] | bootstrap_blocs | 617.485 | 13268.69 | 53487.245 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 99.8 | 2276.591 | [1630.456, 3129.306] | bootstrap_blocs | 695.0 | 7378.322 | 30910.875 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 99.4 | 1632.656 | [1165.39, 2101.805] | bootstrap_blocs | 229.35 | 4762.046 | 26465.467 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 99.8 | 2938.892 | [2505.003, 3599.014] | bootstrap_blocs | 676.9 | 7829.904 | 53264.231 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 1152.857 | [846.307, 1601.916] | bootstrap_blocs | 415.42 | 4118.958 | 8693.171 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 4499.221 | [3655.106, 5598.778] | bootstrap_blocs | 1108.495 | 19307.499 | 106372.157 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 99.4 | 3014.573 | [2555.667, 3570.124] | bootstrap_blocs | 829.59 | 11718.552 | 52688.004 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 99.8 | 5244.554 | [3619.265, 8093.197] | bootstrap_blocs | 1073.41 | 13141.787 | 63140.255 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 99.6 | 2505.464 | [2034.772, 3008.679] | bootstrap_blocs | 826.925 | 8417.576 | 29174.417 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 99.6 | 2816.424 | [2438.083, 3194.765] | bootstrap_blocs | 649.8 | 9508.295 | 30118.186 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 99.8 | 1175.313 | [1042.014, 1269.444] | bootstrap_blocs | 212.12 | 4081.834 | 13067.074 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 99.8 | 3617.063 | [3468.941, 3764.593] | bootstrap_blocs | 1083.01 | 14399.847 | 41574.937 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 99.6 | 3171.0 | [2631.145, 3735.543] | bootstrap_blocs | 621.065 | 9729.401 | 53900.661 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 99.6 | 9255.454 | [2501.709, 21775.557] | bootstrap_blocs | 1036.065 | 9324.396 | 53532.926 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 99.6 | 2586.181 | [1767.226, 3189.282] | bootstrap_blocs | 1009.92 | 8274.31 | 29565.077 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 99.4 | 1159.395 | [1022.632, 1312.957] | bootstrap_blocs | 226.17 | 4115.022 | 11326.418 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 1476.609 | [1048.466, 1894.161] | bootstrap_blocs | 218.03 | 4526.555 | 19979.42 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 99.2 | 6319.634 | [5430.696, 7020.473] | bootstrap_blocs | 1873.36 | 28419.217 | 105504.192 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 99.8 | 3647.981 | [3065.324, 4614.391] | bootstrap_blocs | 1049.48 | 13254.422 | 52671.773 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 99.4 | 5262.529 | [4326.29, 6142.241] | bootstrap_blocs | 1545.05 | 19571.5 | 106474.177 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 3665.98 | [2777.013, 4660.056] | bootstrap_blocs | 1019.7 | 14835.24 | 53479.589 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 98.8 | 3737.721 | [2545.736, 4752.953] | bootstrap_blocs | 1120.335 | 13372.318 | 54049.277 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 1957.043 | [1546.244, 2531.345] | bootstrap_blocs | 248.28 | 5604.381 | 27916.731 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 99.8 | 3175.736 | [2383.256, 3977.011] | bootstrap_blocs | 1093.99 | 9418.43 | 52510.382 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 2114.894 | [1361.327, 3466.958] | bootstrap_blocs | 224.22 | 5866.0 | 28496.677 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 99.0 | 4786.747 | [4012.956, 5569.974] | bootstrap_blocs | 1529.12 | 16405.396 | 59596.017 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 4745.582 | [2923.185, 7201.173] | bootstrap_blocs | 1051.63 | 14876.864 | 57626.271 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 99.6 | 3502.631 | [2980.582, 3868.236] | bootstrap_blocs | 1107.63 | 13424.161 | 54273.011 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 99.6 | 1561.271 | [1257.856, 1867.134] | bootstrap_blocs | 219.425 | 5355.851 | 12943.74 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 99.8 | 3563.268 | [2632.985, 4489.828] | bootstrap_blocs | 1031.26 | 13973.498 | 52930.239 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 99.8 | 1111.261 | [908.757, 1311.46] | bootstrap_blocs | 420.38 | 4339.984 | 13056.618 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 99.0 | 7150.632 | [5127.27, 9680.643] | bootstrap_blocs | 2316.47 | 28919.503 | 106734.413 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 99.4 | 3461.567 | [3136.987, 3784.844] | bootstrap_blocs | 1432.27 | 15280.012 | 29274.912 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 4611.059 | [4114.497, 5314.104] | bootstrap_blocs | 1386.995 | 17812.848 | 54555.341 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 99.8 | 1727.63 | [1432.355, 1939.31] | bootstrap_blocs | 628.81 | 6414.02 | 26367.682 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 98.2 | 7713.212 | [6753.92, 8830.875] | bootstrap_blocs | 2549.24 | 30432.765 | 68023.178 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 99.4 | 3964.394 | [2901.929, 4902.414] | bootstrap_blocs | 1470.18 | 14634.712 | 42205.628 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 99.2 | 5541.366 | [4616.128, 6093.805] | bootstrap_blocs | 1546.88 | 27743.237 | 106433.646 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 99.8 | 2300.169 | [2118.638, 2561.378] | bootstrap_blocs | 226.59 | 6423.182 | 52295.511 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 1434.175 | 1989.479 | -27.9 |
| L1 | mldsa44 | P-256 | classique | 2469.791 | 1989.479 | 24.1 |
| L1 | ed25519 | x25519 | classique | 1251.877 | 1989.479 | -37.1 |
| L1 | mldsa44 | x25519 | classique | 2802.074 | 1989.479 | 40.8 |
| L1 | ed25519 | p256_hqc128 | hybride | 2276.591 | 1989.479 | 14.4 |
| L1 | mldsa44 | p256_hqc128 | hybride | 4499.221 | 1989.479 | 126.2 |
| L1 | ed25519 | p256_mlkem512 | hybride | 1632.656 | 1989.479 | -17.9 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 3014.573 | 1989.479 | 51.5 |
| L1 | ed25519 | x25519_hqc128 | hybride | 2938.892 | 1989.479 | 47.7 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 5244.554 | 1989.479 | 163.6 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 1152.857 | 1989.479 | -42.1 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 2505.464 | 1989.479 | 25.9 |
| L1 | ed25519 | hqc128 | pq_pur | 2816.424 | 1989.479 | 41.6 |
| L1 | mldsa44 | hqc128 | pq_pur | 3617.063 | 1989.479 | 81.8 |
| L1 | ed25519 | mlkem512 | pq_pur | 1175.313 | 1989.479 | -40.9 |
| L1 | mldsa44 | mlkem512 | pq_pur | 3171.0 | 1989.479 | 59.4 |
| L3 | mldsa65 | P-384 | classique | 9255.454 | 3619.41 | 155.7 |
| L3 | secp384r1 | P-384 | classique | 1159.395 | 3619.41 | -68.0 |
| L3 | mldsa65 | x448 | classique | 2586.181 | 3619.41 | -28.5 |
| L3 | secp384r1 | x448 | classique | 1476.609 | 3619.41 | -59.2 |
| L3 | mldsa65 | p384_hqc192 | hybride | 6319.634 | 3619.41 | 74.6 |
| L3 | secp384r1 | p384_hqc192 | hybride | 3737.721 | 3619.41 | 3.3 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 3647.981 | 3619.41 | 0.8 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 1957.043 | 3619.41 | -45.9 |
| L3 | mldsa65 | x448_hqc192 | hybride | 5262.529 | 3619.41 | 45.4 |
| L3 | secp384r1 | x448_hqc192 | hybride | 3175.736 | 3619.41 | -12.3 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 3665.98 | 3619.41 | 1.3 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 2114.894 | 3619.41 | -41.6 |
| L3 | mldsa65 | hqc192 | pq_pur | 4786.747 | 3619.41 | 32.3 |
| L3 | secp384r1 | hqc192 | pq_pur | 3502.631 | 3619.41 | -3.2 |
| L3 | mldsa65 | mlkem768 | pq_pur | 4745.582 | 3619.41 | 31.1 |
| L3 | secp384r1 | mlkem768 | pq_pur | 1561.271 | 3619.41 | -56.9 |
| L5 | mldsa87 | P-521 | classique | 3563.268 | 2337.265 | 52.5 |
| L5 | secp521r1 | P-521 | classique | 1111.261 | 2337.265 | -52.5 |
| L5 | mldsa87 | p521_hqc256 | hybride | 7150.632 | 2337.265 | 205.9 |
| L5 | secp521r1 | p521_hqc256 | hybride | 4611.059 | 2337.265 | 97.3 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 3461.567 | 2337.265 | 48.1 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 1727.63 | 2337.265 | -26.1 |
| L5 | mldsa87 | hqc256 | pq_pur | 7713.212 | 2337.265 | 230.0 |
| L5 | secp521r1 | hqc256 | pq_pur | 5541.366 | 2337.265 | 137.1 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 3964.394 | 2337.265 | 69.6 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 2300.169 | 2337.265 | -1.6 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 1434.1752 | 2468.2463 | -1034.0712 | [-1460.5278, -607.6146] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 2816.274 | 3616.8983 | -800.6243 | [-1110.7425, -382.2868] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 1175.3576 | 3168.8403 | -1993.4827 | [-2557.928, -1525.7962] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 2275.6371 | 4499.2213 | -2223.5842 | [-3712.2047, -734.9636] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 1633.4054 | 3015.8046 | -1382.3991 | [-2251.6673, -510.4856] | oui | 0.125 | 0.125 |
| L1 | x25519 | 1251.8774 | 2802.0743 | -1550.1968 | [-2164.4834, -935.9103] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 2938.0735 | 5253.1267 | -2315.0532 | [-5486.4822, -260.2872] | oui | 0.25 | 0.125 |
| L1 | x25519_mlkem512 | 1152.857 | 2503.5812 | -1350.7242 | [-2081.0044, -577.3908] | oui | 0.125 | 0.125 |
| L3 | P-384 | 1158.8592 | 9229.3192 | -8070.46 | [-20636.7908, -1211.4549] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 3501.8454 | 4790.773 | -1288.9276 | [-2309.6619, -268.1933] | oui | 0.25 | 0.125 |
| L3 | mlkem768 | 1562.4949 | 4745.5817 | -3183.0868 | [-5867.2846, -1033.5022] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 3736.3553 | 6312.4758 | -2576.1205 | [-2854.4673, -2265.0823] | oui | 0.125 | 0.125 |
| L3 | p384_mlkem768 | 1957.0433 | 3646.7966 | -1689.7533 | [-2848.6959, -678.5306] | oui | 0.125 | 0.125 |
| L3 | x448 | 1476.6095 | 2587.8193 | -1111.2098 | [-2136.8269, 126.935] | non | 0.25 | 0.125 |
| L3 | x448_hqc192 | 3174.7141 | 5264.5555 | -2089.8414 | [-3538.9957, -747.8133] | oui | 0.125 | 0.125 |
| L3 | x448_mlkem768 | 2114.8937 | 3665.9799 | -1551.0862 | [-3080.3812, 56.5301] | non | 0.25 | 0.125 |
| L5 | P-521 | 1110.6304 | 3560.9278 | -2450.2974 | [-3355.8136, -1544.7813] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 5545.0363 | 7711.3712 | -2166.335 | [-3506.8552, -825.8147] | oui | 0.125 | 0.125 |
| L5 | mlkem1024 | 2300.1069 | 3963.8529 | -1663.746 | [-2363.3769, -709.4854] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 4611.0585 | 7137.5362 | -2526.4777 | [-5425.2667, 164.3854] | non | 0.25 | 0.125 |
| L5 | p521_mlkem1024 | 1727.6847 | 3461.0131 | -1733.3284 | [-2205.1363, -1269.0758] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.