# Performance de handshake — captures/tls/mutual/stable

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 267.898 | [243.676, 292.12] | bootstrap_blocs | 6.245 | 1248.9 | 2267.278 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 339.579 | [304.947, 383.985] | bootstrap_blocs | 6.915 | 1225.294 | 2248.636 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 595.445 | [479.271, 748.036] | bootstrap_blocs | 23.38 | 1501.687 | 3363.869 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 406.113 | [349.79, 462.436] | bootstrap_blocs | 23.565 | 1698.894 | 3132.556 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 345.026 | [311.432, 378.62] | bootstrap_blocs | 28.52 | 1451.374 | 2323.657 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 279.644 | [270.821, 288.467] | bootstrap_blocs | 12.17 | 1243.808 | 2120.437 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 361.797 | [304.166, 402.615] | bootstrap_blocs | 23.61 | 1310.013 | 2086.667 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 275.742 | [238.194, 313.29] | bootstrap_blocs | 6.91 | 1293.375 | 2108.737 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 99.8 | 576.583 | [465.967, 737.582] | bootstrap_blocs | 48.03 | 1719.167 | 3598.048 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 396.912 | [288.001, 518.14] | bootstrap_blocs | 28.03 | 1494.536 | 3392.775 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 540.984 | [473.32, 646.941] | bootstrap_blocs | 39.56 | 1922.679 | 4124.693 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 377.77 | [306.902, 448.638] | bootstrap_blocs | 23.975 | 1497.089 | 3152.745 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 390.917 | [371.358, 420.261] | bootstrap_blocs | 23.62 | 1529.651 | 3169.104 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 304.321 | [253.612, 357.88] | bootstrap_blocs | 6.48 | 1452.374 | 3072.286 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 485.535 | [388.976, 596.286] | bootstrap_blocs | 38.95 | 1667.423 | 3364.102 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 458.395 | [372.895, 526.099] | bootstrap_blocs | 24.5 | 2080.069 | 4125.567 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 474.259 | [415.714, 527.494] | bootstrap_blocs | 33.91 | 1896.763 | 3776.227 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 432.402 | [394.436, 476.182] | bootstrap_blocs | 34.695 | 1532.449 | 3098.642 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 346.866 | [253.837, 439.895] | bootstrap_blocs | 10.195 | 1288.364 | 3069.823 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 263.692 | [229.302, 319.176] | bootstrap_blocs | 8.99 | 1077.488 | 2101.278 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 551.984 | [529.227, 581.298] | bootstrap_blocs | 87.28 | 1950.303 | 4222.388 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 389.032 | [363.914, 413.798] | bootstrap_blocs | 40.945 | 1522.114 | 3564.288 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 656.712 | [460.635, 904.872] | bootstrap_blocs | 83.67 | 1967.626 | 3787.212 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 437.36 | [359.722, 535.438] | bootstrap_blocs | 35.32 | 1494.821 | 3381.621 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 436.252 | [379.922, 490.83] | bootstrap_blocs | 61.075 | 1728.123 | 3235.631 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 306.791 | [289.97, 318.615] | bootstrap_blocs | 15.705 | 1296.032 | 3133.166 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 456.5 | [391.98, 521.02] | bootstrap_blocs | 57.515 | 1853.106 | 3369.915 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 314.613 | [293.929, 336.137] | bootstrap_blocs | 10.45 | 1439.472 | 2514.494 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 534.016 | [519.189, 556.402] | bootstrap_blocs | 76.86 | 2148.713 | 4251.779 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 489.59 | [397.59, 551.513] | bootstrap_blocs | 33.765 | 1899.195 | 3595.857 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 396.88 | [377.291, 420.588] | bootstrap_blocs | 53.635 | 1670.716 | 3143.211 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 293.566 | [266.033, 332.045] | bootstrap_blocs | 8.3 | 1283.372 | 3088.119 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 491.586 | [407.333, 585.673] | bootstrap_blocs | 49.38 | 1768.437 | 4198.796 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 301.14 | [264.863, 337.417] | bootstrap_blocs | 10.885 | 1251.297 | 2129.429 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 651.063 | [556.047, 783.796] | bootstrap_blocs | 136.995 | 1824.07 | 4698.613 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 475.546 | [406.385, 544.707] | bootstrap_blocs | 59.555 | 1890.795 | 3215.847 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 520.241 | [500.052, 550.577] | bootstrap_blocs | 102.955 | 1782.343 | 3836.993 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 313.285 | [261.95, 358.122] | bootstrap_blocs | 16.39 | 1443.205 | 3080.034 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 691.342 | [564.11, 818.575] | bootstrap_blocs | 147.545 | 2270.626 | 6490.395 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 431.6 | [370.358, 473.404] | bootstrap_blocs | 46.545 | 1501.259 | 3207.488 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 484.138 | [393.214, 610.611] | bootstrap_blocs | 93.825 | 1765.667 | 3449.086 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 302.423 | [188.223, 482.701] | bootstrap_blocs | 9.225 | 1451.344 | 2739.82 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 267.898 | 402.259 | -33.4 |
| L1 | mldsa44 | P-256 | classique | 595.445 | 402.259 | 48.0 |
| L1 | ed25519 | x25519 | classique | 339.579 | 402.259 | -15.6 |
| L1 | mldsa44 | x25519 | classique | 406.113 | 402.259 | 1.0 |
| L1 | ed25519 | p256_hqc128 | hybride | 345.026 | 402.259 | -14.2 |
| L1 | mldsa44 | p256_hqc128 | hybride | 576.583 | 402.259 | 43.3 |
| L1 | ed25519 | p256_mlkem512 | hybride | 279.644 | 402.259 | -30.5 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 396.912 | 402.259 | -1.3 |
| L1 | ed25519 | x25519_hqc128 | hybride | 361.797 | 402.259 | -10.1 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 540.984 | 402.259 | 34.5 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 275.742 | 402.259 | -31.5 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 377.77 | 402.259 | -6.1 |
| L1 | ed25519 | hqc128 | pq_pur | 390.917 | 402.259 | -2.8 |
| L1 | mldsa44 | hqc128 | pq_pur | 485.535 | 402.259 | 20.7 |
| L1 | ed25519 | mlkem512 | pq_pur | 304.321 | 402.259 | -24.3 |
| L1 | mldsa44 | mlkem512 | pq_pur | 458.395 | 402.259 | 14.0 |
| L3 | mldsa65 | P-384 | classique | 474.259 | 379.305 | 25.0 |
| L3 | secp384r1 | P-384 | classique | 346.866 | 379.305 | -8.6 |
| L3 | mldsa65 | x448 | classique | 432.402 | 379.305 | 14.0 |
| L3 | secp384r1 | x448 | classique | 263.692 | 379.305 | -30.5 |
| L3 | mldsa65 | p384_hqc192 | hybride | 551.984 | 379.305 | 45.5 |
| L3 | secp384r1 | p384_hqc192 | hybride | 436.252 | 379.305 | 15.0 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 389.032 | 379.305 | 2.6 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 306.791 | 379.305 | -19.1 |
| L3 | mldsa65 | x448_hqc192 | hybride | 656.712 | 379.305 | 73.1 |
| L3 | secp384r1 | x448_hqc192 | hybride | 456.5 | 379.305 | 20.4 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 437.36 | 379.305 | 15.3 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 314.613 | 379.305 | -17.1 |
| L3 | mldsa65 | hqc192 | pq_pur | 534.016 | 379.305 | 40.8 |
| L3 | secp384r1 | hqc192 | pq_pur | 396.88 | 379.305 | 4.6 |
| L3 | mldsa65 | mlkem768 | pq_pur | 489.59 | 379.305 | 29.1 |
| L3 | secp384r1 | mlkem768 | pq_pur | 293.566 | 379.305 | -22.6 |
| L5 | mldsa87 | P-521 | classique | 491.586 | 396.363 | 24.0 |
| L5 | secp521r1 | P-521 | classique | 301.14 | 396.363 | -24.0 |
| L5 | mldsa87 | p521_hqc256 | hybride | 651.063 | 396.363 | 64.3 |
| L5 | secp521r1 | p521_hqc256 | hybride | 520.241 | 396.363 | 31.3 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 475.546 | 396.363 | 20.0 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 313.285 | 396.363 | -21.0 |
| L5 | mldsa87 | hqc256 | pq_pur | 691.342 | 396.363 | 74.4 |
| L5 | secp521r1 | hqc256 | pq_pur | 484.138 | 396.363 | 22.1 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 431.6 | 396.363 | 8.9 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 302.423 | 396.363 | -23.7 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 267.8978 | 595.4451 | -327.5473 | [-455.8098, -217.6424] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 390.9172 | 485.5353 | -94.6181 | [-179.0437, -10.1924] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 304.3211 | 458.3954 | -154.0743 | [-238.1062, -70.0424] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 345.0262 | 576.3185 | -231.2923 | [-408.004, -129.885] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 279.6441 | 396.9117 | -117.2676 | [-247.344, -10.322] | oui | 0.25 | 0.125 |
| L1 | x25519 | 339.5793 | 406.1127 | -66.5334 | [-93.4581, -25.8749] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 361.7972 | 540.9838 | -179.1866 | [-256.0472, -102.326] | oui | 0.125 | 0.125 |
| L1 | x25519_mlkem512 | 275.742 | 377.7703 | -102.0283 | [-172.844, -31.2126] | oui | 0.125 | 0.125 |
| L3 | P-384 | 346.866 | 474.2594 | -127.3935 | [-254.6809, 11.3057] | non | 0.25 | 0.125 |
| L3 | hqc192 | 396.8796 | 534.0161 | -137.1365 | [-174.4081, -98.6007] | oui | 0.125 | 0.125 |
| L3 | mlkem768 | 293.5658 | 489.5904 | -196.0245 | [-271.717, -63.6617] | oui | 0.25 | 0.125 |
| L3 | p384_hqc192 | 436.2519 | 551.9835 | -115.7316 | [-159.3782, -63.6407] | oui | 0.125 | 0.125 |
| L3 | p384_mlkem768 | 306.791 | 389.0322 | -82.2412 | [-110.7907, -53.6917] | oui | 0.125 | 0.125 |
| L3 | x448 | 263.6923 | 432.4019 | -168.7095 | [-197.5649, -144.7813] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 456.5003 | 656.7117 | -200.2114 | [-481.9619, 48.1336] | non | 0.25 | 0.125 |
| L3 | x448_mlkem768 | 314.6135 | 437.3602 | -122.7467 | [-236.2355, -50.3819] | oui | 0.125 | 0.125 |
| L5 | P-521 | 301.1401 | 491.5859 | -190.4458 | [-239.8444, -148.8768] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 484.1384 | 691.3425 | -207.204 | [-386.7682, -111.5078] | oui | 0.125 | 0.125 |
| L5 | mlkem1024 | 302.4228 | 431.6003 | -129.1775 | [-234.7892, 37.5385] | non | 0.25 | 0.125 |
| L5 | p521_hqc256 | 520.2408 | 651.0633 | -130.8225 | [-274.5803, -21.5825] | oui | 0.125 | 0.125 |
| L5 | p521_mlkem1024 | 313.285 | 475.5458 | -162.2608 | [-272.2709, -52.2507] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.