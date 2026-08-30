# Performance de handshake — captures/tls/mutual/simple_loss1.5833_delay83.52ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 379.672 | [365.249, 394.094] | bootstrap_blocs | 354.845 | 361.692 | 1363.132 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 382.783 | [374.401, 392.024] | bootstrap_blocs | 352.115 | 357.293 | 1358.811 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 436.594 | [420.329, 456.327] | bootstrap_blocs | 390.27 | 576.368 | 1743.784 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 424.079 | [402.647, 447.018] | bootstrap_blocs | 387.395 | 555.566 | 1712.118 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 454.472 | [437.939, 476.907] | bootstrap_blocs | 407.975 | 752.516 | 1727.969 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 387.931 | [377.383, 405.949] | bootstrap_blocs | 364.92 | 370.03 | 1548.28 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 434.052 | [427.456, 443.377] | bootstrap_blocs | 390.7 | 759.093 | 1397.208 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 381.902 | [365.369, 394.94] | bootstrap_blocs | 356.0 | 363.774 | 1519.768 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 490.224 | [476.111, 510.697] | bootstrap_blocs | 431.835 | 665.546 | 1910.294 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 452.637 | [417.054, 486.347] | bootstrap_blocs | 399.145 | 635.838 | 1736.978 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 457.667 | [444.344, 470.99] | bootstrap_blocs | 411.56 | 590.615 | 1915.882 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 440.156 | [412.85, 467.462] | bootstrap_blocs | 391.125 | 729.071 | 1740.041 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 432.58 | [425.886, 439.275] | bootstrap_blocs | 399.705 | 567.389 | 1386.608 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 383.221 | [374.709, 393.471] | bootstrap_blocs | 352.675 | 357.178 | 1365.263 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 471.367 | [446.408, 496.325] | bootstrap_blocs | 420.66 | 615.964 | 1911.748 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 435.865 | [408.711, 477.848] | bootstrap_blocs | 387.64 | 596.055 | 1704.275 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 466.304 | [441.288, 502.219] | bootstrap_blocs | 401.385 | 774.374 | 1777.291 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 438.531 | [423.577, 452.349] | bootstrap_blocs | 399.11 | 715.749 | 1382.309 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 394.95 | [385.878, 401.174] | bootstrap_blocs | 366.105 | 379.712 | 1379.268 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 392.158 | [388.579, 396.302] | bootstrap_blocs | 362.38 | 369.799 | 1374.145 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 693.476 | [655.512, 746.839] | bootstrap_blocs | 626.55 | 960.382 | 1954.819 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 455.637 | [439.722, 464.498] | bootstrap_blocs | 408.785 | 609.83 | 1897.992 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 655.324 | [631.719, 679.765] | bootstrap_blocs | 621.17 | 793.106 | 1474.044 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 453.834 | [423.755, 488.581] | bootstrap_blocs | 403.66 | 613.2 | 1122.427 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 523.879 | [490.649, 567.66] | bootstrap_blocs | 456.57 | 815.423 | 1451.77 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 402.818 | [388.002, 417.634] | bootstrap_blocs | 376.33 | 384.065 | 1390.757 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 511.258 | [482.982, 563.807] | bootstrap_blocs | 452.33 | 714.986 | 1760.006 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 387.314 | [377.361, 397.267] | bootstrap_blocs | 367.46 | 380.024 | 1223.312 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 681.591 | [648.173, 725.025] | bootstrap_blocs | 623.24 | 877.704 | 1962.358 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 462.893 | [437.853, 492.986] | bootstrap_blocs | 399.57 | 621.921 | 1895.886 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 489.545 | [473.141, 517.488] | bootstrap_blocs | 443.31 | 805.795 | 1750.254 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 406.007 | [400.269, 411.746] | bootstrap_blocs | 362.42 | 524.53 | 1543.969 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 605.917 | [600.065, 613.292] | bootstrap_blocs | 573.735 | 748.084 | 1254.196 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 390.358 | [368.615, 412.102] | bootstrap_blocs | 370.14 | 383.741 | 1388.374 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 735.563 | [722.378, 748.748] | bootstrap_blocs | 679.39 | 997.989 | 1917.475 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 634.373 | [604.11, 674.461] | bootstrap_blocs | 590.41 | 756.311 | 1930.089 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 667.353 | [664.593, 671.81] | bootstrap_blocs | 645.44 | 666.029 | 1478.397 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 422.128 | [408.93, 435.327] | bootstrap_blocs | 380.615 | 552.598 | 1548.688 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 789.424 | [730.353, 875.104] | bootstrap_blocs | 699.23 | 1039.629 | 2166.242 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 609.528 | [590.68, 628.375] | bootstrap_blocs | 577.59 | 742.539 | 1929.127 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 727.515 | [667.638, 827.017] | bootstrap_blocs | 655.22 | 977.632 | 2010.934 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 393.014 | [385.175, 402.556] | bootstrap_blocs | 366.745 | 378.78 | 1220.143 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 379.672 | 405.782 | -6.4 |
| L1 | mldsa44 | P-256 | classique | 436.594 | 405.782 | 7.6 |
| L1 | ed25519 | x25519 | classique | 382.783 | 405.782 | -5.7 |
| L1 | mldsa44 | x25519 | classique | 424.079 | 405.782 | 4.5 |
| L1 | ed25519 | p256_hqc128 | hybride | 454.472 | 405.782 | 12.0 |
| L1 | mldsa44 | p256_hqc128 | hybride | 490.224 | 405.782 | 20.8 |
| L1 | ed25519 | p256_mlkem512 | hybride | 387.931 | 405.782 | -4.4 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 452.637 | 405.782 | 11.5 |
| L1 | ed25519 | x25519_hqc128 | hybride | 434.052 | 405.782 | 7.0 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 457.667 | 405.782 | 12.8 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 381.902 | 405.782 | -5.9 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 440.156 | 405.782 | 8.5 |
| L1 | ed25519 | hqc128 | pq_pur | 432.58 | 405.782 | 6.6 |
| L1 | mldsa44 | hqc128 | pq_pur | 471.367 | 405.782 | 16.2 |
| L1 | ed25519 | mlkem512 | pq_pur | 383.221 | 405.782 | -5.6 |
| L1 | mldsa44 | mlkem512 | pq_pur | 435.865 | 405.782 | 7.4 |
| L3 | mldsa65 | P-384 | classique | 466.304 | 422.986 | 10.2 |
| L3 | secp384r1 | P-384 | classique | 394.95 | 422.986 | -6.6 |
| L3 | mldsa65 | x448 | classique | 438.531 | 422.986 | 3.7 |
| L3 | secp384r1 | x448 | classique | 392.158 | 422.986 | -7.3 |
| L3 | mldsa65 | p384_hqc192 | hybride | 693.476 | 422.986 | 63.9 |
| L3 | secp384r1 | p384_hqc192 | hybride | 523.879 | 422.986 | 23.9 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 455.637 | 422.986 | 7.7 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 402.818 | 422.986 | -4.8 |
| L3 | mldsa65 | x448_hqc192 | hybride | 655.324 | 422.986 | 54.9 |
| L3 | secp384r1 | x448_hqc192 | hybride | 511.258 | 422.986 | 20.9 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 453.834 | 422.986 | 7.3 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 387.314 | 422.986 | -8.4 |
| L3 | mldsa65 | hqc192 | pq_pur | 681.591 | 422.986 | 61.1 |
| L3 | secp384r1 | hqc192 | pq_pur | 489.545 | 422.986 | 15.7 |
| L3 | mldsa65 | mlkem768 | pq_pur | 462.893 | 422.986 | 9.4 |
| L3 | secp384r1 | mlkem768 | pq_pur | 406.007 | 422.986 | -4.0 |
| L5 | mldsa87 | P-521 | classique | 605.917 | 498.138 | 21.6 |
| L5 | secp521r1 | P-521 | classique | 390.358 | 498.138 | -21.6 |
| L5 | mldsa87 | p521_hqc256 | hybride | 735.563 | 498.138 | 47.7 |
| L5 | secp521r1 | p521_hqc256 | hybride | 667.353 | 498.138 | 34.0 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 634.373 | 498.138 | 27.3 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 422.128 | 498.138 | -15.3 |
| L5 | mldsa87 | hqc256 | pq_pur | 789.424 | 498.138 | 58.5 |
| L5 | secp521r1 | hqc256 | pq_pur | 727.515 | 498.138 | 46.0 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 609.528 | 498.138 | 22.4 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 393.014 | 498.138 | -21.1 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 379.6716 | 436.5942 | -56.9226 | [-69.3739, -35.8287] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 432.5804 | 471.3667 | -38.7863 | [-61.789, -15.7837] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 383.2215 | 435.8654 | -52.6439 | [-103.1383, -15.7989] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 454.4718 | 490.2237 | -35.752 | [-40.9423, -30.5616] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 387.9307 | 452.6366 | -64.7059 | [-98.1988, -33.9624] | oui | 0.125 | 0.125 |
| L1 | x25519 | 382.783 | 424.0786 | -41.2957 | [-69.8409, -15.7318] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 434.0521 | 457.6672 | -23.6151 | [-30.3424, -16.8877] | oui | 0.125 | 0.125 |
| L1 | x25519_mlkem512 | 381.9022 | 440.1562 | -58.254 | [-73.4072, -43.9857] | oui | 0.125 | 0.125 |
| L3 | P-384 | 394.9505 | 466.3043 | -71.3538 | [-101.513, -45.8693] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 489.5453 | 681.5909 | -192.0456 | [-244.8791, -156.2258] | oui | 0.125 | 0.125 |
| L3 | mlkem768 | 406.0073 | 462.8927 | -56.8854 | [-84.8233, -29.8976] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 523.8787 | 693.4757 | -169.597 | [-178.7402, -162.9435] | oui | 0.125 | 0.125 |
| L3 | p384_mlkem768 | 402.8183 | 455.6366 | -52.8183 | [-74.688, -28.1981] | oui | 0.125 | 0.125 |
| L3 | x448 | 392.1577 | 438.5308 | -46.3731 | [-63.7953, -30.3722] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 511.2584 | 655.3243 | -144.0659 | [-169.6584, -115.1858] | oui | 0.125 | 0.125 |
| L3 | x448_mlkem768 | 387.3141 | 453.8338 | -66.5197 | [-92.9658, -40.0735] | oui | 0.125 | 0.125 |
| L5 | P-521 | 390.3584 | 605.9175 | -215.559 | [-238.8252, -192.2929] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 727.5154 | 789.4239 | -61.9085 | [-88.1927, -37.8061] | oui | 0.125 | 0.125 |
| L5 | mlkem1024 | 393.0137 | 609.5278 | -216.5141 | [-233.2471, -204.3051] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 667.3529 | 735.5633 | -68.2104 | [-79.3376, -55.9522] | oui | 0.125 | 0.125 |
| L5 | p521_mlkem1024 | 422.1283 | 634.3729 | -212.2447 | [-262.6305, -184.6832] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.