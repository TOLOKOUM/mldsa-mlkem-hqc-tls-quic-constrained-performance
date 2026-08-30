# Performance de handshake — captures/quic/single/unstable

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 95.0 | 917.419 | [840.592, 995.222] | bootstrap_blocs | 2.69 | 6996.538 | 7051.104 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 95.8 | 1064.999 | [821.406, 1269.295] | bootstrap_blocs | 2.38 | 6998.403 | 7997.455 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 98.4 | 1279.868 | [1134.747, 1532.734] | bootstrap_blocs | 84.18 | 5109.843 | 10456.684 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 96.2 | 1130.079 | [970.875, 1291.281] | bootstrap_blocs | 35.33 | 6235.37 | 8358.95 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 99.2 | 584.995 | [456.036, 720.734] | bootstrap_blocs | 33.685 | 3094.133 | 7034.785 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 97.4 | 732.252 | [710.41, 758.485] | bootstrap_blocs | 13.39 | 3011.491 | 7006.84 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 99.0 | 574.979 | [495.702, 635.725] | bootstrap_blocs | 26.05 | 3076.418 | 7095.506 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 98.0 | 749.391 | [650.225, 879.628] | bootstrap_blocs | 4.705 | 3002.391 | 7001.404 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 98.8 | 1105.834 | [967.145, 1289.992] | bootstrap_blocs | 80.575 | 6245.35 | 9274.728 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 98.4 | 1285.454 | [1217.797, 1322.677] | bootstrap_blocs | 72.665 | 6139.695 | 8912.586 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 98.6 | 1049.775 | [916.061, 1182.947] | bootstrap_blocs | 65.15 | 4932.184 | 8824.752 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 97.4 | 1408.03 | [1260.597, 1556.069] | bootstrap_blocs | 35.18 | 7002.882 | 9083.985 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 99.4 | 523.147 | [443.606, 604.341] | bootstrap_blocs | 23.21 | 3031.886 | 7029.607 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 97.2 | 901.687 | [764.61, 1044.292] | bootstrap_blocs | 2.555 | 3002.302 | 7196.098 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 98.4 | 1240.378 | [1095.676, 1478.319] | bootstrap_blocs | 86.26 | 7296.345 | 9746.286 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 96.8 | 1233.076 | [1055.175, 1353.626] | bootstrap_blocs | 34.055 | 7000.689 | 8836.737 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 90.8 | 1453.458 | [1371.79, 1533.32] | bootstrap_blocs | 39.875 | 7074.389 | 7673.316 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 95.0 | 1590.582 | [1270.564, 1788.075] | bootstrap_blocs | 57.71 | 5218.429 | 9951.475 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 94.4 | 1001.011 | [933.991, 1078.058] | bootstrap_blocs | 7.11 | 7000.217 | 7001.81 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 94.2 | 1051.029 | [880.656, 1217.822] | bootstrap_blocs | 5.5 | 7000.03 | 7301.493 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 99.0 | 766.013 | [705.843, 814.858] | bootstrap_blocs | 186.59 | 3468.155 | 7268.148 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 97.6 | 1460.15 | [1203.967, 1679.954] | bootstrap_blocs | 79.435 | 6839.846 | 9552.552 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 98.4 | 710.497 | [614.476, 840.477] | bootstrap_blocs | 171.165 | 3273.82 | 6239.11 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 97.4 | 1500.046 | [1386.861, 1618.089] | bootstrap_blocs | 89.44 | 6155.285 | 10180.732 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 99.0 | 594.904 | [481.012, 709.256] | bootstrap_blocs | 78.08 | 3059.636 | 7122.518 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 99.2 | 726.007 | [669.795, 782.674] | bootstrap_blocs | 14.52 | 3021.45 | 7007.014 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 99.2 | 597.865 | [561.879, 635.234] | bootstrap_blocs | 69.34 | 3053.865 | 7065.46 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 98.4 | 738.254 | [652.455, 822.669] | bootstrap_blocs | 8.615 | 3006.713 | 6999.895 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 98.6 | 861.379 | [725.988, 982.834] | bootstrap_blocs | 189.16 | 3734.772 | 7461.677 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 96.8 | 1404.29 | [1251.336, 1484.992] | bootstrap_blocs | 83.395 | 6930.169 | 10019.368 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 99.0 | 542.768 | [442.158, 619.98] | bootstrap_blocs | 56.88 | 3037.173 | 7139.883 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 98.4 | 693.021 | [482.984, 933.893] | bootstrap_blocs | 3.51 | 3001.774 | 6999.627 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 90.4 | 1506.021 | [1251.918, 1766.962] | bootstrap_blocs | 51.475 | 7028.347 | 7259.98 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 94.4 | 1026.742 | [946.808, 1157.282] | bootstrap_blocs | 7.3 | 7000.604 | 7003.173 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 98.6 | 805.086 | [784.908, 829.7] | bootstrap_blocs | 182.01 | 3288.806 | 7064.919 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 96.0 | 1722.647 | [1503.187, 1981.15] | bootstrap_blocs | 52.055 | 7181.354 | 10577.989 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 99.2 | 681.36 | [579.627, 764.197] | bootstrap_blocs | 152.68 | 3075.233 | 7130.592 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 98.8 | 922.58 | [791.375, 1055.927] | bootstrap_blocs | 18.295 | 3519.332 | 7011.857 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 98.8 | 903.243 | [828.963, 1001.35] | bootstrap_blocs | 241.73 | 3373.626 | 7301.466 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 95.0 | 1829.752 | [1790.404, 1870.252] | bootstrap_blocs | 83.98 | 7490.16 | 9961.665 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 99.0 | 784.988 | [712.985, 877.795] | bootstrap_blocs | 180.95 | 3098.494 | 7103.522 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 98.2 | 846.114 | [781.14, 915.44] | bootstrap_blocs | 4.81 | 3084.28 | 6999.876 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 917.419 | 1098.091 | -16.5 |
| L1 | mldsa44 | P-256 | classique | 1279.868 | 1098.091 | 16.6 |
| L1 | ed25519 | x25519 | classique | 1064.999 | 1098.091 | -3.0 |
| L1 | mldsa44 | x25519 | classique | 1130.079 | 1098.091 | 2.9 |
| L1 | ed25519 | p256_hqc128 | hybride | 584.995 | 1098.091 | -46.7 |
| L1 | mldsa44 | p256_hqc128 | hybride | 1105.834 | 1098.091 | 0.7 |
| L1 | ed25519 | p256_mlkem512 | hybride | 732.252 | 1098.091 | -33.3 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 1285.454 | 1098.091 | 17.1 |
| L1 | ed25519 | x25519_hqc128 | hybride | 574.979 | 1098.091 | -47.6 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 1049.775 | 1098.091 | -4.4 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 749.391 | 1098.091 | -31.8 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 1408.03 | 1098.091 | 28.2 |
| L1 | ed25519 | hqc128 | pq_pur | 523.147 | 1098.091 | -52.4 |
| L1 | mldsa44 | hqc128 | pq_pur | 1240.378 | 1098.091 | 13.0 |
| L1 | ed25519 | mlkem512 | pq_pur | 901.687 | 1098.091 | -17.9 |
| L1 | mldsa44 | mlkem512 | pq_pur | 1233.076 | 1098.091 | 12.3 |
| L3 | mldsa65 | P-384 | classique | 1453.458 | 1274.02 | 14.1 |
| L3 | secp384r1 | P-384 | classique | 1001.011 | 1274.02 | -21.4 |
| L3 | mldsa65 | x448 | classique | 1590.582 | 1274.02 | 24.8 |
| L3 | secp384r1 | x448 | classique | 1051.029 | 1274.02 | -17.5 |
| L3 | mldsa65 | p384_hqc192 | hybride | 766.013 | 1274.02 | -39.9 |
| L3 | secp384r1 | p384_hqc192 | hybride | 594.904 | 1274.02 | -53.3 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 1460.15 | 1274.02 | 14.6 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 726.007 | 1274.02 | -43.0 |
| L3 | mldsa65 | x448_hqc192 | hybride | 710.497 | 1274.02 | -44.2 |
| L3 | secp384r1 | x448_hqc192 | hybride | 597.865 | 1274.02 | -53.1 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 1500.046 | 1274.02 | 17.7 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 738.254 | 1274.02 | -42.1 |
| L3 | mldsa65 | hqc192 | pq_pur | 861.379 | 1274.02 | -32.4 |
| L3 | secp384r1 | hqc192 | pq_pur | 542.768 | 1274.02 | -57.4 |
| L3 | mldsa65 | mlkem768 | pq_pur | 1404.29 | 1274.02 | 10.2 |
| L3 | secp384r1 | mlkem768 | pq_pur | 693.021 | 1274.02 | -45.6 |
| L5 | mldsa87 | P-521 | classique | 1506.021 | 1266.381 | 18.9 |
| L5 | secp521r1 | P-521 | classique | 1026.742 | 1266.381 | -18.9 |
| L5 | mldsa87 | p521_hqc256 | hybride | 805.086 | 1266.381 | -36.4 |
| L5 | secp521r1 | p521_hqc256 | hybride | 681.36 | 1266.381 | -46.2 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 1722.647 | 1266.381 | 36.0 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 922.58 | 1266.381 | -27.1 |
| L5 | mldsa87 | hqc256 | pq_pur | 903.243 | 1266.381 | -28.7 |
| L5 | secp521r1 | hqc256 | pq_pur | 784.988 | 1266.381 | -38.0 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 1829.752 | 1266.381 | 44.5 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 846.114 | 1266.381 | -33.2 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 918.0747 | 1278.8828 | -360.8081 | [-650.0464, -162.1514] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 523.117 | 1239.294 | -716.177 | [-948.4342, -522.851] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 900.2933 | 1233.0761 | -332.7827 | [-566.9044, -98.6611] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 585.7195 | 1104.6605 | -518.941 | [-706.4769, -280.455] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 732.5439 | 1285.4151 | -552.8712 | [-610.6938, -457.5789] | oui | 0.125 | 0.125 |
| L1 | x25519 | 1063.7071 | 1130.898 | -67.1908 | [-201.0113, 66.6296] | non | 0.5 | 0.125 |
| L1 | x25519_hqc128 | 575.624 | 1049.4478 | -473.8238 | [-578.2889, -375.2359] | oui | 0.125 | 0.125 |
| L1 | x25519_mlkem512 | 751.1255 | 1408.2125 | -657.0869 | [-854.3076, -511.3919] | oui | 0.125 | 0.125 |
| L3 | P-384 | 1001.3102 | 1456.1224 | -454.8122 | [-592.69, -294.2693] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 542.956 | 861.2966 | -318.3405 | [-462.0608, -174.6203] | oui | 0.125 | 0.125 |
| L3 | mlkem768 | 695.0071 | 1404.9842 | -709.9771 | [-1000.3679, -314.7444] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 595.0654 | 765.921 | -170.8556 | [-278.8461, -68.1384] | oui | 0.125 | 0.125 |
| L3 | p384_mlkem768 | 726.2207 | 1460.9848 | -734.7641 | [-973.3629, -462.7028] | oui | 0.125 | 0.125 |
| L3 | x448 | 1049.1281 | 1593.4913 | -544.3632 | [-795.3934, -322.343] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 598.0616 | 709.2905 | -111.2289 | [-202.3604, -39.7343] | oui | 0.125 | 0.125 |
| L3 | x448_mlkem768 | 737.1499 | 1500.0129 | -762.863 | [-892.4771, -672.768] | oui | 0.125 | 0.125 |
| L5 | P-521 | 1026.639 | 1508.7442 | -482.1052 | [-712.0151, -286.1987] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 785.0189 | 902.9862 | -117.9673 | [-231.8192, -6.0836] | oui | 0.25 | 0.125 |
| L5 | mlkem1024 | 846.6774 | 1830.4184 | -983.741 | [-1052.9989, -885.7731] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 681.2375 | 805.1054 | -123.8678 | [-201.045, -68.2102] | oui | 0.125 | 0.125 |
| L5 | p521_mlkem1024 | 924.0073 | 1724.4698 | -800.4625 | [-986.4575, -637.2559] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.